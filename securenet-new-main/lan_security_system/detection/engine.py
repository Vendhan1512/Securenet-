"""
Real-time detection engine with multi-threaded packet processing and alert generation.
"""

import threading
import time
import queue
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional, Any, Tuple
import logging

from scapy.all import sniff, get_if_list
from scapy.packet import Packet

from ..core.interfaces import (
    DetectionEngine, BaseDetector, SecurityAlert, NetworkBaseline, DetectionConfig, AttackType
)
from ..core.infrastructure_detector import get_infrastructure_detector
from .signature_detectors import ARPSpoofingDetector, MACFloodingDetector, DNSSpoofingDetector
from .anomaly_detectors import ARPRateAnomalyDetector, CAMTableOverflowDetector, DNSAnomalyDetector


logger = logging.getLogger(__name__)


class RealTimeDetectionEngine(DetectionEngine):
    """Real-time detection engine with multi-threaded packet processing."""
    
    def __init__(self, config: DetectionConfig):
        self.config = config
        self.detectors: List[BaseDetector] = []
        self.alert_callback: Optional[Callable[[SecurityAlert], None]] = None
        
        # Threading components
        # Use configurable queue size to handle bursty traffic (e.g., MAC floods)
        self.packet_queue = queue.Queue(maxsize=getattr(self.config, 'queue_maxsize', 10000))
        self.processing_threads: List[threading.Thread] = []
        self.is_running = False
        self.capture_thread: Optional[threading.Thread] = None
        
        # GLOBAL ALERT DEDUPLICATION CACHE (thread-safe)
        # Key: (source_ip, attack_type), Value: (alert_id, timestamp)
        self.alert_cache: Dict[Tuple[str, str], Tuple[str, datetime]] = {}
        self.alert_cache_lock = threading.Lock()
        self.alert_dedup_ttl = timedelta(seconds=60)  # Suppress duplicates for 60 seconds
        
        # Statistics tracking
        self.stats = {
            'packets_processed': 0,
            'alerts_generated': 0,
            'alerts_suppressed': 0,
            'processing_errors': 0,
            'queue_overflows': 0,
            'detection_latencies': [],
            'start_time': None,
            'last_packet_time': None
        }
        self.stats_lock = threading.Lock()
        
        # Performance monitoring
        self.performance_monitor = PerformanceMonitor(config)
        
        # Initialize default detectors
        self._initialize_default_detectors()
        
    def _initialize_default_detectors(self) -> None:
        """Initialize default signature and anomaly-based detectors."""
        # Signature-based detectors
        arp_detector = ARPSpoofingDetector()
        self.register_detector(arp_detector)
        self.register_detector(MACFloodingDetector(
            mac_threshold=self.config.mac_learning_threshold,
            time_window=self.config.detection_window_size
        ))
        
        # DNS detector (safe_mode is handled by MitigationController, not detector)
        dns_detector = DNSSpoofingDetector()
        if hasattr(self.config, 'trusted_dns_servers') and self.config.trusted_dns_servers:
            dns_detector.set_trusted_dns_servers(self.config.trusted_dns_servers)
        self.register_detector(dns_detector)
        
        # Anomaly-based detectors
        self.register_detector(ARPRateAnomalyDetector(self.config))
        self.register_detector(CAMTableOverflowDetector(self.config))
        self.register_detector(DNSAnomalyDetector(self.config))
        
        logger.info(f"Initialized {len(self.detectors)} detectors")
    
    def start_monitoring(self, interface: str) -> None:
        """Start monitoring network traffic on specified interface."""
        if self.is_running:
            logger.warning("Detection engine is already running")
            return
            
        # Validate interface
        available_interfaces = get_if_list()
        if interface not in available_interfaces:
            raise ValueError(f"Interface {interface} not found. Available: {available_interfaces}")
        
        self.is_running = True
        self.stats['start_time'] = datetime.now()
        
        # Start processing threads
        # Make thread count configurable; clamp to at least 1 and at most number of detectors
        configured_threads = getattr(self.config, 'processing_threads', 4)
        try:
            configured_threads = int(configured_threads)
        except Exception:
            configured_threads = 4
        num_threads = max(1, min(configured_threads, len(self.detectors)))
        for i in range(num_threads):
            thread = threading.Thread(
                target=self._packet_processing_worker,
                name=f"DetectionWorker-{i}",
                daemon=True
            )
            thread.start()
            self.processing_threads.append(thread)
        
        # Start packet capture thread
        self.capture_thread = threading.Thread(
            target=self._packet_capture_worker,
            args=(interface,),
            name="PacketCapture",
            daemon=True
        )
        self.capture_thread.start()
        
        # Start performance monitoring
        self.performance_monitor.start()
        
        logger.info(f"Started detection engine on interface {interface} with {num_threads} processing threads")
    
    def stop_monitoring(self) -> None:
        """Stop monitoring network traffic."""
        if not self.is_running:
            return
            
        self.is_running = False
        
        # Stop performance monitoring
        self.performance_monitor.stop()
        
        # Wait for threads to finish
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        
        for thread in self.processing_threads:
            thread.join(timeout=2)
        
        self.processing_threads.clear()
        self.capture_thread = None
        
        logger.info("Stopped detection engine")
    
    def reset_detection_state(self) -> None:
        """Reset detector state for self-healing after recovery (critical for next attack detection)."""
        try:
            # Reset all detector tracking state
            for detector in self.detectors:
                if hasattr(detector, 'reset_state'):
                    detector.reset_state()
            
            # Reset detection statistics (but keep historical data)
            with self.stats_lock:
                self.stats['queue_overflows'] = 0
                self.stats['processing_errors'] = 0
                # Keep counters for historical tracking
            
            # Clear the packet queue to remove stale data
            while not self.packet_queue.empty():
                try:
                    self.packet_queue.get_nowait()
                except:
                    pass
            
            # Clear alert deduplication cache (allow new detections after recovery)
            with self.alert_cache_lock:
                self.alert_cache.clear()
            
            logger.info("Detection engine state reset complete - ready for next attack detection")
        except Exception as e:
            logger.error(f"Failed to reset detection state: {e}")
    
    def _should_suppress_alert(self, source_ip: str, attack_type: AttackType) -> bool:
        """
        Check if alert should be suppressed (already alerted within TTL).
        
        GLOBAL DEDUPLICATION: (source_ip, attack_type) keyed cache with 60-second TTL.
        Prevents log spam from repeated attacks from same source.
        """
        cache_key = (source_ip, attack_type.value)
        now = datetime.now()
        
        with self.alert_cache_lock:
            if cache_key in self.alert_cache:
                cached_alert_id, cached_time = self.alert_cache[cache_key]
                age = now - cached_time
                
                if age < self.alert_dedup_ttl:
                    # Still within TTL - suppress this duplicate
                    with self.stats_lock:
                        self.stats['alerts_suppressed'] += 1
                    logger.debug(f"Alert suppressed (dedup): {attack_type.value} from {source_ip} "
                                f"(cached: {cached_alert_id}, age: {age.total_seconds():.1f}s)")
                    return True
                else:
                    # TTL expired - allow new alert
                    del self.alert_cache[cache_key]
        
        return False
    
    def _record_alert(self, source_ip: str, alert: SecurityAlert) -> None:
        """Record alert in deduplication cache."""
        cache_key = (source_ip, alert.attack_type.value)
        
        with self.alert_cache_lock:
            self.alert_cache[cache_key] = (alert.alert_id, datetime.now())
    
    def register_detector(self, detector: BaseDetector) -> None:
        """Register a detector component."""
        self.detectors.append(detector)
        logger.info(f"Registered detector: {detector.__class__.__name__}")
    
    def set_alert_callback(self, callback: Callable[[SecurityAlert], None]) -> None:
        """Set callback function for alert notifications."""
        self.alert_callback = callback
        logger.info("Alert callback registered")
    
    def update_baseline(self, baseline: NetworkBaseline) -> None:
        """Update baseline for all detectors."""
        for detector in self.detectors:
            detector.update_baseline(baseline)
        logger.info("Updated baseline for all detectors")
    
    def get_detection_stats(self) -> Dict[str, Any]:
        """Get detection engine statistics."""
        with self.stats_lock:
            stats = self.stats.copy()
            
        # Calculate derived statistics
        if stats['start_time']:
            runtime = (datetime.now() - stats['start_time']).total_seconds()
            stats['runtime_seconds'] = runtime
            stats['packets_per_second'] = stats['packets_processed'] / runtime if runtime > 0 else 0
            stats['alerts_per_second'] = stats['alerts_generated'] / runtime if runtime > 0 else 0
        
        # Calculate average detection latency
        if stats['detection_latencies']:
            stats['avg_detection_latency_ms'] = sum(stats['detection_latencies']) / len(stats['detection_latencies'])
            stats['max_detection_latency_ms'] = max(stats['detection_latencies'])
        else:
            stats['avg_detection_latency_ms'] = 0
            stats['max_detection_latency_ms'] = 0
        
        # Add performance metrics
        stats.update(self.performance_monitor.get_metrics())
        
        return stats
    
    def _packet_capture_worker(self, interface: str) -> None:
        """Worker thread for packet capture."""
        def packet_handler(packet):
            if not self.is_running:
                return
                
            try:
                # Convert packet to bytes
                packet_data = bytes(packet)
                
                # Add to processing queue
                try:
                    self.packet_queue.put((packet_data, datetime.now()), block=False)
                except queue.Full:
                    with self.stats_lock:
                        self.stats['queue_overflows'] += 1
                    logger.warning("Packet queue overflow - dropping packet")
                    
            except Exception as e:
                logger.error(f"Error in packet handler: {e}")
        
        try:
            # Start packet capture
            sniff(
                iface=interface,
                prn=packet_handler,
                stop_filter=lambda x: not self.is_running,
                store=False
            )
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            self.is_running = False
    
    def _packet_processing_worker(self) -> None:
        """Worker thread for packet processing and detection."""
        while self.is_running:
            try:
                # Get packet from queue with timeout
                try:
                    packet_data, capture_time = self.packet_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                
                processing_start = datetime.now()
                
                # Process packet through all detectors
                for detector in self.detectors:
                    try:
                        alert = detector.detect(packet_data)
                        if alert:
                            # GLOBAL DEDUPLICATION: Check alert cache before generating alert
                            if self._should_suppress_alert(alert.source_ip, alert.attack_type):
                                continue  # Skip this alert - duplicate suppressed
                            
                            # Calculate detection latency
                            detection_latency = (datetime.now() - capture_time).total_seconds() * 1000
                            
                            # Record alert in cache for deduplication
                            self._record_alert(alert.source_ip, alert)
                            
                            with self.stats_lock:
                                self.stats['alerts_generated'] += 1
                                self.stats['detection_latencies'].append(detection_latency)
                                
                                # Keep only recent latencies for average calculation
                                if len(self.stats['detection_latencies']) > 1000:
                                    self.stats['detection_latencies'] = self.stats['detection_latencies'][-500:]
                            
                            # Send alert through callback
                            if self.alert_callback:
                                try:
                                    self.alert_callback(alert)
                                except Exception as e:
                                    logger.error(f"Error in alert callback: {e}")
                            
                            logger.info(f"Alert generated: {alert.attack_type.value} from {alert.source_ip}")
                            
                    except Exception as e:
                        with self.stats_lock:
                            self.stats['processing_errors'] += 1
                        logger.error(f"Error in detector {detector.__class__.__name__}: {e}")
                
                # Update statistics
                with self.stats_lock:
                    self.stats['packets_processed'] += 1
                    self.stats['last_packet_time'] = datetime.now()
                
                # Update performance monitoring
                processing_time = (datetime.now() - processing_start).total_seconds() * 1000
                self.performance_monitor.record_processing_time(processing_time)
                
                self.packet_queue.task_done()
                
            except Exception as e:
                logger.error(f"Error in packet processing worker: {e}")


class PerformanceMonitor:
    """Performance monitoring for the detection engine."""
    
    def __init__(self, config: DetectionConfig):
        self.config = config
        self.is_running = False
        self.monitor_thread: Optional[threading.Thread] = None
        
        # Performance metrics
        self.metrics = {
            'cpu_usage_percent': 0.0,
            'memory_usage_mb': 0.0,
            'processing_times_ms': [],
            'queue_size': 0,
            'false_positive_rate': 0.0,
            'detection_accuracy': 0.0
        }
        self.metrics_lock = threading.Lock()
        
    def start(self) -> None:
        """Start performance monitoring."""
        if self.is_running:
            return
            
        self.is_running = True
        self.monitor_thread = threading.Thread(
            target=self._monitoring_worker,
            name="PerformanceMonitor",
            daemon=True
        )
        self.monitor_thread.start()
        logger.info("Started performance monitoring")
    
    def stop(self) -> None:
        """Stop performance monitoring."""
        if not self.is_running:
            return
            
        self.is_running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        logger.info("Stopped performance monitoring")
    
    def record_processing_time(self, processing_time_ms: float) -> None:
        """Record packet processing time."""
        with self.metrics_lock:
            self.metrics['processing_times_ms'].append(processing_time_ms)
            # Keep only recent processing times
            if len(self.metrics['processing_times_ms']) > 1000:
                self.metrics['processing_times_ms'] = self.metrics['processing_times_ms'][-500:]
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics."""
        with self.metrics_lock:
            metrics = self.metrics.copy()
        
        # Calculate derived metrics
        if metrics['processing_times_ms']:
            metrics['avg_processing_time_ms'] = sum(metrics['processing_times_ms']) / len(metrics['processing_times_ms'])
            metrics['max_processing_time_ms'] = max(metrics['processing_times_ms'])
        else:
            metrics['avg_processing_time_ms'] = 0
            metrics['max_processing_time_ms'] = 0
        
        return metrics
    
    def _monitoring_worker(self) -> None:
        """Worker thread for performance monitoring."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        
        while self.is_running:
            try:
                # Monitor CPU and memory usage
                cpu_percent = process.cpu_percent()
                memory_info = process.memory_info()
                memory_mb = memory_info.rss / 1024 / 1024
                
                with self.metrics_lock:
                    self.metrics['cpu_usage_percent'] = cpu_percent
                    self.metrics['memory_usage_mb'] = memory_mb
                
                # Check performance thresholds
                if cpu_percent > 80:
                    logger.warning(f"High CPU usage detected: {cpu_percent:.1f}%")
                
                if memory_mb > 1000:  # 1GB threshold
                    logger.warning(f"High memory usage detected: {memory_mb:.1f}MB")
                
                time.sleep(5)  # Monitor every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in performance monitoring: {e}")
                time.sleep(5)