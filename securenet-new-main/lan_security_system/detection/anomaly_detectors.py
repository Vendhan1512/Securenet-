"""
Anomaly-based detection components for identifying unusual network behavior patterns.
"""

import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import uuid
import logging
import threading

from scapy.all import ARP, DNS, Ether, IP
from scapy.packet import Packet

from ..core.interfaces import (
    BaseDetector, SecurityAlert, NetworkBaseline, AttackType, DetectionMethod,
    DetectionConfig
)


logger = logging.getLogger(__name__)


class ARPRateAnomalyDetector(BaseDetector):
    """Detector for ARP rate anomalies indicating potential attacks."""
    
    def __init__(self, config: DetectionConfig):
        self.arp_rate_threshold = config.arp_rate_threshold
        self.detection_window = timedelta(seconds=config.detection_window_size)
        self.arp_request_tracking: Dict[str, deque] = defaultdict(deque)  # IP -> timestamps
        self.baseline_arp_rates: Dict[str, float] = {}  # IP -> normal rate
        
    def detect(self, packet_data: bytes) -> Optional[SecurityAlert]:
        """Detect ARP rate anomalies by monitoring request frequencies."""
        try:
            packet = Ether(packet_data)
            
            # Only process ARP packets
            if not packet.haslayer(ARP):
                return None
                
            arp_layer = packet[ARP]
            
            # Only process ARP requests
            if arp_layer.op != 1:  # ARP request
                return None
                
            sender_ip = arp_layer.psrc
            current_time = datetime.now()
            
            # Track ARP request timestamps
            self.arp_request_tracking[sender_ip].append(current_time)
            
            # Clean old entries
            self._clean_old_entries(sender_ip, current_time)
            
            # Calculate current rate (requests per second)
            request_count = len(self.arp_request_tracking[sender_ip])
            time_span = self.detection_window.total_seconds()
            current_rate = request_count / time_span if time_span > 0 else 0
            
            # Check if rate exceeds threshold
            if current_rate > self.arp_rate_threshold:
                return self._create_alert(
                    packet_data, sender_ip, current_rate, self.arp_rate_threshold
                )
            
            # Check against baseline if available
            if sender_ip in self.baseline_arp_rates:
                baseline_rate = self.baseline_arp_rates[sender_ip]
                # Alert if current rate is significantly higher than baseline
                if current_rate > baseline_rate * 3:  # 3x baseline threshold
                    return self._create_alert(
                        packet_data, sender_ip, current_rate, baseline_rate
                    )
                    
            return None
            
        except Exception as e:
            logger.error(f"Error in ARP rate anomaly detection: {e}")
            return None
    
    def update_baseline(self, baseline: NetworkBaseline) -> None:
        """Update baseline ARP rates (would be calculated from historical data)."""
        # In a real implementation, this would calculate normal ARP rates
        # For now, we'll use a default baseline
        for ip in baseline.arp_table.keys():
            self.baseline_arp_rates[ip] = 2.0  # 2 requests per second as baseline
        logger.info(f"Updated ARP rate baseline for {len(self.baseline_arp_rates)} hosts")
    
    def _clean_old_entries(self, sender_ip: str, current_time: datetime) -> None:
        """Remove old ARP request timestamps outside detection window."""
        cutoff_time = current_time - self.detection_window
        while (self.arp_request_tracking[sender_ip] and 
               self.arp_request_tracking[sender_ip][0] < cutoff_time):
            self.arp_request_tracking[sender_ip].popleft()
    
    def _create_alert(self, packet_data: bytes, sender_ip: str, 
                     current_rate: float, threshold: float) -> SecurityAlert:
        """Create security alert for ARP rate anomaly."""
        packet = Ether(packet_data)
        return SecurityAlert(
            timestamp=datetime.now(),
            alert_id=str(uuid.uuid4()),
            attack_type=AttackType.ARP_SPOOFING,  # High ARP rate often indicates spoofing
            confidence_score=0.75,
            source_mac=packet.src if hasattr(packet, 'src') else "",
            source_ip=sender_ip,
            target_mac="",
            target_ip="",
            affected_hosts=[sender_ip],
            raw_packet_data=packet_data,
            detection_method=DetectionMethod.ANOMALY_BASED
        )


class CAMTableOverflowDetector(BaseDetector):
    """Detector for CAM table overflow conditions indicating MAC flooding."""
    
    def __init__(self, config: DetectionConfig):
        self.cam_table_threshold = config.cam_table_threshold
        self.detection_window = timedelta(seconds=config.detection_window_size)
        self.mac_learning_threshold = config.mac_learning_threshold
        
        # Simulate CAM table tracking
        self.simulated_cam_table: Dict[str, datetime] = {}  # MAC -> last seen
        self.cam_table_capacity = 8192  # Typical switch CAM table size
        self.mac_learning_rate: deque = deque()  # Track MAC learning rate
        self._lock = threading.Lock()  # Add thread lock for safety
        
    def detect(self, packet_data: bytes) -> Optional[SecurityAlert]:
        """Detect CAM table overflow by monitoring MAC learning patterns."""
        try:
            packet = Ether(packet_data)
            current_time = datetime.now()
            
            source_mac = packet.src
            
            with self._lock:
                # Update simulated CAM table
                is_new_mac = source_mac not in self.simulated_cam_table
                self.simulated_cam_table[source_mac] = current_time
                
                # Track new MAC learning rate
                if is_new_mac:
                    self.mac_learning_rate.append(current_time)
                
                # Clean old entries
                self._clean_old_entries(current_time)
                
                # Check CAM table utilization
                utilization = len(self.simulated_cam_table) / self.cam_table_capacity
                if utilization >= self.cam_table_threshold:
                    return self._create_alert(
                        packet_data, source_mac, utilization, len(self.simulated_cam_table)
                    )
                
                # Check MAC learning rate
                learning_rate = len(self.mac_learning_rate) / self.detection_window.total_seconds()
                if learning_rate > self.mac_learning_threshold:
                    return self._create_alert(
                        packet_data, source_mac, utilization, len(self.simulated_cam_table),
                        f"High MAC learning rate: {learning_rate:.2f} MACs/sec"
                    )
                
            return None
            
        except Exception as e:
            logger.error(f"Error in CAM table overflow detection: {e}")
            return None
    
    def update_baseline(self, baseline: NetworkBaseline) -> None:
        """Update baseline MAC-port mappings."""
        # Initialize CAM table with baseline mappings
        current_time = datetime.now()
        with self._lock:
            for mac in baseline.mac_port_mappings.keys():
                self.simulated_cam_table[mac] = current_time
        logger.info(f"Updated CAM table baseline with {len(baseline.mac_port_mappings)} entries")
    
    def _clean_old_entries(self, current_time: datetime) -> None:
        """Remove old MAC entries and learning rate timestamps.
        
        Note: Must be called with self._lock held.
        """
        # Clean CAM table entries (simulate aging)
        aging_time = timedelta(minutes=5)  # Typical CAM table aging time
        cutoff_time = current_time - aging_time
        
        # Create list of expired MACs to avoid "dictionary changed size during iteration"
        expired_macs = [
            mac for mac, timestamp in self.simulated_cam_table.items()
            if timestamp < cutoff_time
        ]
        for mac in expired_macs:
            del self.simulated_cam_table[mac]
        
        # Clean MAC learning rate tracking
        learning_cutoff = current_time - self.detection_window
        while (self.mac_learning_rate and 
               self.mac_learning_rate[0] < learning_cutoff):
            self.mac_learning_rate.popleft()
    
    def _create_alert(self, packet_data: bytes, source_mac: str, 
                     utilization: float, table_size: int, 
                     additional_info: str = "") -> SecurityAlert:
        """Create security alert for CAM table overflow."""
        return SecurityAlert(
            timestamp=datetime.now(),
            alert_id=str(uuid.uuid4()),
            attack_type=AttackType.MAC_FLOODING,
            confidence_score=0.8,
            source_mac=source_mac,
            source_ip="",
            target_mac="",
            target_ip="",
            affected_hosts=[f"cam_table_utilization_{utilization:.2f}"],
            raw_packet_data=packet_data,
            detection_method=DetectionMethod.ANOMALY_BASED
        )


class DNSAnomalyDetector(BaseDetector):
    """Detector for DNS anomalies including TTL and IP changes."""
    
    def __init__(self, config: DetectionConfig):
        self.ttl_variance_threshold = config.dns_ttl_variance_threshold
        self.detection_window = timedelta(seconds=config.detection_window_size)
        
        # Track DNS response patterns
        self.dns_response_tracking: Dict[str, List[Tuple[str, int, datetime]]] = defaultdict(list)  # Domain -> [(IP, TTL, timestamp)]
        self.baseline_dns_ttls: Dict[str, int] = {}  # Domain -> normal TTL
        
    def detect(self, packet_data: bytes) -> Optional[SecurityAlert]:
        """Detect DNS anomalies by monitoring TTL and IP changes."""
        try:
            packet = Ether(packet_data)
            
            # Only process DNS packets
            if not (packet.haslayer(IP) and packet.haslayer(DNS)):
                return None
                
            dns_layer = packet[DNS]
            ip_layer = packet[IP]
            
            # Only process DNS responses
            if dns_layer.qr != 1:  # DNS response
                return None
                
            current_time = datetime.now()
            
            # Process DNS answers
            if dns_layer.ancount > 0 and dns_layer.an:
                # Handle both single answer and list of answers
                answers = dns_layer.an if isinstance(dns_layer.an, list) else [dns_layer.an]
                
                for answer in answers:
                    if hasattr(answer, 'rrname') and hasattr(answer, 'rdata') and hasattr(answer, 'ttl'):
                        domain = answer.rrname.decode() if isinstance(answer.rrname, bytes) else str(answer.rrname)
                        ip_address = str(answer.rdata)
                        ttl = answer.ttl
                        
                        # Remove trailing dot from domain if present
                        domain = domain.rstrip('.')
                        
                        # Track response
                        self.dns_response_tracking[domain].append((ip_address, ttl, current_time))
                        
                        # Clean old entries
                        self._clean_old_entries(domain, current_time)
                        
                        # Check TTL anomalies
                        if domain in self.baseline_dns_ttls:
                            baseline_ttl = self.baseline_dns_ttls[domain]
                            ttl_variance = abs(ttl - baseline_ttl)
                            if ttl_variance > self.ttl_variance_threshold:
                                return self._create_alert(
                                    packet_data, domain, ip_address, ip_layer.src,
                                    f"Abnormal TTL variance: {ttl_variance}s"
                                )
                        
                        # Check for rapid IP changes
                        recent_responses = self.dns_response_tracking[domain]
                        if len(recent_responses) >= 3:
                            recent_ips = [ip for ip, _, _ in recent_responses[-3:]]
                            unique_ips = set(recent_ips)
                            if len(unique_ips) > 1:
                                return self._create_alert(
                                    packet_data, domain, ip_address, ip_layer.src,
                                    f"Rapid IP changes detected: {unique_ips}"
                                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error in DNS anomaly detection: {e}")
            return None
    
    def update_baseline(self, baseline: NetworkBaseline) -> None:
        """Update baseline DNS TTL values."""
        # In a real implementation, this would calculate normal TTL values
        # For now, we'll use default baselines
        for domain in baseline.dns_cache.keys():
            self.baseline_dns_ttls[domain] = 3600  # 1 hour default TTL
        logger.info(f"Updated DNS TTL baseline for {len(self.baseline_dns_ttls)} domains")
    
    def _clean_old_entries(self, domain: str, current_time: datetime) -> None:
        """Remove old DNS response entries outside detection window."""
        cutoff_time = current_time - self.detection_window
        self.dns_response_tracking[domain] = [
            (ip, ttl, timestamp) for ip, ttl, timestamp in self.dns_response_tracking[domain]
            if timestamp > cutoff_time
        ]
        if not self.dns_response_tracking[domain]:
            del self.dns_response_tracking[domain]
    
    def _create_alert(self, packet_data: bytes, domain: str, response_ip: str,
                     source_ip: str, anomaly_description: str) -> SecurityAlert:
        """Create security alert for DNS anomaly."""
        packet = Ether(packet_data)
        return SecurityAlert(
            timestamp=datetime.now(),
            alert_id=str(uuid.uuid4()),
            attack_type=AttackType.DNS_SPOOFING,
            confidence_score=0.7,
            source_mac=packet.src if hasattr(packet, 'src') else "",
            source_ip=source_ip,
            target_mac=packet.dst if hasattr(packet, 'dst') else "",
            target_ip="",
            affected_hosts=[domain],
            raw_packet_data=packet_data,
            detection_method=DetectionMethod.ANOMALY_BASED
        )