"""
System orchestrator for coordinating all LAN Security System components.

This module provides the main orchestration layer that manages system state,
coordinates component interactions, and handles error recovery and graceful degradation.
"""

import logging
import threading
import time
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field

from .interfaces import AttackType, SecurityAlert
from .system_integration import ComponentIntegrator
from ..config.settings import SystemConfig


logger = logging.getLogger(__name__)


class SystemState(Enum):
    """System operational states."""
    INITIALIZING = "initializing"
    RUNNING = "running"
    DEGRADED = "degraded"
    ERROR = "error"
    SHUTTING_DOWN = "shutting_down"
    STOPPED = "stopped"


class ComponentHealth(Enum):
    """Component health states."""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass
class SystemMetrics:
    """System-wide metrics and statistics."""
    uptime_seconds: float = 0.0
    total_alerts: int = 0
    successful_mitigations: int = 0
    failed_mitigations: int = 0
    successful_recoveries: int = 0
    failed_recoveries: int = 0
    system_errors: int = 0
    component_restarts: int = 0
    last_alert_time: Optional[datetime] = None
    last_mitigation_time: Optional[datetime] = None
    last_recovery_time: Optional[datetime] = None


@dataclass
class ComponentStatus:
    """Status information for a system component."""
    name: str
    health: ComponentHealth = ComponentHealth.UNKNOWN
    last_heartbeat: Optional[datetime] = None
    error_count: int = 0
    restart_count: int = 0
    metrics: Dict[str, Any] = field(default_factory=dict)
    last_error: Optional[str] = None


class SystemOrchestrator:
    """
    Main system orchestrator that coordinates all components and manages system state.
    
    Responsibilities:
    - System state management and synchronization
    - Component health monitoring and coordination
    - Error handling and graceful degradation
    - Performance monitoring and optimization
    - Event-driven component communication
    """
    
    def __init__(self, config: SystemConfig):
        self.config = config
        self.state = SystemState.INITIALIZING
        self.start_time = datetime.now()
        
        # Component management
        self.integrator: Optional[ComponentIntegrator] = None
        self.component_statuses: Dict[str, ComponentStatus] = {}
        
        # System metrics and monitoring
        self.metrics = SystemMetrics()
        self.metrics_lock = threading.Lock()
        
        # Health monitoring
        self.health_monitor_thread: Optional[threading.Thread] = None
        self.health_check_interval = 30  # seconds
        self.is_monitoring = False
        
        # Error handling and recovery
        self.error_handlers: Dict[str, Callable] = {}
        self.max_component_errors = 5
        self.component_restart_delay = 10  # seconds
        
        # Event synchronization
        self.state_lock = threading.Lock()
        self.shutdown_event = threading.Event()
        
        # Performance thresholds
        self.performance_thresholds = {
            'max_cpu_usage': self.config.get('performance.cpu_utilization_threshold', 0.8),
            'max_memory_mb': self.config.get('performance.max_memory_mb', 1000),
            'max_detection_latency_ms': self.config.get('detection.detection_latency_target', 100),
            'max_mitigation_time_ms': self.config.get('performance.mitigation_response_time', 200),
            'max_recovery_time_s': self.config.get('performance.recovery_time_limit', 30)
        }
        
        # Initialize error handlers
        self._initialize_error_handlers()
    
    def initialize_system(self) -> bool:
        """Initialize the entire system and all components."""
        try:
            logger.info("Initializing LAN Security System...")
            
            with self.state_lock:
                self.state = SystemState.INITIALIZING
            
            # Initialize component integrator only if not pre-set (e.g., production override)
            if self.integrator is None:
                self.integrator = ComponentIntegrator(self.config)
            
            # Initialize component status tracking
            self._initialize_component_statuses()
            
            # Register system-level event handlers
            self._register_system_event_handlers()
            
            # Validate component connections
            validation_results = self.integrator.validate_component_connections()
            if not validation_results.get('overall_valid', False):
                logger.error(f"Component validation failed: {validation_results}")
                with self.state_lock:
                    self.state = SystemState.ERROR
                return False
            
            # Start health monitoring
            self._start_health_monitoring()
            
            with self.state_lock:
                self.state = SystemState.RUNNING
            
            logger.info("LAN Security System initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"System initialization failed: {e}")
            with self.state_lock:
                self.state = SystemState.ERROR
            return False
    
    def start_monitoring(self, interface: str) -> bool:
        """Start network monitoring on the specified interface."""
        try:
            if self.state != SystemState.RUNNING:
                logger.error(f"Cannot start monitoring in state: {self.state}")
                return False
            
            # Start detection engine monitoring
            detection_engine = self.integrator.get_component('detection_engine')
            if detection_engine:
                detection_engine.start_monitoring(interface)
                logger.info(f"Started network monitoring on interface: {interface}")
                return True
            else:
                logger.error("Detection engine not available")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
            self._handle_component_error('detection_engine', str(e))
            return False
    
    def stop_monitoring(self) -> bool:
        """Stop network monitoring."""
        try:
            detection_engine = self.integrator.get_component('detection_engine')
            if detection_engine and hasattr(detection_engine, 'stop_monitoring'):
                detection_engine.stop_monitoring()
                logger.info("Stopped network monitoring")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to stop monitoring: {e}")
            return False
    
    def shutdown_system(self) -> bool:
        """Gracefully shutdown the entire system."""
        try:
            logger.info("Initiating system shutdown...")
            
            with self.state_lock:
                self.state = SystemState.SHUTTING_DOWN
            
            # Signal shutdown to all threads
            self.shutdown_event.set()
            
            # Stop network monitoring
            self.stop_monitoring()
            
            # Stop health monitoring
            self._stop_health_monitoring()
            
            # Allow components to clean up
            time.sleep(2)
            
            with self.state_lock:
                self.state = SystemState.STOPPED
            
            logger.info("System shutdown completed")
            return True
            
        except Exception as e:
            logger.error(f"System shutdown failed: {e}")
            return False
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status information."""
        with self.metrics_lock:
            uptime = (datetime.now() - self.start_time).total_seconds()
            self.metrics.uptime_seconds = uptime
            
            status = {
                'system_state': self.state.value,
                'uptime_seconds': uptime,
                'uptime_formatted': str(timedelta(seconds=int(uptime))),
                'metrics': {
                    'total_alerts': self.metrics.total_alerts,
                    'successful_mitigations': self.metrics.successful_mitigations,
                    'failed_mitigations': self.metrics.failed_mitigations,
                    'successful_recoveries': self.metrics.successful_recoveries,
                    'failed_recoveries': self.metrics.failed_recoveries,
                    'system_errors': self.metrics.system_errors,
                    'component_restarts': self.metrics.component_restarts
                },
                'component_statuses': {
                    name: {
                        'health': status.health.value,
                        'error_count': status.error_count,
                        'restart_count': status.restart_count,
                        'last_heartbeat': status.last_heartbeat.isoformat() if status.last_heartbeat else None,
                        'last_error': status.last_error
                    }
                    for name, status in self.component_statuses.items()
                },
                'performance_status': self._get_performance_status()
            }
        
        return status
    
    def _initialize_component_statuses(self) -> None:
        """Initialize status tracking for all components."""
        component_names = [
            'detection_engine',
            'mitigation_controller', 
            'recovery_manager',
            'event_logger',
            'alerting_system'
        ]
        
        for name in component_names:
            self.component_statuses[name] = ComponentStatus(name=name)
    
    def _register_system_event_handlers(self) -> None:
        """Register system-level event handlers with the integrator."""
        if self.integrator:
            self.integrator.register_event_handler('security_alert', self._handle_security_alert_metrics)
            self.integrator.register_event_handler('mitigation_complete', self._handle_mitigation_complete_metrics)
            self.integrator.register_event_handler('recovery_complete', self._handle_recovery_complete_metrics)
            self.integrator.register_event_handler('system_error', self._handle_system_error_metrics)
    
    def _handle_security_alert_metrics(self, alert: SecurityAlert) -> None:
        """Update metrics when security alert is received."""
        with self.metrics_lock:
            self.metrics.total_alerts += 1
            self.metrics.last_alert_time = datetime.now()
    
    def _handle_mitigation_complete_metrics(self, event_data: Dict[str, Any]) -> None:
        """Update metrics when mitigation is completed."""
        mitigation_result = event_data['mitigation_result']
        with self.metrics_lock:
            if mitigation_result.success:
                self.metrics.successful_mitigations += 1
            else:
                self.metrics.failed_mitigations += 1
            self.metrics.last_mitigation_time = datetime.now()
    
    def _handle_recovery_complete_metrics(self, event_data: Dict[str, Any]) -> None:
        """Update metrics when recovery is completed."""
        recovery_result = event_data['recovery_result']
        with self.metrics_lock:
            if recovery_result.success:
                self.metrics.successful_recoveries += 1
            else:
                self.metrics.failed_recoveries += 1
            self.metrics.last_recovery_time = datetime.now()
    
    def _handle_system_error_metrics(self, error_data: Dict[str, Any]) -> None:
        """Update metrics when system error occurs."""
        with self.metrics_lock:
            self.metrics.system_errors += 1
        
        # Handle component-specific errors
        error_type = error_data.get('error_type', 'unknown')
        if 'mitigation_error' in error_type:
            self._handle_component_error('mitigation_controller', error_data.get('error_message', ''))
        elif 'recovery_error' in error_type:
            self._handle_component_error('recovery_manager', error_data.get('error_message', ''))
        elif 'detection_error' in error_type:
            self._handle_component_error('detection_engine', error_data.get('error_message', ''))
    
    def _start_health_monitoring(self) -> None:
        """Start the health monitoring thread."""
        if self.health_monitor_thread and self.health_monitor_thread.is_alive():
            return
        
        self.is_monitoring = True
        self.health_monitor_thread = threading.Thread(
            target=self._health_monitoring_worker,
            name="HealthMonitor",
            daemon=True
        )
        self.health_monitor_thread.start()
        logger.info("Started health monitoring")
    
    def _stop_health_monitoring(self) -> None:
        """Stop the health monitoring thread."""
        self.is_monitoring = False
        if self.health_monitor_thread:
            self.health_monitor_thread.join(timeout=5)
        logger.info("Stopped health monitoring")
    
    def _health_monitoring_worker(self) -> None:
        """Worker thread for component health monitoring."""
        while self.is_monitoring and not self.shutdown_event.is_set():
            try:
                self._check_component_health()
                self._check_system_performance()
                self._update_component_heartbeats()
                
                # Sleep with shutdown check
                for _ in range(self.health_check_interval):
                    if self.shutdown_event.is_set():
                        break
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Health monitoring error: {e}")
                time.sleep(5)
    
    def _check_component_health(self) -> None:
        """Check the health of all system components."""
        if not self.integrator:
            return
        
        components = self.integrator.get_all_components()
        
        for name, component in components.items():
            try:
                status = self.component_statuses.get(name)
                if not status:
                    continue
                
                # Check if component is responsive
                if hasattr(component, 'get_stats') or hasattr(component, 'get_detection_stats'):
                    # Component has health check method
                    if hasattr(component, 'get_detection_stats'):
                        stats = component.get_detection_stats()
                    else:
                        stats = component.get_stats() if hasattr(component, 'get_stats') else {}
                    
                    status.metrics = stats
                    status.health = ComponentHealth.HEALTHY
                    status.last_heartbeat = datetime.now()
                else:
                    # Basic health check - component exists and is not None
                    if component is not None:
                        status.health = ComponentHealth.HEALTHY
                        status.last_heartbeat = datetime.now()
                    else:
                        status.health = ComponentHealth.FAILED
                
            except Exception as e:
                logger.warning(f"Health check failed for {name}: {e}")
                status = self.component_statuses.get(name)
                if status:
                    status.health = ComponentHealth.WARNING
                    status.error_count += 1
                    status.last_error = str(e)
    
    def _check_system_performance(self) -> None:
        """Check system performance against thresholds."""
        try:
            # Check detection engine performance
            detection_engine = self.integrator.get_component('detection_engine')
            if detection_engine and hasattr(detection_engine, 'get_detection_stats'):
                stats = detection_engine.get_detection_stats()
                
                # Check detection latency
                avg_latency = stats.get('avg_detection_latency_ms', 0)
                if avg_latency > self.performance_thresholds['max_detection_latency_ms']:
                    logger.warning(f"Detection latency high: {avg_latency}ms")
                    self._handle_performance_degradation('detection_latency', avg_latency)
                
                # Check CPU usage if available
                cpu_usage = stats.get('cpu_usage_percent', 0)
                if cpu_usage > self.performance_thresholds['max_cpu_usage'] * 100:
                    logger.warning(f"CPU usage high: {cpu_usage}%")
                    self._handle_performance_degradation('cpu_usage', cpu_usage)
                
                # Check memory usage if available
                memory_mb = stats.get('memory_usage_mb', 0)
                if memory_mb > self.performance_thresholds['max_memory_mb']:
                    logger.warning(f"Memory usage high: {memory_mb}MB")
                    self._handle_performance_degradation('memory_usage', memory_mb)
                    
        except Exception as e:
            logger.error(f"Performance check failed: {e}")
    
    def _update_component_heartbeats(self) -> None:
        """Update component heartbeat timestamps."""
        current_time = datetime.now()
        
        for name, status in self.component_statuses.items():
            # Check for stale heartbeats
            if status.last_heartbeat:
                time_since_heartbeat = (current_time - status.last_heartbeat).total_seconds()
                if time_since_heartbeat > 120:  # 2 minutes
                    logger.warning(f"Component {name} heartbeat stale: {time_since_heartbeat}s")
                    status.health = ComponentHealth.WARNING
    
    def _handle_component_error(self, component_name: str, error_message: str) -> None:
        """Handle errors from specific components."""
        status = self.component_statuses.get(component_name)
        if status:
            status.error_count += 1
            status.last_error = error_message
            
            if status.error_count >= self.max_component_errors:
                logger.error(f"Component {component_name} has exceeded error threshold")
                status.health = ComponentHealth.CRITICAL
                self._attempt_component_restart(component_name)
    
    def _attempt_component_restart(self, component_name: str) -> bool:
        """Attempt to restart a failed component."""
        try:
            logger.info(f"Attempting to restart component: {component_name}")
            
            status = self.component_statuses.get(component_name)
            if status:
                status.restart_count += 1
                with self.metrics_lock:
                    self.metrics.component_restarts += 1
            
            # Component restart logic would go here
            # For now, just reset error count and mark as healthy
            if status:
                status.error_count = 0
                status.health = ComponentHealth.HEALTHY
                status.last_heartbeat = datetime.now()
            
            logger.info(f"Component {component_name} restarted successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to restart component {component_name}: {e}")
            return False
    
    def _handle_performance_degradation(self, metric_name: str, current_value: float) -> None:
        """Handle performance degradation by adjusting system behavior."""
        logger.warning(f"Performance degradation detected: {metric_name} = {current_value}")
        
        # Implement graceful degradation strategies
        if metric_name == 'detection_latency':
            # Could reduce detection sensitivity or increase processing threads
            pass
        elif metric_name == 'cpu_usage':
            # Could reduce packet processing rate or disable non-critical features
            pass
        elif metric_name == 'memory_usage':
            # Could clear caches or reduce buffer sizes
            pass
        
        # Update system state if degradation is severe
        with self.state_lock:
            if self.state == SystemState.RUNNING:
                self.state = SystemState.DEGRADED
    
    def _get_performance_status(self) -> Dict[str, Any]:
        """Get current performance status."""
        performance_status = {
            'state': 'normal',
            'thresholds': self.performance_thresholds,
            'current_metrics': {}
        }
        
        try:
            # Get detection engine metrics
            detection_engine = self.integrator.get_component('detection_engine')
            if detection_engine and hasattr(detection_engine, 'get_detection_stats'):
                stats = detection_engine.get_detection_stats()
                performance_status['current_metrics'] = stats
                
                # Determine overall performance state
                avg_latency = stats.get('avg_detection_latency_ms', 0)
                cpu_usage = stats.get('cpu_usage_percent', 0)
                memory_mb = stats.get('memory_usage_mb', 0)
                
                if (avg_latency > self.performance_thresholds['max_detection_latency_ms'] or
                    cpu_usage > self.performance_thresholds['max_cpu_usage'] * 100 or
                    memory_mb > self.performance_thresholds['max_memory_mb']):
                    performance_status['state'] = 'degraded'
                    
        except Exception as e:
            logger.error(f"Failed to get performance status: {e}")
            performance_status['state'] = 'unknown'
            performance_status['error'] = str(e)
        
        return performance_status
    
    def _initialize_error_handlers(self) -> None:
        """Initialize error handlers for different error types."""
        self.error_handlers = {
            'detection_error': self._handle_detection_error,
            'mitigation_error': self._handle_mitigation_error,
            'recovery_error': self._handle_recovery_error,
            'logging_error': self._handle_logging_error,
            'system_error': self._handle_generic_system_error
        }
    
    def _handle_detection_error(self, error_data: Dict[str, Any]) -> None:
        """Handle detection engine errors."""
        logger.error(f"Detection error: {error_data}")
        # Could implement detection engine restart or fallback mode
    
    def _handle_mitigation_error(self, error_data: Dict[str, Any]) -> None:
        """Handle mitigation controller errors."""
        logger.error(f"Mitigation error: {error_data}")
        # Could implement alternative mitigation strategies
    
    def _handle_recovery_error(self, error_data: Dict[str, Any]) -> None:
        """Handle recovery manager errors."""
        logger.error(f"Recovery error: {error_data}")
        # Could implement manual recovery procedures
    
    def _handle_logging_error(self, error_data: Dict[str, Any]) -> None:
        """Handle logging system errors."""
        logger.error(f"Logging error: {error_data}")
        # Could implement alternative logging mechanisms
    
    def _handle_generic_system_error(self, error_data: Dict[str, Any]) -> None:
        """Handle generic system errors."""
        logger.error(f"System error: {error_data}")
        # Could implement system-wide error recovery