"""
Production system integration module without attack simulation.

This module provides component integration for production deployment,
excluding attack simulation capabilities and focusing on core security functions.
"""

import logging
import threading
from typing import Dict, Any, Optional, Callable
from datetime import datetime

from .interfaces import (
    DetectionEngine, MitigationController, RecoveryManager, LoggingSystem,
    SecurityAlert, MitigationResult, RecoveryResult, AttackType
)
from ..detection.engine import RealTimeDetectionEngine
from ..mitigation.controller import AutomatedMitigationController
from ..recovery.manager import NetworkRecoveryManager
from ..event_logging.event_logger import StructuredEventLogger
from ..event_logging.alerting_system import AlertingSystem
from ..config.settings import SystemConfig


logger = logging.getLogger(__name__)


class ProductionComponentIntegrator:
    """
    Production component integrator without attack simulation capabilities.
    
    This class manages the connections between core security components:
    - Detection Engine -> Mitigation Controller
    - Mitigation Controller -> Recovery Manager
    - All components -> Logging System
    
    Attack simulation is excluded for production deployment.
    """
    
    def __init__(self, config: SystemConfig):
        self.config = config
        self._components: Dict[str, Any] = {}
        self._event_handlers: Dict[str, list] = {
            'security_alert': [],
            'mitigation_complete': [],
            'recovery_complete': [],
            'system_error': []
        }
        self._integration_lock = threading.Lock()
        
        # Ensure production mode
        self.config.set('system.production_mode', True)
        self.config.set('system.attack_simulation_enabled', False)
        
        # Initialize production components only
        self._initialize_production_components()
        
        # Wire components together
        self._wire_production_components()
    
    def _initialize_production_components(self) -> None:
        """Initialize only production-ready security components."""
        try:
            logger.info("Initializing production security components...")
            
            # Initialize detection engine for real network monitoring
            from ..core.interfaces import DetectionConfig
            detection_config = DetectionConfig(
                arp_rate_threshold=self.config.get('detection.arp_rate_threshold', 10),
                mac_learning_threshold=self.config.get('detection.mac_learning_threshold', 50),
                cam_table_threshold=self.config.get('detection.cam_table_threshold', 0.9),
                dns_ttl_variance_threshold=self.config.get('detection.dns_ttl_variance_threshold', 300),
                detection_window_size=self.config.get('detection.detection_window_size', 60),
                detection_latency_target=self.config.get('detection.detection_latency_target', 100),
                false_positive_threshold=self.config.get('detection.false_positive_threshold', 0.05),
                dns_safe_mode=self.config.get('detection.dns_safe_mode', True),
                processing_threads=self.config.get('performance.processing_threads', 4),
                queue_maxsize=self.config.get('performance.queue_maxsize', 10000),
                excluded_source_ips=self.config.get('detection.excluded_source_ips', []) or [],
                trusted_dns_servers=self.config.get('detection.trusted_dns_servers', []) or []
            )
            self._components['detection_engine'] = RealTimeDetectionEngine(detection_config)
            
            # Initialize mitigation controller for automated response
            self._components['mitigation_controller'] = AutomatedMitigationController(
                dns_safe_mode=self.config.get('detection.dns_safe_mode', True)
            )
            
            # Initialize recovery manager for network restoration
            # Production mode: real network operations, not simulation
            self._components['recovery_manager'] = NetworkRecoveryManager(simulation_mode=False)
            
            # Initialize logging system for audit trails
            log_directory = self.config.get('logging.log_directory', 'logs')
            max_file_size = self.config.get('logging.max_file_size', 10 * 1024 * 1024)
            self._components['event_logger'] = StructuredEventLogger(log_directory, max_file_size)
            
            # Initialize alerting system for real-time notifications
            self._components['alerting_system'] = AlertingSystem()
            
            logger.info("Production security components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize production components: {e}")
            raise
    
    def _wire_production_components(self) -> None:
        """Wire production components together with event-driven communication."""
        try:
            logger.info("Wiring production components...")
            
            # Wire detection engine to mitigation controller
            detection_engine = self._components['detection_engine']
            detection_engine.set_alert_callback(self._handle_security_alert)
            
            # Register event handlers for production workflow
            self.register_event_handler('security_alert', self._handle_security_alert_logging)
            self.register_event_handler('security_alert', self._handle_security_alert_mitigation)
            
            self.register_event_handler('mitigation_complete', self._handle_mitigation_complete_logging)
            self.register_event_handler('mitigation_complete', self._handle_mitigation_complete_recovery)
            
            self.register_event_handler('recovery_complete', self._handle_recovery_complete_logging)
            
            self.register_event_handler('system_error', self._handle_system_error_logging)
            
            logger.info("Production component wiring completed successfully")
            
        except Exception as e:
            logger.error(f"Failed to wire production components: {e}")
            raise
    
    def register_event_handler(self, event_type: str, handler: Callable) -> None:
        """Register an event handler for a specific event type."""
        with self._integration_lock:
            if event_type not in self._event_handlers:
                self._event_handlers[event_type] = []
            self._event_handlers[event_type].append(handler)
            logger.debug(f"Registered production event handler for {event_type}")
    
    def emit_event(self, event_type: str, event_data: Any) -> None:
        """Emit an event to all registered handlers."""
        with self._integration_lock:
            handlers = self._event_handlers.get(event_type, [])
        
        for handler in handlers:
            try:
                handler(event_data)
            except Exception as e:
                logger.error(f"Error in production event handler for {event_type}: {e}")
                self.emit_event('system_error', {
                    'error_type': 'event_handler_error',
                    'event_type': event_type,
                    'error_message': str(e),
                    'timestamp': datetime.now()
                })
    
    def _handle_security_alert(self, alert: SecurityAlert) -> None:
        """Handle security alert from detection engine in production."""
        logger.warning(f"PRODUCTION ALERT: {alert.attack_type.value} from {alert.source_ip}")
        self.emit_event('security_alert', alert)
    
    def _handle_security_alert_logging(self, alert: SecurityAlert) -> None:
        """Log security alert in production environment."""
        try:
            event_logger = self._components['event_logger']
            event_logger.log_security_event(alert)
            
            # Generate immediate alert for SOC/security team
            alerting_system = self._components['alerting_system']
            alerting_system.generate_console_alert(alert)
            
            # In production, also send to external systems (SIEM, etc.)
            self._send_to_external_systems(alert)
            
        except Exception as e:
            logger.error(f"Failed to log production security alert: {e}")
    
    def _handle_security_alert_mitigation(self, alert: SecurityAlert) -> None:
        """Handle security alert by triggering automated mitigation in production."""
        try:
            logger.info(f"Executing production mitigation for {alert.attack_type.value}")
            
            mitigation_controller = self._components['mitigation_controller']
            mitigation_result = mitigation_controller.execute_mitigation(alert)
            
            # Emit mitigation complete event
            self.emit_event('mitigation_complete', {
                'alert': alert,
                'mitigation_result': mitigation_result
            })
            
        except Exception as e:
            logger.error(f"Failed to execute production mitigation: {e}")
            self.emit_event('system_error', {
                'error_type': 'mitigation_error',
                'alert_id': alert.alert_id,
                'error_message': str(e),
                'timestamp': datetime.now()
            })
    
    def _handle_mitigation_complete_logging(self, event_data: Dict[str, Any]) -> None:
        """Log mitigation completion in production."""
        try:
            mitigation_result = event_data['mitigation_result']
            if mitigation_result is None:
                logger.error("Mitigation result missing; skipping logging")
                return
            event_logger = self._components['event_logger']
            event_logger.log_mitigation_action(mitigation_result)
            
        except Exception as e:
            logger.error(f"Failed to log production mitigation action: {e}")
    
    def _handle_mitigation_complete_recovery(self, event_data: Dict[str, Any]) -> None:
        """Handle mitigation completion by triggering recovery in production."""
        try:
            alert = event_data.get('alert')
            mitigation_result = event_data.get('mitigation_result')
            if mitigation_result is None or alert is None:
                logger.error("Mitigation result or alert missing; skipping recovery")
                return
            
            # Only trigger recovery if mitigation was successful
            if mitigation_result.success:
                logger.info(f"Initiating production recovery for {alert.attack_type.value}")
                
                recovery_manager = self._components['recovery_manager']
                recovery_result = recovery_manager.initiate_recovery(alert.attack_type)
                
                # Emit recovery complete event
                self.emit_event('recovery_complete', {
                    'alert': alert,
                    'mitigation_result': mitigation_result,
                    'recovery_result': recovery_result
                })
            else:
                logger.warning(f"Skipping recovery due to failed mitigation: {mitigation_result.error_message}")
                
        except Exception as e:
            logger.error(f"Failed to initiate production recovery: {e}")
            self.emit_event('system_error', {
                'error_type': 'recovery_error',
                'mitigation_id': (event_data.get('mitigation_result').mitigation_id
                                  if event_data.get('mitigation_result') is not None else None),
                'error_message': str(e),
                'timestamp': datetime.now()
            })
    
    def _handle_recovery_complete_logging(self, event_data: Dict[str, Any]) -> None:
        """Log recovery completion in production."""
        try:
            recovery_result = event_data.get('recovery_result')
            if recovery_result is None:
                logger.error("Recovery result missing; skipping recovery logging")
                return
            event_logger = self._components['event_logger']
            event_logger.log_recovery_confirmation(recovery_result)
            
        except Exception as e:
            logger.error(f"Failed to log production recovery confirmation: {e}")
    
    def _handle_system_error_logging(self, error_data: Dict[str, Any]) -> None:
        """Log system errors in production environment."""
        try:
            logger.error(f"PRODUCTION ERROR: {error_data['error_type']} - {error_data['error_message']}")
            
            # In production, send critical errors to external monitoring
            self._send_error_to_monitoring(error_data)
            
        except Exception as e:
            logger.error(f"Failed to log production system error: {e}")
    
    def _send_to_external_systems(self, alert: SecurityAlert) -> None:
        """Send security alerts to external systems (SIEM, SOC, etc.)."""
        # This would integrate with external security systems
        # Examples: Splunk, ELK, QRadar, Sentinel, etc.
        logger.debug(f"Sending alert {alert.alert_id} to external systems")
    
    def _send_error_to_monitoring(self, error_data: Dict[str, Any]) -> None:
        """Send critical errors to external monitoring systems."""
        # This would integrate with monitoring systems
        # Examples: Prometheus, Grafana, DataDog, New Relic, etc.
        logger.debug(f"Sending error to monitoring: {error_data['error_type']}")
    
    def get_component(self, component_name: str) -> Optional[Any]:
        """Get a specific production component by name."""
        return self._components.get(component_name)
    
    def get_all_components(self) -> Dict[str, Any]:
        """Get all production components."""
        return self._components.copy()
    
    def validate_component_connections(self) -> Dict[str, bool]:
        """Validate that all production component connections are working."""
        validation_results = {}
        
        try:
            # Check core production components
            detection_engine = self._components.get('detection_engine')
            validation_results['detection_engine'] = detection_engine is not None
            
            mitigation_controller = self._components.get('mitigation_controller')
            validation_results['mitigation_controller'] = mitigation_controller is not None
            
            recovery_manager = self._components.get('recovery_manager')
            validation_results['recovery_manager'] = recovery_manager is not None
            
            event_logger = self._components.get('event_logger')
            validation_results['event_logger'] = event_logger is not None
            
            alerting_system = self._components.get('alerting_system')
            validation_results['alerting_system'] = alerting_system is not None
            
            # Check event handler registrations
            validation_results['security_alert_handlers'] = len(self._event_handlers.get('security_alert', [])) > 0
            validation_results['mitigation_complete_handlers'] = len(self._event_handlers.get('mitigation_complete', [])) > 0
            validation_results['recovery_complete_handlers'] = len(self._event_handlers.get('recovery_complete', [])) > 0
            
            # Overall validation
            validation_results['overall_valid'] = all(validation_results.values())
            validation_results['deployment_mode'] = 'production'
            validation_results['attack_simulation_enabled'] = False
            
            logger.info(f"Production component validation: {validation_results}")
            return validation_results
            
        except Exception as e:
            logger.error(f"Production component validation failed: {e}")
            return {'overall_valid': False, 'error': str(e), 'deployment_mode': 'production'}