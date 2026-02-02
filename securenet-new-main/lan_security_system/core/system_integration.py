"""
System integration module for wiring all components together.

This module provides the core integration layer that connects the detection engine,
mitigation controller, recovery manager, and logging system components.
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


class ComponentIntegrator:
    """
    Component integrator that wires all system components together.
    
    This class manages the connections between:
    - Detection Engine -> Mitigation Controller
    - Mitigation Controller -> Recovery Manager
    - All components -> Logging System
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
        
        # Initialize components
        self._initialize_components()
        
        # Wire components together
        self._wire_components()
    
    def _initialize_components(self) -> None:
        """Initialize all system components with configuration."""
        try:
            # Initialize detection engine
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
            
            # Initialize mitigation controller
            self._components['mitigation_controller'] = AutomatedMitigationController(
                dns_safe_mode=self.config.get('detection.dns_safe_mode', True)
            )
            
            # Initialize recovery manager
            simulation_mode = self.config.get('system.simulation_mode', True)
            self._components['recovery_manager'] = NetworkRecoveryManager(simulation_mode=simulation_mode)
            
            # Initialize logging system
            log_directory = self.config.get('logging.log_directory', 'logs')
            max_file_size = self.config.get('logging.max_file_size', 10 * 1024 * 1024)
            self._components['event_logger'] = StructuredEventLogger(log_directory, max_file_size)
            
            # Initialize alerting system
            self._components['alerting_system'] = AlertingSystem()
            
            logger.info("All system components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")
            raise
    
    def _wire_components(self) -> None:
        """Wire components together with event-driven communication."""
        try:
            # Wire detection engine to mitigation controller
            detection_engine = self._components['detection_engine']
            detection_engine.set_alert_callback(self._handle_security_alert)
            
            # Register event handlers for component communication
            self.register_event_handler('security_alert', self._handle_security_alert_logging)
            self.register_event_handler('security_alert', self._handle_security_alert_mitigation)
            
            self.register_event_handler('mitigation_complete', self._handle_mitigation_complete_logging)
            self.register_event_handler('mitigation_complete', self._handle_mitigation_complete_recovery)
            
            # CRITICAL: Register self-healing reset on recovery completion
            self.register_event_handler('recovery_complete', self._handle_recovery_complete_logging)
            self.register_event_handler('recovery_complete', self._handle_recovery_complete_reset)
            
            self.register_event_handler('system_error', self._handle_system_error_logging)
            
            logger.info("Component wiring completed successfully")
            
        except Exception as e:
            logger.error(f"Failed to wire components: {e}")
            raise
    
    def register_event_handler(self, event_type: str, handler: Callable) -> None:
        """Register an event handler for a specific event type."""
        with self._integration_lock:
            if event_type not in self._event_handlers:
                self._event_handlers[event_type] = []
            self._event_handlers[event_type].append(handler)
            logger.debug(f"Registered event handler for {event_type}")
    
    def emit_event(self, event_type: str, event_data: Any) -> None:
        """Emit an event to all registered handlers."""
        with self._integration_lock:
            handlers = self._event_handlers.get(event_type, [])
        
        for handler in handlers:
            try:
                handler(event_data)
            except Exception as e:
                logger.error(f"Error in event handler for {event_type}: {e}")
                self.emit_event('system_error', {
                    'error_type': 'event_handler_error',
                    'event_type': event_type,
                    'error_message': str(e),
                    'timestamp': datetime.now()
                })
    
    def _handle_security_alert(self, alert: SecurityAlert) -> None:
        """Handle security alert from detection engine."""
        logger.info(f"Security alert received: {alert.attack_type.value} from {alert.source_ip}")
        self.emit_event('security_alert', alert)
    
    def _handle_security_alert_logging(self, alert: SecurityAlert) -> None:
        """Log security alert."""
        try:
            event_logger = self._components['event_logger']
            event_logger.log_security_event(alert)
            
            # Generate console alert
            alerting_system = self._components['alerting_system']
            alerting_system.generate_console_alert(alert)
            
        except Exception as e:
            logger.error(f"Failed to log security alert: {e}")
    
    def _handle_security_alert_mitigation(self, alert: SecurityAlert) -> None:
        """Handle security alert by triggering mitigation."""
        try:
            mitigation_controller = self._components['mitigation_controller']
            mitigation_result = mitigation_controller.execute_mitigation(alert)
            
            # Emit mitigation complete event
            self.emit_event('mitigation_complete', {
                'alert': alert,
                'mitigation_result': mitigation_result
            })
            
        except Exception as e:
            logger.error(f"Failed to execute mitigation: {e}")
            self.emit_event('system_error', {
                'error_type': 'mitigation_error',
                'alert_id': alert.alert_id,
                'error_message': str(e),
                'timestamp': datetime.now()
            })
    
    def _handle_mitigation_complete_logging(self, event_data: Dict[str, Any]) -> None:
        """Log mitigation completion."""
        try:
            mitigation_result = event_data['mitigation_result']
            event_logger = self._components['event_logger']
            event_logger.log_mitigation_action(mitigation_result)
            
        except Exception as e:
            logger.error(f"Failed to log mitigation action: {e}")
    
    def _handle_mitigation_complete_recovery(self, event_data: Dict[str, Any]) -> None:
        """Handle mitigation completion by triggering recovery if needed."""
        try:
            alert = event_data['alert']
            mitigation_result = event_data['mitigation_result']
            
            # Only trigger recovery if mitigation was successful
            if mitigation_result.success:
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
            logger.error(f"Failed to initiate recovery: {e}")
            self.emit_event('system_error', {
                'error_type': 'recovery_error',
                'mitigation_id': event_data['mitigation_result'].mitigation_id,
                'error_message': str(e),
                'timestamp': datetime.now()
            })
    
    def _handle_recovery_complete_logging(self, event_data: Dict[str, Any]) -> None:
        """Log recovery completion."""
        try:
            recovery_result = event_data['recovery_result']
            event_logger = self._components['event_logger']
            event_logger.log_recovery_confirmation(recovery_result)
            
        except Exception as e:
            logger.error(f"Failed to log recovery confirmation: {e}")
    
    def _handle_recovery_complete_reset(self, event_data: Dict[str, Any]) -> None:
        """Reset all detection and mitigation state for self-healing after recovery (CRITICAL)."""
        try:
            # Reset detection engine state (clear tracking dictionaries and deques)
            detection_engine = self._components.get('detection_engine')
            if detection_engine:
                detection_engine.reset_detection_state()
            
            # Reset mitigation controller state (clear active mitigations)
            mitigation_controller = self._components.get('mitigation_controller')
            if mitigation_controller:
                mitigation_controller.reset_mitigation_state()
            
            # Re-enable logging (ensure handlers are active)
            event_logger = self._components.get('event_logger')
            if event_logger and hasattr(event_logger, 'ensure_logging_active'):
                event_logger.ensure_logging_active()
            
            alerting_system = self._components.get('alerting_system')
            if alerting_system and hasattr(alerting_system, 'ensure_alerting_active'):
                alerting_system.ensure_alerting_active()
            
            # Log clear confirmation that system is ready (VISIBLE MARKER FOR USER)
            logger.info("=" * 80)
            logger.info("✅ SYSTEM SELF-HEALING COMPLETE - READY FOR NEXT ATTACK")
            logger.info("=" * 80)
            logger.info("All components reset: detection engine | mitigation controller | logging | alerting")
            logger.info("=" * 80)
            
        except Exception as e:
            logger.error(f"Failed to perform self-healing reset after recovery: {e}")
    
    def _handle_system_error_logging(self, error_data: Dict[str, Any]) -> None:
        """Log system errors."""
        try:
            logger.error(f"System error: {error_data['error_type']} - {error_data['error_message']}")
            
            # Could also send error alerts through alerting system
            alerting_system = self._components['alerting_system']
            # Note: Would need to create an error alert format for this
            
        except Exception as e:
            logger.error(f"Failed to log system error: {e}")
    
    def get_component(self, component_name: str) -> Optional[Any]:
        """Get a specific component by name."""
        return self._components.get(component_name)
    
    def get_all_components(self) -> Dict[str, Any]:
        """Get all components."""
        return self._components.copy()
    
    def validate_component_connections(self) -> Dict[str, bool]:
        """Validate that all component connections are working."""
        validation_results = {}
        
        try:
            # Check detection engine
            detection_engine = self._components.get('detection_engine')
            validation_results['detection_engine'] = detection_engine is not None
            
            # Check mitigation controller
            mitigation_controller = self._components.get('mitigation_controller')
            validation_results['mitigation_controller'] = mitigation_controller is not None
            
            # Check recovery manager
            recovery_manager = self._components.get('recovery_manager')
            validation_results['recovery_manager'] = recovery_manager is not None
            
            # Check logging components
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
            
            logger.info(f"Component connection validation: {validation_results}")
            return validation_results
            
        except Exception as e:
            logger.error(f"Component validation failed: {e}")
            return {'overall_valid': False, 'error': str(e)}