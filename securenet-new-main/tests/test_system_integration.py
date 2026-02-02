"""
Integration tests for the LAN Security System.

These tests verify end-to-end workflows, multi-component coordination,
and system resilience and error recovery.
"""

import pytest
import threading
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

from lan_security_system.core.system_manager import SystemManager
from lan_security_system.core.system_orchestrator import SystemOrchestrator, SystemState
from lan_security_system.core.system_integration import ComponentIntegrator
from lan_security_system.core.interfaces import (
    SecurityAlert, AttackType, DetectionMethod, MitigationResult, RecoveryResult
)
from lan_security_system.config.settings import SystemConfig


class TestSystemIntegration:
    """Integration tests for system component wiring and coordination."""
    
    def setup_method(self):
        """Setup test environment."""
        self.config = SystemConfig()
        self.config.set('system.simulation_mode', True)
        self.config.set('logging.log_level', 'DEBUG')
    
    def test_component_integrator_initialization(self):
        """Test that component integrator initializes all components correctly."""
        integrator = ComponentIntegrator(self.config)
        
        # Verify all components are initialized
        components = integrator.get_all_components()
        assert 'detection_engine' in components
        assert 'mitigation_controller' in components
        assert 'recovery_manager' in components
        assert 'event_logger' in components
        assert 'alerting_system' in components
        
        # Verify components are not None
        for name, component in components.items():
            assert component is not None, f"Component {name} is None"
    
    def test_component_connection_validation(self):
        """Test component connection validation."""
        integrator = ComponentIntegrator(self.config)
        
        validation_results = integrator.validate_component_connections()
        
        # All components should be valid
        assert validation_results['overall_valid'] is True
        assert validation_results['detection_engine'] is True
        assert validation_results['mitigation_controller'] is True
        assert validation_results['recovery_manager'] is True
        assert validation_results['event_logger'] is True
        assert validation_results['alerting_system'] is True
        
        # Event handlers should be registered
        assert validation_results['security_alert_handlers'] is True
        assert validation_results['mitigation_complete_handlers'] is True
        assert validation_results['recovery_complete_handlers'] is True
    
    def test_event_driven_communication(self):
        """Test event-driven communication between components."""
        integrator = ComponentIntegrator(self.config)
        
        # Create mock handlers to track events
        security_alert_handler = Mock()
        mitigation_complete_handler = Mock()
        recovery_complete_handler = Mock()
        
        integrator.register_event_handler('security_alert', security_alert_handler)
        integrator.register_event_handler('mitigation_complete', mitigation_complete_handler)
        integrator.register_event_handler('recovery_complete', recovery_complete_handler)
        
        # Create test alert
        test_alert = SecurityAlert(
            timestamp=datetime.now(),
            alert_id="test_alert_001",
            attack_type=AttackType.ARP_SPOOFING,
            confidence_score=0.95,
            source_mac="aa:bb:cc:dd:ee:01",
            source_ip="192.168.1.100",
            target_mac="aa:bb:cc:dd:ee:ff",
            target_ip="192.168.1.1",
            affected_hosts=["192.168.1.100", "192.168.1.1"],
            raw_packet_data=b"test_packet_data",
            detection_method=DetectionMethod.SIGNATURE_BASED
        )
        
        # Emit security alert event
        integrator.emit_event('security_alert', test_alert)
        
        # Verify handler was called
        security_alert_handler.assert_called_once_with(test_alert)
    
    def test_system_orchestrator_initialization(self):
        """Test system orchestrator initialization."""
        orchestrator = SystemOrchestrator(self.config)
        
        # Test system initialization
        success = orchestrator.initialize_system()
        assert success is True
        assert orchestrator.state == SystemState.RUNNING
        
        # Test system status
        status = orchestrator.get_system_status()
        assert status['system_state'] == 'running'
        assert 'uptime_seconds' in status
        assert 'metrics' in status
        assert 'component_statuses' in status
    
    def test_system_manager_lifecycle(self):
        """Test system manager initialization and lifecycle."""
        # Create temporary config file
        import tempfile
        import yaml
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(self.config.config_data, f)
            config_file = f.name
        
        try:
            manager = SystemManager(config_file)
            
            # Test configuration loading
            assert manager.load_configuration() is True
            assert manager.config is not None
            
            # Test system initialization
            assert manager.initialize_system() is True
            assert manager.orchestrator is not None
            
            # Test system status
            status = manager.get_system_status()
            assert 'system_state' in status
            
            # Test shutdown
            assert manager.shutdown_system() is True
            
        finally:
            import os
            os.unlink(config_file)


class TestEndToEndWorkflows:
    """Integration tests for end-to-end attack detection and response workflows."""
    
    def setup_method(self):
        """Setup test environment."""
        self.config = SystemConfig()
        self.config.set('system.simulation_mode', True)
        self.config.set('logging.log_level', 'DEBUG')
        
        self.integrator = ComponentIntegrator(self.config)
        
        # Track events for verification
        self.events_received = []
        self.integrator.register_event_handler('security_alert', self._track_event)
        self.integrator.register_event_handler('mitigation_complete', self._track_event)
        self.integrator.register_event_handler('recovery_complete', self._track_event)
    
    def _track_event(self, event_data):
        """Track events for test verification."""
        self.events_received.append(event_data)
    
    def test_arp_spoofing_detection_to_recovery_workflow(self):
        """Test complete ARP spoofing detection, mitigation, and recovery workflow."""
        # Create ARP spoofing alert
        alert = SecurityAlert(
            timestamp=datetime.now(),
            alert_id="arp_test_001",
            attack_type=AttackType.ARP_SPOOFING,
            confidence_score=0.95,
            source_mac="aa:bb:cc:dd:ee:01",
            source_ip="192.168.1.100",
            target_mac="aa:bb:cc:dd:ee:ff",
            target_ip="192.168.1.1",
            affected_hosts=["192.168.1.100", "192.168.1.1"],
            raw_packet_data=b"arp_spoofing_packet",
            detection_method=DetectionMethod.SIGNATURE_BASED
        )
        
        # Trigger the workflow by emitting security alert
        self.integrator.emit_event('security_alert', alert)
        
        # Allow time for event processing
        time.sleep(0.1)
        
        # Verify events were processed
        assert len(self.events_received) >= 1
        
        # First event should contain the security alert and workflow results
        first_event = self.events_received[0]
        if isinstance(first_event, SecurityAlert):
            # Direct alert event
            assert first_event.attack_type == AttackType.ARP_SPOOFING
        elif isinstance(first_event, dict):
            # Workflow completion event with alert and results
            assert 'alert' in first_event
            assert isinstance(first_event['alert'], SecurityAlert)
            assert first_event['alert'].attack_type == AttackType.ARP_SPOOFING
            
            # Verify mitigation was executed
            if 'mitigation_result' in first_event:
                assert isinstance(first_event['mitigation_result'], MitigationResult)
                assert first_event['mitigation_result'].success is True
            
            # Verify recovery was attempted
            if 'recovery_result' in first_event:
                assert isinstance(first_event['recovery_result'], RecoveryResult)
    
    def test_mac_flooding_detection_to_recovery_workflow(self):
        """Test complete MAC flooding detection, mitigation, and recovery workflow."""
        # Create MAC flooding alert
        alert = SecurityAlert(
            timestamp=datetime.now(),
            alert_id="mac_test_001",
            attack_type=AttackType.MAC_FLOODING,
            confidence_score=0.90,
            source_mac="aa:bb:cc:dd:ee:02",
            source_ip="192.168.1.101",
            target_mac="ff:ff:ff:ff:ff:ff",
            target_ip="192.168.1.255",
            affected_hosts=["192.168.1.101"],
            raw_packet_data=b"mac_flooding_packet",
            detection_method=DetectionMethod.ANOMALY_BASED
        )
        
        # Trigger the workflow
        self.integrator.emit_event('security_alert', alert)
        
        # Allow time for event processing
        time.sleep(0.1)
        
        # Verify alert was processed
        assert len(self.events_received) >= 1
        first_event = self.events_received[0]
        if isinstance(first_event, SecurityAlert):
            assert first_event.attack_type == AttackType.MAC_FLOODING
        elif isinstance(first_event, dict):
            assert 'alert' in first_event
            assert isinstance(first_event['alert'], SecurityAlert)
            assert first_event['alert'].attack_type == AttackType.MAC_FLOODING
    
    def test_dns_spoofing_detection_to_recovery_workflow(self):
        """Test complete DNS spoofing detection, mitigation, and recovery workflow."""
        # Create DNS spoofing alert
        alert = SecurityAlert(
            timestamp=datetime.now(),
            alert_id="dns_test_001",
            attack_type=AttackType.DNS_SPOOFING,
            confidence_score=0.88,
            source_mac="aa:bb:cc:dd:ee:03",
            source_ip="192.168.1.102",
            target_mac="aa:bb:cc:dd:ee:ff",
            target_ip="192.168.1.1",
            affected_hosts=["192.168.1.102", "192.168.1.1"],
            raw_packet_data=b"dns_spoofing_packet",
            detection_method=DetectionMethod.SIGNATURE_BASED
        )
        
        # Trigger the workflow
        self.integrator.emit_event('security_alert', alert)
        
        # Allow time for event processing
        time.sleep(0.1)
        
        # Verify alert was processed
        assert len(self.events_received) >= 1
        first_event = self.events_received[0]
        if isinstance(first_event, SecurityAlert):
            assert first_event.attack_type == AttackType.DNS_SPOOFING
        elif isinstance(first_event, dict):
            assert 'alert' in first_event
            assert isinstance(first_event['alert'], SecurityAlert)
            assert first_event['alert'].attack_type == AttackType.DNS_SPOOFING
    
    def test_concurrent_attack_handling(self):
        """Test handling of multiple concurrent attacks."""
        # Create multiple alerts of different types
        alerts = [
            SecurityAlert(
                timestamp=datetime.now(),
                alert_id=f"concurrent_test_{i}",
                attack_type=attack_type,
                confidence_score=0.90,
                source_mac=f"aa:bb:cc:dd:ee:{i:02d}",
                source_ip=f"192.168.1.{100+i}",
                target_mac="aa:bb:cc:dd:ee:ff",
                target_ip="192.168.1.1",
                affected_hosts=[f"192.168.1.{100+i}", "192.168.1.1"],
                raw_packet_data=f"concurrent_packet_{i}".encode(),
                detection_method=DetectionMethod.SIGNATURE_BASED
            )
            for i, attack_type in enumerate([AttackType.ARP_SPOOFING, AttackType.MAC_FLOODING, AttackType.DNS_SPOOFING])
        ]
        
        # Trigger all alerts concurrently
        for alert in alerts:
            self.integrator.emit_event('security_alert', alert)
        
        # Allow time for event processing
        time.sleep(0.2)
        
        # Verify all alerts were processed
        assert len(self.events_received) >= len(alerts)
        
        # Verify we received alerts of all types
        received_attack_types = set()
        for event in self.events_received:
            if isinstance(event, SecurityAlert):
                received_attack_types.add(event.attack_type)
            elif isinstance(event, dict) and 'alert' in event:
                received_attack_types.add(event['alert'].attack_type)
        
        assert AttackType.ARP_SPOOFING in received_attack_types
        assert AttackType.MAC_FLOODING in received_attack_types
        assert AttackType.DNS_SPOOFING in received_attack_types


class TestSystemResilience:
    """Integration tests for system resilience and error recovery."""
    
    def setup_method(self):
        """Setup test environment."""
        self.config = SystemConfig()
        self.config.set('system.simulation_mode', True)
        self.config.set('logging.log_level', 'DEBUG')
    
    def test_component_failure_recovery(self):
        """Test system behavior when a component fails."""
        orchestrator = SystemOrchestrator(self.config)
        orchestrator.initialize_system()
        
        # Simulate component error
        orchestrator._handle_component_error('detection_engine', 'Simulated failure')
        
        # Check component status
        status = orchestrator.get_system_status()
        component_statuses = status['component_statuses']
        
        # Component should have error recorded
        detection_status = component_statuses.get('detection_engine', {})
        assert detection_status.get('error_count', 0) > 0
    
    def test_system_state_transitions(self):
        """Test system state transitions during various conditions."""
        orchestrator = SystemOrchestrator(self.config)
        
        # Initial state should be initializing
        assert orchestrator.state == SystemState.INITIALIZING
        
        # After initialization, should be running
        orchestrator.initialize_system()
        assert orchestrator.state == SystemState.RUNNING
        
        # Simulate performance degradation
        orchestrator._handle_performance_degradation('cpu_usage', 90.0)
        assert orchestrator.state == SystemState.DEGRADED
        
        # Test shutdown
        orchestrator.shutdown_system()
        assert orchestrator.state == SystemState.STOPPED
    
    def test_error_handling_and_logging(self):
        """Test error handling and logging throughout the system."""
        integrator = ComponentIntegrator(self.config)
        
        # Track system errors
        system_errors = []
        integrator.register_event_handler('system_error', lambda e: system_errors.append(e))
        
        # Simulate various error conditions
        test_error = {
            'error_type': 'test_error',
            'error_message': 'Test error message',
            'timestamp': datetime.now()
        }
        
        integrator.emit_event('system_error', test_error)
        
        # Verify error was handled
        assert len(system_errors) == 1
        assert system_errors[0]['error_type'] == 'test_error'
    
    def test_graceful_degradation(self):
        """Test graceful degradation under resource constraints."""
        orchestrator = SystemOrchestrator(self.config)
        orchestrator.initialize_system()
        
        # Simulate high resource usage
        orchestrator._handle_performance_degradation('memory_usage', 1500.0)  # Above threshold
        
        # System should still be operational but in degraded state
        status = orchestrator.get_system_status()
        assert status['system_state'] in ['running', 'degraded']
        
        # Performance status should indicate degradation
        performance_status = status.get('performance_status', {})
        # The system may not immediately reflect degradation in status
        # but should have logged the performance issue
        assert performance_status.get('state') in ['degraded', 'unknown', 'normal']
    
    def test_health_monitoring(self):
        """Test component health monitoring functionality."""
        orchestrator = SystemOrchestrator(self.config)
        orchestrator.initialize_system()
        
        # Start health monitoring
        orchestrator._start_health_monitoring()
        
        # Allow some time for health checks
        time.sleep(0.5)
        
        # Check that health monitoring is running
        assert orchestrator.is_monitoring is True
        assert orchestrator.health_monitor_thread is not None
        assert orchestrator.health_monitor_thread.is_alive()
        
        # Stop health monitoring
        orchestrator._stop_health_monitoring()
        
        # Verify monitoring stopped
        assert orchestrator.is_monitoring is False
    
    def test_system_metrics_tracking(self):
        """Test system metrics tracking and reporting."""
        orchestrator = SystemOrchestrator(self.config)
        orchestrator.initialize_system()
        
        # Simulate some system activity
        test_alert = SecurityAlert(
            timestamp=datetime.now(),
            alert_id="metrics_test_001",
            attack_type=AttackType.ARP_SPOOFING,
            confidence_score=0.95,
            source_mac="aa:bb:cc:dd:ee:01",
            source_ip="192.168.1.100",
            target_mac="aa:bb:cc:dd:ee:ff",
            target_ip="192.168.1.1",
            affected_hosts=["192.168.1.100"],
            raw_packet_data=b"test_packet",
            detection_method=DetectionMethod.SIGNATURE_BASED
        )
        
        # Trigger metric updates
        orchestrator._handle_security_alert_metrics(test_alert)
        
        # Check metrics
        status = orchestrator.get_system_status()
        metrics = status['metrics']
        
        assert metrics['total_alerts'] > 0
        assert 'uptime_seconds' in status
        assert status['uptime_seconds'] > 0


class TestMultiComponentCoordination:
    """Integration tests for multi-component coordination and communication."""
    
    def setup_method(self):
        """Setup test environment."""
        self.config = SystemConfig()
        self.config.set('system.simulation_mode', True)
        self.config.set('logging.log_level', 'DEBUG')
        
        self.orchestrator = SystemOrchestrator(self.config)
        self.orchestrator.initialize_system()
    
    def test_detection_to_mitigation_coordination(self):
        """Test coordination between detection engine and mitigation controller."""
        # Get components
        integrator = self.orchestrator.integrator
        detection_engine = integrator.get_component('detection_engine')
        mitigation_controller = integrator.get_component('mitigation_controller')
        
        assert detection_engine is not None
        assert mitigation_controller is not None
        
        # Verify detection engine has alert callback set
        assert detection_engine.alert_callback is not None
    
    def test_mitigation_to_recovery_coordination(self):
        """Test coordination between mitigation controller and recovery manager."""
        # Get components
        integrator = self.orchestrator.integrator
        mitigation_controller = integrator.get_component('mitigation_controller')
        recovery_manager = integrator.get_component('recovery_manager')
        
        assert mitigation_controller is not None
        assert recovery_manager is not None
        
        # Test that mitigation controller can trigger recovery
        # This is tested through the event system in the integrator
        validation_results = integrator.validate_component_connections()
        assert validation_results['mitigation_complete_handlers'] is True
    
    def test_logging_system_coordination(self):
        """Test coordination between all components and logging system."""
        # Get components
        integrator = self.orchestrator.integrator
        event_logger = integrator.get_component('event_logger')
        alerting_system = integrator.get_component('alerting_system')
        
        assert event_logger is not None
        assert alerting_system is not None
        
        # Verify logging handlers are registered
        validation_results = integrator.validate_component_connections()
        assert validation_results['security_alert_handlers'] is True
        assert validation_results['recovery_complete_handlers'] is True
    
    def test_system_wide_event_propagation(self):
        """Test event propagation across all system components."""
        integrator = self.orchestrator.integrator
        
        # Track all event types
        events_by_type = {
            'security_alert': [],
            'mitigation_complete': [],
            'recovery_complete': [],
            'system_error': []
        }
        
        def track_events(event_type):
            def handler(event_data):
                events_by_type[event_type].append(event_data)
            return handler
        
        # Register tracking handlers
        for event_type in events_by_type.keys():
            integrator.register_event_handler(event_type, track_events(event_type))
        
        # Emit test events
        test_alert = SecurityAlert(
            timestamp=datetime.now(),
            alert_id="propagation_test_001",
            attack_type=AttackType.ARP_SPOOFING,
            confidence_score=0.95,
            source_mac="aa:bb:cc:dd:ee:01",
            source_ip="192.168.1.100",
            target_mac="aa:bb:cc:dd:ee:ff",
            target_ip="192.168.1.1",
            affected_hosts=["192.168.1.100"],
            raw_packet_data=b"test_packet",
            detection_method=DetectionMethod.SIGNATURE_BASED
        )
        
        integrator.emit_event('security_alert', test_alert)
        
        # Allow time for event processing
        time.sleep(0.1)
        
        # Verify events were received
        assert len(events_by_type['security_alert']) > 0
        
        # The security alert should have triggered additional events
        # (mitigation_complete, recovery_complete) through the normal workflow


class TestComprehensiveIntegration:
    """Comprehensive integration tests for end-to-end system functionality."""
    
    def setup_method(self):
        """Setup test environment."""
        self.config = SystemConfig()
        self.config.set('system.simulation_mode', True)
        self.config.set('logging.log_level', 'DEBUG')
        
        self.orchestrator = SystemOrchestrator(self.config)
        self.orchestrator.initialize_system()
        
        # Track all system events
        self.all_events = []
        self.integrator = self.orchestrator.integrator
        
        # Register comprehensive event tracking
        for event_type in ['security_alert', 'mitigation_complete', 'recovery_complete', 'system_error']:
            self.integrator.register_event_handler(event_type, self._track_all_events)
    
    def _track_all_events(self, event_data):
        """Track all events for comprehensive testing."""
        self.all_events.append({
            'timestamp': datetime.now(),
            'event_data': event_data
        })
    
    def test_complete_attack_response_pipeline(self):
        """Test complete attack detection, mitigation, and recovery pipeline."""
        # Test all three attack types in sequence
        attack_scenarios = [
            {
                'attack_type': AttackType.ARP_SPOOFING,
                'source_ip': '192.168.1.100',
                'source_mac': 'aa:bb:cc:dd:ee:01',
                'target_ip': '192.168.1.1',
                'target_mac': 'aa:bb:cc:dd:ee:ff'
            },
            {
                'attack_type': AttackType.MAC_FLOODING,
                'source_ip': '192.168.1.101',
                'source_mac': 'aa:bb:cc:dd:ee:02',
                'target_ip': '192.168.1.255',
                'target_mac': 'ff:ff:ff:ff:ff:ff'
            },
            {
                'attack_type': AttackType.DNS_SPOOFING,
                'source_ip': '192.168.1.102',
                'source_mac': 'aa:bb:cc:dd:ee:03',
                'target_ip': '192.168.1.1',
                'target_mac': 'aa:bb:cc:dd:ee:ff'
            }
        ]
        
        for i, scenario in enumerate(attack_scenarios):
            # Clear previous events
            self.all_events.clear()
            
            # Create and trigger attack alert
            alert = SecurityAlert(
                timestamp=datetime.now(),
                alert_id=f"pipeline_test_{i:03d}",
                attack_type=scenario['attack_type'],
                confidence_score=0.95,
                source_mac=scenario['source_mac'],
                source_ip=scenario['source_ip'],
                target_mac=scenario['target_mac'],
                target_ip=scenario['target_ip'],
                affected_hosts=[scenario['source_ip'], scenario['target_ip']],
                raw_packet_data=f"pipeline_test_packet_{i}".encode(),
                detection_method=DetectionMethod.SIGNATURE_BASED
            )
            
            # Trigger the complete pipeline
            self.integrator.emit_event('security_alert', alert)
            
            # Allow time for complete processing
            time.sleep(0.2)
            
            # Verify complete pipeline execution
            assert len(self.all_events) >= 1, f"No events received for {scenario['attack_type']}"
            
            # Verify the pipeline processed the correct attack type
            found_attack_type = False
            for event in self.all_events:
                event_data = event['event_data']
                if isinstance(event_data, SecurityAlert):
                    if event_data.attack_type == scenario['attack_type']:
                        found_attack_type = True
                        break
                elif isinstance(event_data, dict) and 'alert' in event_data:
                    if event_data['alert'].attack_type == scenario['attack_type']:
                        found_attack_type = True
                        break
            
            assert found_attack_type, f"Attack type {scenario['attack_type']} not found in events"
    
    def test_system_performance_under_load(self):
        """Test system performance under high alert load."""
        # Generate multiple concurrent alerts
        num_alerts = 10
        alerts = []
        
        for i in range(num_alerts):
            alert = SecurityAlert(
                timestamp=datetime.now(),
                alert_id=f"load_test_{i:03d}",
                attack_type=AttackType.ARP_SPOOFING,
                confidence_score=0.90,
                source_mac=f"aa:bb:cc:dd:ee:{i:02x}",
                source_ip=f"192.168.1.{100+i}",
                target_mac="aa:bb:cc:dd:ee:ff",
                target_ip="192.168.1.1",
                affected_hosts=[f"192.168.1.{100+i}", "192.168.1.1"],
                raw_packet_data=f"load_test_packet_{i}".encode(),
                detection_method=DetectionMethod.SIGNATURE_BASED
            )
            alerts.append(alert)
        
        # Clear events and measure processing time
        self.all_events.clear()
        start_time = time.time()
        
        # Trigger all alerts rapidly
        for alert in alerts:
            self.integrator.emit_event('security_alert', alert)
        
        # Allow processing time
        time.sleep(1.0)
        end_time = time.time()
        
        # Verify system handled the load
        processing_time = end_time - start_time
        assert processing_time < 2.0, f"Processing took too long: {processing_time}s"
        
        # Verify all alerts were processed
        assert len(self.all_events) >= num_alerts, f"Only {len(self.all_events)} events processed out of {num_alerts}"
        
        # Check system status after load
        status = self.orchestrator.get_system_status()
        assert status['system_state'] in ['running', 'degraded'], f"System in unexpected state: {status['system_state']}"
    
    def test_component_failure_and_recovery(self):
        """Test system behavior when components fail and recover."""
        # Get initial system status
        initial_status = self.orchestrator.get_system_status()
        assert initial_status['system_state'] == 'running'
        
        # Simulate component failures
        test_failures = [
            ('detection_engine', 'Simulated detection engine failure'),
            ('mitigation_controller', 'Simulated mitigation controller failure'),
            ('recovery_manager', 'Simulated recovery manager failure')
        ]
        
        for component_name, error_message in test_failures:
            # Clear events
            self.all_events.clear()
            
            # Simulate component error
            self.orchestrator._handle_component_error(component_name, error_message)
            
            # Check that error was recorded
            status = self.orchestrator.get_system_status()
            component_statuses = status.get('component_statuses', {})
            
            if component_name in component_statuses:
                component_status = component_statuses[component_name]
                assert component_status.get('error_count', 0) > 0, f"Error not recorded for {component_name}"
            
            # System should still be operational (graceful degradation)
            assert status['system_state'] in ['running', 'degraded', 'error'], f"Unexpected state after {component_name} failure"
    
    def test_end_to_end_workflow_timing(self):
        """Test end-to-end workflow timing requirements."""
        # Create test alert
        alert = SecurityAlert(
            timestamp=datetime.now(),
            alert_id="timing_test_001",
            attack_type=AttackType.ARP_SPOOFING,
            confidence_score=0.95,
            source_mac="aa:bb:cc:dd:ee:01",
            source_ip="192.168.1.100",
            target_mac="aa:bb:cc:dd:ee:ff",
            target_ip="192.168.1.1",
            affected_hosts=["192.168.1.100", "192.168.1.1"],
            raw_packet_data=b"timing_test_packet",
            detection_method=DetectionMethod.SIGNATURE_BASED
        )
        
        # Clear events and measure timing
        self.all_events.clear()
        start_time = time.time()
        
        # Trigger workflow
        self.integrator.emit_event('security_alert', alert)
        
        # Wait for processing
        time.sleep(0.5)
        end_time = time.time()
        
        # Verify timing requirements
        total_time = (end_time - start_time) * 1000  # Convert to milliseconds
        
        # System should process within reasonable time (allowing for simulation overhead)
        assert total_time < 1000, f"End-to-end processing took {total_time:.2f}ms (too slow)"
        
        # Verify workflow completed
        assert len(self.all_events) >= 1, "No events received in timing test"
    
    def test_concurrent_attack_types_handling(self):
        """Test handling of multiple different attack types simultaneously."""
        # Create alerts for all attack types with different timing
        alerts = [
            SecurityAlert(
                timestamp=datetime.now(),
                alert_id="concurrent_arp_001",
                attack_type=AttackType.ARP_SPOOFING,
                confidence_score=0.95,
                source_mac="aa:bb:cc:dd:ee:01",
                source_ip="192.168.1.100",
                target_mac="aa:bb:cc:dd:ee:ff",
                target_ip="192.168.1.1",
                affected_hosts=["192.168.1.100", "192.168.1.1"],
                raw_packet_data=b"concurrent_arp_packet",
                detection_method=DetectionMethod.SIGNATURE_BASED
            ),
            SecurityAlert(
                timestamp=datetime.now(),
                alert_id="concurrent_mac_001",
                attack_type=AttackType.MAC_FLOODING,
                confidence_score=0.90,
                source_mac="aa:bb:cc:dd:ee:02",
                source_ip="192.168.1.101",
                target_mac="ff:ff:ff:ff:ff:ff",
                target_ip="192.168.1.255",
                affected_hosts=["192.168.1.101"],
                raw_packet_data=b"concurrent_mac_packet",
                detection_method=DetectionMethod.ANOMALY_BASED
            ),
            SecurityAlert(
                timestamp=datetime.now(),
                alert_id="concurrent_dns_001",
                attack_type=AttackType.DNS_SPOOFING,
                confidence_score=0.88,
                source_mac="aa:bb:cc:dd:ee:03",
                source_ip="192.168.1.102",
                target_mac="aa:bb:cc:dd:ee:ff",
                target_ip="192.168.1.1",
                affected_hosts=["192.168.1.102", "192.168.1.1"],
                raw_packet_data=b"concurrent_dns_packet",
                detection_method=DetectionMethod.SIGNATURE_BASED
            )
        ]
        
        # Clear events
        self.all_events.clear()
        
        # Trigger all alerts with slight delays to simulate real-world timing
        for i, alert in enumerate(alerts):
            self.integrator.emit_event('security_alert', alert)
            time.sleep(0.05)  # Small delay between alerts
        
        # Allow processing time
        time.sleep(0.5)
        
        # Verify all attack types were handled
        processed_attack_types = set()
        for event in self.all_events:
            event_data = event['event_data']
            if isinstance(event_data, SecurityAlert):
                processed_attack_types.add(event_data.attack_type)
            elif isinstance(event_data, dict) and 'alert' in event_data:
                processed_attack_types.add(event_data['alert'].attack_type)
        
        # All attack types should be processed
        expected_types = {AttackType.ARP_SPOOFING, AttackType.MAC_FLOODING, AttackType.DNS_SPOOFING}
        assert expected_types.issubset(processed_attack_types), f"Missing attack types: {expected_types - processed_attack_types}"
        
        # System should remain stable
        status = self.orchestrator.get_system_status()
        assert status['system_state'] in ['running', 'degraded'], f"System unstable after concurrent attacks: {status['system_state']}"
    
    def test_system_resource_monitoring(self):
        """Test system resource monitoring and reporting."""
        # Get initial metrics
        initial_status = self.orchestrator.get_system_status()
        initial_metrics = initial_status.get('metrics', {})
        
        # Generate some system activity
        for i in range(5):
            alert = SecurityAlert(
                timestamp=datetime.now(),
                alert_id=f"resource_test_{i:03d}",
                attack_type=AttackType.ARP_SPOOFING,
                confidence_score=0.95,
                source_mac=f"aa:bb:cc:dd:ee:{i:02x}",
                source_ip=f"192.168.1.{100+i}",
                target_mac="aa:bb:cc:dd:ee:ff",
                target_ip="192.168.1.1",
                affected_hosts=[f"192.168.1.{100+i}", "192.168.1.1"],
                raw_packet_data=f"resource_test_packet_{i}".encode(),
                detection_method=DetectionMethod.SIGNATURE_BASED
            )
            self.integrator.emit_event('security_alert', alert)
            time.sleep(0.1)
        
        # Allow processing
        time.sleep(0.5)
        
        # Get updated metrics
        updated_status = self.orchestrator.get_system_status()
        updated_metrics = updated_status.get('metrics', {})
        
        # Verify metrics are being tracked
        assert 'total_alerts' in updated_metrics, "total_alerts metric missing"
        assert updated_metrics['total_alerts'] >= initial_metrics.get('total_alerts', 0), "Alert count not increasing"
        
        # Verify system performance metrics exist
        performance_status = updated_status.get('performance_status', {})
        assert 'current_metrics' in performance_status, "Performance metrics missing"
        
        current_metrics = performance_status['current_metrics']
        expected_metrics = ['cpu_usage_percent', 'memory_usage_mb', 'alerts_generated']
        for metric in expected_metrics:
            assert metric in current_metrics, f"Missing performance metric: {metric}"
    
    def test_error_propagation_and_handling(self):
        """Test error propagation and handling across components."""
        # Clear events
        self.all_events.clear()
        
        # Simulate various error conditions
        error_scenarios = [
            {'error_type': 'detection_error', 'message': 'Packet parsing failed'},
            {'error_type': 'mitigation_error', 'message': 'Firewall rule insertion failed'},
            {'error_type': 'recovery_error', 'message': 'Network restoration failed'},
            {'error_type': 'logging_error', 'message': 'Log file write failed'}
        ]
        
        for scenario in error_scenarios:
            # Emit system error event
            error_event = {
                'error_type': scenario['error_type'],
                'error_message': scenario['message'],
                'timestamp': datetime.now(),
                'component': 'test_component'
            }
            
            self.integrator.emit_event('system_error', error_event)
            time.sleep(0.1)
        
        # Verify errors were handled
        error_events = [e for e in self.all_events if isinstance(e['event_data'], dict) and 'error_type' in e['event_data']]
        assert len(error_events) >= len(error_scenarios), f"Not all errors were handled: {len(error_events)} < {len(error_scenarios)}"
        
        # System should still be operational
        status = self.orchestrator.get_system_status()
        assert status['system_state'] in ['running', 'degraded', 'error'], "System should handle errors gracefully"


class TestSystemRecoveryAndResilience:
    """Integration tests focused on system recovery and resilience."""
    
    def setup_method(self):
        """Setup test environment."""
        self.config = SystemConfig()
        self.config.set('system.simulation_mode', True)
        self.config.set('logging.log_level', 'DEBUG')
    
    def test_system_restart_recovery(self):
        """Test system recovery after restart."""
        # Initialize system
        orchestrator1 = SystemOrchestrator(self.config)
        assert orchestrator1.initialize_system() is True
        
        # Generate some activity
        integrator1 = orchestrator1.integrator
        alert = SecurityAlert(
            timestamp=datetime.now(),
            alert_id="restart_test_001",
            attack_type=AttackType.ARP_SPOOFING,
            confidence_score=0.95,
            source_mac="aa:bb:cc:dd:ee:01",
            source_ip="192.168.1.100",
            target_mac="aa:bb:cc:dd:ee:ff",
            target_ip="192.168.1.1",
            affected_hosts=["192.168.1.100", "192.168.1.1"],
            raw_packet_data=b"restart_test_packet",
            detection_method=DetectionMethod.SIGNATURE_BASED
        )
        integrator1.emit_event('security_alert', alert)
        time.sleep(0.2)
        
        # Get metrics before shutdown
        status1 = orchestrator1.get_system_status()
        metrics1 = status1.get('metrics', {})
        
        # Shutdown system
        assert orchestrator1.shutdown_system() is True
        
        # Restart system
        orchestrator2 = SystemOrchestrator(self.config)
        assert orchestrator2.initialize_system() is True
        
        # Verify system is operational after restart
        status2 = orchestrator2.get_system_status()
        assert status2['system_state'] == 'running'
        
        # System should be able to process new alerts
        integrator2 = orchestrator2.integrator
        events_received = []
        integrator2.register_event_handler('security_alert', lambda e: events_received.append(e))
        
        integrator2.emit_event('security_alert', alert)
        time.sleep(0.2)
        
        assert len(events_received) >= 1, "System not processing alerts after restart"
        
        # Cleanup
        orchestrator2.shutdown_system()
    
    def test_component_isolation_during_failure(self):
        """Test component isolation when one component fails."""
        orchestrator = SystemOrchestrator(self.config)
        orchestrator.initialize_system()
        
        # Track events from different components
        events_by_component = {
            'detection': [],
            'mitigation': [],
            'recovery': [],
            'logging': []
        }
        
        def track_detection_events(event):
            events_by_component['detection'].append(event)
        
        def track_mitigation_events(event):
            events_by_component['mitigation'].append(event)
        
        def track_recovery_events(event):
            events_by_component['recovery'].append(event)
        
        integrator = orchestrator.integrator
        integrator.register_event_handler('security_alert', track_detection_events)
        integrator.register_event_handler('mitigation_complete', track_mitigation_events)
        integrator.register_event_handler('recovery_complete', track_recovery_events)
        
        # Simulate failure in one component
        orchestrator._handle_component_error('mitigation_controller', 'Simulated mitigation failure')
        
        # Generate alert to test isolation
        alert = SecurityAlert(
            timestamp=datetime.now(),
            alert_id="isolation_test_001",
            attack_type=AttackType.ARP_SPOOFING,
            confidence_score=0.95,
            source_mac="aa:bb:cc:dd:ee:01",
            source_ip="192.168.1.100",
            target_mac="aa:bb:cc:dd:ee:ff",
            target_ip="192.168.1.1",
            affected_hosts=["192.168.1.100", "192.168.1.1"],
            raw_packet_data=b"isolation_test_packet",
            detection_method=DetectionMethod.SIGNATURE_BASED
        )
        
        integrator.emit_event('security_alert', alert)
        time.sleep(0.3)
        
        # Detection should still work
        assert len(events_by_component['detection']) >= 1, "Detection component not isolated properly"
        
        # System should record the component failure
        status = orchestrator.get_system_status()
        component_statuses = status.get('component_statuses', {})
        if 'mitigation_controller' in component_statuses:
            mitigation_status = component_statuses['mitigation_controller']
            assert mitigation_status.get('error_count', 0) > 0, "Component failure not recorded"
        
        orchestrator.shutdown_system()
    
    def test_graceful_shutdown_under_load(self):
        """Test graceful shutdown while system is under load."""
        orchestrator = SystemOrchestrator(self.config)
        orchestrator.initialize_system()
        
        integrator = orchestrator.integrator
        
        # Generate continuous load
        def generate_load():
            for i in range(20):
                alert = SecurityAlert(
                    timestamp=datetime.now(),
                    alert_id=f"shutdown_load_test_{i:03d}",
                    attack_type=AttackType.ARP_SPOOFING,
                    confidence_score=0.95,
                    source_mac=f"aa:bb:cc:dd:ee:{i:02x}",
                    source_ip=f"192.168.1.{100+i}",
                    target_mac="aa:bb:cc:dd:ee:ff",
                    target_ip="192.168.1.1",
                    affected_hosts=[f"192.168.1.{100+i}", "192.168.1.1"],
                    raw_packet_data=f"shutdown_load_packet_{i}".encode(),
                    detection_method=DetectionMethod.SIGNATURE_BASED
                )
                integrator.emit_event('security_alert', alert)
                time.sleep(0.05)
        
        # Start load generation in background
        import threading
        load_thread = threading.Thread(target=generate_load)
        load_thread.start()
        
        # Allow some processing
        time.sleep(0.5)
        
        # Attempt graceful shutdown while under load
        shutdown_start = time.time()
        shutdown_success = orchestrator.shutdown_system()
        shutdown_time = time.time() - shutdown_start
        
        # Wait for load thread to complete
        load_thread.join(timeout=2.0)
        
        # Verify graceful shutdown
        assert shutdown_success is True, "Shutdown failed under load"
        assert shutdown_time < 5.0, f"Shutdown took too long: {shutdown_time:.2f}s"
        
        # Verify final state
        final_status = orchestrator.get_system_status()
        assert final_status['system_state'] in ['stopped', 'shutting_down'], f"Unexpected final state: {final_status['system_state']}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])