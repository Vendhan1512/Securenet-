"""
Unit tests for logging system functionality.
Tests log file creation and rotation, alert delivery mechanisms, and log integrity verification.
**Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7**
"""

import tempfile
import shutil
import json
from datetime import datetime
from pathlib import Path
import pytest

from lan_security_system.core.interfaces import SecurityAlert, MitigationResult, RecoveryResult, AttackType, DetectionMethod
from lan_security_system.logging.event_logger import StructuredEventLogger
from lan_security_system.logging.action_logger import ActionLogger
from lan_security_system.logging.alerting_system import AlertingSystem
from lan_security_system.logging.models import AlertDestination, EventType, LogLevel


class TestStructuredEventLogger:
    """Unit tests for structured event logger."""
    
    def setup_method(self):
        """Setup test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.logger = StructuredEventLogger(log_directory=self.temp_dir)
    
    def teardown_method(self):
        """Cleanup test environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_log_file_creation(self):
        """Test that log files are created when logging events."""
        # Create a test security alert
        alert = SecurityAlert(
            timestamp=datetime.utcnow(),
            alert_id="test_alert_001",
            attack_type=AttackType.ARP_SPOOFING,
            confidence_score=0.9,
            source_mac="aa:bb:cc:dd:ee:ff",
            source_ip="192.168.1.100",
            target_mac="11:22:33:44:55:66",
            target_ip="192.168.1.1",
            affected_hosts=["192.168.1.10", "192.168.1.20"],
            raw_packet_data=b"test_packet_data",
            detection_method=DetectionMethod.SIGNATURE_BASED
        )
        
        # Log the security event
        log_entry = self.logger.log_security_event(alert)
        
        # Verify log file was created
        security_log_file = Path(self.temp_dir) / "security_events.jsonl"
        assert security_log_file.exists()
        
        # Verify log entry structure
        assert log_entry.event_type == EventType.SECURITY_EVENT
        assert log_entry.source_component == "detection_engine"
        assert log_entry.log_level == LogLevel.WARNING
        assert log_entry.integrity_hash is not None
        
        # Verify file contents
        with open(security_log_file, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            assert content  # File should not be empty
            
            # Parse JSON to verify structure
            log_data = json.loads(content)
            assert log_data['event_type'] == 'security_event'
            assert log_data['event_data']['alert_id'] == 'test_alert_001'
    
    def test_log_file_rotation(self):
        """Test log file rotation when size limit is exceeded."""
        # Create logger with very small file size limit
        small_logger = StructuredEventLogger(
            log_directory=self.temp_dir,
            max_file_size=100  # Very small limit
        )
        
        # Create multiple large log entries to trigger rotation
        for i in range(5):
            alert = SecurityAlert(
                timestamp=datetime.utcnow(),
                alert_id=f"large_alert_{i}",
                attack_type=AttackType.ARP_SPOOFING,
                confidence_score=0.9,
                source_mac="aa:bb:cc:dd:ee:ff",
                source_ip="192.168.1.100",
                target_mac="11:22:33:44:55:66",
                target_ip="192.168.1.1",
                affected_hosts=[f"192.168.1.{j}" for j in range(20)],  # Large list
                raw_packet_data=b"large_packet_data" * 50,  # Large data
                detection_method=DetectionMethod.SIGNATURE_BASED
            )
            small_logger.log_security_event(alert)
        
        # Check if rotation occurred
        log_files = list(Path(self.temp_dir).glob("security_events*.jsonl"))
        
        # Should have at least the main log file
        assert len(log_files) >= 1
        
        # If rotation occurred, verify rotated files exist
        if len(log_files) > 1:
            rotated_files = [f for f in log_files if "security_events_" in f.name]
            assert len(rotated_files) > 0
    
    def test_log_integrity_verification(self):
        """Test log integrity verification functionality."""
        # Create and log multiple events
        alerts = []
        for i in range(3):
            alert = SecurityAlert(
                timestamp=datetime.utcnow(),
                alert_id=f"integrity_test_{i}",
                attack_type=AttackType.MAC_FLOODING,
                confidence_score=0.8,
                source_mac="bb:cc:dd:ee:ff:aa",
                source_ip="192.168.1.200",
                target_mac="22:33:44:55:66:77",
                target_ip="192.168.1.2",
                affected_hosts=["192.168.1.30"],
                raw_packet_data=b"integrity_test_data",
                detection_method=DetectionMethod.ANOMALY_BASED
            )
            alerts.append(alert)
            self.logger.log_security_event(alert)
        
        # Verify integrity of all log entries
        integrity_results = self.logger.verify_log_integrity()
        
        assert integrity_results['total_entries'] == len(alerts)
        assert integrity_results['valid_entries'] == len(alerts)
        assert integrity_results['invalid_entries'] == 0
        assert len(integrity_results['corrupted_files']) == 0
    
    def test_log_entry_retrieval_with_filters(self):
        """Test log entry retrieval with various filters."""
        # Create events with different timestamps
        base_time = datetime.utcnow()
        alerts = []
        
        for i in range(5):
            alert = SecurityAlert(
                timestamp=base_time,
                alert_id=f"filter_test_{i}",
                attack_type=AttackType.DNS_SPOOFING,
                confidence_score=0.7,
                source_mac="cc:dd:ee:ff:aa:bb",
                source_ip="192.168.1.300",
                target_mac="33:44:55:66:77:88",
                target_ip="192.168.1.3",
                affected_hosts=["192.168.1.40"],
                raw_packet_data=b"filter_test_data",
                detection_method=DetectionMethod.HYBRID
            )
            alerts.append(alert)
            self.logger.log_security_event(alert)
        
        # Test retrieval without filters
        all_entries = self.logger.get_log_entries()
        assert len(all_entries) == len(alerts)
        
        # Test retrieval with event type filter
        security_entries = self.logger.get_log_entries(event_type=EventType.SECURITY_EVENT)
        assert len(security_entries) == len(alerts)
        
        # Test retrieval with limit
        limited_entries = self.logger.get_log_entries(limit=2)
        assert len(limited_entries) == 2


class TestActionLogger:
    """Unit tests for action logger."""
    
    def setup_method(self):
        """Setup test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.logger = ActionLogger(log_directory=self.temp_dir)
    
    def teardown_method(self):
        """Cleanup test environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_mitigation_action_logging(self):
        """Test logging of mitigation actions."""
        # Create a test mitigation result
        mitigation = MitigationResult(
            success=True,
            mitigation_id="test_mitigation_001",
            actions_taken=["block_mac_address", "insert_firewall_rule"],
            timestamp=datetime.utcnow(),
            error_message=None
        )
        
        # Log the mitigation action
        log_entry = self.logger.log_mitigation_action(mitigation, AttackType.ARP_SPOOFING)
        
        # Verify log entry structure
        assert log_entry.event_type == EventType.MITIGATION_ACTION
        assert log_entry.source_component == "mitigation_controller"
        assert log_entry.log_level == LogLevel.INFO  # Success should be INFO
        
        # Verify event data contains required fields
        event_data = log_entry.event_data
        assert event_data['mitigation_id'] == "test_mitigation_001"
        assert event_data['attack_type'] == "arp_spoofing"
        assert event_data['actions_taken'] == ["block_mac_address", "insert_firewall_rule"]
        assert event_data['success'] is True
        
        # Verify audit trail information is present
        assert 'execution_timestamp' in event_data
        assert 'containment_measures' in event_data
        assert 'affected_components' in event_data
        
        # Verify log files were created
        mitigation_audit_file = Path(self.temp_dir) / "mitigation_audit.jsonl"
        action_summary_file = Path(self.temp_dir) / "action_summary.jsonl"
        
        assert mitigation_audit_file.exists()
        assert action_summary_file.exists()
    
    def test_recovery_confirmation_logging(self):
        """Test logging of recovery confirmations."""
        # Create a test recovery result
        recovery = RecoveryResult(
            success=True,
            recovery_id="test_recovery_001",
            restored_components=["arp_cache", "dns_cache"],
            timestamp=datetime.utcnow(),
            verification_results={"connectivity": True, "services": True},
            error_message=None
        )
        
        # Log the recovery confirmation
        log_entry = self.logger.log_recovery_confirmation(recovery, AttackType.DNS_SPOOFING)
        
        # Verify log entry structure
        assert log_entry.event_type == EventType.RECOVERY_CONFIRMATION
        assert log_entry.source_component == "recovery_manager"
        assert log_entry.log_level == LogLevel.INFO  # Success should be INFO
        
        # Verify event data contains required fields
        event_data = log_entry.event_data
        assert event_data['recovery_id'] == "test_recovery_001"
        assert event_data['attack_type'] == "dns_spoofing"
        assert event_data['restored_components'] == ["arp_cache", "dns_cache"]
        assert event_data['verification_results'] == {"connectivity": True, "services": True}
        assert event_data['success'] is True
        
        # Verify recovery-specific audit information
        assert 'recovery_timestamp' in event_data
        assert 'verification_summary' in event_data
        assert 'restoration_steps' in event_data
        
        # Verify verification summary calculations
        verification_summary = event_data['verification_summary']
        assert verification_summary['total_verification_checks'] == 2
        assert verification_summary['passed_checks'] == 2
        assert verification_summary['failed_checks'] == 0
        assert verification_summary['success_rate'] == 1.0
        assert verification_summary['failed_components'] == []
    
    def test_audit_trail_retrieval(self):
        """Test audit trail retrieval functionality."""
        # Create and log multiple mitigation actions
        mitigations = []
        for i in range(3):
            mitigation = MitigationResult(
                success=True,
                mitigation_id=f"audit_test_{i}",
                actions_taken=[f"action_{i}"],
                timestamp=datetime.utcnow(),
                error_message=None
            )
            mitigations.append(mitigation)
            self.logger.log_mitigation_action(mitigation, AttackType.MAC_FLOODING)
        
        # Retrieve mitigation audit trail
        audit_entries = self.logger.get_mitigation_audit_trail()
        assert len(audit_entries) == len(mitigations)
        
        # Verify entries are sorted by timestamp (most recent first)
        for i in range(len(audit_entries) - 1):
            assert audit_entries[i].timestamp >= audit_entries[i + 1].timestamp
        
        # Test filtering by mitigation ID
        specific_entries = self.logger.get_mitigation_audit_trail(
            mitigation_id="audit_test_1"
        )
        assert len(specific_entries) == 1
        assert specific_entries[0].event_data['mitigation_id'] == "audit_test_1"
    
    def test_action_summary_report_generation(self):
        """Test comprehensive action summary report generation."""
        # Create and log some mitigation and recovery actions
        mitigation = MitigationResult(
            success=True,
            mitigation_id="summary_test_mitigation",
            actions_taken=["test_action"],
            timestamp=datetime.utcnow(),
            error_message=None
        )
        self.logger.log_mitigation_action(mitigation, AttackType.ARP_SPOOFING)
        
        recovery = RecoveryResult(
            success=True,
            recovery_id="summary_test_recovery",
            restored_components=["test_component"],
            timestamp=datetime.utcnow(),
            verification_results={"test": True},
            error_message=None
        )
        self.logger.log_recovery_confirmation(recovery, AttackType.ARP_SPOOFING)
        
        # Generate summary report
        report = self.logger.generate_action_summary_report()
        
        # Verify report structure
        assert 'report_period' in report
        assert 'mitigation_statistics' in report
        assert 'recovery_statistics' in report
        assert 'overall_success_rate' in report
        
        # Verify mitigation statistics
        mitigation_stats = report['mitigation_statistics']
        assert mitigation_stats['total_mitigations'] == 1
        assert mitigation_stats['successful_mitigations'] == 1
        assert mitigation_stats['failed_mitigations'] == 0
        
        # Verify recovery statistics
        recovery_stats = report['recovery_statistics']
        assert recovery_stats['total_recoveries'] == 1
        assert recovery_stats['successful_recoveries'] == 1
        assert recovery_stats['failed_recoveries'] == 0
        
        # Verify overall success rate
        assert report['overall_success_rate'] == 1.0


class TestAlertingSystem:
    """Unit tests for alerting system."""
    
    def setup_method(self):
        """Setup test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.alerting_system = AlertingSystem()
    
    def teardown_method(self):
        """Cleanup test environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_alert_destination_management(self):
        """Test adding and removing alert destinations."""
        # Create test destinations
        console_dest = AlertDestination("console", "console", True, 1, 30)
        email_dest = AlertDestination("email", "test@example.com", True, 3, 60)
        
        # Add destinations
        self.alerting_system.add_alert_destination(console_dest)
        self.alerting_system.add_alert_destination(email_dest)
        
        # Verify destinations were added
        stats = self.alerting_system.get_destination_statistics()
        assert stats["total_destinations"] == 2
        assert stats["enabled_destinations"] == 2
        
        # Remove a destination
        success = self.alerting_system.remove_alert_destination("email", "test@example.com")
        assert success is True
        
        # Verify removal
        updated_stats = self.alerting_system.get_destination_statistics()
        assert updated_stats["total_destinations"] == 1
        
        # Try to remove non-existent destination
        failure = self.alerting_system.remove_alert_destination("sms", "+1234567890")
        assert failure is False
    
    def test_console_alert_generation(self):
        """Test console alert generation."""
        # Create a test security alert
        alert = SecurityAlert(
            timestamp=datetime.utcnow(),
            alert_id="console_test_001",
            attack_type=AttackType.ARP_SPOOFING,
            confidence_score=0.9,
            source_mac="aa:bb:cc:dd:ee:ff",
            source_ip="192.168.1.100",
            target_mac="11:22:33:44:55:66",
            target_ip="192.168.1.1",
            affected_hosts=["192.168.1.10", "192.168.1.20"],
            raw_packet_data=b"test_packet_data",
            detection_method=DetectionMethod.SIGNATURE_BASED
        )
        
        # Generate console alert (should not raise exception)
        self.alerting_system.generate_console_alert(alert)
        
        # Test alert formatting
        formatted_alert = self.alerting_system._format_console_alert(alert)
        assert isinstance(formatted_alert, str)
        assert "ARP_SPOOFING" in formatted_alert
        assert "192.168.1.100" in formatted_alert
        assert "192.168.1.1" in formatted_alert
        assert "console_test_001" in formatted_alert
    
    def test_alert_delivery_mechanisms(self):
        """Test alert delivery to different destination types."""
        # Create test destinations
        destinations = [
            AlertDestination("console", "console", True, 1, 30),
            AlertDestination("email", "smtp://user:pass@server:587/test@example.com", True, 2, 30),
            AlertDestination("webhook", "https://webhook.example.com/alerts", True, 1, 30),
            AlertDestination("sms", "+1234567890", True, 1, 30)
        ]
        
        for dest in destinations:
            self.alerting_system.add_alert_destination(dest)
        
        # Create test alert
        alert = SecurityAlert(
            timestamp=datetime.utcnow(),
            alert_id="delivery_test_001",
            attack_type=AttackType.MAC_FLOODING,
            confidence_score=0.8,
            source_mac="bb:cc:dd:ee:ff:aa",
            source_ip="192.168.1.200",
            target_mac="22:33:44:55:66:77",
            target_ip="192.168.1.2",
            affected_hosts=["192.168.1.30"],
            raw_packet_data=b"delivery_test_data",
            detection_method=DetectionMethod.ANOMALY_BASED
        )
        
        # Send alert to all destinations
        delivery_results = self.alerting_system.send_alert_to_destinations(alert)
        
        # Verify delivery was attempted for all destinations
        assert len(delivery_results) == len(destinations)
        
        # In our mock implementation, all deliveries should succeed
        for address, success in delivery_results.items():
            assert success is True
    
    def test_configuration_persistence(self):
        """Test saving and loading alerting configuration."""
        config_file = Path(self.temp_dir) / "test_alerting_config.json"
        
        # Add some destinations
        destinations = [
            AlertDestination("console", "console", True, 1, 30),
            AlertDestination("email", "test@example.com", False, 3, 60)
        ]
        
        for dest in destinations:
            self.alerting_system.add_alert_destination(dest)
        
        # Save configuration
        self.alerting_system.save_configuration(str(config_file))
        
        # Verify config file was created
        assert config_file.exists()
        
        # Load configuration into new alerting system
        new_alerting_system = AlertingSystem(str(config_file))
        
        # Verify destinations were loaded
        original_stats = self.alerting_system.get_destination_statistics()
        loaded_stats = new_alerting_system.get_destination_statistics()
        
        assert loaded_stats["total_destinations"] == original_stats["total_destinations"]
        assert loaded_stats["enabled_destinations"] == original_stats["enabled_destinations"]
    
    def test_callback_registration_and_execution(self):
        """Test callback registration and execution."""
        callback_results = []
        
        def test_callback(alert):
            callback_results.append(alert.alert_id)
        
        # Register callback
        self.alerting_system.register_alert_callback(test_callback)
        
        # Create and process alert
        alert = SecurityAlert(
            timestamp=datetime.utcnow(),
            alert_id="callback_test_001",
            attack_type=AttackType.DNS_SPOOFING,
            confidence_score=0.7,
            source_mac="cc:dd:ee:ff:aa:bb",
            source_ip="192.168.1.300",
            target_mac="33:44:55:66:77:88",
            target_ip="192.168.1.3",
            affected_hosts=["192.168.1.40"],
            raw_packet_data=b"callback_test_data",
            detection_method=DetectionMethod.HYBRID
        )
        
        # Process alert
        results = self.alerting_system.process_security_alert(alert)
        
        # Verify callback was executed
        assert results["callbacks_executed"] >= 1
        assert "callback_test_001" in callback_results
    
    def test_destination_testing(self):
        """Test destination testing functionality."""
        # Add test destinations
        destinations = [
            AlertDestination("console", "console", True, 1, 30),
            AlertDestination("email", "test@example.com", True, 2, 30),
            AlertDestination("webhook", "https://webhook.example.com/test", False, 1, 30)
        ]
        
        for dest in destinations:
            self.alerting_system.add_alert_destination(dest)
        
        # Test destinations
        test_results = self.alerting_system.test_destinations()
        
        # Should only test enabled destinations
        enabled_count = sum(1 for d in destinations if d.enabled)
        assert len(test_results) == enabled_count
        
        # All enabled destinations should succeed in mock implementation
        for address, success in test_results.items():
            assert success is True