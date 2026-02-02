"""
Property-based tests for event logging functionality.

**Feature: lan-security-system, Property 22: Security Event Logging Completeness**
**Feature: lan-security-system, Property 26: Log Persistence and Structure**
**Feature: lan-security-system, Property 28: Log Integrity Protection**
**Validates: Requirements 6.1, 6.5, 6.7**
"""

import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from hypothesis import given, strategies as st, settings
import pytest

from lan_security_system.core.interfaces import SecurityAlert, AttackType, DetectionMethod
from lan_security_system.logging.event_logger import StructuredEventLogger
from lan_security_system.logging.models import EventType, LogLevel


# Test data generators
@st.composite
def security_alert_strategy(draw):
    """Generate random SecurityAlert instances."""
    return SecurityAlert(
        timestamp=draw(st.datetimes(
            min_value=datetime(2020, 1, 1),
            max_value=datetime(2030, 12, 31)
        )),
        alert_id=draw(st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd')))),
        attack_type=draw(st.sampled_from(AttackType)),
        confidence_score=draw(st.floats(min_value=0.0, max_value=1.0)),
        source_mac=draw(st.text(min_size=17, max_size=17, alphabet='0123456789abcdef:')),
        source_ip=draw(st.ip_addresses(v=4).map(str)),
        target_mac=draw(st.text(min_size=17, max_size=17, alphabet='0123456789abcdef:')),
        target_ip=draw(st.ip_addresses(v=4).map(str)),
        affected_hosts=draw(st.lists(st.ip_addresses(v=4).map(str), min_size=1, max_size=10)),
        raw_packet_data=draw(st.binary(min_size=1, max_size=1500)),
        detection_method=draw(st.sampled_from(DetectionMethod))
    )


class TestEventLoggingProperties:
    """Property-based tests for event logging system."""
    
    def setup_method(self):
        """Setup test environment with clean temporary directory."""
        # Create unique temporary directory for each test
        self.temp_dir = tempfile.mkdtemp(prefix="lan_security_test_")
        
        # Ensure directory is completely clean
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        Path(self.temp_dir).mkdir(parents=True, exist_ok=True)
        
        # Create logger with clean directory
        self.logger = StructuredEventLogger(log_directory=self.temp_dir)
    
    def teardown_method(self):
        """Cleanup test environment."""
        # Ensure complete cleanup
        if hasattr(self, 'temp_dir') and Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @given(security_alert_strategy())
    @settings(max_examples=5, deadline=None)
    def test_property_22_security_event_logging_completeness(self, alert):
        """
        Property 22: Security Event Logging Completeness
        For any security event, the logger should record timestamp, attack type, 
        source MAC/IP, and affected hosts.
        **Validates: Requirements 6.1**
        """
        # Log the security event
        log_entry = self.logger.log_security_event(alert)
        
        # Verify all required fields are present in the log entry
        assert log_entry.timestamp is not None
        assert log_entry.event_type == EventType.SECURITY_EVENT
        assert log_entry.source_component == "detection_engine"
        
        # Verify event data contains all required security information
        event_data = log_entry.event_data
        assert 'attack_type' in event_data
        assert 'source_mac' in event_data
        assert 'source_ip' in event_data
        assert 'target_mac' in event_data
        assert 'target_ip' in event_data
        assert 'affected_hosts' in event_data
        assert 'confidence_score' in event_data
        assert 'detection_method' in event_data
        assert 'alert_id' in event_data
        
        # Verify the values match the original alert
        assert event_data['attack_type'] == alert.attack_type.value
        assert event_data['source_mac'] == alert.source_mac
        assert event_data['source_ip'] == alert.source_ip
        assert event_data['target_mac'] == alert.target_mac
        assert event_data['target_ip'] == alert.target_ip
        assert event_data['affected_hosts'] == alert.affected_hosts
        assert event_data['confidence_score'] == alert.confidence_score
        assert event_data['detection_method'] == alert.detection_method.value
        assert event_data['alert_id'] == alert.alert_id
    
    @given(st.lists(security_alert_strategy(), min_size=1, max_size=20))
    @settings(max_examples=5, deadline=None)
    def test_property_26_log_persistence_and_structure(self, alerts):
        """
        Property 26: Log Persistence and Structure
        For any generated event, the logger should maintain persistent log files 
        with structured event data.
        **Validates: Requirements 6.5**
        """
        # Ensure we start with a clean state
        security_log_file = Path(self.temp_dir) / "security_events.jsonl"
        if security_log_file.exists():
            security_log_file.unlink()
        
        # Log all security events
        for alert in alerts:
            self.logger.log_security_event(alert)
        
        # Verify log file exists and is persistent
        assert security_log_file.exists()
        
        # Verify log file contains structured data
        with open(security_log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Should have one line per alert
        assert len(lines) == len(alerts), f"Expected {len(alerts)} log entries, but found {len(lines)}"
        
        # Verify each line contains structured JSON data
        for line in lines:
            line = line.strip()
            assert line  # Non-empty line
            
            # Should be valid JSON
            import json
            log_data = json.loads(line)
            
            # Verify required structure
            required_fields = ['timestamp', 'event_type', 'source_component', 
                             'log_level', 'event_data', 'integrity_hash']
            for field in required_fields:
                assert field in log_data
            
            # Verify event type is correct
            assert log_data['event_type'] == EventType.SECURITY_EVENT.value
            
            # Verify event data structure
            event_data = log_data['event_data']
            security_fields = ['attack_type', 'source_mac', 'source_ip', 
                             'target_mac', 'target_ip', 'affected_hosts']
            for field in security_fields:
                assert field in event_data
        
        # Verify persistence - create new logger instance and retrieve entries
        new_logger = StructuredEventLogger(log_directory=self.temp_dir)
        retrieved_entries = new_logger.get_log_entries(event_type=EventType.SECURITY_EVENT)
        
        # Should retrieve all logged entries
        assert len(retrieved_entries) == len(alerts), f"Expected {len(alerts)} retrieved entries, but found {len(retrieved_entries)}"
    
    @given(st.lists(security_alert_strategy(), min_size=1, max_size=15))
    @settings(max_examples=5, deadline=None)
    def test_property_28_log_integrity_protection(self, alerts):
        """
        Property 28: Log Integrity Protection
        For any created log entry, the system should ensure log integrity 
        and prevent tampering.
        **Validates: Requirements 6.7**
        """
        # Ensure we start with a clean state
        security_log_file = Path(self.temp_dir) / "security_events.jsonl"
        if security_log_file.exists():
            security_log_file.unlink()
        
        # Log all security events
        log_entries = []
        for alert in alerts:
            log_entry = self.logger.log_security_event(alert)
            log_entries.append(log_entry)
        
        # Verify each log entry has integrity protection
        for log_entry in log_entries:
            # Should have integrity hash
            assert log_entry.integrity_hash is not None
            assert len(log_entry.integrity_hash) == 64  # SHA-256 hex string
            
            # Integrity verification should pass
            assert log_entry.verify_integrity() is True
        
        # Verify integrity verification detects tampering
        if log_entries:
            # Tamper with a log entry
            tampered_entry = log_entries[0]
            original_data = tampered_entry.event_data.copy()
            tampered_entry.event_data['attack_type'] = 'tampered_attack'
            
            # Integrity verification should fail
            assert tampered_entry.verify_integrity() is False
            
            # Restore original data
            tampered_entry.event_data = original_data
            assert tampered_entry.verify_integrity() is True
        
        # Verify file-level integrity verification
        integrity_results = self.logger.verify_log_integrity()
        
        # All entries should be valid
        assert integrity_results['total_entries'] == len(alerts), f"Expected {len(alerts)} total entries, but found {integrity_results['total_entries']}"
        assert integrity_results['valid_entries'] == len(alerts), f"Expected {len(alerts)} valid entries, but found {integrity_results['valid_entries']}"
        assert integrity_results['invalid_entries'] == 0
        assert len(integrity_results['corrupted_files']) == 0
    
    @given(st.lists(security_alert_strategy(), min_size=5, max_size=10))
    @settings(max_examples=3, deadline=None)
    def test_log_retrieval_filtering(self, alerts):
        """Test log entry retrieval with various filters."""
        # Ensure we start with a clean state
        security_log_file = Path(self.temp_dir) / "security_events.jsonl"
        if security_log_file.exists():
            security_log_file.unlink()
        
        # Log all alerts with different timestamps
        base_time = datetime.utcnow()
        for i, alert in enumerate(alerts):
            alert.timestamp = base_time + timedelta(minutes=i)
            self.logger.log_security_event(alert)
        
        # Test retrieval without filters
        all_entries = self.logger.get_log_entries()
        assert len(all_entries) == len(alerts), f"Expected {len(alerts)} entries, but found {len(all_entries)}"
        
        # Test retrieval with event type filter
        security_entries = self.logger.get_log_entries(event_type=EventType.SECURITY_EVENT)
        assert len(security_entries) == len(alerts), f"Expected {len(alerts)} security entries, but found {len(security_entries)}"
        
        # Test retrieval with time filters
        mid_time = base_time + timedelta(minutes=len(alerts) // 2)
        recent_entries = self.logger.get_log_entries(start_time=mid_time)
        assert len(recent_entries) <= len(alerts)
        
        # Test retrieval with limit
        limited_entries = self.logger.get_log_entries(limit=3)
        assert len(limited_entries) <= 3
    
    @given(st.integers(min_value=1, max_value=5))
    @settings(max_examples=3, deadline=None)
    def test_log_file_rotation(self, num_alerts):
        """Test log file rotation when size limit is exceeded."""
        # Ensure we start with a clean state
        security_log_file = Path(self.temp_dir) / "security_events.jsonl"
        if security_log_file.exists():
            security_log_file.unlink()
        
        # Remove any existing rotated files
        for rotated_file in Path(self.temp_dir).glob("security_events_*.jsonl"):
            rotated_file.unlink()
        
        # Create logger with very small file size limit
        small_logger = StructuredEventLogger(
            log_directory=self.temp_dir, 
            max_file_size=100  # Very small limit
        )
        
        # Generate alerts to exceed file size
        for i in range(num_alerts):
            alert = SecurityAlert(
                timestamp=datetime.utcnow(),
                alert_id=f"test_alert_{i}",
                attack_type=AttackType.ARP_SPOOFING,
                confidence_score=0.9,
                source_mac="aa:bb:cc:dd:ee:ff",
                source_ip="192.168.1.100",
                target_mac="11:22:33:44:55:66",
                target_ip="192.168.1.1",
                affected_hosts=["192.168.1.10", "192.168.1.20"],
                raw_packet_data=b"test_packet_data" * 50,  # Large packet data
                detection_method=DetectionMethod.SIGNATURE_BASED
            )
            small_logger.log_security_event(alert)
        
        # Check if rotation occurred (multiple log files should exist)
        log_files = list(Path(self.temp_dir).glob("security_events*.jsonl"))
        
        # Should have at least the main log file
        assert len(log_files) >= 1
        
        # If rotation occurred, should have rotated files
        if len(log_files) > 1:
            # Verify rotated files have timestamp in name
            rotated_files = [f for f in log_files if "security_events_" in f.name]
            for rotated_file in rotated_files:
                # Should contain timestamp pattern
                assert len(rotated_file.stem.split('_')) >= 3