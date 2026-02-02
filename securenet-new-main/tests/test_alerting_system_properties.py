"""
Property-based tests for alerting system functionality.

**Feature: lan-security-system, Property 25: Real-time Alert Generation**
**Feature: lan-security-system, Property 27: Configurable Alert Destinations**
**Validates: Requirements 6.4, 6.6**
"""

import tempfile
import shutil
import json
from datetime import datetime
from pathlib import Path
from hypothesis import given, strategies as st, settings
import pytest

from lan_security_system.core.interfaces import SecurityAlert, AttackType, DetectionMethod
from lan_security_system.logging.alerting_system import AlertingSystem
from lan_security_system.logging.models import AlertDestination


# Test data generators
@st.composite
def security_alert_strategy(draw):
    """Generate random SecurityAlert instances with ASCII-safe strings."""
    return SecurityAlert(
        timestamp=draw(st.datetimes(
            min_value=datetime(2020, 1, 1),
            max_value=datetime(2030, 12, 31)
        )),
        alert_id=draw(st.text(min_size=1, max_size=50, alphabet=st.characters(min_codepoint=32, max_codepoint=126))),
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


@st.composite
def alert_destination_strategy(draw):
    """Generate random AlertDestination instances."""
    destination_types = ["console", "email", "webhook", "sms"]
    dest_type = draw(st.sampled_from(destination_types))
    
    if dest_type == "email":
        address = f"smtp://user:pass@server:587/{draw(st.emails())}"
    elif dest_type == "webhook":
        address = f"https://webhook.example.com/{draw(st.text(min_size=1, max_size=20, alphabet=st.characters(min_codepoint=97, max_codepoint=122)))}"
    elif dest_type == "sms":
        address = f"+1{draw(st.integers(min_value=1000000000, max_value=9999999999))}"
    else:  # console
        address = "console"
    
    return AlertDestination(
        destination_type=dest_type,
        address=address,
        enabled=draw(st.booleans()),
        retry_count=draw(st.integers(min_value=1, max_value=5)),
        timeout=draw(st.integers(min_value=10, max_value=60))
    )


class TestAlertingSystemProperties:
    """Property-based tests for alerting system."""
    
    def setup_method(self):
        """Setup test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.alerting_system = AlertingSystem()
        self.generated_alerts = []
        
        # Ensure clean state - clear any existing destinations
        self.alerting_system.destinations.clear()
        self.alerting_system.alert_callbacks.clear()
        
        # Register callback to capture alerts
        def capture_alert(alert):
            self.generated_alerts.append(alert)
        
        self.alerting_system.register_alert_callback(capture_alert)
    
    def teardown_method(self):
        """Cleanup test environment."""
        # Clear alerting system state
        if hasattr(self, 'alerting_system'):
            self.alerting_system.destinations.clear()
            self.alerting_system.alert_callbacks.clear()
        
        # Clear generated alerts
        self.generated_alerts.clear()
        
        # Clean up temp directory
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @given(security_alert_strategy())
    @settings(max_examples=5, deadline=None)
    def test_property_25_real_time_alert_generation(self, alert):
        """
        Property 25: Real-time Alert Generation
        For any detected attack, the logger should generate real-time console alerts.
        **Validates: Requirements 6.4**
        """
        # Clear any previous alerts
        self.generated_alerts.clear()
        
        # Process the security alert
        results = self.alerting_system.process_security_alert(alert)
        
        # Verify console alert was generated
        assert results["console_alert_generated"] is True
        
        # Verify alert processing results structure
        assert "alert_id" in results
        assert "timestamp" in results
        assert "console_alert_generated" in results
        assert "destinations_notified" in results
        assert "callbacks_executed" in results
        assert "errors" in results
        
        # Verify alert ID matches
        assert results["alert_id"] == alert.alert_id
        
        # Verify callback was executed (our capture callback)
        assert results["callbacks_executed"] >= 1
        
        # Verify our callback captured the alert
        assert len(self.generated_alerts) >= 1
        captured_alert = self.generated_alerts[-1]  # Get the most recent
        assert captured_alert.alert_id == alert.alert_id
        assert captured_alert.attack_type == alert.attack_type
        assert captured_alert.source_ip == alert.source_ip
        assert captured_alert.target_ip == alert.target_ip
        
        # Verify timestamp is recent (within last few seconds)
        result_timestamp = datetime.fromisoformat(results["timestamp"])
        time_diff = abs((datetime.utcnow() - result_timestamp).total_seconds())
        assert time_diff < 5.0  # Should be very recent
    
    @given(st.lists(alert_destination_strategy(), min_size=1, max_size=5))
    @settings(max_examples=5, deadline=None)
    def test_property_27_configurable_alert_destinations(self, destinations):
        """
        Property 27: Configurable Alert Destinations
        For any configured alert destination, the logger should successfully 
        send alerts to that destination.
        **Validates: Requirements 6.6**
        """
        # Clear any existing destinations to ensure clean state
        self.alerting_system.destinations.clear()
        
        # Add all destinations to the alerting system
        for destination in destinations:
            self.alerting_system.add_alert_destination(destination)
        
        # Verify destinations were added
        stats = self.alerting_system.get_destination_statistics()
        assert stats["total_destinations"] == len(destinations)
        
        # Count enabled destinations
        enabled_destinations = [d for d in destinations if d.enabled]
        assert stats["enabled_destinations"] == len(enabled_destinations)
        
        # Verify destinations by type are correctly counted
        type_counts = {}
        for dest in destinations:
            type_counts[dest.destination_type] = type_counts.get(dest.destination_type, 0) + 1
        
        for dest_type, count in type_counts.items():
            assert stats["destinations_by_type"][dest_type]["total"] == count
        
        # Create a test alert
        test_alert = SecurityAlert(
            timestamp=datetime.utcnow(),
            alert_id="test_alert_123",
            attack_type=AttackType.ARP_SPOOFING,
            confidence_score=0.8,
            source_mac="aa:bb:cc:dd:ee:ff",
            source_ip="192.168.1.100",
            target_mac="11:22:33:44:55:66",
            target_ip="192.168.1.1",
            affected_hosts=["192.168.1.10", "192.168.1.20"],
            raw_packet_data=b"test_packet_data",
            detection_method=DetectionMethod.SIGNATURE_BASED
        )
        
        # Send alert to all destinations
        delivery_results = self.alerting_system.send_alert_to_destinations(test_alert)
        
        # Group destinations by address to handle duplicates correctly
        destinations_by_address = {}
        for dest in destinations:
            if dest.address not in destinations_by_address:
                destinations_by_address[dest.address] = []
            destinations_by_address[dest.address].append(dest)
        
        # Verify delivery logic: an address should have delivery results if ANY destination 
        # with that address is enabled
        for address, dests_for_address in destinations_by_address.items():
            has_enabled_dest = any(d.enabled for d in dests_for_address)
            
            if has_enabled_dest:
                # Should have delivery results for this address
                assert address in delivery_results
                assert delivery_results[address] is True
            else:
                # Should NOT have delivery results for this address
                assert address not in delivery_results
    
    @given(st.lists(alert_destination_strategy(), min_size=1, max_size=3))
    @settings(max_examples=3, deadline=None)
    def test_destination_management(self, destinations):
        """Test adding and removing alert destinations."""
        # Add all destinations
        for destination in destinations:
            self.alerting_system.add_alert_destination(destination)
        
        # Verify all were added
        stats = self.alerting_system.get_destination_statistics()
        assert stats["total_destinations"] == len(destinations)
        
        # Remove destinations one by one
        for destination in destinations:
            success = self.alerting_system.remove_alert_destination(
                destination.destination_type, 
                destination.address
            )
            assert success is True
        
        # Verify all were removed
        final_stats = self.alerting_system.get_destination_statistics()
        assert final_stats["total_destinations"] == 0
        
        # Try to remove non-existent destination
        non_existent_removal = self.alerting_system.remove_alert_destination(
            "email", "nonexistent@example.com"
        )
        assert non_existent_removal is False
    
    @given(st.lists(alert_destination_strategy(), min_size=1, max_size=3))
    @settings(max_examples=3, deadline=None)
    def test_configuration_persistence(self, destinations):
        """Test saving and loading alerting configuration."""
        config_file = Path(self.temp_dir) / "alerting_config.json"
        
        # Add destinations to the system
        for destination in destinations:
            self.alerting_system.add_alert_destination(destination)
        
        # Save configuration
        self.alerting_system.save_configuration(str(config_file))
        
        # Verify config file was created
        assert config_file.exists()
        
        # Load configuration into a new alerting system
        new_alerting_system = AlertingSystem()
        new_alerting_system.load_configuration(str(config_file))
        
        # Verify destinations were loaded correctly
        original_stats = self.alerting_system.get_destination_statistics()
        loaded_stats = new_alerting_system.get_destination_statistics()
        
        assert loaded_stats["total_destinations"] == original_stats["total_destinations"]
        assert loaded_stats["enabled_destinations"] == original_stats["enabled_destinations"]
        assert loaded_stats["destinations_by_type"] == original_stats["destinations_by_type"]
    
    @given(st.lists(security_alert_strategy(), min_size=1, max_size=5))
    @settings(max_examples=3, deadline=None)
    def test_callback_registration_and_execution(self, alerts):
        """Test callback registration and execution for alerts."""
        callback_results = []
        
        def test_callback_1(alert):
            callback_results.append(f"callback1_{alert.alert_id}")
        
        def test_callback_2(alert):
            callback_results.append(f"callback2_{alert.alert_id}")
        
        # Register callbacks
        self.alerting_system.register_alert_callback(test_callback_1)
        self.alerting_system.register_alert_callback(test_callback_2)
        
        # Process all alerts
        for alert in alerts:
            results = self.alerting_system.process_security_alert(alert)
            
            # Should execute our 2 callbacks plus the setup callback (3 total)
            assert results["callbacks_executed"] >= 3
        
        # Verify callbacks were executed for each alert
        expected_callback_count = len(alerts) * 2  # 2 callbacks per alert
        assert len(callback_results) == expected_callback_count
        
        # Verify callback results contain expected patterns
        for alert in alerts:
            assert f"callback1_{alert.alert_id}" in callback_results
            assert f"callback2_{alert.alert_id}" in callback_results
    
    @given(security_alert_strategy())
    @settings(max_examples=3, deadline=None)
    def test_alert_severity_calculation(self, alert):
        """Test alert severity calculation based on confidence score."""
        # Process the alert to trigger severity calculation
        self.alerting_system.process_security_alert(alert)
        
        # Test severity calculation directly
        severity = self.alerting_system._calculate_severity(alert)
        
        # Verify severity matches confidence score ranges
        if alert.confidence_score >= 0.9:
            assert severity == "CRITICAL"
        elif alert.confidence_score >= 0.7:
            assert severity == "HIGH"
        elif alert.confidence_score >= 0.5:
            assert severity == "MEDIUM"
        else:
            assert severity == "LOW"
    
    @given(security_alert_strategy())
    @settings(max_examples=3, deadline=None)
    def test_alert_formatting_methods(self, alert):
        """Test various alert formatting methods."""
        # Test console alert formatting
        console_message = self.alerting_system._format_console_alert(alert)
        assert isinstance(console_message, str)
        assert len(console_message) > 0
        assert alert.attack_type.value.upper() in console_message
        assert alert.source_ip in console_message
        assert alert.target_ip in console_message
        
        # Test email alert formatting
        email_content = self.alerting_system._format_email_alert(alert)
        assert isinstance(email_content, str)
        assert len(email_content) > 0
        assert alert.attack_type.value.upper() in email_content
        assert alert.alert_id in email_content
        assert f"{alert.confidence_score:.2f}" in email_content
        
        # Test webhook alert formatting
        webhook_data = self.alerting_system._format_webhook_alert(alert)
        assert isinstance(webhook_data, dict)
        assert webhook_data["alert_id"] == alert.alert_id
        assert webhook_data["attack_type"] == alert.attack_type.value
        assert webhook_data["confidence_score"] == alert.confidence_score
        assert webhook_data["source"]["ip"] == alert.source_ip
        assert webhook_data["target"]["ip"] == alert.target_ip
        
        # Test SMS alert formatting
        sms_content = self.alerting_system._format_sms_alert(alert)
        assert isinstance(sms_content, str)
        assert len(sms_content) > 0
        assert len(sms_content) <= 160  # SMS length limit
        assert alert.attack_type.value.upper() in sms_content
        assert alert.source_ip in sms_content
        assert alert.alert_id in sms_content
    
    def test_destination_testing_functionality(self):
        """Test the destination testing functionality."""
        # Add some test destinations
        destinations = [
            AlertDestination("console", "console", True, 1, 30),
            AlertDestination("email", "smtp://test:pass@server:587/test@example.com", True, 2, 30),
            AlertDestination("webhook", "https://webhook.example.com/test", False, 1, 30)
        ]
        
        for dest in destinations:
            self.alerting_system.add_alert_destination(dest)
        
        # Test all destinations
        test_results = self.alerting_system.test_destinations()
        
        # Should have results for enabled destinations only
        enabled_destinations = [d for d in destinations if d.enabled]
        assert len(test_results) == len(enabled_destinations)
        
        # All enabled destinations should succeed in our mock implementation
        for address, success in test_results.items():
            assert success is True