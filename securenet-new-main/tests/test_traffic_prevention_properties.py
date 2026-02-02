"""
Property-based tests for traffic prevention functionality.

**Feature: lan-security-system, Property 16: Attack Traffic Prevention**
"""

import pytest
from datetime import datetime, timedelta
from hypothesis import given, strategies as st, settings, HealthCheck

from lan_security_system.core.interfaces import AttackType, DetectionMethod, SecurityAlert
from lan_security_system.mitigation.controller import AutomatedMitigationController
from lan_security_system.mitigation.traffic_filter import TrafficFilter


# Strategies for generating test data
def generate_ip_address():
    """Generate a valid IP address."""
    return st.builds(
        lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
        st.integers(1, 254), st.integers(0, 255), 
        st.integers(0, 255), st.integers(1, 254)
    )

def generate_mac_address():
    """Generate a valid MAC address."""
    return st.builds(
        lambda a, b, c, d, e, f: f"{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}",
        st.integers(0, 255), st.integers(0, 255), st.integers(0, 255),
        st.integers(0, 255), st.integers(0, 255), st.integers(0, 255)
    )

ip_address_strategy = generate_ip_address()
mac_address_strategy = generate_mac_address()
packet_data_strategy = st.binary(min_size=64, max_size=1500)


def create_security_alert(attack_type: AttackType, source_mac: str, source_ip: str, 
                         target_mac: str, target_ip: str) -> SecurityAlert:
    """Create a security alert for testing."""
    return SecurityAlert(
        timestamp=datetime.now(),
        alert_id="test-alert-123",
        attack_type=attack_type,
        confidence_score=0.9,
        source_mac=source_mac,
        source_ip=source_ip,
        target_mac=target_mac,
        target_ip=target_ip,
        affected_hosts=[target_ip],
        raw_packet_data=b"test_packet_data",
        detection_method=DetectionMethod.SIGNATURE_BASED
    )


class TestAttackTrafficPrevention:
    """Test attack traffic prevention property."""
    
    @given(
        attack_type=st.sampled_from([AttackType.ARP_SPOOFING, AttackType.MAC_FLOODING, AttackType.DNS_SPOOFING]),
        source_mac=mac_address_strategy,
        source_ip=ip_address_strategy,
        target_mac=mac_address_strategy,
        target_ip=ip_address_strategy,
        packet_data=packet_data_strategy
    )
    def test_attack_traffic_prevention_after_mitigation(self, attack_type, source_mac, source_ip, target_mac, target_ip, packet_data):
        """
        **Property 16: Attack Traffic Prevention**
        *For any* identified attack source after mitigation, the system should prevent further attack traffic from that source
        **Validates: Requirements 4.7**
        """
        # Create security alert
        alert = create_security_alert(attack_type, source_mac, source_ip, target_mac, target_ip)
        
        # Create mitigation controller
        controller = AutomatedMitigationController()
        
        # Execute mitigation
        result = controller.execute_mitigation(alert)
        
        # Verify mitigation was successful
        assert result.success, f"Mitigation failed: {result.error_message}"
        
        # Verify the source is now blocked
        assert controller.is_source_blocked(source_ip, source_mac), f"Source {source_ip} ({source_mac}) should be blocked after mitigation"
        
        # Test traffic filtering - packets from the blocked source should be blocked
        traffic_filter = controller.get_traffic_filter()
        packet_allowed = traffic_filter.filter_packet(source_ip, source_mac, packet_data)
        
        assert not packet_allowed, f"Traffic from blocked source {source_ip} ({source_mac}) should be prevented"
        
        # Verify traffic statistics show blocked packets
        stats = traffic_filter.get_traffic_stats()
        assert stats["blocked_packets"] > 0, "Traffic statistics should show blocked packets"
    
    @given(
        attack_type=st.sampled_from([AttackType.ARP_SPOOFING, AttackType.MAC_FLOODING, AttackType.DNS_SPOOFING]),
        source_mac=mac_address_strategy,
        source_ip=ip_address_strategy,
        target_mac=mac_address_strategy,
        target_ip=ip_address_strategy,
        legitimate_ip=ip_address_strategy,
        legitimate_mac=mac_address_strategy,
        packet_data=packet_data_strategy
    )
    def test_legitimate_traffic_not_blocked(self, attack_type, source_mac, source_ip, target_mac, target_ip, 
                                          legitimate_ip, legitimate_mac, packet_data):
        """Test that legitimate traffic is not blocked after mitigation."""
        # Ensure legitimate source is different from attack source
        if legitimate_ip == source_ip or legitimate_mac == source_mac:
            return  # Skip this test case
        
        # Create security alert
        alert = create_security_alert(attack_type, source_mac, source_ip, target_mac, target_ip)
        
        # Create mitigation controller
        controller = AutomatedMitigationController()
        
        # Execute mitigation
        result = controller.execute_mitigation(alert)
        
        # Verify mitigation was successful
        assert result.success, f"Mitigation failed: {result.error_message}"
        
        # Test that legitimate traffic is still allowed
        traffic_filter = controller.get_traffic_filter()
        packet_allowed = traffic_filter.filter_packet(legitimate_ip, legitimate_mac, packet_data)
        
        assert packet_allowed, f"Legitimate traffic from {legitimate_ip} ({legitimate_mac}) should be allowed"
        
        # Verify legitimate source is not blocked
        assert not controller.is_source_blocked(legitimate_ip, legitimate_mac), f"Legitimate source {legitimate_ip} ({legitimate_mac}) should not be blocked"


class TestTrafficFilterEffectiveness:
    """Test traffic filter effectiveness."""
    
    @given(
        source_mac=mac_address_strategy,
        source_ip=ip_address_strategy,
        target_mac=mac_address_strategy,
        target_ip=ip_address_strategy,
        packet_data=packet_data_strategy
    )
    def test_traffic_filter_blocks_after_source_blocking(self, source_mac, source_ip, target_mac, target_ip, packet_data):
        """Test that traffic filter correctly blocks packets after source is blocked."""
        # Create traffic filter
        traffic_filter = TrafficFilter()
        
        # Create security alert
        alert = create_security_alert(AttackType.ARP_SPOOFING, source_mac, source_ip, target_mac, target_ip)
        
        # Initially, traffic should be allowed
        initial_allowed = traffic_filter.filter_packet(source_ip, source_mac, packet_data)
        assert initial_allowed, "Traffic should initially be allowed"
        
        # Block the attack source
        mitigation_id = "test-mitigation-123"
        block_success = traffic_filter.block_attack_source(alert, mitigation_id)
        assert block_success, "Source blocking should be successful"
        
        # Now traffic should be blocked
        blocked_packet = traffic_filter.filter_packet(source_ip, source_mac, packet_data)
        assert not blocked_packet, "Traffic should be blocked after source blocking"
        
        # Verify source is marked as blocked
        assert traffic_filter.is_source_blocked(source_ip, source_mac), "Source should be marked as blocked"
    
    @given(
        source_mac=mac_address_strategy,
        source_ip=ip_address_strategy,
        target_mac=mac_address_strategy,
        target_ip=ip_address_strategy
    )
    def test_mitigation_effectiveness_validation(self, source_mac, source_ip, target_mac, target_ip):
        """Test that mitigation effectiveness can be validated."""
        # Create traffic filter
        traffic_filter = TrafficFilter()
        
        # Create security alert
        alert = create_security_alert(AttackType.DNS_SPOOFING, source_mac, source_ip, target_mac, target_ip)
        
        # Block the attack source
        mitigation_id = "test-mitigation-456"
        block_success = traffic_filter.block_attack_source(alert, mitigation_id)
        assert block_success, "Source blocking should be successful"
        
        # Validate mitigation effectiveness
        effectiveness = traffic_filter.validate_mitigation_effectiveness(mitigation_id)
        assert effectiveness, "Mitigation should be validated as effective"
    
    @given(
        source_mac=mac_address_strategy,
        source_ip=ip_address_strategy,
        target_mac=mac_address_strategy,
        target_ip=ip_address_strategy
    )
    def test_source_unblocking(self, source_mac, source_ip, target_mac, target_ip):
        """Test that sources can be unblocked and traffic resumes."""
        # Create traffic filter
        traffic_filter = TrafficFilter()
        
        # Create security alert
        alert = create_security_alert(AttackType.MAC_FLOODING, source_mac, source_ip, target_mac, target_ip)
        
        # Block the source
        mitigation_id = "test-mitigation-789"
        block_success = traffic_filter.block_attack_source(alert, mitigation_id)
        assert block_success, "Source blocking should be successful"
        
        # Verify source is blocked
        assert traffic_filter.is_source_blocked(source_ip, source_mac), "Source should be blocked"
        
        # Unblock the source
        unblock_success = traffic_filter.unblock_source(source_ip)
        assert unblock_success, "Source unblocking should be successful"
        
        # Verify source is no longer blocked
        assert not traffic_filter.is_source_blocked(source_ip, source_mac), "Source should no longer be blocked"
        
        # Verify traffic is now allowed
        packet_data = b"test_packet"
        packet_allowed = traffic_filter.filter_packet(source_ip, source_mac, packet_data)
        assert packet_allowed, "Traffic should be allowed after unblocking"


class TestTemporaryBlocking:
    """Test temporary blocking functionality."""
    
    @given(
        source_mac=mac_address_strategy,
        source_ip=ip_address_strategy,
        target_mac=mac_address_strategy,
        target_ip=ip_address_strategy
    )
    @settings(suppress_health_check=[HealthCheck.too_slow], max_examples=3, deadline=None)
    def test_temporary_block_expiration(self, source_mac, source_ip, target_mac, target_ip):
        """Test that temporary blocks expire correctly."""
        # Create traffic filter
        traffic_filter = TrafficFilter()
        
        # Create security alert
        alert = create_security_alert(AttackType.ARP_SPOOFING, source_mac, source_ip, target_mac, target_ip)
        
        # Block the source with a short duration (100 milliseconds)
        mitigation_id = "test-mitigation-temp"
        block_duration = timedelta(milliseconds=100)
        block_success = traffic_filter.block_attack_source(alert, mitigation_id, block_duration)
        assert block_success, "Temporary source blocking should be successful"
        
        # Initially, source should be blocked
        assert traffic_filter.is_source_blocked(source_ip, source_mac), "Source should initially be blocked"
        
        # Wait for block to expire (simulate by checking after the duration)
        import time
        time.sleep(0.11)  # Wait 110 milliseconds to ensure expiration
        
        # Check if source is still blocked (should trigger expiration check)
        is_blocked = traffic_filter.is_source_blocked(source_ip, source_mac)
        assert not is_blocked, "Source should no longer be blocked after expiration"


class TestTrafficStatistics:
    """Test traffic filtering statistics."""
    
    @given(
        source_mac=mac_address_strategy,
        source_ip=ip_address_strategy,
        legitimate_ip=ip_address_strategy,
        legitimate_mac=mac_address_strategy,
        packet_data=packet_data_strategy
    )
    def test_traffic_statistics_accuracy(self, source_mac, source_ip, legitimate_ip, legitimate_mac, packet_data):
        """Test that traffic statistics are accurately maintained."""
        # Ensure legitimate source is different from blocked source
        if legitimate_ip == source_ip or legitimate_mac == source_mac:
            return  # Skip this test case
        
        # Create traffic filter
        traffic_filter = TrafficFilter()
        
        # Reset statistics
        traffic_filter.reset_stats()
        initial_stats = traffic_filter.get_traffic_stats()
        assert initial_stats["blocked_packets"] == 0
        assert initial_stats["allowed_packets"] == 0
        
        # Create and block a source
        alert = create_security_alert(AttackType.DNS_SPOOFING, source_mac, source_ip, "00:00:00:00:00:01", "192.168.1.1")
        mitigation_id = "test-stats"
        traffic_filter.block_attack_source(alert, mitigation_id)
        
        # Filter some packets
        # Blocked packet
        blocked_result = traffic_filter.filter_packet(source_ip, source_mac, packet_data)
        assert not blocked_result, "Packet from blocked source should be blocked"
        
        # Allowed packet
        allowed_result = traffic_filter.filter_packet(legitimate_ip, legitimate_mac, packet_data)
        assert allowed_result, "Packet from legitimate source should be allowed"
        
        # Check statistics
        final_stats = traffic_filter.get_traffic_stats()
        assert final_stats["blocked_packets"] >= 1, "Should have at least 1 blocked packet"
        assert final_stats["allowed_packets"] >= 1, "Should have at least 1 allowed packet"
        assert final_stats["total_blocks"] >= 1, "Should have at least 1 total block"