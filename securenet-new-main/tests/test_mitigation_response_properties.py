"""
Property-based tests for mitigation response strategies.

**Feature: lan-security-system, Property 11: ARP Spoofing Mitigation Response**
**Feature: lan-security-system, Property 12: MAC Flooding Mitigation Response**
**Feature: lan-security-system, Property 13: DNS Spoofing Mitigation Response**
"""

import pytest
from datetime import datetime
from hypothesis import given, strategies as st

from lan_security_system.core.interfaces import AttackType, DetectionMethod, SecurityAlert
from lan_security_system.mitigation.controller import AutomatedMitigationController
from lan_security_system.mitigation.strategies import (
    ARPSpoofingMitigationStrategy,
    MACFloodingMitigationStrategy,
    DNSSpoofingMitigationStrategy
)


# Strategies for generating test data
def generate_mac_address():
    """Generate a valid MAC address."""
    return st.builds(
        lambda a, b, c, d, e, f: f"{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}",
        st.integers(0, 255), st.integers(0, 255), st.integers(0, 255),
        st.integers(0, 255), st.integers(0, 255), st.integers(0, 255)
    )

def generate_ip_address():
    """Generate a valid IP address."""
    return st.builds(
        lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
        st.integers(1, 254), st.integers(0, 255), 
        st.integers(0, 255), st.integers(1, 254)
    )

mac_address_strategy = generate_mac_address()
ip_address_strategy = generate_ip_address()

alert_id_strategy = st.text(min_size=1, max_size=50)

confidence_strategy = st.floats(min_value=0.0, max_value=1.0)

packet_data_strategy = st.binary(min_size=64, max_size=1500)

affected_hosts_strategy = st.lists(ip_address_strategy, min_size=1, max_size=5)


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


class TestARPSpoofingMitigationResponse:
    """Test ARP spoofing mitigation response property."""
    
    @given(
        source_mac=mac_address_strategy,
        source_ip=ip_address_strategy,
        target_mac=mac_address_strategy,
        target_ip=ip_address_strategy
    )
    def test_arp_spoofing_mitigation_blocks_attacker_mac(self, source_mac, source_ip, target_mac, target_ip):
        """
        **Property 11: ARP Spoofing Mitigation Response**
        *For any* detected ARP spoofing attack, the mitigation controller should block the attacker's MAC address
        **Validates: Requirements 4.1**
        """
        # Create ARP spoofing alert
        alert = create_security_alert(
            AttackType.ARP_SPOOFING, source_mac, source_ip, target_mac, target_ip
        )
        
        # Create mitigation strategy
        strategy = ARPSpoofingMitigationStrategy()
        
        # Execute mitigation
        result = strategy.execute(alert)
        
        # Verify mitigation was successful
        assert result.success, f"Mitigation failed: {result.error_message}"
        
        # Verify that MAC address blocking action was taken
        mac_blocking_action = any(
            f"Blocked MAC address {source_mac}" in action 
            for action in result.actions_taken
        )
        assert mac_blocking_action, f"MAC address {source_mac} was not blocked in actions: {result.actions_taken}"
        
        # Verify the MAC is tracked for rollback
        assert source_mac in strategy.blocked_macs
        assert strategy.blocked_macs[source_mac] == result.mitigation_id


class TestMACFloodingMitigationResponse:
    """Test MAC flooding mitigation response property."""
    
    @given(
        source_mac=mac_address_strategy,
        source_ip=ip_address_strategy,
        target_mac=mac_address_strategy,
        target_ip=ip_address_strategy
    )
    def test_mac_flooding_mitigation_disables_switch_port(self, source_mac, source_ip, target_mac, target_ip):
        """
        **Property 12: MAC Flooding Mitigation Response**
        *For any* detected MAC flooding attack, the mitigation controller should disable the affected switch port
        **Validates: Requirements 4.2**
        """
        # Create MAC flooding alert
        alert = create_security_alert(
            AttackType.MAC_FLOODING, source_mac, source_ip, target_mac, target_ip
        )
        
        # Create mitigation strategy
        strategy = MACFloodingMitigationStrategy()
        
        # Execute mitigation
        result = strategy.execute(alert)
        
        # Verify mitigation was successful
        assert result.success, f"Mitigation failed: {result.error_message}"
        
        # Verify that switch port disabling action was taken
        port_disabling_action = any(
            "Disabled switch port" in action 
            for action in result.actions_taken
        )
        assert port_disabling_action, f"Switch port was not disabled in actions: {result.actions_taken}"
        
        # Verify a port is tracked for rollback
        assert len(strategy.disabled_ports) > 0, "No ports were tracked for rollback"
        
        # Verify the mitigation ID is associated with a disabled port
        mitigation_found = any(
            mid == result.mitigation_id 
            for mid in strategy.disabled_ports.values()
        )
        assert mitigation_found, f"Mitigation ID {result.mitigation_id} not found in disabled ports"


class TestDNSSpoofingMitigationResponse:
    """Test DNS spoofing mitigation response property."""
    
    @given(
        source_mac=mac_address_strategy,
        source_ip=ip_address_strategy,
        target_mac=mac_address_strategy,
        target_ip=ip_address_strategy
    )
    def test_dns_spoofing_mitigation_blocks_dns_server(self, source_mac, source_ip, target_mac, target_ip):
        """
        **Property 13: DNS Spoofing Mitigation Response**
        *For any* detected DNS spoofing attack, the mitigation controller should insert firewall rules blocking the malicious DNS server
        **Validates: Requirements 4.3**
        """
        # Create DNS spoofing alert
        alert = create_security_alert(
            AttackType.DNS_SPOOFING, source_mac, source_ip, target_mac, target_ip
        )
        
        # Create mitigation strategy
        strategy = DNSSpoofingMitigationStrategy()
        
        # Execute mitigation
        result = strategy.execute(alert)
        
        # Verify mitigation was successful
        assert result.success, f"Mitigation failed: {result.error_message}"
        
        # Verify that DNS server blocking action was taken
        dns_blocking_action = any(
            f"Blocked DNS server {source_ip}" in action 
            for action in result.actions_taken
        )
        assert dns_blocking_action, f"DNS server {source_ip} was not blocked in actions: {result.actions_taken}"
        
        # Verify the DNS server IP is tracked for rollback
        assert source_ip in strategy.blocked_dns_servers
        assert strategy.blocked_dns_servers[source_ip] == result.mitigation_id


class TestMitigationControllerIntegration:
    """Test mitigation controller integration with strategies."""
    
    @given(
        attack_type=st.sampled_from([AttackType.ARP_SPOOFING, AttackType.MAC_FLOODING, AttackType.DNS_SPOOFING]),
        source_mac=mac_address_strategy,
        source_ip=ip_address_strategy,
        target_mac=mac_address_strategy,
        target_ip=ip_address_strategy
    )
    def test_mitigation_controller_executes_appropriate_strategy(self, attack_type, source_mac, source_ip, target_mac, target_ip):
        """
        Test that the mitigation controller executes the appropriate strategy for each attack type.
        """
        # Create alert for the given attack type
        alert = create_security_alert(attack_type, source_mac, source_ip, target_mac, target_ip)
        
        # Create mitigation controller
        controller = AutomatedMitigationController()
        
        # Execute mitigation
        result = controller.execute_mitigation(alert)
        
        # Verify mitigation was successful
        assert result.success, f"Mitigation failed: {result.error_message}"
        
        # Verify appropriate actions were taken based on attack type
        if attack_type == AttackType.ARP_SPOOFING:
            assert any("Blocked MAC address" in action for action in result.actions_taken)
        elif attack_type == AttackType.MAC_FLOODING:
            assert any("Disabled switch port" in action for action in result.actions_taken)
        elif attack_type == AttackType.DNS_SPOOFING:
            assert any("Blocked DNS server" in action for action in result.actions_taken)
        
        # Verify the mitigation is tracked as active
        assert result.mitigation_id in controller.get_active_mitigations()