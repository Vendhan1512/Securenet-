"""
Unit tests for the mitigation controller functionality.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from lan_security_system.core.interfaces import (
    AttackType, DetectionMethod, SecurityAlert, MitigationResult, NetworkBaseline
)
from lan_security_system.mitigation.controller import AutomatedMitigationController
from lan_security_system.mitigation.strategies import (
    ARPSpoofingMitigationStrategy, MACFloodingMitigationStrategy, DNSSpoofingMitigationStrategy
)


class TestMitigationController:
    """Test mitigation controller functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.controller = AutomatedMitigationController()
        self.sample_alert = SecurityAlert(
            timestamp=datetime.now(),
            alert_id="test-alert-123",
            attack_type=AttackType.ARP_SPOOFING,
            confidence_score=0.9,
            source_mac="aa:bb:cc:dd:ee:ff",
            source_ip="192.168.1.100",
            target_mac="11:22:33:44:55:66",
            target_ip="192.168.1.1",
            affected_hosts=["192.168.1.1"],
            raw_packet_data=b"test_packet_data",
            detection_method=DetectionMethod.SIGNATURE_BASED
        )
    
    def test_controller_initialization(self):
        """Test that controller initializes with default strategies."""
        # Verify default strategies are registered
        assert AttackType.ARP_SPOOFING in self.controller.strategies
        assert AttackType.MAC_FLOODING in self.controller.strategies
        assert AttackType.DNS_SPOOFING in self.controller.strategies
        
        # Verify strategy types
        assert isinstance(self.controller.strategies[AttackType.ARP_SPOOFING], ARPSpoofingMitigationStrategy)
        assert isinstance(self.controller.strategies[AttackType.MAC_FLOODING], MACFloodingMitigationStrategy)
        assert isinstance(self.controller.strategies[AttackType.DNS_SPOOFING], DNSSpoofingMitigationStrategy)
        
        # Verify no active mitigations initially
        assert len(self.controller.active_mitigations) == 0
    
    def test_execute_mitigation_success(self):
        """Test successful mitigation execution."""
        result = self.controller.execute_mitigation(self.sample_alert)
        
        # Verify mitigation was successful
        assert result.success
        assert result.mitigation_id is not None
        assert len(result.actions_taken) > 0
        assert result.error_message is None
        
        # Verify mitigation is tracked as active
        assert result.mitigation_id in self.controller.active_mitigations
        
        # Verify appropriate actions were taken for ARP spoofing
        actions_text = " ".join(result.actions_taken)
        assert "Blocked MAC address" in actions_text
        assert self.sample_alert.source_mac in actions_text
    
    def test_execute_mitigation_unknown_attack_type(self):
        """Test mitigation execution with unknown attack type."""
        # Create alert with unsupported attack type (simulate by removing strategy)
        unknown_alert = SecurityAlert(
            timestamp=datetime.now(),
            alert_id="test-alert-456",
            attack_type=AttackType.ARP_SPOOFING,  # We'll remove this strategy
            confidence_score=0.8,
            source_mac="ff:ee:dd:cc:bb:aa",
            source_ip="192.168.1.200",
            target_mac="66:55:44:33:22:11",
            target_ip="192.168.1.1",
            affected_hosts=["192.168.1.1"],
            raw_packet_data=b"test_packet_data",
            detection_method=DetectionMethod.ANOMALY_BASED
        )
        
        # Remove the strategy to simulate unknown attack type
        del self.controller.strategies[AttackType.ARP_SPOOFING]
        
        result = self.controller.execute_mitigation(unknown_alert)
        
        # Verify mitigation failed
        assert not result.success
        assert result.error_message is not None
        assert "No mitigation strategy registered" in result.error_message
        
        # Verify no mitigation is tracked as active
        assert result.mitigation_id not in self.controller.active_mitigations
    
    def test_rollback_mitigation_success(self):
        """Test successful mitigation rollback."""
        # First execute a mitigation
        result = self.controller.execute_mitigation(self.sample_alert)
        assert result.success
        
        mitigation_id = result.mitigation_id
        
        # Verify mitigation is active
        assert mitigation_id in self.controller.active_mitigations
        
        # Rollback the mitigation
        rollback_success = self.controller.rollback_mitigation(mitigation_id)
        
        # Verify rollback was successful
        assert rollback_success
        
        # Verify mitigation is no longer active
        assert mitigation_id not in self.controller.active_mitigations
    
    def test_rollback_mitigation_not_found(self):
        """Test rollback of non-existent mitigation."""
        fake_mitigation_id = "non-existent-mitigation-123"
        
        rollback_success = self.controller.rollback_mitigation(fake_mitigation_id)
        
        # Verify rollback failed
        assert not rollback_success
    
    def test_register_custom_strategy(self):
        """Test registering a custom mitigation strategy."""
        # Create a mock strategy
        mock_strategy = Mock()
        custom_attack_type = AttackType.DNS_SPOOFING  # Use existing type for simplicity
        
        # Register the custom strategy
        self.controller.register_mitigation_strategy(custom_attack_type, mock_strategy)
        
        # Verify strategy was registered
        assert self.controller.strategies[custom_attack_type] == mock_strategy
    
    def test_get_active_mitigations(self):
        """Test getting active mitigations."""
        # Initially no active mitigations
        active = self.controller.get_active_mitigations()
        assert len(active) == 0
        
        # Execute a mitigation
        result = self.controller.execute_mitigation(self.sample_alert)
        assert result.success
        
        # Verify active mitigations
        active = self.controller.get_active_mitigations()
        assert len(active) == 1
        assert result.mitigation_id in active
        assert active[result.mitigation_id] == result
    
    def test_get_mitigation_stats(self):
        """Test getting mitigation statistics."""
        # Initially no mitigations
        stats = self.controller.get_mitigation_stats()
        assert stats["total_mitigations"] == 0
        assert stats["arp_spoofing_mitigations"] == 0
        assert stats["mac_flooding_mitigations"] == 0
        assert stats["dns_spoofing_mitigations"] == 0
        
        # Execute ARP spoofing mitigation
        arp_alert = self.sample_alert  # Already ARP_SPOOFING type
        result1 = self.controller.execute_mitigation(arp_alert)
        assert result1.success
        
        # Execute MAC flooding mitigation
        mac_alert = SecurityAlert(
            timestamp=datetime.now(),
            alert_id="test-alert-mac",
            attack_type=AttackType.MAC_FLOODING,
            confidence_score=0.8,
            source_mac="aa:bb:cc:dd:ee:ff",
            source_ip="192.168.1.101",
            target_mac="11:22:33:44:55:66",
            target_ip="192.168.1.1",
            affected_hosts=["192.168.1.1"],
            raw_packet_data=b"test_packet_data",
            detection_method=DetectionMethod.SIGNATURE_BASED
        )
        result2 = self.controller.execute_mitigation(mac_alert)
        assert result2.success
        
        # Check updated stats
        stats = self.controller.get_mitigation_stats()
        assert stats["total_mitigations"] == 2
        assert stats["arp_spoofing_mitigations"] == 1
        assert stats["mac_flooding_mitigations"] == 1
        assert stats["dns_spoofing_mitigations"] == 0


class TestFirewallRuleManagement:
    """Test firewall rule insertion and removal functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.controller = AutomatedMitigationController()
    
    def test_arp_spoofing_firewall_rules(self):
        """Test firewall rule insertion for ARP spoofing."""
        alert = SecurityAlert(
            timestamp=datetime.now(),
            alert_id="test-arp-firewall",
            attack_type=AttackType.ARP_SPOOFING,
            confidence_score=0.9,
            source_mac="aa:bb:cc:dd:ee:ff",
            source_ip="192.168.1.100",
            target_mac="11:22:33:44:55:66",
            target_ip="192.168.1.1",
            affected_hosts=["192.168.1.1"],
            raw_packet_data=b"test_packet_data",
            detection_method=DetectionMethod.SIGNATURE_BASED
        )
        
        result = self.controller.execute_mitigation(alert)
        
        # Verify mitigation was successful
        assert result.success
        
        # Verify MAC address blocking action was taken
        actions_text = " ".join(result.actions_taken)
        assert "Blocked MAC address" in actions_text
        assert alert.source_mac in actions_text
        
        # Verify traffic blocking was applied
        assert "Blocked traffic from" in actions_text
        assert alert.source_ip in actions_text
    
    def test_dns_spoofing_firewall_rules(self):
        """Test firewall rule insertion for DNS spoofing."""
        alert = SecurityAlert(
            timestamp=datetime.now(),
            alert_id="test-dns-firewall",
            attack_type=AttackType.DNS_SPOOFING,
            confidence_score=0.8,
            source_mac="bb:cc:dd:ee:ff:aa",
            source_ip="8.8.8.8",  # Malicious DNS server
            target_mac="22:33:44:55:66:77",
            target_ip="192.168.1.50",
            affected_hosts=["192.168.1.50"],
            raw_packet_data=b"dns_packet_data",
            detection_method=DetectionMethod.SIGNATURE_BASED
        )
        
        result = self.controller.execute_mitigation(alert)
        
        # Verify mitigation was successful
        assert result.success
        
        # Verify DNS server blocking actions were taken
        actions_text = " ".join(result.actions_taken)
        assert "Blocked DNS server" in actions_text
        assert alert.source_ip in actions_text
        
        # Verify both UDP and TCP DNS blocking
        assert "Blocked TCP DNS" in actions_text
    
    def test_mac_flooding_port_control(self):
        """Test switch port control for MAC flooding."""
        alert = SecurityAlert(
            timestamp=datetime.now(),
            alert_id="test-mac-port",
            attack_type=AttackType.MAC_FLOODING,
            confidence_score=0.95,
            source_mac="cc:dd:ee:ff:aa:bb",
            source_ip="192.168.1.150",
            target_mac="33:44:55:66:77:88",
            target_ip="192.168.1.1",
            affected_hosts=["192.168.1.1"],
            raw_packet_data=b"flood_packet_data",
            detection_method=DetectionMethod.ANOMALY_BASED
        )
        
        result = self.controller.execute_mitigation(alert)
        
        # Verify mitigation was successful
        assert result.success
        
        # Verify switch port disabling action was taken
        actions_text = " ".join(result.actions_taken)
        assert "Disabled switch port" in actions_text
        
        # Verify CAM table cleanup
        assert "Cleared CAM table entries" in actions_text


class TestMitigationRollback:
    """Test mitigation rollback procedures."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.controller = AutomatedMitigationController()
    
    def test_rollback_arp_spoofing_mitigation(self):
        """Test rollback of ARP spoofing mitigation."""
        alert = SecurityAlert(
            timestamp=datetime.now(),
            alert_id="test-arp-rollback",
            attack_type=AttackType.ARP_SPOOFING,
            confidence_score=0.9,
            source_mac="dd:ee:ff:aa:bb:cc",
            source_ip="192.168.1.200",
            target_mac="44:55:66:77:88:99",
            target_ip="192.168.1.1",
            affected_hosts=["192.168.1.1"],
            raw_packet_data=b"test_packet_data",
            detection_method=DetectionMethod.SIGNATURE_BASED
        )
        
        # Execute mitigation
        result = self.controller.execute_mitigation(alert)
        assert result.success
        
        mitigation_id = result.mitigation_id
        
        # Verify source is blocked
        assert self.controller.is_source_blocked(alert.source_ip, alert.source_mac)
        
        # Rollback mitigation
        rollback_success = self.controller.rollback_mitigation(mitigation_id)
        assert rollback_success
        
        # Verify mitigation is no longer active
        assert mitigation_id not in self.controller.active_mitigations
    
    def test_rollback_mac_flooding_mitigation(self):
        """Test rollback of MAC flooding mitigation."""
        alert = SecurityAlert(
            timestamp=datetime.now(),
            alert_id="test-mac-rollback",
            attack_type=AttackType.MAC_FLOODING,
            confidence_score=0.85,
            source_mac="ee:ff:aa:bb:cc:dd",
            source_ip="192.168.1.250",
            target_mac="55:66:77:88:99:aa",
            target_ip="192.168.1.1",
            affected_hosts=["192.168.1.1"],
            raw_packet_data=b"flood_packet_data",
            detection_method=DetectionMethod.ANOMALY_BASED
        )
        
        # Execute mitigation
        result = self.controller.execute_mitigation(alert)
        assert result.success
        
        mitigation_id = result.mitigation_id
        
        # Rollback mitigation
        rollback_success = self.controller.rollback_mitigation(mitigation_id)
        assert rollback_success
        
        # Verify mitigation is no longer active
        assert mitigation_id not in self.controller.active_mitigations
    
    def test_rollback_dns_spoofing_mitigation(self):
        """Test rollback of DNS spoofing mitigation."""
        alert = SecurityAlert(
            timestamp=datetime.now(),
            alert_id="test-dns-rollback",
            attack_type=AttackType.DNS_SPOOFING,
            confidence_score=0.75,
            source_mac="ff:aa:bb:cc:dd:ee",
            source_ip="1.1.1.1",  # Malicious DNS server
            target_mac="66:77:88:99:aa:bb",
            target_ip="192.168.1.75",
            affected_hosts=["192.168.1.75"],
            raw_packet_data=b"dns_spoof_data",
            detection_method=DetectionMethod.HYBRID
        )
        
        # Execute mitigation
        result = self.controller.execute_mitigation(alert)
        assert result.success
        
        mitigation_id = result.mitigation_id
        
        # Rollback mitigation
        rollback_success = self.controller.rollback_mitigation(mitigation_id)
        assert rollback_success
        
        # Verify mitigation is no longer active
        assert mitigation_id not in self.controller.active_mitigations


class TestCacheIntegration:
    """Test cache management integration."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.controller = AutomatedMitigationController()
        
        # Set up a baseline for cache operations
        baseline = NetworkBaseline(
            arp_table={"192.168.1.1": "11:22:33:44:55:66", "192.168.1.100": "aa:bb:cc:dd:ee:ff"},
            dns_cache={"example.com": "93.184.216.34", "google.com": "8.8.8.8"},
            mac_port_mappings={"11:22:33:44:55:66": 1, "aa:bb:cc:dd:ee:ff": 2},
            baseline_timestamp=datetime.now()
        )
        self.controller.get_cache_manager().save_network_baseline(baseline)
    
    def test_arp_cache_cleanup_integration(self):
        """Test ARP cache cleanup during ARP spoofing mitigation."""
        alert = SecurityAlert(
            timestamp=datetime.now(),
            alert_id="test-arp-cache",
            attack_type=AttackType.ARP_SPOOFING,
            confidence_score=0.9,
            source_mac="aa:bb:cc:dd:ee:ff",
            source_ip="192.168.1.100",
            target_mac="11:22:33:44:55:66",
            target_ip="192.168.1.1",
            affected_hosts=["192.168.1.1"],
            raw_packet_data=b"arp_spoof_data",
            detection_method=DetectionMethod.SIGNATURE_BASED
        )
        
        result = self.controller.execute_mitigation(alert)
        
        # Verify mitigation was successful
        assert result.success
        
        # Verify ARP cache reset action was taken
        actions_text = " ".join(result.actions_taken)
        assert "Reset ARP cache" in actions_text
        assert alert.target_ip in actions_text
    
    def test_dns_cache_cleanup_integration(self):
        """Test DNS cache cleanup during DNS spoofing mitigation."""
        alert = SecurityAlert(
            timestamp=datetime.now(),
            alert_id="test-dns-cache",
            attack_type=AttackType.DNS_SPOOFING,
            confidence_score=0.8,
            source_mac="bb:cc:dd:ee:ff:aa",
            source_ip="8.8.8.8",
            target_mac="22:33:44:55:66:77",
            target_ip="192.168.1.50",
            affected_hosts=["192.168.1.50"],
            raw_packet_data=b"dns_spoof_data",
            detection_method=DetectionMethod.SIGNATURE_BASED
        )
        
        result = self.controller.execute_mitigation(alert)
        
        # Verify mitigation was successful
        assert result.success
        
        # Verify DNS cache flush action was taken
        actions_text = " ".join(result.actions_taken)
        assert "Flushed DNS cache" in actions_text
    
    def test_cache_status_reporting(self):
        """Test cache status reporting functionality."""
        cache_manager = self.controller.get_cache_manager()
        
        # Get initial cache status
        status = cache_manager.get_cache_status()
        
        # Verify baseline data is reflected in status
        assert status["original_arp_entries"] == 2  # From baseline
        assert status["original_dns_entries"] == 2  # From baseline
        assert status["poisoned_arp_entries"] == 0  # Initially clean
        assert status["poisoned_dns_entries"] == 0  # Initially clean