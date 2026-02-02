"""
Unit tests for attack simulation module edge cases.

These tests validate specific scenarios, edge cases, and error conditions
for the attack simulation components.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from lan_security_system.simulation.attack_simulator import NetworkAttackSimulator
from lan_security_system.core.interfaces import AttackType


class TestAttackSimulationEdgeCases:
    """Unit tests for attack simulation edge cases and error conditions."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logging_system = Mock()
        self.simulator = NetworkAttackSimulator(self.mock_logging_system)
    
    def test_arp_spoofing_with_invalid_parameters(self):
        """Test ARP spoofing with invalid IP addresses and parameters."""
        with patch('lan_security_system.simulation.attack_simulator.sendp') as mock_sendp:
            with patch('lan_security_system.simulation.attack_simulator.get_if_list') as mock_get_if_list:
                with patch('lan_security_system.simulation.attack_simulator.get_if_hwaddr') as mock_get_hwaddr:
                    mock_get_if_list.return_value = ['eth0']
                    mock_get_hwaddr.return_value = '02:00:00:aa:bb:cc'
                    
                    # Test with same target and gateway IP (should still work but be ineffective)
                    self.simulator.execute_arp_spoofing(
                        target_ip="192.168.1.1",
                        gateway_ip="192.168.1.1",
                        packet_count=1
                    )
                    
                    # Should still send packets even with same IPs
                    assert mock_sendp.call_count == 1
                    
                    # Test with zero packet count
                    mock_sendp.reset_mock()
                    self.simulator.execute_arp_spoofing(
                        target_ip="192.168.1.10",
                        gateway_ip="192.168.1.1",
                        packet_count=0
                    )
                    
                    # Should not send any packets
                    assert mock_sendp.call_count == 0
    
    def test_arp_spoofing_network_interface_failure(self):
        """Test ARP spoofing when network interface detection fails."""
        with patch('lan_security_system.simulation.attack_simulator.sendp') as mock_sendp:
            with patch('lan_security_system.simulation.attack_simulator.get_if_list') as mock_get_if_list:
                with patch('lan_security_system.simulation.attack_simulator.get_if_hwaddr') as mock_get_hwaddr:
                    # Simulate no available interfaces
                    mock_get_if_list.return_value = []
                    mock_get_hwaddr.side_effect = Exception("Interface not found")
                    
                    # Should still work with fallback values
                    self.simulator.execute_arp_spoofing(
                        target_ip="192.168.1.10",
                        gateway_ip="192.168.1.1",
                        packet_count=1
                    )
                    
                    # Should send packet with generated MAC
                    assert mock_sendp.call_count == 1
                    
                    # Verify fallback MAC was used
                    call_args = mock_sendp.call_args[1]
                    assert call_args['iface'] == 'eth0'  # Default fallback
    
    def test_mac_flooding_with_extreme_parameters(self):
        """Test MAC flooding with extreme parameter values."""
        with patch('lan_security_system.simulation.attack_simulator.sendp') as mock_sendp:
            # Test with very large packet count
            self.simulator.execute_mac_flooding(
                interface="eth0",
                packet_count=10000,
                burst_mode=True,
                burst_size=1000
            )
            
            # Should handle large numbers correctly
            assert mock_sendp.call_count == 10  # 10000 / 1000 = 10 bursts
            
            # Test with burst size larger than packet count
            mock_sendp.reset_mock()
            self.simulator.execute_mac_flooding(
                interface="eth0",
                packet_count=5,
                burst_mode=True,
                burst_size=10
            )
            
            # Should send only one burst with 5 packets
            assert mock_sendp.call_count == 1
            sent_packets = mock_sendp.call_args[0][0]
            assert len(sent_packets) == 5
    
    def test_mac_flooding_unique_mac_generation(self):
        """Test that MAC flooding generates unique MAC addresses."""
        with patch('lan_security_system.simulation.attack_simulator.sendp') as mock_sendp:
            sent_packets = []
            def capture_packets(packet_or_list, iface=None, verbose=False):
                if isinstance(packet_or_list, list):
                    sent_packets.extend(packet_or_list)
                else:
                    sent_packets.append(packet_or_list)
            mock_sendp.side_effect = capture_packets
            
            # Generate many packets to test uniqueness
            self.simulator.execute_mac_flooding(
                interface="eth0",
                packet_count=100,
                burst_mode=False
            )
            
            # Extract MAC addresses
            macs = set()
            for packet in sent_packets:
                eth_layer = packet.getlayer('Ether')
                if eth_layer and eth_layer.src:
                    macs.add(eth_layer.src)
            
            # Should have high uniqueness (allowing for some random collisions)
            assert len(macs) >= 95, f"Expected at least 95 unique MACs, got {len(macs)}"
            
            # All MACs should follow locally administered format
            for mac in macs:
                assert mac.startswith('02:'), f"MAC {mac} should be locally administered"
    
    def test_dns_spoofing_with_invalid_domains(self):
        """Test DNS spoofing with various domain formats."""
        with patch('lan_security_system.simulation.attack_simulator.sendp') as mock_sendp:
            with patch('lan_security_system.simulation.attack_simulator.get_if_list') as mock_get_if_list:
                with patch('lan_security_system.simulation.attack_simulator.get_if_addr') as mock_get_addr:
                    mock_get_if_list.return_value = ['eth0']
                    mock_get_addr.return_value = '192.168.1.100'
                    
                    # Test with very long domain name
                    long_domain = "a" * 50 + ".example.com"
                    self.simulator.execute_dns_spoofing(
                        target_domain=long_domain,
                        fake_ip="1.2.3.4",
                        response_count=1
                    )
                    
                    assert mock_sendp.call_count == 1
                    
                    # Test with domain containing special characters
                    mock_sendp.reset_mock()
                    special_domain = "test-site.co.uk"
                    self.simulator.execute_dns_spoofing(
                        target_domain=special_domain,
                        fake_ip="5.6.7.8",
                        response_count=1
                    )
                    
                    assert mock_sendp.call_count == 1
    
    def test_dns_spoofing_network_detection_failure(self):
        """Test DNS spoofing when network detection fails."""
        with patch('lan_security_system.simulation.attack_simulator.sendp') as mock_sendp:
            with patch('lan_security_system.simulation.attack_simulator.get_if_list') as mock_get_if_list:
                with patch('lan_security_system.simulation.attack_simulator.get_if_addr') as mock_get_addr:
                    # Simulate interface detection failures
                    mock_get_if_list.return_value = []
                    mock_get_addr.side_effect = Exception("Cannot get interface address")
                    
                    # Should still work with fallback values
                    self.simulator.execute_dns_spoofing(
                        target_domain="example.com",
                        fake_ip="9.10.11.12",
                        response_count=1
                    )
                    
                    assert mock_sendp.call_count == 1
                    
                    # Verify fallback interface was used
                    call_args = mock_sendp.call_args[1]
                    assert call_args['iface'] == 'eth0'  # Default fallback
    
    def test_attack_logging_without_external_logger(self):
        """Test attack logging when no external logging system is provided."""
        # Create simulator without external logging system
        simulator_no_logger = NetworkAttackSimulator(logging_system=None)
        
        # Should not raise exception when logging
        simulator_no_logger.log_attack_initiation(AttackType.ARP_SPOOFING)
        
        # Should still log internally (no exception means success)
        assert True  # If we reach here, no exception was raised
    
    def test_attack_logging_with_external_logger_failure(self):
        """Test attack logging when external logging system fails."""
        # Create mock that raises exception
        failing_logger = Mock()
        failing_logger.log_security_event.side_effect = Exception("Logging failed")
        
        simulator = NetworkAttackSimulator(failing_logger)
        
        # Should not raise exception even if external logging fails
        simulator.log_attack_initiation(AttackType.MAC_FLOODING)
        
        # Verify external logger was called despite failure
        failing_logger.log_security_event.assert_called_once()
    
    def test_concurrent_attack_coordination(self):
        """Test coordination of multiple concurrent attack simulations."""
        with patch('lan_security_system.simulation.attack_simulator.sendp') as mock_sendp:
            with patch('lan_security_system.simulation.attack_simulator.get_if_list') as mock_get_if_list:
                with patch('lan_security_system.simulation.attack_simulator.get_if_hwaddr') as mock_get_hwaddr:
                    with patch('lan_security_system.simulation.attack_simulator.get_if_addr') as mock_get_addr:
                        mock_get_if_list.return_value = ['eth0']
                        mock_get_hwaddr.return_value = '02:00:00:aa:bb:cc'
                        mock_get_addr.return_value = '192.168.1.100'
                        
                        # Simulate multiple attacks in sequence
                        self.simulator.execute_arp_spoofing(
                            target_ip="192.168.1.10",
                            gateway_ip="192.168.1.1",
                            packet_count=2
                        )
                        
                        self.simulator.execute_mac_flooding(
                            interface="eth0",
                            packet_count=3
                        )
                        
                        self.simulator.execute_dns_spoofing(
                            target_domain="test.com",
                            fake_ip="1.2.3.4",
                            response_count=1
                        )
                        
                        # Verify all attacks were recorded
                        history = self.simulator.get_attack_history()
                        assert len(history) == 3
                        
                        # Verify attack types
                        attack_types = [attack['attack_type'] for attack in history]
                        assert AttackType.ARP_SPOOFING in attack_types
                        assert AttackType.MAC_FLOODING in attack_types
                        assert AttackType.DNS_SPOOFING in attack_types
                        
                        # Verify timestamps are in order
                        timestamps = [attack['timestamp'] for attack in history]
                        assert timestamps == sorted(timestamps)
    
    def test_attack_history_management(self):
        """Test attack history tracking and management."""
        # Initially empty
        assert len(self.simulator.get_attack_history()) == 0
        
        # Add some attacks to history
        self.simulator.log_attack_initiation(AttackType.ARP_SPOOFING)
        self.simulator.log_attack_initiation(AttackType.MAC_FLOODING)
        
        # Should have logged attacks (but not in history since we only called log_attack_initiation)
        # History is only updated by actual attack execution
        
        # Clear history
        self.simulator.clear_attack_history()
        assert len(self.simulator.get_attack_history()) == 0
    
    def test_supported_attacks_list(self):
        """Test that supported attacks list is correct and immutable."""
        supported = self.simulator.get_supported_attacks()
        
        # Should contain all three attack types
        assert AttackType.ARP_SPOOFING in supported
        assert AttackType.MAC_FLOODING in supported
        assert AttackType.DNS_SPOOFING in supported
        assert len(supported) == 3
        
        # Should return a copy (modifying returned list shouldn't affect internal state)
        original_length = len(supported)
        supported.append("fake_attack")
        
        # Get fresh copy
        supported_again = self.simulator.get_supported_attacks()
        assert len(supported_again) == original_length
    
    def test_malformed_packet_handling(self):
        """Test handling of malformed packet scenarios."""
        with patch('lan_security_system.simulation.attack_simulator.sendp') as mock_sendp:
            # Simulate sendp raising an exception
            mock_sendp.side_effect = Exception("Network error")
            
            # Should raise exception for network errors
            with pytest.raises(Exception, match="Network error"):
                self.simulator.execute_arp_spoofing(
                    target_ip="192.168.1.10",
                    gateway_ip="192.168.1.1",
                    packet_count=1
                )
            
            # Reset mock for MAC flooding test
            mock_sendp.side_effect = Exception("Network error")
            
            with pytest.raises(Exception, match="Network error"):
                self.simulator.execute_mac_flooding(
                    interface="eth0",
                    packet_count=1
                )
            
            # Reset mock for DNS spoofing test
            mock_sendp.side_effect = Exception("Network error")
            
            with pytest.raises(Exception, match="Network error"):
                self.simulator.execute_dns_spoofing(
                    target_domain="test.com",
                    fake_ip="1.2.3.4",
                    response_count=1
                )
    
    def test_attack_parameter_validation(self):
        """Test validation of attack parameters."""
        with patch('lan_security_system.simulation.attack_simulator.sendp') as mock_sendp:
            with patch('lan_security_system.simulation.attack_simulator.get_if_list') as mock_get_if_list:
                with patch('lan_security_system.simulation.attack_simulator.get_if_hwaddr') as mock_get_hwaddr:
                    mock_get_if_list.return_value = ['eth0']
                    mock_get_hwaddr.return_value = '02:00:00:aa:bb:cc'
                    
                    # Test with negative packet count (should be handled gracefully)
                    self.simulator.execute_arp_spoofing(
                        target_ip="192.168.1.10",
                        gateway_ip="192.168.1.1",
                        packet_count=-1  # Negative count
                    )
                    
                    # Should not send any packets for negative count
                    assert mock_sendp.call_count == 0
                    
                    # Test with very small interval
                    mock_sendp.reset_mock()
                    self.simulator.execute_arp_spoofing(
                        target_ip="192.168.1.10",
                        gateway_ip="192.168.1.1",
                        packet_count=2,
                        interval=0.001  # Very small interval
                    )
                    
                    # Should still work with small intervals
                    assert mock_sendp.call_count == 2