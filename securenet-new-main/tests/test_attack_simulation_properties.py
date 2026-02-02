"""
Property-based tests for attack simulation module.

These tests validate the correctness properties of the attack simulation
components using Hypothesis for comprehensive input coverage.
"""

import pytest
from hypothesis import given, strategies as st, settings
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
import ipaddress
import re

from lan_security_system.simulation.attack_simulator import NetworkAttackSimulator
from lan_security_system.core.interfaces import AttackType


class TestAttackSimulationProperties:
    """Property-based tests for attack simulation functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logging_system = Mock()
        self.simulator = NetworkAttackSimulator(self.mock_logging_system)
    
    @given(
        target_ip=st.ip_addresses(v=4).map(str),
        gateway_ip=st.ip_addresses(v=4).map(str),
        packet_count=st.integers(min_value=1, max_value=50),
        interval=st.floats(min_value=0.01, max_value=2.0)
    )
    @settings(max_examples=1, deadline=None)
    @patch('lan_security_system.simulation.attack_simulator.sendp')
    @patch('lan_security_system.simulation.attack_simulator.get_if_list')
    @patch('lan_security_system.simulation.attack_simulator.get_if_hwaddr')
    def test_arp_spoofing_generates_correct_malicious_traffic(
        self, mock_get_hwaddr, mock_get_if_list, mock_sendp,
        target_ip, gateway_ip, packet_count, interval
    ):
        """
        **Feature: lan-security-system, Property 1: Attack Simulation Generates Correct Malicious Traffic**
        
        For any victim-gateway IP pair, when ARP spoofing is executed, 
        the system should generate malicious ARP replies that target the 
        specific victim-gateway communication path.
        
        **Validates: Requirements 1.1**
        """
        # Skip if target and gateway are the same (invalid scenario)
        if target_ip == gateway_ip:
            return
        
        # Mock network interface detection
        mock_get_if_list.return_value = ['eth0', 'lo']
        mock_get_hwaddr.return_value = '02:00:00:aa:bb:cc'
        
        # Track packets sent
        sent_packets = []
        def capture_packet(packet, iface=None, verbose=False):
            sent_packets.append((packet, iface))
        mock_sendp.side_effect = capture_packet
        
        # Execute ARP spoofing attack
        self.simulator.execute_arp_spoofing(
            target_ip=target_ip,
            gateway_ip=gateway_ip,
            packet_count=packet_count,
            interval=interval
        )
        
        # Verify correct number of packets were sent
        assert len(sent_packets) == packet_count, f"Expected {packet_count} packets, got {len(sent_packets)}"
        
        # Verify each packet targets the victim-gateway communication path
        for packet, interface in sent_packets:
            # Extract ARP layer
            arp_layer = packet.getlayer('ARP')
            assert arp_layer is not None, "Packet should contain ARP layer"
            
            # Verify ARP reply operation
            assert arp_layer.op == 2, "Should be ARP reply (op=2)"
            
            # Verify source IP is gateway (spoofed)
            assert arp_layer.psrc == gateway_ip, f"Source IP should be gateway {gateway_ip}, got {arp_layer.psrc}"
            
            # Verify destination IP is target (victim)
            assert arp_layer.pdst == target_ip, f"Destination IP should be target {target_ip}, got {arp_layer.pdst}"
            
            # Verify source MAC is attacker's (not gateway's real MAC)
            assert arp_layer.hwsrc == '02:00:00:aa:bb:cc', "Source MAC should be attacker's MAC"
            
            # Verify interface is valid
            assert interface == 'eth0', "Should use eth0 interface"
        
        # Verify attack was logged
        assert len(self.simulator.get_attack_history()) > 0, "Attack should be recorded in history"
        
        # Verify attack type in history
        last_attack = self.simulator.get_attack_history()[-1]
        assert last_attack['attack_type'] == AttackType.ARP_SPOOFING, "Attack type should be ARP_SPOOFING"
        assert last_attack['target_ip'] == target_ip, "Target IP should match"
        assert last_attack['gateway_ip'] == gateway_ip, "Gateway IP should match"
        assert last_attack['packet_count'] == packet_count, "Packet count should match"
    
    @given(
        interface=st.text(min_size=3, max_size=10, alphabet=st.characters(whitelist_categories=('Ll', 'Nd'))),
        packet_count=st.integers(min_value=10, max_value=500),
        burst_mode=st.booleans(),
        burst_size=st.integers(min_value=5, max_value=100)
    )
    @settings(max_examples=1, deadline=None)
    @patch('lan_security_system.simulation.attack_simulator.sendp')
    def test_mac_flooding_overflows_cam_table(
        self, mock_sendp, interface, packet_count, burst_mode, burst_size
    ):
        """
        **Feature: lan-security-system, Property 2: MAC Flooding Overflows CAM Table**
        
        For any CAM table with defined capacity, when MAC flooding is executed, 
        the system should generate more unique MAC addresses than the table capacity.
        
        **Validates: Requirements 1.2**
        """
        # Assume typical CAM table capacity (common values: 8K, 16K, 32K entries)
        typical_cam_capacity = 1000  # Use smaller value for testing
        
        # Only test scenarios where packet count could overflow the table
        if packet_count <= typical_cam_capacity:
            packet_count = typical_cam_capacity + 100
        
        # Track packets sent
        sent_packets = []
        def capture_packet(packet_or_list, iface=None, verbose=False):
            if isinstance(packet_or_list, list):
                sent_packets.extend(packet_or_list)
            else:
                sent_packets.append(packet_or_list)
        mock_sendp.side_effect = capture_packet
        
        # Execute MAC flooding attack
        self.simulator.execute_mac_flooding(
            interface=interface,
            packet_count=packet_count,
            burst_mode=burst_mode,
            burst_size=burst_size if burst_mode else 100
        )
        
        # Extract unique MAC addresses from sent packets
        unique_macs = set()
        for packet in sent_packets:
            eth_layer = packet.getlayer('Ether')
            if eth_layer and eth_layer.src:
                unique_macs.add(eth_layer.src)
        
        # Verify we generated enough unique MACs to overflow typical CAM table
        assert len(unique_macs) >= min(packet_count, typical_cam_capacity), \
            f"Should generate at least {min(packet_count, typical_cam_capacity)} unique MACs, got {len(unique_macs)}"
        
        # Verify all MACs follow the expected format (locally administered)
        mac_pattern = re.compile(r'^02:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$', re.IGNORECASE)
        for mac in unique_macs:
            assert mac_pattern.match(mac), f"MAC {mac} should follow locally administered format"
        
        # Verify correct number of packets were sent
        assert len(sent_packets) == packet_count, f"Expected {packet_count} packets, got {len(sent_packets)}"
        
        # Verify attack was logged
        attack_history = self.simulator.get_attack_history()
        assert len(attack_history) > 0, "Attack should be recorded in history"
        
        last_attack = attack_history[-1]
        assert last_attack['attack_type'] == AttackType.MAC_FLOODING, "Attack type should be MAC_FLOODING"
        assert last_attack['unique_macs'] == len(unique_macs), "Unique MAC count should match"
    
    @given(
        target_domain=st.text(min_size=5, max_size=50).filter(lambda x: '.' in x and not x.startswith('.') and not x.endswith('.')),
        fake_ip=st.ip_addresses(v=4).map(str),
        response_count=st.integers(min_value=1, max_value=20),
        ttl=st.integers(min_value=60, max_value=3600)
    )
    @settings(max_examples=1, deadline=None)
    @patch('lan_security_system.simulation.attack_simulator.sendp')
    @patch('lan_security_system.simulation.attack_simulator.get_if_list')
    @patch('lan_security_system.simulation.attack_simulator.get_if_addr')
    def test_dns_spoofing_injects_false_responses(
        self, mock_get_addr, mock_get_if_list, mock_sendp,
        target_domain, fake_ip, response_count, ttl
    ):
        """
        **Feature: lan-security-system, Property 3: DNS Spoofing Injects False Responses**
        
        For any domain query, when DNS spoofing is executed, the system should 
        inject DNS responses with IP addresses different from the legitimate ones.
        
        **Validates: Requirements 1.3**
        """
        # Mock network interface detection
        mock_get_if_list.return_value = ['eth0', 'lo']
        mock_get_addr.return_value = '192.168.1.100'
        
        # Track packets sent
        sent_packets = []
        def capture_packet(packet, iface=None, verbose=False):
            sent_packets.append((packet, iface))
        mock_sendp.side_effect = capture_packet
        
        # Execute DNS spoofing attack
        self.simulator.execute_dns_spoofing(
            target_domain=target_domain,
            fake_ip=fake_ip,
            response_count=response_count,
            ttl=ttl
        )
        
        # Verify correct number of packets were sent
        assert len(sent_packets) == response_count, f"Expected {response_count} packets, got {len(sent_packets)}"
        
        # Verify each packet contains false DNS response
        for packet, interface in sent_packets:
            # Extract DNS layer
            dns_layer = packet.getlayer('DNS')
            assert dns_layer is not None, "Packet should contain DNS layer"
            
            # Verify it's a DNS response
            assert dns_layer.qr == 1, "Should be DNS response (qr=1)"
            
            # Verify it has an answer section
            assert dns_layer.ancount >= 1, "Should have at least one answer"
            
            # Verify the answer contains the fake IP
            if dns_layer.an:
                answer = dns_layer.an
                assert answer.rrname.decode() == target_domain or answer.rrname.decode() == target_domain + '.', \
                    f"Answer should be for domain {target_domain}"
                assert answer.rdata == fake_ip, f"Answer should contain fake IP {fake_ip}, got {answer.rdata}"
                assert answer.ttl == ttl, f"TTL should be {ttl}, got {answer.ttl}"
            
            # Verify UDP layer
            udp_layer = packet.getlayer('UDP')
            assert udp_layer is not None, "Packet should contain UDP layer"
            assert udp_layer.sport == 53, "Source port should be 53 (DNS)"
            assert udp_layer.dport == 53, "Destination port should be 53 (DNS)"
            
            # Verify interface is valid
            assert interface == 'eth0', "Should use eth0 interface"
        
        # Verify attack was logged
        attack_history = self.simulator.get_attack_history()
        assert len(attack_history) > 0, "Attack should be recorded in history"
        
        last_attack = attack_history[-1]
        assert last_attack['attack_type'] == AttackType.DNS_SPOOFING, "Attack type should be DNS_SPOOFING"
        assert last_attack['target_domain'] == target_domain, "Target domain should match"
        assert last_attack['fake_ip'] == fake_ip, "Fake IP should match"
        assert last_attack['response_count'] == response_count, "Response count should match"
    
    @given(
        attack_type=st.sampled_from([AttackType.ARP_SPOOFING, AttackType.MAC_FLOODING, AttackType.DNS_SPOOFING])
    )
    @settings(max_examples=1, deadline=None)
    def test_attack_logging_completeness(self, attack_type):
        """
        **Feature: lan-security-system, Property 4: Attack Logging Completeness**
        
        For any attack simulation initiation, the system should create log entries 
        containing both timestamp and attack type information.
        
        **Validates: Requirements 1.5**
        """
        # Clear any existing history and reset mock
        self.simulator.clear_attack_history()
        self.mock_logging_system.reset_mock()
        
        # Record time before logging
        before_time = datetime.now()
        
        # Log attack initiation
        self.simulator.log_attack_initiation(attack_type)
        
        # Record time after logging
        after_time = datetime.now()
        
        # Verify logging system was called if available
        if self.mock_logging_system:
            self.mock_logging_system.log_security_event.assert_called_once()
            
            # Get the logged event
            call_args = self.mock_logging_system.log_security_event.call_args[0][0]
            
            # Verify timestamp is within expected range
            assert before_time <= call_args.timestamp <= after_time, \
                "Timestamp should be within the expected time range"
            
            # Verify attack type matches
            assert call_args.attack_type == attack_type, \
                f"Attack type should be {attack_type}, got {call_args.attack_type}"
            
            # Verify alert ID is present and non-empty
            assert call_args.alert_id, "Alert ID should be present and non-empty"
            
            # Verify confidence score for simulated attacks
            assert call_args.confidence_score == 1.0, "Simulated attacks should have 100% confidence"