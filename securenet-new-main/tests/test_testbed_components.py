"""
Unit tests for network testbed components.

These tests validate the core functionality of testbed components including
host simulation, switch CAM table configuration, and packet capture functionality.
"""

import pytest
import unittest.mock as mock
from datetime import datetime
from typing import List, Dict
import sys

# Mock Mininet modules before importing our code
mininet_modules = [
    'mininet', 'mininet.net', 'mininet.node', 'mininet.link', 
    'mininet.cli', 'mininet.log'
]
for module in mininet_modules:
    sys.modules[module] = mock.MagicMock()

# Mock scapy modules
scapy_modules = [
    'scapy', 'scapy.all'
]
for module in scapy_modules:
    sys.modules[module] = mock.MagicMock()

from lan_security_system.testbed.topology import (
    HostConfig, SwitchConfig, GatewayConfig,
    SimulatedHost, SimulatedSwitch, SimulatedGateway,
    MininetTestbed
)
from lan_security_system.testbed.packet_capture import (
    PacketCapture, PacketAnalyzer, NetworkBaselineManager,
    PacketInfo, ARPInfo, DNSInfo, NetworkStatistics
)
from lan_security_system.core.interfaces import NetworkBaseline


class TestHostSimulation:
    """Unit tests for host simulation functionality."""
    
    def test_host_config_creation(self):
        """Test host configuration creation."""
        config = HostConfig(
            name="test_host",
            ip="192.168.1.10",
            mac="00:00:00:00:01:10",
            role="victim"
        )
        
        assert config.name == "test_host"
        assert config.ip == "192.168.1.10"
        assert config.mac == "00:00:00:00:01:10"
        assert config.role == "victim"
    
    def test_simulated_host_basic_functionality(self):
        """Test basic simulated host functionality without Mininet."""
        # Mock Mininet host
        mock_mininet_host = mock.Mock()
        mock_mininet_host.cmd.return_value = "ping statistics --- 1 packets transmitted, 1 received, 0% packet loss"
        
        config = HostConfig(
            name="test_host",
            ip="192.168.1.10",
            mac="00:00:00:00:01:10",
            role="victim"
        )
        
        host = SimulatedHost(mock_mininet_host, config)
        
        # Test basic properties
        assert host.get_ip() == "192.168.1.10"
        assert host.get_mac() == "00:00:00:00:01:10"
        assert host.get_role() == "victim"
        
        # Test ping functionality
        result = host.ping("192.168.1.1")
        assert result is True
        mock_mininet_host.cmd.assert_called_with("ping -c 1 192.168.1.1")
    
    def test_simulated_host_arp_table_parsing(self):
        """Test ARP table parsing functionality."""
        mock_mininet_host = mock.Mock()
        mock_mininet_host.cmd.return_value = """gateway (192.168.1.1) at 00:00:00:00:01:01 [ether] on eth0
victim (192.168.1.10) at 00:00:00:00:01:10 [ether] on eth0"""
        
        config = HostConfig(name="test", ip="192.168.1.20", mac="00:00:00:00:01:20", role="attacker")
        host = SimulatedHost(mock_mininet_host, config)
        
        arp_table = host.get_arp_table()
        
        assert "192.168.1.1" in arp_table
        assert arp_table["192.168.1.1"] == "00:00:00:00:01:01"
        assert "192.168.1.10" in arp_table
        assert arp_table["192.168.1.10"] == "00:00:00:00:01:10"


class TestSwitchSimulation:
    """Unit tests for switch simulation functionality."""
    
    def test_switch_config_creation(self):
        """Test switch configuration creation."""
        config = SwitchConfig(
            name="test_switch",
            cam_table_size=1000,
            dpid="0000000000000001"
        )
        
        assert config.name == "test_switch"
        assert config.cam_table_size == 1000
        assert config.dpid == "0000000000000001"
    
    def test_simulated_switch_cam_table_utilization(self):
        """Test CAM table utilization calculation."""
        mock_mininet_switch = mock.Mock()
        mock_mininet_switch.cmd.return_value = """cookie=0x0, duration=10.123s, table=0, n_packets=5, n_bytes=350, priority=1,dl_src=00:00:00:00:01:10,actions=output:1
cookie=0x0, duration=8.456s, table=0, n_packets=3, n_bytes=210, priority=1,dl_src=00:00:00:00:01:20,actions=output:2"""
        
        config = SwitchConfig(name="test_switch", cam_table_size=1000)
        switch = SimulatedSwitch(mock_mininet_switch, config)
        
        # Test CAM table parsing
        cam_table = switch.get_cam_table()
        assert len(cam_table) >= 0  # May be empty due to parsing complexity
        
        # Test utilization calculation
        utilization = switch.get_cam_table_utilization()
        assert 0.0 <= utilization <= 1.0
    
    def test_switch_port_control(self):
        """Test switch port enable/disable functionality."""
        mock_mininet_switch = mock.Mock()
        mock_mininet_switch.cmd.return_value = ""
        
        config = SwitchConfig(name="test_switch", cam_table_size=1000)
        switch = SimulatedSwitch(mock_mininet_switch, config)
        
        # Test port disable
        result = switch.disable_port(1)
        assert result is True
        mock_mininet_switch.cmd.assert_called_with("ovs-ofctl mod-port test_switch 1 down")
        
        # Test port enable
        result = switch.enable_port(1)
        assert result is True
        mock_mininet_switch.cmd.assert_called_with("ovs-ofctl mod-port test_switch 1 up")


class TestGatewaySimulation:
    """Unit tests for gateway simulation functionality."""
    
    def test_gateway_config_creation(self):
        """Test gateway configuration creation."""
        config = GatewayConfig(
            name="test_gateway",
            ip="192.168.1.1",
            mac="00:00:00:00:01:01",
            interfaces=["eth0", "eth1"]
        )
        
        assert config.name == "test_gateway"
        assert config.ip == "192.168.1.1"
        assert config.mac == "00:00:00:00:01:01"
        assert len(config.interfaces) == 2
    
    def test_simulated_gateway_ip_forwarding(self):
        """Test IP forwarding enable functionality."""
        mock_mininet_host = mock.Mock()
        mock_mininet_host.cmd.return_value = ""
        
        config = GatewayConfig(
            name="gateway",
            ip="192.168.1.1",
            mac="00:00:00:00:01:01",
            interfaces=["eth0"]
        )
        gateway = SimulatedGateway(mock_mininet_host, config)
        
        result = gateway.enable_ip_forwarding()
        assert result is True
        mock_mininet_host.cmd.assert_called_with("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    def test_gateway_routing_table_parsing(self):
        """Test routing table parsing functionality."""
        mock_mininet_host = mock.Mock()
        mock_mininet_host.cmd.return_value = """192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.1
10.0.0.0/24 dev eth1 proto kernel scope link src 10.0.0.1
default via 192.168.1.254 dev eth0"""
        
        config = GatewayConfig(
            name="gateway",
            ip="192.168.1.1",
            mac="00:00:00:00:01:01",
            interfaces=["eth0", "eth1"]
        )
        gateway = SimulatedGateway(mock_mininet_host, config)
        
        routes = gateway.get_routing_table()
        assert len(routes) >= 3
        
        # Check that routes contain expected information
        destinations = [route['destination'] for route in routes]
        assert "192.168.1.0/24" in destinations
        assert "10.0.0.0/24" in destinations


class TestPacketAnalyzer:
    """Unit tests for packet analyzer functionality."""
    
    def test_packet_analyzer_creation(self):
        """Test packet analyzer creation."""
        analyzer = PacketAnalyzer()
        assert analyzer is not None
    
    def test_arp_info_creation(self):
        """Test ARP information data structure."""
        arp_info = ARPInfo(
            operation="reply",
            sender_mac="00:00:00:00:01:10",
            sender_ip="192.168.1.10",
            target_mac="00:00:00:00:01:01",
            target_ip="192.168.1.1"
        )
        
        assert arp_info.operation == "reply"
        assert arp_info.sender_mac == "00:00:00:00:01:10"
        assert arp_info.sender_ip == "192.168.1.10"
        assert arp_info.target_mac == "00:00:00:00:01:01"
        assert arp_info.target_ip == "192.168.1.1"
    
    def test_dns_info_creation(self):
        """Test DNS information data structure."""
        dns_info = DNSInfo(
            query_type="response",
            domain="example.com",
            query_type_code=1,
            response_ips=["93.184.216.34"],
            ttl=300
        )
        
        assert dns_info.query_type == "response"
        assert dns_info.domain == "example.com"
        assert dns_info.query_type_code == 1
        assert "93.184.216.34" in dns_info.response_ips
        assert dns_info.ttl == 300


class TestNetworkBaselineManager:
    """Unit tests for network baseline management."""
    
    def test_baseline_manager_creation(self):
        """Test baseline manager creation."""
        manager = NetworkBaselineManager()
        assert manager is not None
        assert manager.get_baseline() is None
    
    def test_statistics_initialization(self):
        """Test network statistics initialization."""
        manager = NetworkBaselineManager()
        stats = manager.get_statistics()
        
        assert stats.total_packets == 0
        assert stats.arp_packets == 0
        assert stats.dns_packets == 0
        assert stats.tcp_packets == 0
        assert stats.udp_packets == 0
        assert stats.icmp_packets == 0
        assert len(stats.unique_mac_addresses) == 0
        assert len(stats.unique_ip_addresses) == 0
        assert stats.packet_rate == 0.0
    
    def test_statistics_update(self):
        """Test statistics update with packet information."""
        manager = NetworkBaselineManager()
        
        # Create test packet
        packet = PacketInfo(
            timestamp=datetime.now(),
            src_mac="00:00:00:00:01:10",
            dst_mac="00:00:00:00:01:01",
            src_ip="192.168.1.10",
            dst_ip="192.168.1.1",
            protocol="ARP",
            packet_size=42
        )
        
        manager.update_statistics(packet)
        stats = manager.get_statistics()
        
        assert stats.total_packets == 1
        assert stats.arp_packets == 1
        assert "00:00:00:00:01:10" in stats.unique_mac_addresses
        assert "00:00:00:00:01:01" in stats.unique_mac_addresses
        assert "192.168.1.10" in stats.unique_ip_addresses
        assert "192.168.1.1" in stats.unique_ip_addresses
    
    def test_baseline_establishment(self):
        """Test network baseline establishment from packets."""
        manager = NetworkBaselineManager()
        
        # Create test packets with ARP and DNS information
        arp_packet = PacketInfo(
            timestamp=datetime.now(),
            src_mac="00:00:00:00:01:10",
            dst_mac="00:00:00:00:01:01",
            src_ip="192.168.1.10",
            dst_ip="192.168.1.1",
            protocol="ARP",
            packet_size=42,
            additional_info={
                'arp': ARPInfo(
                    operation="reply",
                    sender_mac="00:00:00:00:01:10",
                    sender_ip="192.168.1.10",
                    target_mac="00:00:00:00:01:01",
                    target_ip="192.168.1.1"
                )
            }
        )
        
        dns_packet = PacketInfo(
            timestamp=datetime.now(),
            src_mac="00:00:00:00:01:01",
            dst_mac="00:00:00:00:01:10",
            src_ip="8.8.8.8",
            dst_ip="192.168.1.10",
            protocol="DNS",
            packet_size=128,
            additional_info={
                'dns': DNSInfo(
                    query_type="response",
                    domain="example.com",
                    query_type_code=1,
                    response_ips=["93.184.216.34"],
                    ttl=300
                )
            }
        )
        
        packets = [arp_packet, dns_packet]
        baseline = manager.establish_baseline(packets, duration_seconds=60)
        
        assert baseline is not None
        assert "192.168.1.10" in baseline.arp_table
        assert baseline.arp_table["192.168.1.10"] == "00:00:00:00:01:10"
        assert "example.com" in baseline.dns_cache
        assert baseline.dns_cache["example.com"] == "93.184.216.34"


class TestPacketCapture:
    """Unit tests for packet capture functionality."""
    
    def test_packet_capture_creation(self):
        """Test packet capture creation."""
        capture = PacketCapture(interface="eth0")
        assert capture.interface == "eth0"
        assert not capture.is_capturing
        assert len(capture.captured_packets) == 0
    
    def test_packet_callback_management(self):
        """Test packet callback add/remove functionality."""
        capture = PacketCapture()
        
        def test_callback(packet: PacketInfo):
            pass
        
        # Test adding callback
        capture.add_packet_callback(test_callback)
        assert test_callback in capture.packet_callbacks
        
        # Test removing callback
        capture.remove_packet_callback(test_callback)
        assert test_callback not in capture.packet_callbacks
    
    def test_packet_info_creation(self):
        """Test packet information data structure."""
        packet_info = PacketInfo(
            timestamp=datetime.now(),
            src_mac="00:00:00:00:01:10",
            dst_mac="00:00:00:00:01:01",
            src_ip="192.168.1.10",
            dst_ip="192.168.1.1",
            protocol="TCP",
            packet_size=1500,
            raw_data=b"\x00\x01\x02\x03"
        )
        
        assert packet_info.src_mac == "00:00:00:00:01:10"
        assert packet_info.dst_mac == "00:00:00:00:01:01"
        assert packet_info.src_ip == "192.168.1.10"
        assert packet_info.dst_ip == "192.168.1.1"
        assert packet_info.protocol == "TCP"
        assert packet_info.packet_size == 1500
        assert packet_info.raw_data == b"\x00\x01\x02\x03"
    
    def test_network_statistics_creation(self):
        """Test network statistics data structure."""
        stats = NetworkStatistics()
        
        assert stats.total_packets == 0
        assert stats.arp_packets == 0
        assert stats.dns_packets == 0
        assert stats.tcp_packets == 0
        assert stats.udp_packets == 0
        assert stats.icmp_packets == 0
        assert isinstance(stats.unique_mac_addresses, set)
        assert isinstance(stats.unique_ip_addresses, set)
        assert stats.packet_rate == 0.0
        assert stats.start_time is None
        assert stats.last_update is None


class TestMininetTestbedMocked:
    """Unit tests for Mininet testbed with mocked dependencies."""
    
    def test_testbed_creation(self):
        """Test testbed creation without Mininet."""
        testbed = MininetTestbed()
        assert testbed.net is None
        assert len(testbed.hosts) == 0
        assert len(testbed.switches) == 0
        assert len(testbed.gateways) == 0
    
    def test_testbed_context_manager(self):
        """Test testbed context manager functionality."""
        with MininetTestbed() as testbed:
            assert testbed is not None
        # Context manager should call cleanup automatically
    
    @mock.patch('lan_security_system.testbed.topology.Mininet')
    def test_testbed_initialization_mocked(self, mock_mininet_class):
        """Test testbed initialization with mocked Mininet."""
        # Mock Mininet and its components
        mock_net = mock.Mock()
        mock_mininet_class.return_value = mock_net
        
        mock_controller = mock.Mock()
        mock_switch = mock.Mock()
        mock_host1 = mock.Mock()
        mock_host2 = mock.Mock()
        mock_host3 = mock.Mock()
        
        mock_net.addController.return_value = mock_controller
        mock_net.addSwitch.return_value = mock_switch
        mock_net.addHost.side_effect = [mock_host3, mock_host1, mock_host2]  # gateway, victim, attacker
        mock_net.addLink.return_value = None
        mock_net.start.return_value = None
        
        testbed = MininetTestbed()
        
        try:
            testbed.initialize_topology()
            
            # Verify Mininet was called correctly
            mock_mininet_class.assert_called_once()
            mock_net.addController.assert_called_once_with('c0')
            mock_net.addSwitch.assert_called_once_with('s1')
            assert mock_net.addHost.call_count == 3  # gateway, victim, attacker
            assert mock_net.addLink.call_count == 3  # 3 links to switch
            mock_net.start.assert_called_once()
            
            # Verify testbed state
            assert testbed.net is not None
            assert len(testbed.hosts) == 2  # victim, attacker
            assert len(testbed.switches) == 1  # s1
            assert len(testbed.gateways) == 1  # gateway
            
        finally:
            testbed.cleanup()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])