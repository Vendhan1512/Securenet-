"""
Network topology simulation using Mininet integration.

This module provides classes for simulating network hosts, switches, and gateways
in a controlled testbed environment for security testing.
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from mininet.net import Mininet
from mininet.node import Host, OVSSwitch, Controller
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
import time
import subprocess
import json

from ..core.interfaces import NetworkTestbed


@dataclass
class HostConfig:
    """Configuration for a simulated host."""
    name: str
    ip: str
    mac: str
    role: str  # 'attacker', 'victim', 'gateway', 'normal'


@dataclass
class SwitchConfig:
    """Configuration for a simulated switch."""
    name: str
    cam_table_size: int = 1000
    dpid: Optional[str] = None


@dataclass
class GatewayConfig:
    """Configuration for a gateway/router."""
    name: str
    ip: str
    mac: str
    interfaces: List[str]


class SimulatedHost:
    """Represents a simulated network host in the testbed."""
    
    def __init__(self, mininet_host: Host, config: HostConfig):
        self.mininet_host = mininet_host
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{config.name}")
    
    def ping(self, target_ip: str, count: int = 1) -> bool:
        """Ping a target IP address."""
        try:
            result = self.mininet_host.cmd(f'ping -c {count} {target_ip}')
            return '0% packet loss' in result
        except Exception as e:
            self.logger.error(f"Ping failed: {e}")
            return False
    
    def get_arp_table(self) -> Dict[str, str]:
        """Get the host's ARP table."""
        try:
            result = self.mininet_host.cmd('arp -a')
            arp_table = {}
            for line in result.strip().split('\n'):
                if '(' in line and ')' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[1].strip('()')
                        mac = parts[3]
                        arp_table[ip] = mac
            return arp_table
        except Exception as e:
            self.logger.error(f"Failed to get ARP table: {e}")
            return {}
    
    def execute_command(self, command: str) -> str:
        """Execute a command on the host."""
        try:
            return self.mininet_host.cmd(command)
        except Exception as e:
            self.logger.error(f"Command execution failed: {e}")
            return ""
    
    def get_ip(self) -> str:
        """Get the host's IP address."""
        return self.config.ip
    
    def get_mac(self) -> str:
        """Get the host's MAC address."""
        return self.config.mac
    
    def get_role(self) -> str:
        """Get the host's role."""
        return self.config.role


class SimulatedSwitch:
    """Represents a simulated network switch in the testbed."""
    
    def __init__(self, mininet_switch: OVSSwitch, config: SwitchConfig):
        self.mininet_switch = mininet_switch
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{config.name}")
        self._cam_table: Dict[str, int] = {}  # MAC -> Port mapping
    
    def get_cam_table(self) -> Dict[str, int]:
        """Get the switch's CAM table (MAC to port mappings)."""
        try:
            # Query OpenFlow table for MAC learning
            result = self.mininet_switch.cmd('ovs-ofctl dump-flows ' + self.config.name)
            cam_table = {}
            
            for line in result.split('\n'):
                if 'dl_src=' in line and 'actions=output:' in line:
                    # Parse MAC address and output port
                    parts = line.split(',')
                    mac = None
                    port = None
                    
                    for part in parts:
                        if 'dl_src=' in part:
                            mac = part.split('dl_src=')[1].split(',')[0]
                        elif 'actions=output:' in part:
                            port_str = part.split('actions=output:')[1].split(',')[0]
                            try:
                                port = int(port_str)
                            except ValueError:
                                continue
                    
                    if mac and port is not None:
                        cam_table[mac] = port
            
            self._cam_table = cam_table
            return cam_table
        except Exception as e:
            self.logger.error(f"Failed to get CAM table: {e}")
            return self._cam_table
    
    def get_cam_table_utilization(self) -> float:
        """Get CAM table utilization as a percentage."""
        current_entries = len(self.get_cam_table())
        return current_entries / self.config.cam_table_size
    
    def disable_port(self, port: int) -> bool:
        """Disable a specific switch port."""
        try:
            cmd = f'ovs-ofctl mod-port {self.config.name} {port} down'
            result = self.mininet_switch.cmd(cmd)
            self.logger.info(f"Disabled port {port} on switch {self.config.name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to disable port {port}: {e}")
            return False
    
    def enable_port(self, port: int) -> bool:
        """Enable a specific switch port."""
        try:
            cmd = f'ovs-ofctl mod-port {self.config.name} {port} up'
            result = self.mininet_switch.cmd(cmd)
            self.logger.info(f"Enabled port {port} on switch {self.config.name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to enable port {port}: {e}")
            return False
    
    def get_port_stats(self) -> Dict[int, Dict[str, int]]:
        """Get statistics for all switch ports."""
        try:
            result = self.mininet_switch.cmd(f'ovs-ofctl dump-ports {self.config.name}')
            port_stats = {}
            
            for line in result.split('\n'):
                if 'port' in line and 'rx pkts' in line:
                    # Parse port statistics
                    parts = line.split(',')
                    port_num = None
                    rx_packets = 0
                    tx_packets = 0
                    
                    for part in parts:
                        if 'port' in part and ':' in part:
                            try:
                                port_num = int(part.split(':')[0].strip().split()[-1])
                            except (ValueError, IndexError):
                                continue
                        elif 'rx pkts=' in part:
                            try:
                                rx_packets = int(part.split('rx pkts=')[1])
                            except (ValueError, IndexError):
                                continue
                        elif 'tx pkts=' in part:
                            try:
                                tx_packets = int(part.split('tx pkts=')[1])
                            except (ValueError, IndexError):
                                continue
                    
                    if port_num is not None:
                        port_stats[port_num] = {
                            'rx_packets': rx_packets,
                            'tx_packets': tx_packets
                        }
            
            return port_stats
        except Exception as e:
            self.logger.error(f"Failed to get port stats: {e}")
            return {}


class SimulatedGateway:
    """Represents a simulated gateway/router in the testbed."""
    
    def __init__(self, mininet_host: Host, config: GatewayConfig):
        self.mininet_host = mininet_host
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{config.name}")
    
    def enable_ip_forwarding(self) -> bool:
        """Enable IP forwarding on the gateway."""
        try:
            self.mininet_host.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')
            self.logger.info("IP forwarding enabled")
            return True
        except Exception as e:
            self.logger.error(f"Failed to enable IP forwarding: {e}")
            return False
    
    def add_route(self, network: str, interface: str) -> bool:
        """Add a routing table entry."""
        try:
            cmd = f'ip route add {network} dev {interface}'
            self.mininet_host.cmd(cmd)
            self.logger.info(f"Added route: {network} via {interface}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to add route: {e}")
            return False
    
    def get_routing_table(self) -> List[Dict[str, str]]:
        """Get the gateway's routing table."""
        try:
            result = self.mininet_host.cmd('ip route show')
            routes = []
            
            for line in result.strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        route = {
                            'destination': parts[0],
                            'interface': parts[2] if 'dev' in parts[1:3] else 'unknown'
                        }
                        routes.append(route)
            
            return routes
        except Exception as e:
            self.logger.error(f"Failed to get routing table: {e}")
            return []
    
    def ping(self, target_ip: str, count: int = 1) -> bool:
        """Ping a target IP address from the gateway."""
        try:
            result = self.mininet_host.cmd(f'ping -c {count} {target_ip}')
            return '0% packet loss' in result
        except Exception as e:
            self.logger.error(f"Gateway ping failed: {e}")
            return False


class MininetTestbed(NetworkTestbed):
    """Network testbed implementation using Mininet."""
    
    def __init__(self):
        self.net: Optional[Mininet] = None
        self.hosts: Dict[str, SimulatedHost] = {}
        self.switches: Dict[str, SimulatedSwitch] = {}
        self.gateways: Dict[str, SimulatedGateway] = {}
        self.logger = logging.getLogger(__name__)
        
        # Set Mininet log level to reduce noise
        setLogLevel('warning')
    
    def initialize_topology(self) -> None:
        """Initialize the network topology with default configuration."""
        try:
            # Create Mininet instance
            self.net = Mininet(
                controller=Controller,
                switch=OVSSwitch,
                link=TCLink,
                autoSetMacs=True
            )
            
            # Add controller
            controller = self.net.addController('c0')
            
            # Create default topology: 1 switch, 1 gateway, 2 hosts
            switch_config = SwitchConfig(name='s1', cam_table_size=1000)
            switch = self.net.addSwitch(switch_config.name)
            self.switches[switch_config.name] = SimulatedSwitch(switch, switch_config)
            
            # Add gateway
            gateway_config = GatewayConfig(
                name='gateway',
                ip='192.168.1.1/24',
                mac='00:00:00:00:01:01',
                interfaces=['gateway-eth0']
            )
            gateway_host = self.net.addHost(
                gateway_config.name,
                ip=gateway_config.ip,
                mac=gateway_config.mac
            )
            self.gateways[gateway_config.name] = SimulatedGateway(gateway_host, gateway_config)
            
            # Add victim host
            victim_config = HostConfig(
                name='victim',
                ip='192.168.1.10',
                mac='00:00:00:00:01:10',
                role='victim'
            )
            victim_host = self.net.addHost(
                victim_config.name,
                ip=victim_config.ip,
                mac=victim_config.mac
            )
            self.hosts[victim_config.name] = SimulatedHost(victim_host, victim_config)
            
            # Add attacker host
            attacker_config = HostConfig(
                name='attacker',
                ip='192.168.1.20',
                mac='00:00:00:00:01:20',
                role='attacker'
            )
            attacker_host = self.net.addHost(
                attacker_config.name,
                ip=attacker_config.ip,
                mac=attacker_config.mac
            )
            self.hosts[attacker_config.name] = SimulatedHost(attacker_host, attacker_config)
            
            # Create links
            self.net.addLink(gateway_host, switch)
            self.net.addLink(victim_host, switch)
            self.net.addLink(attacker_host, switch)
            
            # Start the network
            self.net.start()
            
            # Configure gateway
            gateway = self.gateways['gateway']
            gateway.enable_ip_forwarding()
            
            # Wait for network to stabilize
            time.sleep(2)
            
            self.logger.info("Network topology initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize topology: {e}")
            if self.net:
                self.net.stop()
            raise
    
    def create_host(self, name: str, ip: str, mac: str, role: str) -> SimulatedHost:
        """Create a new host in the testbed."""
        if not self.net:
            raise RuntimeError("Network not initialized")
        
        try:
            config = HostConfig(name=name, ip=ip, mac=mac, role=role)
            mininet_host = self.net.addHost(name, ip=ip, mac=mac)
            host = SimulatedHost(mininet_host, config)
            self.hosts[name] = host
            
            # Connect to default switch if available
            if 's1' in self.switches:
                switch = self.switches['s1'].mininet_switch
                self.net.addLink(mininet_host, switch)
            
            self.logger.info(f"Created host {name} with IP {ip}")
            return host
            
        except Exception as e:
            self.logger.error(f"Failed to create host {name}: {e}")
            raise
    
    def create_switch(self, name: str, cam_table_size: int = 1000) -> SimulatedSwitch:
        """Create a new switch in the testbed."""
        if not self.net:
            raise RuntimeError("Network not initialized")
        
        try:
            config = SwitchConfig(name=name, cam_table_size=cam_table_size)
            mininet_switch = self.net.addSwitch(name)
            switch = SimulatedSwitch(mininet_switch, config)
            self.switches[name] = switch
            
            self.logger.info(f"Created switch {name} with CAM table size {cam_table_size}")
            return switch
            
        except Exception as e:
            self.logger.error(f"Failed to create switch {name}: {e}")
            raise
    
    def create_gateway(self, name: str, ip: str, mac: str) -> SimulatedGateway:
        """Create a new gateway in the testbed."""
        if not self.net:
            raise RuntimeError("Network not initialized")
        
        try:
            config = GatewayConfig(name=name, ip=ip, mac=mac, interfaces=[f"{name}-eth0"])
            mininet_host = self.net.addHost(name, ip=ip, mac=mac)
            gateway = SimulatedGateway(mininet_host, config)
            self.gateways[name] = gateway
            
            # Enable IP forwarding
            gateway.enable_ip_forwarding()
            
            self.logger.info(f"Created gateway {name} with IP {ip}")
            return gateway
            
        except Exception as e:
            self.logger.error(f"Failed to create gateway {name}: {e}")
            raise
    
    def verify_connectivity(self) -> bool:
        """Verify network connectivity between all hosts."""
        if not self.net or not self.hosts:
            return False
        
        try:
            # Test connectivity between all host pairs
            host_list = list(self.hosts.values())
            gateway_list = list(self.gateways.values())
            all_nodes = host_list + gateway_list
            
            connectivity_results = []
            
            for i, source in enumerate(all_nodes):
                for j, target in enumerate(all_nodes):
                    if i != j:
                        if hasattr(source, 'ping'):
                            target_ip = target.config.ip.split('/')[0] if hasattr(target, 'config') else target.config.ip
                            result = source.ping(target_ip, count=1)
                            connectivity_results.append(result)
                            
                            if not result:
                                self.logger.warning(f"Connectivity failed: {source.config.name} -> {target.config.name}")
            
            # Return True if at least 80% of connectivity tests pass
            success_rate = sum(connectivity_results) / len(connectivity_results) if connectivity_results else 0
            is_connected = success_rate >= 0.8
            
            self.logger.info(f"Connectivity verification: {success_rate:.2%} success rate")
            return is_connected
            
        except Exception as e:
            self.logger.error(f"Connectivity verification failed: {e}")
            return False
    
    def enable_packet_capture(self, interface: str) -> None:
        """Enable packet capture on the specified interface."""
        try:
            # This is a placeholder for packet capture setup
            # In a real implementation, this would configure tcpdump or similar
            self.logger.info(f"Packet capture enabled on interface {interface}")
        except Exception as e:
            self.logger.error(f"Failed to enable packet capture on {interface}: {e}")
            raise
    
    def get_host(self, name: str) -> Optional[SimulatedHost]:
        """Get a host by name."""
        return self.hosts.get(name)
    
    def get_switch(self, name: str) -> Optional[SimulatedSwitch]:
        """Get a switch by name."""
        return self.switches.get(name)
    
    def get_gateway(self, name: str) -> Optional[SimulatedGateway]:
        """Get a gateway by name."""
        return self.gateways.get(name)
    
    def get_all_hosts(self) -> Dict[str, SimulatedHost]:
        """Get all hosts in the testbed."""
        return self.hosts.copy()
    
    def get_all_switches(self) -> Dict[str, SimulatedSwitch]:
        """Get all switches in the testbed."""
        return self.switches.copy()
    
    def get_all_gateways(self) -> Dict[str, SimulatedGateway]:
        """Get all gateways in the testbed."""
        return self.gateways.copy()
    
    def cleanup(self) -> None:
        """Clean up the testbed and stop the network."""
        try:
            if self.net:
                self.net.stop()
                self.net = None
            
            self.hosts.clear()
            self.switches.clear()
            self.gateways.clear()
            
            self.logger.info("Testbed cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.cleanup()