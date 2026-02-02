"""
Packet capture and analysis capabilities for the network testbed.

This module provides real-time packet capture using libpcap integration
and packet parsing utilities for network baseline establishment.
"""

import logging
import threading
import time
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import socket
import struct

try:
    from scapy.all import (
        sniff, Ether, ARP, IP, UDP, DNS, DNSQR, DNSRR,
        get_if_list, conf, AsyncSniffer
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from ..core.interfaces import NetworkBaseline


@dataclass
class PacketInfo:
    """Information extracted from a captured packet."""
    timestamp: datetime
    src_mac: str
    dst_mac: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: str = "unknown"
    packet_size: int = 0
    raw_data: bytes = b""
    additional_info: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ARPInfo:
    """ARP packet information."""
    operation: str  # 'request' or 'reply'
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str


@dataclass
class DNSInfo:
    """DNS packet information."""
    query_type: str  # 'query' or 'response'
    domain: str
    query_type_code: int
    response_ips: List[str] = field(default_factory=list)
    ttl: Optional[int] = None


@dataclass
class NetworkStatistics:
    """Network traffic statistics."""
    total_packets: int = 0
    arp_packets: int = 0
    dns_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    unique_mac_addresses: set = field(default_factory=set)
    unique_ip_addresses: set = field(default_factory=set)
    packet_rate: float = 0.0  # packets per second
    start_time: Optional[datetime] = None
    last_update: Optional[datetime] = None


class PacketAnalyzer:
    """Analyzes captured packets and extracts relevant information."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def analyze_packet(self, packet) -> Optional[PacketInfo]:
        """Analyze a single packet and extract information."""
        if not SCAPY_AVAILABLE:
            self.logger.warning("Scapy not available, cannot analyze packets")
            return None
        
        try:
            timestamp = datetime.now()
            packet_info = PacketInfo(
                timestamp=timestamp,
                src_mac="",
                dst_mac="",
                packet_size=len(packet),
                raw_data=bytes(packet)
            )
            
            # Extract Ethernet layer information
            if packet.haslayer(Ether):
                eth = packet[Ether]
                packet_info.src_mac = eth.src
                packet_info.dst_mac = eth.dst
            
            # Extract IP layer information
            if packet.haslayer(IP):
                ip = packet[IP]
                packet_info.src_ip = ip.src
                packet_info.dst_ip = ip.dst
                packet_info.protocol = "IP"
                
                # Check for specific protocols
                if packet.haslayer(UDP):
                    packet_info.protocol = "UDP"
                    if packet.haslayer(DNS):
                        packet_info.protocol = "DNS"
                        dns_info = self._extract_dns_info(packet)
                        if dns_info:
                            packet_info.additional_info['dns'] = dns_info
                
                elif ip.proto == 1:  # ICMP
                    packet_info.protocol = "ICMP"
                elif ip.proto == 6:  # TCP
                    packet_info.protocol = "TCP"
            
            # Extract ARP information
            elif packet.haslayer(ARP):
                packet_info.protocol = "ARP"
                arp_info = self._extract_arp_info(packet)
                if arp_info:
                    packet_info.additional_info['arp'] = arp_info
            
            return packet_info
            
        except Exception as e:
            self.logger.error(f"Error analyzing packet: {e}")
            return None
    
    def _extract_arp_info(self, packet) -> Optional[ARPInfo]:
        """Extract ARP-specific information from packet."""
        try:
            arp = packet[ARP]
            operation = "request" if arp.op == 1 else "reply"
            
            return ARPInfo(
                operation=operation,
                sender_mac=arp.hwsrc,
                sender_ip=arp.psrc,
                target_mac=arp.hwdst,
                target_ip=arp.pdst
            )
        except Exception as e:
            self.logger.error(f"Error extracting ARP info: {e}")
            return None
    
    def _extract_dns_info(self, packet) -> Optional[DNSInfo]:
        """Extract DNS-specific information from packet."""
        try:
            dns = packet[DNS]
            
            if dns.qr == 0:  # Query
                if dns.qdcount > 0:
                    query = dns.qd
                    domain = query.qname.decode('utf-8').rstrip('.')
                    return DNSInfo(
                        query_type="query",
                        domain=domain,
                        query_type_code=query.qtype
                    )
            else:  # Response
                if dns.ancount > 0:
                    query = dns.qd
                    domain = query.qname.decode('utf-8').rstrip('.')
                    response_ips = []
                    ttl = None
                    
                    # Extract answer records
                    for i in range(dns.ancount):
                        answer = dns.an[i] if hasattr(dns.an, '__getitem__') else dns.an
                        if hasattr(answer, 'rdata'):
                            response_ips.append(str(answer.rdata))
                        if hasattr(answer, 'ttl') and ttl is None:
                            ttl = answer.ttl
                    
                    return DNSInfo(
                        query_type="response",
                        domain=domain,
                        query_type_code=query.qtype,
                        response_ips=response_ips,
                        ttl=ttl
                    )
        except Exception as e:
            self.logger.error(f"Error extracting DNS info: {e}")
            return None


class NetworkBaselineManager:
    """Manages network baseline establishment and maintenance."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.baseline: Optional[NetworkBaseline] = None
        self.statistics = NetworkStatistics()
    
    def establish_baseline(self, packets: List[PacketInfo], duration_seconds: int = 60) -> NetworkBaseline:
        """Establish network baseline from captured packets."""
        try:
            arp_table = {}
            dns_cache = {}
            mac_port_mappings = {}
            
            # Process packets to build baseline
            for packet in packets:
                # Update statistics
                self.statistics.unique_mac_addresses.add(packet.src_mac)
                self.statistics.unique_mac_addresses.add(packet.dst_mac)
                
                if packet.src_ip:
                    self.statistics.unique_ip_addresses.add(packet.src_ip)
                if packet.dst_ip:
                    self.statistics.unique_ip_addresses.add(packet.dst_ip)
                
                # Extract ARP mappings
                if 'arp' in packet.additional_info:
                    arp_info = packet.additional_info['arp']
                    if arp_info.operation == 'reply':
                        arp_table[arp_info.sender_ip] = arp_info.sender_mac
                
                # Extract DNS mappings
                if 'dns' in packet.additional_info:
                    dns_info = packet.additional_info['dns']
                    if dns_info.query_type == 'response' and dns_info.response_ips:
                        # Use the first IP in the response
                        dns_cache[dns_info.domain] = dns_info.response_ips[0]
            
            # Create baseline
            self.baseline = NetworkBaseline(
                arp_table=arp_table,
                dns_cache=dns_cache,
                mac_port_mappings=mac_port_mappings,
                baseline_timestamp=datetime.now()
            )
            
            self.logger.info(f"Network baseline established with {len(arp_table)} ARP entries and {len(dns_cache)} DNS entries")
            return self.baseline
            
        except Exception as e:
            self.logger.error(f"Error establishing baseline: {e}")
            raise
    
    def update_statistics(self, packet: PacketInfo) -> None:
        """Update network statistics with new packet."""
        try:
            now = datetime.now()
            
            if self.statistics.start_time is None:
                self.statistics.start_time = now
            
            self.statistics.total_packets += 1
            self.statistics.last_update = now
            
            # Update protocol counters
            if packet.protocol == "ARP":
                self.statistics.arp_packets += 1
            elif packet.protocol == "DNS":
                self.statistics.dns_packets += 1
            elif packet.protocol == "TCP":
                self.statistics.tcp_packets += 1
            elif packet.protocol == "UDP":
                self.statistics.udp_packets += 1
            elif packet.protocol == "ICMP":
                self.statistics.icmp_packets += 1
            
            # Update unique addresses
            self.statistics.unique_mac_addresses.add(packet.src_mac)
            self.statistics.unique_mac_addresses.add(packet.dst_mac)
            
            if packet.src_ip:
                self.statistics.unique_ip_addresses.add(packet.src_ip)
            if packet.dst_ip:
                self.statistics.unique_ip_addresses.add(packet.dst_ip)
            
            # Calculate packet rate
            if self.statistics.start_time:
                duration = (now - self.statistics.start_time).total_seconds()
                if duration > 0:
                    self.statistics.packet_rate = self.statistics.total_packets / duration
            
        except Exception as e:
            self.logger.error(f"Error updating statistics: {e}")
    
    def get_baseline(self) -> Optional[NetworkBaseline]:
        """Get the current network baseline."""
        return self.baseline
    
    def get_statistics(self) -> NetworkStatistics:
        """Get current network statistics."""
        return self.statistics


class PacketCapture:
    """Real-time packet capture using libpcap integration via Scapy."""
    
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.logger = logging.getLogger(__name__)
        self.analyzer = PacketAnalyzer()
        self.baseline_manager = NetworkBaselineManager()
        self.is_capturing = False
        self.capture_thread: Optional[threading.Thread] = None
        self.packet_callbacks: List[Callable[[PacketInfo], None]] = []
        self.captured_packets: List[PacketInfo] = []
        self.max_packets = 10000  # Limit memory usage
        self._sniffer: Optional[AsyncSniffer] = None
        
        if not SCAPY_AVAILABLE:
            self.logger.warning("Scapy not available, packet capture functionality limited")
    
    def add_packet_callback(self, callback: Callable[[PacketInfo], None]) -> None:
        """Add a callback function to be called for each captured packet."""
        self.packet_callbacks.append(callback)
    
    def remove_packet_callback(self, callback: Callable[[PacketInfo], None]) -> None:
        """Remove a packet callback."""
        if callback in self.packet_callbacks:
            self.packet_callbacks.remove(callback)
    
    def start_capture(self, filter_expression: Optional[str] = None, packet_count: Optional[int] = None) -> None:
        """Start packet capture on the specified interface."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not available, cannot start packet capture")
        
        if self.is_capturing:
            self.logger.warning("Packet capture already running")
            return
        
        try:
            # Determine interface to use
            interface = self.interface
            if not interface:
                available_interfaces = get_if_list()
                if available_interfaces:
                    # Use first available interface
                    interface = available_interfaces[0]
                    self.logger.info(f"Using interface: {interface}")
                else:
                    raise RuntimeError("No network interfaces available")
            
            self.is_capturing = True
            self.captured_packets.clear()
            
            # Start async sniffer
            self._sniffer = AsyncSniffer(
                iface=interface,
                filter=filter_expression,
                prn=self._packet_handler,
                count=packet_count,
                store=False  # Don't store packets in sniffer to save memory
            )
            
            self._sniffer.start()
            self.logger.info(f"Started packet capture on interface {interface}")
            
        except Exception as e:
            self.is_capturing = False
            self.logger.error(f"Failed to start packet capture: {e}")
            raise
    
    def stop_capture(self) -> None:
        """Stop packet capture."""
        if not self.is_capturing:
            return
        
        try:
            self.is_capturing = False
            
            if self._sniffer:
                self._sniffer.stop()
                self._sniffer = None
            
            self.logger.info("Stopped packet capture")
            
        except Exception as e:
            self.logger.error(f"Error stopping packet capture: {e}")
    
    def _packet_handler(self, packet) -> None:
        """Handle captured packets."""
        try:
            if not self.is_capturing:
                return
            
            # Analyze packet
            packet_info = self.analyzer.analyze_packet(packet)
            if not packet_info:
                return
            
            # Update statistics
            self.baseline_manager.update_statistics(packet_info)
            
            # Store packet (with memory limit)
            if len(self.captured_packets) < self.max_packets:
                self.captured_packets.append(packet_info)
            else:
                # Remove oldest packet to make room
                self.captured_packets.pop(0)
                self.captured_packets.append(packet_info)
            
            # Call registered callbacks
            for callback in self.packet_callbacks:
                try:
                    callback(packet_info)
                except Exception as e:
                    self.logger.error(f"Error in packet callback: {e}")
            
        except Exception as e:
            self.logger.error(f"Error handling packet: {e}")
    
    def get_captured_packets(self) -> List[PacketInfo]:
        """Get list of captured packets."""
        return self.captured_packets.copy()
    
    def get_statistics(self) -> NetworkStatistics:
        """Get capture statistics."""
        return self.baseline_manager.get_statistics()
    
    def establish_baseline(self, duration_seconds: int = 60) -> NetworkBaseline:
        """Establish network baseline from captured traffic."""
        if not self.captured_packets:
            raise RuntimeError("No packets captured, cannot establish baseline")
        
        return self.baseline_manager.establish_baseline(self.captured_packets, duration_seconds)
    
    def get_baseline(self) -> Optional[NetworkBaseline]:
        """Get the current network baseline."""
        return self.baseline_manager.get_baseline()
    
    def capture_for_duration(self, duration_seconds: int, filter_expression: Optional[str] = None) -> List[PacketInfo]:
        """Capture packets for a specified duration."""
        try:
            self.start_capture(filter_expression=filter_expression)
            time.sleep(duration_seconds)
            self.stop_capture()
            return self.get_captured_packets()
        except Exception as e:
            self.logger.error(f"Error during timed capture: {e}")
            self.stop_capture()
            raise
    
    def get_available_interfaces(self) -> List[str]:
        """Get list of available network interfaces."""
        if not SCAPY_AVAILABLE:
            return []
        
        try:
            return get_if_list()
        except Exception as e:
            self.logger.error(f"Error getting interfaces: {e}")
            return []
    
    def cleanup(self) -> None:
        """Clean up resources."""
        try:
            self.stop_capture()
            self.captured_packets.clear()
            self.packet_callbacks.clear()
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.cleanup()