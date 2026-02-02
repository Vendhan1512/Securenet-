"""
Signature-based detection components for identifying known attack patterns.
"""

import struct
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
import uuid
import logging
import threading

from scapy.all import ARP, DNS, Ether, IP, Raw, UDP
from scapy.packet import Packet

from ..core.interfaces import (
    BaseDetector, SecurityAlert, NetworkBaseline, AttackType, DetectionMethod
)


logger = logging.getLogger(__name__)


class ARPSpoofingDetector(BaseDetector):
    """Detector for ARP spoofing attacks using signature-based detection."""
    
    def __init__(self):
        self.baseline_arp_table: Dict[str, str] = {}  # IP -> MAC mappings
        self.recent_arp_replies: Dict[str, List[Tuple[str, datetime]]] = defaultdict(list)
        self.detection_window = timedelta(seconds=30)
        
    def detect(self, packet_data: bytes) -> Optional[SecurityAlert]:
        """Detect ARP spoofing by analyzing ARP reply inconsistencies."""
        try:
            packet = Ether(packet_data)
            
            # Only process ARP packets
            if not packet.haslayer(ARP):
                return None
                
            arp_layer = packet[ARP]
            
            # Only process ARP replies
            if arp_layer.op != 2:  # ARP reply
                return None
                
            sender_ip = arp_layer.psrc
            sender_mac = arp_layer.hwsrc
            current_time = datetime.now()
            
            # Clean old entries
            self._clean_old_entries(current_time)
            
            # Check against baseline
            if sender_ip in self.baseline_arp_table:
                baseline_mac = self.baseline_arp_table[sender_ip]
                if baseline_mac != sender_mac:
                    # Potential ARP spoofing detected
                    return self._create_alert(
                        packet_data, sender_ip, sender_mac, baseline_mac,
                        "ARP reply contains inconsistent MAC-IP mapping"
                    )
            
            # Track recent ARP replies for the same IP
            self.recent_arp_replies[sender_ip].append((sender_mac, current_time))
            
            # Check for multiple MAC addresses claiming the same IP
            recent_macs = set(mac for mac, _ in self.recent_arp_replies[sender_ip])
            if len(recent_macs) > 1:
                return self._create_alert(
                    packet_data, sender_ip, sender_mac, list(recent_macs)[0],
                    f"Multiple MAC addresses detected for IP {sender_ip}"
                )
                
            return None
            
        except Exception as e:
            logger.error(f"Error in ARP spoofing detection: {e}")
            return None
    
    def update_baseline(self, baseline: NetworkBaseline) -> None:
        """Update ARP baseline mappings."""
        self.baseline_arp_table = baseline.arp_table.copy()
        logger.info(f"Updated ARP baseline with {len(self.baseline_arp_table)} entries")
    
    def _clean_old_entries(self, current_time: datetime) -> None:
        """Remove old ARP reply entries outside detection window."""
        cutoff_time = current_time - self.detection_window
        for ip in list(self.recent_arp_replies.keys()):
            self.recent_arp_replies[ip] = [
                (mac, timestamp) for mac, timestamp in self.recent_arp_replies[ip]
                if timestamp > cutoff_time
            ]
            if not self.recent_arp_replies[ip]:
                del self.recent_arp_replies[ip]
    
    def _create_alert(self, packet_data: bytes, sender_ip: str, sender_mac: str, 
                     expected_mac: str, description: str) -> SecurityAlert:
        """Create security alert for ARP spoofing detection."""
        packet = Ether(packet_data)
        return SecurityAlert(
            timestamp=datetime.now(),
            alert_id=str(uuid.uuid4()),
            attack_type=AttackType.ARP_SPOOFING,
            confidence_score=0.9,
            source_mac=sender_mac,
            source_ip=sender_ip,
            target_mac=packet.dst if hasattr(packet, 'dst') else "",
            target_ip="",
            affected_hosts=[sender_ip],
            raw_packet_data=packet_data,
            detection_method=DetectionMethod.SIGNATURE_BASED
        )


class MACFloodingDetector(BaseDetector):
    """Detector for MAC flooding attacks using signature-based detection."""
    
    def __init__(self, mac_threshold: int = 50, time_window: int = 60):
        self.mac_threshold = mac_threshold
        self.time_window = timedelta(seconds=time_window)
        self.port_mac_tracking: Dict[int, deque] = defaultdict(deque)
        self.baseline_mac_port_mappings: Dict[str, int] = {}
        self._lock = threading.Lock()  # Add thread lock for safety
        
    def detect(self, packet_data: bytes) -> Optional[SecurityAlert]:
        """Detect MAC flooding by monitoring MAC addresses per port."""
        try:
            packet = Ether(packet_data)
            current_time = datetime.now()
            
            # Extract source MAC
            source_mac = packet.src
            
            # Simulate port detection (in real implementation, this would come from switch)
            # For simulation, we'll use a hash of the MAC to assign a port
            simulated_port = hash(source_mac) % 24 + 1  # Simulate 24-port switch
            
            with self._lock:
                # Track MAC addresses per port
                self.port_mac_tracking[simulated_port].append((source_mac, current_time))
                
                # Clean old entries
                self._clean_old_entries(simulated_port, current_time)
                
                # Check if we have multiple MAC addresses on this port
                # Create a defensive copy to avoid "deque mutated during iteration" error
                port_entries = list(self.port_mac_tracking[simulated_port])
                unique_macs = set(mac for mac, _ in port_entries)
                
                if len(unique_macs) > self.mac_threshold:
                    return self._create_alert(
                        packet_data, source_mac, simulated_port, len(unique_macs)
                    )
                
            return None
            
        except Exception as e:
            logger.error(f"Error in MAC flooding detection: {e}")
            return None
    
    def update_baseline(self, baseline: NetworkBaseline) -> None:
        """Update MAC-to-port baseline mappings."""
        with self._lock:
            self.baseline_mac_port_mappings = baseline.mac_port_mappings.copy()
        logger.info(f"Updated MAC-port baseline with {len(self.baseline_mac_port_mappings)} entries")
    
    def _clean_old_entries(self, port: int, current_time: datetime) -> None:
        """Remove old MAC entries outside time window.
        
        Note: Must be called with self._lock held.
        """
        cutoff_time = current_time - self.time_window
        while (self.port_mac_tracking[port] and 
               self.port_mac_tracking[port][0][1] < cutoff_time):
            self.port_mac_tracking[port].popleft()
    
    def _create_alert(self, packet_data: bytes, source_mac: str, 
                     port: int, mac_count: int) -> SecurityAlert:
        """Create security alert for MAC flooding detection."""
        packet = Ether(packet_data)
        # Try to extract IP layer info if present
        source_ip = packet[IP].src if IP in packet else ""
        target_ip = packet[IP].dst if IP in packet else ""
        target_mac = packet.dst if hasattr(packet, "dst") else ""
        return SecurityAlert(
            timestamp=datetime.now(),
            alert_id=str(uuid.uuid4()),
            attack_type=AttackType.MAC_FLOODING,
            confidence_score=0.85,
            source_mac=source_mac,
            source_ip=source_ip,
            target_mac=target_mac,
            target_ip=target_ip,
            affected_hosts=[f"port_{port}"],
            raw_packet_data=packet_data,
            detection_method=DetectionMethod.SIGNATURE_BASED
        )


class DNSSpoofingDetector(BaseDetector):
    """Detector for DNS spoofing attacks using signature-based detection."""
    
    def __init__(self):
        self.baseline_dns_cache: Dict[str, str] = {}  # Domain -> IP mappings
        self.recent_dns_responses: Dict[str, List[Tuple[str, datetime]]] = defaultdict(list)
        self.detection_window = timedelta(seconds=60)
        
    def detect(self, packet_data: bytes) -> Optional[SecurityAlert]:
        """Detect DNS spoofing by analyzing DNS response mismatches."""
        try:
            packet = Ether(packet_data)
            
            # Only process DNS packets (check for UDP layer first)
            if not (packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS)):
                return None
                
            dns_layer = packet[DNS]
            ip_layer = packet[IP]
            udp_layer = packet[UDP]
            
            # Only process DNS responses from port 53
            if udp_layer.sport != 53 or dns_layer.qr != 1:
                return None
                
            current_time = datetime.now()
            
            # Clean old entries
            self._clean_old_entries(current_time)
            
            # Process DNS answers
            if dns_layer.ancount > 0 and hasattr(dns_layer, 'an') and dns_layer.an:
                answer = dns_layer.an
                if hasattr(answer, 'rrname') and hasattr(answer, 'rdata'):
                    domain = answer.rrname.decode() if isinstance(answer.rrname, bytes) else str(answer.rrname)
                    ip_address = str(answer.rdata)
                    
                    # Remove trailing dot from domain if present
                    domain = domain.rstrip('.')
                    
                    # Check against baseline
                    if domain in self.baseline_dns_cache:
                        baseline_ip = self.baseline_dns_cache[domain]
                        if baseline_ip != ip_address:
                            return self._create_alert(
                                packet_data, domain, ip_address, baseline_ip,
                                ip_layer.src
                            )
                    
                    # Track recent responses
                    self.recent_dns_responses[domain].append((ip_address, current_time))
                    
                    # Check for multiple IPs for same domain
                    recent_ips = set(ip for ip, _ in self.recent_dns_responses[domain])
                    if len(recent_ips) > 1:
                        return self._create_alert(
                            packet_data, domain, ip_address, list(recent_ips)[0],
                            ip_layer.src
                        )
            
            return None
            
        except Exception as e:
            logger.error(f"Error in DNS spoofing detection: {e}")
            return None
    
    def update_baseline(self, baseline: NetworkBaseline) -> None:
        """Update DNS baseline mappings."""
        self.baseline_dns_cache = baseline.dns_cache.copy()
        logger.info(f"Updated DNS baseline with {len(self.baseline_dns_cache)} entries")
    
    def _clean_old_entries(self, current_time: datetime) -> None:
        """Remove old DNS response entries outside detection window."""
        cutoff_time = current_time - self.detection_window
        for domain in list(self.recent_dns_responses.keys()):
            self.recent_dns_responses[domain] = [
                (ip, timestamp) for ip, timestamp in self.recent_dns_responses[domain]
                if timestamp > cutoff_time
            ]
            if not self.recent_dns_responses[domain]:
                del self.recent_dns_responses[domain]
    
    def _create_alert(self, packet_data: bytes, domain: str, response_ip: str,
                     expected_ip: str, source_ip: str) -> SecurityAlert:
        """Create security alert for DNS spoofing detection."""
        packet = Ether(packet_data)
        return SecurityAlert(
            timestamp=datetime.now(),
            alert_id=str(uuid.uuid4()),
            attack_type=AttackType.DNS_SPOOFING,
            confidence_score=0.88,
            source_mac=packet.src if hasattr(packet, 'src') else "",
            source_ip=source_ip,
            target_mac=packet.dst if hasattr(packet, 'dst') else "",
            target_ip="",
            affected_hosts=[domain],
            raw_packet_data=packet_data,
            detection_method=DetectionMethod.SIGNATURE_BASED
        )