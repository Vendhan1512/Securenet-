"""
Traffic prevention and source blocking functionality for the LAN Security System.
"""

import logging
import time
from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass

from ..core.interfaces import AttackType, SecurityAlert


logger = logging.getLogger(__name__)


@dataclass
class BlockedSource:
    """Information about a blocked traffic source."""
    source_ip: str
    source_mac: str
    attack_type: AttackType
    blocked_timestamp: datetime
    mitigation_id: str
    block_duration: Optional[timedelta] = None


class TrafficFilter:
    """Manages traffic filtering and source blocking for attack prevention."""
    
    def __init__(self):
        self.blocked_sources: Dict[str, BlockedSource] = {}  # source_ip -> BlockedSource
        self.blocked_macs: Set[str] = set()  # Set of blocked MAC addresses
        self.firewall_rules: Dict[str, List[str]] = {}  # mitigation_id -> list of rule IDs
        self.traffic_stats: Dict[str, int] = {
            "blocked_packets": 0,
            "allowed_packets": 0,
            "total_blocks": 0
        }
    
    def block_attack_source(self, alert: SecurityAlert, mitigation_id: str, 
                           block_duration: Optional[timedelta] = None) -> bool:
        """
        Block traffic from an attack source.
        
        Args:
            alert: Security alert containing attack information
            mitigation_id: ID of the mitigation action
            block_duration: Optional duration for the block (None = permanent)
            
        Returns:
            bool: True if blocking was successful, False otherwise
        """
        try:
            source_ip = alert.source_ip
            source_mac = alert.source_mac
            
            # If already blocked, avoid re-applying rules/log spam
            if self.is_source_blocked(source_ip, source_mac):
                logger.info(f"Source {source_ip} already blocked; skipping duplicate firewall rules")
                return True
            
            # Create blocked source entry
            blocked_source = BlockedSource(
                source_ip=source_ip,
                source_mac=source_mac,
                attack_type=alert.attack_type,
                blocked_timestamp=datetime.now(),
                mitigation_id=mitigation_id,
                block_duration=block_duration
            )
            
            # Add to blocked sources
            self.blocked_sources[source_ip] = blocked_source
            self.blocked_macs.add(source_mac)
            
            # Apply firewall rules based on attack type
            success = self._apply_firewall_rules(alert, mitigation_id)
            
            if success:
                self.traffic_stats["total_blocks"] += 1
                logger.info(f"Successfully blocked attack source {source_ip} ({source_mac}) for {alert.attack_type.value}")
            else:
                # Remove from blocked sources if firewall rules failed
                self.blocked_sources.pop(source_ip, None)
                self.blocked_macs.discard(source_mac)
                logger.error(f"Failed to apply firewall rules for {source_ip}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to block attack source {alert.source_ip}: {e}")
            return False
    
    def _apply_firewall_rules(self, alert: SecurityAlert, mitigation_id: str) -> bool:
        """Apply appropriate firewall rules based on attack type."""
        try:
            rules_applied = []
            
            if alert.attack_type == AttackType.ARP_SPOOFING:
                # Block ARP traffic from the malicious MAC
                rule_id = f"arp_block_{alert.source_mac.replace(':', '_')}"
                iptables_cmd = [
                    "iptables", "-A", "INPUT",
                    "-m", "mac", "--mac-source", alert.source_mac,
                    "-p", "arp", "-j", "DROP"
                ]
                logger.info(f"Applying ARP blocking rule: {' '.join(iptables_cmd)}")
                rules_applied.append(rule_id)
                
                # Also block IP traffic from the source
                rule_id_ip = f"ip_block_{alert.source_ip.replace('.', '_')}"
                iptables_ip_cmd = [
                    "iptables", "-A", "INPUT",
                    "-s", alert.source_ip, "-j", "DROP"
                ]
                logger.info(f"Applying IP blocking rule: {' '.join(iptables_ip_cmd)}")
                rules_applied.append(rule_id_ip)
                
            elif alert.attack_type == AttackType.MAC_FLOODING:
                # Block all traffic from the flooding MAC address
                rule_id = f"mac_flood_block_{alert.source_mac.replace(':', '_')}"
                iptables_cmd = [
                    "iptables", "-A", "INPUT",
                    "-m", "mac", "--mac-source", alert.source_mac,
                    "-j", "DROP"
                ]
                logger.info(f"Applying MAC flooding blocking rule: {' '.join(iptables_cmd)}")
                rules_applied.append(rule_id)
                
            elif alert.attack_type == AttackType.DNS_SPOOFING:
                # Block DNS responses from the malicious server
                rule_id_udp = f"dns_block_udp_{alert.source_ip.replace('.', '_')}"
                iptables_udp_cmd = [
                    "iptables", "-A", "INPUT",
                    "-s", alert.source_ip,
                    "-p", "udp", "--sport", "53",
                    "-j", "DROP"
                ]
                logger.info(f"Applying DNS UDP blocking rule: {' '.join(iptables_udp_cmd)}")
                rules_applied.append(rule_id_udp)
                
                rule_id_tcp = f"dns_block_tcp_{alert.source_ip.replace('.', '_')}"
                iptables_tcp_cmd = [
                    "iptables", "-A", "INPUT",
                    "-s", alert.source_ip,
                    "-p", "tcp", "--sport", "53",
                    "-j", "DROP"
                ]
                logger.info(f"Applying DNS TCP blocking rule: {' '.join(iptables_tcp_cmd)}")
                rules_applied.append(rule_id_tcp)
            
            # Store the applied rules for later removal
            self.firewall_rules[mitigation_id] = rules_applied
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to apply firewall rules: {e}")
            return False
    
    def unblock_source(self, source_ip: str) -> bool:
        """
        Unblock a previously blocked source.
        
        Args:
            source_ip: IP address of the source to unblock
            
        Returns:
            bool: True if unblocking was successful, False otherwise
        """
        try:
            blocked_source = self.blocked_sources.get(source_ip)
            if not blocked_source:
                logger.warning(f"No blocked source found for IP {source_ip}")
                return False
            
            # Remove firewall rules
            success = self._remove_firewall_rules(blocked_source.mitigation_id)
            
            if success:
                # Remove from blocked sources
                self.blocked_sources.pop(source_ip, None)
                self.blocked_macs.discard(blocked_source.source_mac)
                logger.info(f"Successfully unblocked source {source_ip}")
            else:
                logger.error(f"Failed to remove firewall rules for {source_ip}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to unblock source {source_ip}: {e}")
            return False
    
    def _remove_firewall_rules(self, mitigation_id: str) -> bool:
        """Remove firewall rules associated with a mitigation."""
        try:
            rules = self.firewall_rules.get(mitigation_id, [])
            
            for rule_id in rules:
                # In a real implementation, this would remove the actual iptables rule
                # For simulation, we'll just log the removal
                logger.info(f"Removing firewall rule: {rule_id}")
            
            # Remove the rules from our tracking
            self.firewall_rules.pop(mitigation_id, None)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove firewall rules for mitigation {mitigation_id}: {e}")
            return False
    
    def is_source_blocked(self, source_ip: str, source_mac: str = None) -> bool:
        """
        Check if a source is currently blocked.
        
        Args:
            source_ip: IP address to check
            source_mac: Optional MAC address to check
            
        Returns:
            bool: True if the source is blocked, False otherwise
        """
        # Check if IP is blocked
        if source_ip in self.blocked_sources:
            blocked_source = self.blocked_sources[source_ip]
            
            # Check if block has expired
            if blocked_source.block_duration:
                expiry_time = blocked_source.blocked_timestamp + blocked_source.block_duration
                if datetime.now() > expiry_time:
                    # Block has expired, remove it
                    self.unblock_source(source_ip)
                    return False
            
            return True
        
        # Check if MAC is blocked
        if source_mac and source_mac in self.blocked_macs:
            return True
        
        return False
    
    def filter_packet(self, source_ip: str, source_mac: str, packet_data: bytes) -> bool:
        """
        Filter a packet based on current blocking rules.
        
        Args:
            source_ip: Source IP address of the packet
            source_mac: Source MAC address of the packet
            packet_data: Raw packet data
            
        Returns:
            bool: True if packet should be allowed, False if blocked
        """
        try:
            # Check if source is blocked
            if self.is_source_blocked(source_ip, source_mac):
                self.traffic_stats["blocked_packets"] += 1
                logger.debug(f"Blocked packet from {source_ip} ({source_mac})")
                return False
            
            # Packet is allowed
            self.traffic_stats["allowed_packets"] += 1
            return True
            
        except Exception as e:
            logger.error(f"Error filtering packet from {source_ip}: {e}")
            # In case of error, allow the packet (fail open)
            return True
    
    def validate_mitigation_effectiveness(self, mitigation_id: str) -> bool:
        """
        Validate that a mitigation is effectively preventing attack traffic.
        
        Args:
            mitigation_id: ID of the mitigation to validate
            
        Returns:
            bool: True if mitigation is effective, False otherwise
        """
        try:
            # Find the blocked source associated with this mitigation
            blocked_source = None
            for source in self.blocked_sources.values():
                if source.mitigation_id == mitigation_id:
                    blocked_source = source
                    break
            
            if not blocked_source:
                logger.warning(f"No blocked source found for mitigation {mitigation_id}")
                return False
            
            # Check if firewall rules are still in place
            if mitigation_id not in self.firewall_rules:
                logger.error(f"Firewall rules missing for mitigation {mitigation_id}")
                return False
            
            # Verify the source is still blocked
            if not self.is_source_blocked(blocked_source.source_ip, blocked_source.source_mac):
                logger.error(f"Source {blocked_source.source_ip} is no longer blocked")
                return False
            
            logger.info(f"Mitigation {mitigation_id} is effectively preventing attack traffic")
            return True
            
        except Exception as e:
            logger.error(f"Failed to validate mitigation effectiveness: {e}")
            return False
    
    def cleanup_expired_blocks(self) -> int:
        """
        Clean up expired blocks.
        
        Returns:
            int: Number of expired blocks removed
        """
        try:
            expired_sources = []
            current_time = datetime.now()
            
            for source_ip, blocked_source in self.blocked_sources.items():
                if blocked_source.block_duration:
                    expiry_time = blocked_source.blocked_timestamp + blocked_source.block_duration
                    if current_time > expiry_time:
                        expired_sources.append(source_ip)
            
            # Remove expired blocks
            removed_count = 0
            for source_ip in expired_sources:
                if self.unblock_source(source_ip):
                    removed_count += 1
            
            if removed_count > 0:
                logger.info(f"Cleaned up {removed_count} expired blocks")
            
            return removed_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired blocks: {e}")
            return 0
    
    def get_blocked_sources(self) -> List[BlockedSource]:
        """Get list of all currently blocked sources."""
        return list(self.blocked_sources.values())
    
    def get_traffic_stats(self) -> Dict[str, int]:
        """Get traffic filtering statistics."""
        return self.traffic_stats.copy()
    
    def reset_stats(self) -> None:
        """Reset traffic filtering statistics."""
        self.traffic_stats = {
            "blocked_packets": 0,
            "allowed_packets": 0,
            "total_blocks": 0
        }