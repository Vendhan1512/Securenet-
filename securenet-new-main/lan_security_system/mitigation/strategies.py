"""
Attack-specific mitigation strategies for the LAN Security System.
"""

import logging
import subprocess
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from ..core.interfaces import (
    AttackType, MitigationResult, MitigationStrategy, SecurityAlert
)


logger = logging.getLogger(__name__)


class ARPSpoofingMitigationStrategy(MitigationStrategy):
    """Mitigation strategy for ARP spoofing attacks."""
    
    def __init__(self):
        self.blocked_macs: Dict[str, str] = {}  # MAC -> mitigation_id
        self.rule_timestamps: Dict[str, datetime] = {}  # Rule key -> timestamp for TTL tracking
        self.rule_ttl_seconds = 300  # 5 minutes default TTL for mitigation rules
        
    def execute(self, alert: SecurityAlert) -> MitigationResult:
        """Execute MAC address blocking for ARP spoofing (idempotent)."""
        mitigation_id = str(uuid.uuid4())
        actions_taken = []
        source_mac = alert.source_mac
        
        try:
            # IDEMPOTENT CHECK: Check if rule already exists with iptables -C
            rule_key = f"arp_mac_{source_mac}"
            is_rule_active, was_recent = self._check_rule_freshness(rule_key)
            
            if is_rule_active and was_recent:
                # Rule already active and within TTL - skip
                logger.info(f"Skipping duplicate mitigation: MAC {source_mac} already blocked (TTL active)")
                actions_taken.append(f"Skipped: MAC {source_mac} already blocked (within TTL)")
                return MitigationResult(
                    success=True,
                    mitigation_id=mitigation_id,
                    actions_taken=actions_taken,
                    timestamp=datetime.now(),
                    error_message="Duplicate mitigation skipped (within TTL)"
                )
            
            if is_rule_active and not was_recent:
                # Rule exists but TTL expired - remove old rule first
                logger.info(f"TTL expired for MAC {source_mac}, removing old rule")
                self._remove_mac_rule(source_mac)
            
            # Add iptables rule to drop packets from the malicious MAC (only if not already present)
            iptables_cmd = [
                "iptables", "-A", "INPUT", 
                "-m", "mac", "--mac-source", source_mac,
                "-j", "DROP"
            ]
            
            # For simulation purposes, we'll log the command instead of executing
            # In a real environment, this would execute the actual iptables command
            logger.info(f"Executing iptables command: {' '.join(iptables_cmd)}")
            actions_taken.append(f"Blocked MAC address {source_mac} using iptables")
            
            # Store the blocked MAC for potential rollback and track rule TTL
            self.blocked_macs[source_mac] = mitigation_id
            self.rule_timestamps[rule_key] = datetime.now()
            
            # Additional action: Update ARP table to remove poisoned entries
            arp_cmd = ["arp", "-d", alert.target_ip]
            logger.info(f"Executing ARP command: {' '.join(arp_cmd)}")
            actions_taken.append(f"Removed ARP entry for {alert.target_ip}")
            
            return MitigationResult(
                success=True,
                mitigation_id=mitigation_id,
                actions_taken=actions_taken,
                timestamp=datetime.now()
            )
            
        except Exception as e:
            logger.error(f"Failed to execute ARP spoofing mitigation: {e}")
            return MitigationResult(
                success=False,
                mitigation_id=mitigation_id,
                actions_taken=actions_taken,
                timestamp=datetime.now(),
                error_message=str(e)
            )
    
    def _check_rule_freshness(self, rule_key: str) -> Tuple[bool, bool]:
        """Check if rule exists and if it's still within TTL.
        
        Returns:
            (rule_exists, within_ttl): True if rule exists, True if within TTL window
        """
        if rule_key not in self.rule_timestamps:
            return False, False
        
        time_since_rule = (datetime.now() - self.rule_timestamps[rule_key]).total_seconds()
        within_ttl = time_since_rule < self.rule_ttl_seconds
        
        return True, within_ttl
    
    def _remove_mac_rule(self, source_mac: str) -> bool:
        """Remove existing MAC rule after TTL expiry."""
        try:
            iptables_cmd = [
                "iptables", "-D", "INPUT",
                "-m", "mac", "--mac-source", source_mac,
                "-j", "DROP"
            ]
            logger.info(f"Removing expired rule: {' '.join(iptables_cmd)}")
            return True
        except Exception as e:
            logger.error(f"Failed to remove MAC rule: {e}")
            return False
    
    def rollback(self, mitigation_id: str) -> bool:
        """Rollback MAC address blocking."""
        try:
            # Find the MAC address associated with this mitigation
            mac_to_unblock = None
            for mac, mid in self.blocked_macs.items():
                if mid == mitigation_id:
                    mac_to_unblock = mac
                    break
            
            if not mac_to_unblock:
                logger.warning(f"No MAC address found for mitigation ID {mitigation_id}")
                return False
            
            # Remove iptables rule
            iptables_cmd = [
                "iptables", "-D", "INPUT",
                "-m", "mac", "--mac-source", mac_to_unblock,
                "-j", "DROP"
            ]
            
            logger.info(f"Rolling back iptables command: {' '.join(iptables_cmd)}")
            
            # Remove from blocked MACs
            del self.blocked_macs[mac_to_unblock]
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to rollback ARP spoofing mitigation: {e}")
            return False


class MACFloodingMitigationStrategy(MitigationStrategy):
    """Mitigation strategy for MAC flooding attacks."""
    
    def __init__(self):
        self.disabled_ports: Dict[int, str] = {}  # Port -> mitigation_id
        self.rule_timestamps: Dict[str, datetime] = {}  # Rule key -> timestamp for TTL tracking
        self.rule_ttl_seconds = 300  # 5 minutes default TTL for mitigation rules
        
    def execute(self, alert: SecurityAlert) -> MitigationResult:
        """Execute switch port disabling for MAC flooding (idempotent)."""
        mitigation_id = str(uuid.uuid4())
        actions_taken = []
        
        try:
            # Determine the switch port from the source MAC
            # In a real implementation, this would query the switch's CAM table
            # For simulation, we'll use a mock port number
            switch_port = self._get_port_from_mac(alert.source_mac)
            
            # IDEMPOTENT CHECK: Check if port already disabled and within TTL
            rule_key = f"mac_flood_port_{switch_port}"
            is_rule_active, was_recent = self._check_rule_freshness(rule_key)
            
            if is_rule_active and was_recent:
                # Port already disabled and within TTL - skip
                logger.info(f"Skipping duplicate mitigation: port {switch_port} already disabled (TTL active)")
                actions_taken.append(f"Skipped: port {switch_port} already disabled (within TTL)")
                return MitigationResult(
                    success=True,
                    mitigation_id=mitigation_id,
                    actions_taken=actions_taken,
                    timestamp=datetime.now(),
                    error_message="Duplicate mitigation skipped (within TTL)"
                )
            
            if is_rule_active and not was_recent:
                # Port disabling already expired - reset it
                logger.info(f"TTL expired for port {switch_port}, re-enabling and re-disabling")
            
            # Disable the switch port
            # In a real environment, this would use SNMP or switch API
            logger.info(f"Disabling switch port {switch_port} for MAC flooding mitigation")
            actions_taken.append(f"Disabled switch port {switch_port}")
            
            # Store the disabled port for potential rollback
            self.disabled_ports[switch_port] = mitigation_id
            self.rule_timestamps[rule_key] = datetime.now()
            
            # Additional action: Clear CAM table entries for the port
            logger.info(f"Clearing CAM table entries for port {switch_port}")
            actions_taken.append(f"Cleared CAM table entries for port {switch_port}")
            
            return MitigationResult(
                success=True,
                mitigation_id=mitigation_id,
                actions_taken=actions_taken,
                timestamp=datetime.now()
            )
            
        except Exception as e:
            logger.error(f"Failed to execute MAC flooding mitigation: {e}")
            return MitigationResult(
                success=False,
                mitigation_id=mitigation_id,
                actions_taken=actions_taken,
                timestamp=datetime.now(),
                error_message=str(e)
            )
    
    def _check_rule_freshness(self, rule_key: str) -> Tuple[bool, bool]:
        """Check if rule exists and if it's still within TTL.
        
        Returns:
            (rule_exists, within_ttl): True if rule exists, True if within TTL window
        """
        if rule_key not in self.rule_timestamps:
            return False, False
        
        time_since_rule = (datetime.now() - self.rule_timestamps[rule_key]).total_seconds()
        within_ttl = time_since_rule < self.rule_ttl_seconds
        
        return True, within_ttl
    
    def rollback(self, mitigation_id: str) -> bool:
        """Rollback switch port disabling."""
        try:
            # Find the port associated with this mitigation
            port_to_enable = None
            for port, mid in self.disabled_ports.items():
                if mid == mitigation_id:
                    port_to_enable = port
                    break
            
            if port_to_enable is None:
                logger.warning(f"No port found for mitigation ID {mitigation_id}")
                return False
            
            # Re-enable the switch port
            logger.info(f"Re-enabling switch port {port_to_enable}")
            
            # Remove from disabled ports
            del self.disabled_ports[port_to_enable]
            
            # Clean up TTL tracking
            rule_key = f"mac_flood_port_{port_to_enable}"
            if rule_key in self.rule_timestamps:
                del self.rule_timestamps[rule_key]
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to rollback MAC flooding mitigation: {e}")
            return False
    
    def _get_port_from_mac(self, mac_address: str) -> int:
        """Get switch port number from MAC address (simulation)."""
        # In a real implementation, this would query the switch's CAM table
        # For simulation, we'll hash the MAC to get a consistent port number
        return hash(mac_address) % 24 + 1  # Simulate 24-port switch


class DNSSpoofingMitigationStrategy(MitigationStrategy):
    """Mitigation strategy for DNS spoofing attacks."""
    
    def __init__(self):
        self.blocked_dns_servers: Dict[str, str] = {}  # DNS_IP -> mitigation_id
        self.rule_timestamps: Dict[str, datetime] = {}  # Rule key -> timestamp for TTL tracking
        self.rule_ttl_seconds = 300  # 5 minutes default TTL for mitigation rules
        
    def execute(self, alert: SecurityAlert) -> MitigationResult:
        """Execute firewall rule insertion for DNS spoofing (idempotent)."""
        mitigation_id = str(uuid.uuid4())
        actions_taken = []
        dns_server_ip = alert.source_ip
        
        try:
            # IDEMPOTENT CHECK: Check if rules already exist for this DNS server
            rule_key = f"dns_spoofing_{dns_server_ip}"
            is_rule_active, was_recent = self._check_rule_freshness(rule_key)
            
            if is_rule_active and was_recent:
                # Rules already active and within TTL - skip
                logger.info(f"Skipping duplicate mitigation: DNS server {dns_server_ip} already blocked (TTL active)")
                actions_taken.append(f"Skipped: DNS server {dns_server_ip} already blocked (within TTL)")
                return MitigationResult(
                    success=True,
                    mitigation_id=mitigation_id,
                    actions_taken=actions_taken,
                    timestamp=datetime.now(),
                    error_message="Duplicate mitigation skipped (within TTL)"
                )
            
            if is_rule_active and not was_recent:
                # Rules exist but TTL expired - remove old rules first
                logger.info(f"TTL expired for DNS server {dns_server_ip}, removing old rules")
                self._remove_dns_rules(dns_server_ip)
            
            # Add iptables rule to block DNS traffic from malicious server
            iptables_cmd = [
                "iptables", "-A", "INPUT",
                "-s", dns_server_ip,
                "-p", "udp", "--sport", "53",
                "-j", "DROP"
            ]
            
            logger.info(f"Executing iptables command: {' '.join(iptables_cmd)}")
            actions_taken.append(f"Blocked DNS server {dns_server_ip} using iptables")
            
            # Store the blocked DNS server for potential rollback and track rule TTL
            self.blocked_dns_servers[dns_server_ip] = mitigation_id
            self.rule_timestamps[rule_key] = datetime.now()
            
            # Additional action: Add rule to block TCP DNS as well
            iptables_tcp_cmd = [
                "iptables", "-A", "INPUT",
                "-s", dns_server_ip,
                "-p", "tcp", "--sport", "53",
                "-j", "DROP"
            ]
            
            logger.info(f"Executing iptables TCP command: {' '.join(iptables_tcp_cmd)}")
            actions_taken.append(f"Blocked TCP DNS from {dns_server_ip}")
            
            return MitigationResult(
                success=True,
                mitigation_id=mitigation_id,
                actions_taken=actions_taken,
                timestamp=datetime.now()
            )
            
        except Exception as e:
            logger.error(f"Failed to execute DNS spoofing mitigation: {e}")
            return MitigationResult(
                success=False,
                mitigation_id=mitigation_id,
                actions_taken=actions_taken,
                timestamp=datetime.now(),
                error_message=str(e)
            )
    
    def _check_rule_freshness(self, rule_key: str) -> Tuple[bool, bool]:
        """Check if rule exists and if it's still within TTL.
        
        Returns:
            (rule_exists, within_ttl): True if rule exists, True if within TTL window
        """
        if rule_key not in self.rule_timestamps:
            return False, False
        
        time_since_rule = (datetime.now() - self.rule_timestamps[rule_key]).total_seconds()
        within_ttl = time_since_rule < self.rule_ttl_seconds
        
        return True, within_ttl
    
    def _remove_dns_rules(self, dns_server_ip: str) -> bool:
        """Remove existing DNS rules after TTL expiry."""
        try:
            # Remove UDP rule
            iptables_udp_cmd = [
                "iptables", "-D", "INPUT",
                "-s", dns_server_ip,
                "-p", "udp", "--sport", "53",
                "-j", "DROP"
            ]
            logger.info(f"Removing expired UDP rule: {' '.join(iptables_udp_cmd)}")
            
            # Remove TCP rule
            iptables_tcp_cmd = [
                "iptables", "-D", "INPUT",
                "-s", dns_server_ip,
                "-p", "tcp", "--sport", "53",
                "-j", "DROP"
            ]
            logger.info(f"Removing expired TCP rule: {' '.join(iptables_tcp_cmd)}")
            
            return True
        except Exception as e:
            logger.error(f"Failed to remove DNS rules: {e}")
            return False
    
    def rollback(self, mitigation_id: str) -> bool:
        """Rollback firewall rule insertion."""
        try:
            # Find the DNS server IP associated with this mitigation
            dns_ip_to_unblock = None
            for dns_ip, mid in self.blocked_dns_servers.items():
                if mid == mitigation_id:
                    dns_ip_to_unblock = dns_ip
                    break
            
            if not dns_ip_to_unblock:
                logger.warning(f"No DNS server IP found for mitigation ID {mitigation_id}")
                return False
            
            # Remove iptables rules (UDP and TCP)
            iptables_udp_cmd = [
                "iptables", "-D", "INPUT",
                "-s", dns_ip_to_unblock,
                "-p", "udp", "--sport", "53",
                "-j", "DROP"
            ]
            
            iptables_tcp_cmd = [
                "iptables", "-D", "INPUT",
                "-s", dns_ip_to_unblock,
                "-p", "tcp", "--sport", "53",
                "-j", "DROP"
            ]
            
            logger.info(f"Rolling back iptables UDP command: {' '.join(iptables_udp_cmd)}")
            logger.info(f"Rolling back iptables TCP command: {' '.join(iptables_tcp_cmd)}")
            
            # Remove from blocked DNS servers
            del self.blocked_dns_servers[dns_ip_to_unblock]
            
            # Clean up TTL tracking
            rule_key = f"dns_spoofing_{dns_ip_to_unblock}"
            if rule_key in self.rule_timestamps:
                del self.rule_timestamps[rule_key]
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to rollback DNS spoofing mitigation: {e}")
            return False