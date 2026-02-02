"""Infrastructure detection for network security system."""

import netifaces
from typing import Set, Optional
import logging

logger = logging.getLogger(__name__)

_infrastructure_detector_instance: Optional['InfrastructureDetector'] = None


def get_infrastructure_detector() -> 'InfrastructureDetector':
    """Get singleton instance of infrastructure detector."""
    global _infrastructure_detector_instance
    if _infrastructure_detector_instance is None:
        _infrastructure_detector_instance = InfrastructureDetector()
    return _infrastructure_detector_instance


class InfrastructureDetector:
    """Detects and manages network infrastructure information."""
    
    def __init__(self):
        """Initialize infrastructure detector."""
        self.gateway_ip: Optional[str] = None
        self.dns_servers: Set[str] = set()
        self._detect_infrastructure()
    
    def _detect_infrastructure(self):
        """Detect network infrastructure (gateway and DNS servers)."""
        try:
            # Detect gateway
            gws = netifaces.gateways()
            default_gw = gws.get('default', {}).get(netifaces.AF_INET)
            if default_gw:
                self.gateway_ip = default_gw[0]
                logger.info(f"Detected gateway: {self.gateway_ip}")
            
            # Common DNS servers (fallback)
            self.dns_servers = {'8.8.8.8', '8.8.4.4'}
            
            # Try to detect from resolv.conf
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            dns = line.split()[1].strip()
                            self.dns_servers.add(dns)
            except Exception as e:
                logger.debug(f"Could not read resolv.conf: {e}")
            
            # Add gateway as potential DNS server
            if self.gateway_ip:
                self.dns_servers.add(self.gateway_ip)
            
            logger.info(f"Infrastructure detection complete: gateway={self.gateway_ip}, dns={self.dns_servers}")
            
        except Exception as e:
            logger.error(f"Error detecting infrastructure: {e}")
            # Set defaults
            self.gateway_ip = "192.168.1.1"
            self.dns_servers = {'8.8.8.8', '8.8.4.4', '192.168.1.1'}
    
    def get_gateway(self) -> Optional[str]:
        """Get detected gateway IP."""
        return self.gateway_ip
    
    def get_dns_servers(self) -> Set[str]:
        """Get detected DNS servers."""
        return self.dns_servers
    
    def is_gateway(self, ip: str) -> bool:
        """Check if IP is the gateway."""
        return ip == self.gateway_ip
    
    def is_dns_server(self, ip: str) -> bool:
        """Check if IP is a known DNS server."""
        return ip in self.dns_servers
    
    def is_infrastructure(self, ip: str, mac: str = None) -> tuple:
        """Check if IP is part of infrastructure (gateway or DNS server).
        
        Args:
            ip: IP address to check
            mac: MAC address (optional, for logging)
            
        Returns:
            (is_infrastructure: bool, reason: str)
        """
        if self.is_gateway(ip):
            return True, f"Gateway IP {ip}"
        if self.is_dns_server(ip):
            return True, f"DNS server {ip}"
        return False, f"Non-infrastructure IP {ip}"
