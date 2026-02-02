#!/usr/bin/env python3
"""
Test the interface filtering logic directly.
"""

import psutil
import socket

def test_interface_logic():
    """Test the interface filtering logic."""
    print("🔍 Testing Interface Filtering Logic...")
    
    # Get system network interfaces
    network_stats = psutil.net_if_stats()
    network_addrs = psutil.net_if_addrs()
    
    def is_internet_capable_ip(ip_address):
        """Check if IP address is in a range that could have internet access."""
        if not ip_address:
            return False
        
        # Skip loopback and APIPA addresses
        if ip_address.startswith('127.') or ip_address.startswith('169.254.'):
            return False
        
        try:
            ip_parts = ip_address.split('.')
            if len(ip_parts) != 4:
                return False
            
            first_octet = int(ip_parts[0])
            second_octet = int(ip_parts[1])
            
            # Common internet-capable IP ranges:
            # Private: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
            # Public: 1-223 (excluding reserved ranges)
            if (first_octet == 10 or 
                (first_octet == 172 and 16 <= second_octet <= 31) or
                (first_octet == 192 and second_octet == 168) or
                (8 <= first_octet <= 223 and first_octet not in [127, 169])):
                return True
                
        except (ValueError, IndexError):
            pass
        
        return False
    
    interface_count = 0
    
    for iface_name in network_stats.keys():
        print(f"\n📡 Processing: {iface_name}")
        
        # Skip obvious virtual/loopback interfaces
        if any(skip in iface_name.lower() for skip in ['loopback', 'pseudo']):
            print(f"   ❌ Skipped: matches skip pattern")
            continue
        
        # Get interface statistics
        stats = network_stats.get(iface_name)
        addrs = network_addrs.get(iface_name, [])
        
        # Must be up
        if not (stats and stats.isup):
            print(f"   ❌ Skipped: interface is down")
            continue
        
        # Extract IP and MAC addresses
        ip_address = None
        mac_address = None
        
        for addr in addrs:
            if addr.family == socket.AF_INET:  # IPv4
                ip_address = addr.address
            elif addr.family == psutil.AF_LINK:  # MAC address
                mac_address = addr.address
        
        print(f"   IP: {ip_address}")
        print(f"   MAC: {mac_address}")
        
        # Must have internet-capable IP
        if not is_internet_capable_ip(ip_address):
            print(f"   ❌ Skipped: not internet-capable IP")
            continue
        
        print(f"   ✅ Would be included!")
        interface_count += 1
    
    print(f"\n🎉 Total interfaces that would be included: {interface_count}")

if __name__ == "__main__":
    test_interface_logic()