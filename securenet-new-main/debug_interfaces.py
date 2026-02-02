#!/usr/bin/env python3
"""
Debug interface detection to see what's being filtered out.
"""

import psutil
import socket

def debug_interfaces():
    """Debug interface detection."""
    print("🔍 Debugging Interface Detection...")
    
    # Get system network interfaces
    network_stats = psutil.net_if_stats()
    network_addrs = psutil.net_if_addrs()
    
    print(f"\nFound {len(network_stats)} total interfaces:")
    
    for iface_name in network_stats.keys():
        print(f"\n📡 Interface: {iface_name}")
        
        # Check if it would be skipped by our filters
        skip_reasons = []
        
        # Check skip patterns
        skip_patterns = ['loopback', 'pseudo', 'docker', 'veth', 'br-', 'vmware', 'virtualbox', 'hyper-v']
        for pattern in skip_patterns:
            if pattern in iface_name.lower():
                skip_reasons.append(f"matches skip pattern: {pattern}")
        
        # Get interface details
        stats = network_stats.get(iface_name)
        addrs = network_addrs.get(iface_name, [])
        
        ip_address = None
        mac_address = None
        
        for addr in addrs:
            if addr.family == socket.AF_INET:  # IPv4
                ip_address = addr.address
            elif addr.family == psutil.AF_LINK:  # MAC address
                mac_address = addr.address
        
        print(f"   IP: {ip_address or 'None'}")
        print(f"   MAC: {mac_address or 'None'}")
        print(f"   Up: {stats.isup if stats else False}")
        
        # Check IP filtering
        if not ip_address:
            skip_reasons.append("no IP address")
        elif ip_address.startswith('127.'):
            skip_reasons.append("loopback IP")
        elif ip_address.startswith('169.254.'):
            skip_reasons.append("APIPA IP")
        
        # Check if interface is up
        if not (stats and stats.isup):
            skip_reasons.append("interface is down")
        
        # Check IP range validity
        if ip_address:
            ip_parts = ip_address.split('.')
            if len(ip_parts) == 4:
                try:
                    first_octet = int(ip_parts[0])
                    second_octet = int(ip_parts[1])
                    
                    valid_ip = False
                    if (first_octet == 10 or 
                        (first_octet == 172 and 16 <= second_octet <= 31) or
                        (first_octet == 192 and second_octet == 168) or
                        (1 <= first_octet <= 223 and first_octet not in [127, 169, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239])):
                        valid_ip = True
                    
                    if not valid_ip:
                        skip_reasons.append("invalid IP range")
                    else:
                        print(f"   ✅ Valid IP range")
                        
                except ValueError:
                    skip_reasons.append("invalid IP format")
        
        if skip_reasons:
            print(f"   ❌ Would be skipped: {', '.join(skip_reasons)}")
        else:
            print(f"   ✅ Would be included")

if __name__ == "__main__":
    debug_interfaces()