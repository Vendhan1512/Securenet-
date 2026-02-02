#!/usr/bin/env python3
"""
Debug psutil interface names.
"""

import psutil
from scapy.interfaces import get_if_list

def debug_psutil_interfaces():
    """Debug what interface names psutil sees."""
    print("🔍 Debugging psutil interface names...")
    
    print("\n1. Scapy interfaces:")
    scapy_interfaces = get_if_list()
    for i, iface in enumerate(scapy_interfaces[:5]):
        print(f"   {i}: '{iface}'")
    
    print("\n2. psutil network stats keys:")
    network_stats = psutil.net_if_stats()
    for i, iface in enumerate(list(network_stats.keys())[:5]):
        print(f"   {i}: '{iface}'")
    
    print("\n3. psutil network addrs keys:")
    network_addrs = psutil.net_if_addrs()
    for i, iface in enumerate(list(network_addrs.keys())[:5]):
        print(f"   {i}: '{iface}'")
    
    # Check if they match
    scapy_set = set(scapy_interfaces)
    psutil_stats_set = set(network_stats.keys())
    psutil_addrs_set = set(network_addrs.keys())
    
    print(f"\n4. Interface name comparison:")
    print(f"   Scapy interfaces: {len(scapy_set)}")
    print(f"   psutil stats: {len(psutil_stats_set)}")
    print(f"   psutil addrs: {len(psutil_addrs_set)}")
    
    common_scapy_stats = scapy_set & psutil_stats_set
    print(f"   Common (scapy & stats): {len(common_scapy_stats)}")
    
    if common_scapy_stats:
        print("   Common interfaces:")
        for iface in list(common_scapy_stats)[:3]:
            print(f"     '{iface}'")

if __name__ == "__main__":
    debug_psutil_interfaces()