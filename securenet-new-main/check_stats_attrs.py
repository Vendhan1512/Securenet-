#!/usr/bin/env python3
"""
Check what attributes are available on psutil network stats.
"""

import psutil

def check_stats_attrs():
    """Check network stats attributes."""
    network_stats = psutil.net_if_stats()
    
    for iface_name, stats in network_stats.items():
        if iface_name == "Wi-Fi":  # Check the Wi-Fi interface
            print(f"Interface: {iface_name}")
            print(f"Stats object type: {type(stats)}")
            print(f"Available attributes: {dir(stats)}")
            print(f"Stats: {stats}")
            break

if __name__ == "__main__":
    check_stats_attrs()