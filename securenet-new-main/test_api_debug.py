#!/usr/bin/env python3
"""
Debug API test with detailed output.
"""

import requests
import json
import psutil
import socket

def test_api_debug():
    """Test API with debug output."""
    print("🔍 Debug API Test...")
    
    # First, test the logic locally
    print("\n1. Testing logic locally...")
    network_stats = psutil.net_if_stats()
    network_addrs = psutil.net_if_addrs()
    
    def is_internet_capable_ip(ip_address):
        if not ip_address:
            return False
        if ip_address.startswith('127.') or ip_address.startswith('169.254.'):
            return False
        try:
            ip_parts = ip_address.split('.')
            if len(ip_parts) != 4:
                return False
            first_octet = int(ip_parts[0])
            second_octet = int(ip_parts[1])
            if (first_octet == 10 or 
                (first_octet == 172 and 16 <= second_octet <= 31) or
                (first_octet == 192 and second_octet == 168) or
                (8 <= first_octet <= 223 and first_octet not in [127, 169])):
                return True
        except (ValueError, IndexError):
            pass
        return False
    
    local_interfaces = []
    for iface_name in network_stats.keys():
        if any(skip in iface_name.lower() for skip in ['loopback', 'pseudo']):
            continue
        stats = network_stats.get(iface_name)
        addrs = network_addrs.get(iface_name, [])
        if not (stats and stats.isup):
            continue
        
        ip_address = None
        mac_address = None
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip_address = addr.address
            elif addr.family == psutil.AF_LINK:
                mac_address = addr.address
        
        if not is_internet_capable_ip(ip_address):
            continue
        
        local_interfaces.append({
            "name": iface_name,
            "ip": ip_address,
            "mac": mac_address
        })
    
    print(f"   Local logic found {len(local_interfaces)} interfaces:")
    for iface in local_interfaces:
        print(f"     - {iface['name']}: {iface['ip']}")
    
    # Now test the API
    print("\n2. Testing API...")
    base_url = "http://localhost:8000"
    
    # Login
    login_data = {"username": "admin", "password": "admin123"}
    response = requests.post(f"{base_url}/api/auth/login", json=login_data)
    if response.status_code != 200:
        print("❌ Login failed")
        return
    
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Get interfaces
    response = requests.get(f"{base_url}/api/network/interfaces", headers=headers)
    print(f"   API Status: {response.status_code}")
    print(f"   API Response: {response.text}")
    
    if response.status_code == 200:
        api_interfaces = response.json()["interfaces"]
        print(f"   API found {len(api_interfaces)} interfaces")
        for iface in api_interfaces:
            print(f"     - {iface['name']}: {iface['ip_address']}")

if __name__ == "__main__":
    test_api_debug()