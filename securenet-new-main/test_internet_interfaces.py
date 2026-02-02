#!/usr/bin/env python3
"""
Test script for internet-connected interface detection.
"""

import requests
import json

def test_internet_interfaces():
    """Test the internet-connected interface detection."""
    base_url = "http://localhost:8000"
    
    print("🌐 Testing Internet-Connected Interface Detection...")
    
    # Login first
    login_data = {"username": "admin", "password": "admin123"}
    response = requests.post(f"{base_url}/api/auth/login", json=login_data)
    if response.status_code != 200:
        print("❌ Login failed")
        return False
    
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test internet-connected interface detection
    print("\n1. Testing internet-connected interface detection...")
    response = requests.get(f"{base_url}/api/network/interfaces", headers=headers)
    if response.status_code == 200:
        interfaces = response.json()["interfaces"]
        print(f"✅ Found {len(interfaces)} internet-connected interfaces")
        
        if len(interfaces) == 0:
            print("   📡 No internet-connected interfaces detected")
            print("   This could mean:")
            print("   - No active internet connection")
            print("   - All interfaces are virtual/loopback")
            print("   - Connectivity check failed")
        else:
            for i, iface in enumerate(interfaces):
                print(f"\n   📡 Interface {i+1}: {iface['name']}")
                print(f"      Status: {iface['status']}")
                print(f"      IP: {iface['ip_address']}")
                print(f"      MAC: {iface['mac_address'] or 'Unknown'}")
                print(f"      Device: {iface.get('device_name', 'Not mapped')}")
                print(f"      Speed: {iface['speed']} Mbps" if iface['speed'] > 0 else "      Speed: Unknown")
                print(f"      Traffic: ↑{format_bytes(iface['bytes_sent'])} ↓{format_bytes(iface['bytes_recv'])}")
                
                # Test health monitoring for internet interfaces
                if iface.get('device_name'):
                    health_response = requests.get(f"{base_url}/api/network/interfaces/{requests.utils.quote(iface['name'], safe='')}/health", headers=headers)
                    if health_response.status_code == 200:
                        health = health_response.json()
                        print(f"      Health: {'✅ Healthy' if health['is_healthy'] else '❌ Issues'}")
                        if health.get('issues'):
                            for issue in health['issues']:
                                print(f"        - {issue}")
    else:
        print(f"❌ Interface detection failed: {response.status_code}")
        print(f"   Error: {response.text}")
        return False
    
    # Test monitoring with internet interface
    if interfaces:
        print(f"\n2. Testing monitoring with internet-connected interface...")
        test_interface = interfaces[0]
        print(f"   Using interface: {test_interface['name']}")
        
        monitoring_data = {"interface": test_interface['name']}
        response = requests.post(f"{base_url}/api/system/start-monitoring", json=monitoring_data, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ {result['message']}")
            
            # Stop monitoring
            stop_response = requests.post(f"{base_url}/api/system/stop-monitoring", headers=headers)
            if stop_response.status_code == 200:
                print(f"   ✅ Monitoring stopped successfully")
        else:
            print(f"   ❌ Monitoring failed: {response.text}")
    
    print(f"\n🎉 Internet-connected interface detection complete!")
    return True

def format_bytes(bytes_val):
    """Format bytes in human readable format."""
    if bytes_val == 0:
        return "0 B"
    
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.1f} TB"

if __name__ == "__main__":
    test_internet_interfaces()