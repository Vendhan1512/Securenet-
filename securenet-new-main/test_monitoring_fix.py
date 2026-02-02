#!/usr/bin/env python3
"""
Test script for the monitoring functionality fix.
"""

import requests
import json

def test_monitoring_functionality():
    """Test the monitoring functionality with interface name mapping."""
    base_url = "http://localhost:8000"
    
    print("🔧 Testing Monitoring Functionality Fix...")
    
    # Login first
    login_data = {"username": "admin", "password": "admin123"}
    response = requests.post(f"{base_url}/api/auth/login", json=login_data)
    if response.status_code != 200:
        print("❌ Login failed")
        return False
    
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Get interfaces with device mapping
    print("\n1. Testing interface detection with device mapping...")
    response = requests.get(f"{base_url}/api/network/interfaces", headers=headers)
    if response.status_code == 200:
        interfaces = response.json()["interfaces"]
        print(f"✅ Found {len(interfaces)} network interfaces")
        
        # Show interface mapping
        for iface in interfaces[:3]:
            print(f"   📡 {iface['name']}")
            print(f"      Device Name: {iface.get('device_name', 'Not mapped')}")
            print(f"      Status: {iface['status']}")
            print(f"      MAC: {iface['mac_address'] or 'Unknown'}")
            print()
    else:
        print("❌ Interface detection failed")
        return False
    
    # Test monitoring start with a mapped interface
    print("2. Testing monitoring start with interface mapping...")
    
    # Find an interface that has a device mapping
    test_interface = None
    for iface in interfaces:
        if iface.get('device_name') and iface['status'] != 'down':
            test_interface = iface
            break
    
    if not test_interface:
        # Try with any interface
        test_interface = interfaces[0] if interfaces else None
    
    if test_interface:
        print(f"   Testing with interface: {test_interface['name']}")
        print(f"   Device name: {test_interface.get('device_name', 'Not mapped')}")
        
        monitoring_data = {"interface": test_interface['name']}
        response = requests.post(f"{base_url}/api/system/start-monitoring", json=monitoring_data, headers=headers)
        
        print(f"   Response status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ {result['message']}")
        else:
            print(f"   ❌ Error: {response.text}")
            
        # Test stop monitoring
        print("\n3. Testing monitoring stop...")
        response = requests.post(f"{base_url}/api/system/stop-monitoring", headers=headers)
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ {result['message']}")
        else:
            print(f"   ❌ Stop failed: {response.text}")
    else:
        print("   ❌ No suitable interface found for testing")
    
    # Test system status
    print("\n4. Testing system status...")
    response = requests.get(f"{base_url}/api/system/status", headers=headers)
    if response.status_code == 200:
        status = response.json()
        print(f"   ✅ System State: {status['system_state']}")
        print(f"   ✅ Monitoring Active: {status['monitoring_active']}")
    else:
        print(f"   ❌ Status check failed: {response.text}")
    
    return True

if __name__ == "__main__":
    test_monitoring_functionality()