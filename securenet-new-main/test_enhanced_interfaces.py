#!/usr/bin/env python3
"""
Test script for the enhanced network interface functionality.
"""

import requests
import json

def test_enhanced_interfaces():
    """Test the enhanced network interface detection."""
    base_url = "http://localhost:8000"
    
    print("🔍 Testing Enhanced Network Interface Detection...")
    
    # Login first
    login_data = {"username": "admin", "password": "admin123"}
    response = requests.post(f"{base_url}/api/auth/login", json=login_data)
    if response.status_code != 200:
        print("❌ Login failed")
        return False
    
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test enhanced interface detection
    print("\n1. Testing enhanced interface detection...")
    response = requests.get(f"{base_url}/api/network/interfaces", headers=headers)
    if response.status_code == 200:
        interfaces = response.json()["interfaces"]
        print(f"✅ Found {len(interfaces)} network interfaces")
        
        for iface in interfaces[:3]:  # Show first 3 interfaces
            print(f"   📡 {iface['name']}")
            print(f"      Status: {iface['status']}")
            print(f"      IP: {iface['ip_address'] or 'Not assigned'}")
            print(f"      MAC: {iface['mac_address'] or 'Unknown'}")
            print(f"      Speed: {iface['speed']} Mbps" if iface['speed'] > 0 else "      Speed: Unknown")
            print(f"      Traffic: ↑{format_bytes(iface['bytes_sent'])} ↓{format_bytes(iface['bytes_recv'])}")
            print()
    else:
        print("❌ Interface detection failed")
        return False
    
    # Test interface health monitoring
    if interfaces:
        print("2. Testing interface health monitoring...")
        test_interface = interfaces[0]['name']
        response = requests.get(f"{base_url}/api/network/interfaces/{test_interface}/health", headers=headers)
        if response.status_code == 200:
            health = response.json()
            print(f"✅ Health check for {test_interface}:")
            print(f"   Healthy: {health['is_healthy']}")
            print(f"   Issues: {len(health.get('issues', []))}")
            if health.get('issues'):
                for issue in health['issues']:
                    print(f"     - {issue}")
        else:
            print("❌ Health monitoring failed")
            return False
    
    print("\n🎉 Enhanced interface detection working perfectly!")
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
    test_enhanced_interfaces()