#!/usr/bin/env python3
"""
Complete system test for the enhanced LAN Security System.
"""

import requests
import json
import time

def test_complete_system():
    """Test the complete enhanced system functionality."""
    base_url = "http://localhost:8000"
    
    print("🚀 Testing Complete Enhanced LAN Security System...")
    
    # 1. Authentication Test
    print("\n1. 🔐 Testing Authentication...")
    login_data = {"username": "admin", "password": "admin123"}
    response = requests.post(f"{base_url}/api/auth/login", json=login_data)
    if response.status_code != 200:
        print("❌ Authentication failed")
        return False
    
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("✅ Authentication successful")
    
    # 2. System Status Test
    print("\n2. 📊 Testing System Status...")
    response = requests.get(f"{base_url}/api/system/status", headers=headers)
    if response.status_code == 200:
        status = response.json()
        print(f"✅ System State: {status['system_state']}")
        print(f"✅ Deployment Mode: {status['deployment_mode']}")
        print(f"✅ Monitoring Active: {status['monitoring_active']}")
        print(f"✅ Uptime: {status['uptime_formatted']}")
    else:
        print("❌ System status failed")
        return False
    
    # 3. Security Metrics Test
    print("\n3. 📈 Testing Security Metrics...")
    response = requests.get(f"{base_url}/api/system/metrics", headers=headers)
    if response.status_code == 200:
        metrics = response.json()
        print(f"✅ Threats Detected: {metrics['total_threats_detected']}")
        print(f"✅ Successful Mitigations: {metrics['successful_mitigations']}")
        print(f"✅ Detection Accuracy: {metrics['detection_accuracy']:.1f}%")
        print(f"✅ Response Time: {metrics['average_response_time_ms']:.0f}ms")
    else:
        print("❌ Security metrics failed")
        return False
    
    # 4. Enhanced Network Interface Detection Test
    print("\n4. 🌐 Testing Enhanced Network Interface Detection...")
    response = requests.get(f"{base_url}/api/network/interfaces", headers=headers)
    if response.status_code == 200:
        interfaces = response.json()["interfaces"]
        print(f"✅ Found {len(interfaces)} network interfaces")
        
        active_interfaces = [i for i in interfaces if i['status'] == 'active']
        up_interfaces = [i for i in interfaces if i['status'] == 'up']
        down_interfaces = [i for i in interfaces if i['status'] == 'down']
        
        print(f"   📡 Active: {len(active_interfaces)}")
        print(f"   📡 Up: {len(up_interfaces)}")
        print(f"   📡 Down: {len(down_interfaces)}")
        
        # Show details for first few interfaces
        for i, iface in enumerate(interfaces[:3]):
            print(f"   Interface {i+1}: {iface['name']}")
            print(f"     Status: {iface['status']}")
            print(f"     IP: {iface['ip_address'] or 'Not assigned'}")
            print(f"     MAC: {iface['mac_address'] or 'Unknown'}")
            print(f"     Speed: {iface['speed']} Mbps" if iface['speed'] > 0 else "     Speed: Unknown")
            print(f"     Traffic: ↑{format_bytes(iface['bytes_sent'])} ↓{format_bytes(iface['bytes_recv'])}")
    else:
        print("❌ Interface detection failed")
        return False
    
    # 5. Interface Health Monitoring Test
    print("\n5. 🏥 Testing Interface Health Monitoring...")
    if interfaces:
        test_interface = interfaces[0]['name']
        response = requests.get(f"{base_url}/api/network/interfaces/{requests.utils.quote(test_interface, safe='')}/health", headers=headers)
        if response.status_code == 200:
            health = response.json()
            print(f"✅ Health check for '{test_interface}':")
            print(f"   Healthy: {health['is_healthy']}")
            print(f"   Current Speed: {health['current_speed']} Mbps")
            print(f"   Issues: {len(health.get('issues', []))}")
            if health.get('issues'):
                for issue in health['issues']:
                    print(f"     - {issue}")
        else:
            print(f"❌ Health monitoring failed for {test_interface}")
            return False
    
    # 6. Security Alerts Test
    print("\n6. 🚨 Testing Security Alerts...")
    response = requests.get(f"{base_url}/api/security/alerts", headers=headers)
    if response.status_code == 200:
        alerts_data = response.json()
        print(f"✅ Retrieved {len(alerts_data['alerts'])} security alerts")
        print(f"   Total alerts: {alerts_data['total']}")
    else:
        print("❌ Security alerts failed")
        return False
    
    # 7. Mitigation Actions Test
    print("\n7. 🛡️ Testing Mitigation Actions...")
    response = requests.get(f"{base_url}/api/security/mitigations", headers=headers)
    if response.status_code == 200:
        mitigations_data = response.json()
        print(f"✅ Retrieved {len(mitigations_data['mitigations'])} mitigation actions")
        print(f"   Total mitigations: {mitigations_data['total']}")
    else:
        print("❌ Mitigation actions failed")
        return False
    
    # 8. Configuration Test
    print("\n8. ⚙️ Testing Configuration Management...")
    response = requests.get(f"{base_url}/api/config", headers=headers)
    if response.status_code == 200:
        config = response.json()["configuration"]
        print("✅ Configuration retrieved successfully")
        print(f"   Detection settings: {len(config['detection'])} parameters")
        print(f"   Performance settings: {len(config['performance'])} parameters")
        print(f"   Logging settings: {len(config['logging'])} parameters")
    else:
        print("❌ Configuration failed")
        return False
    
    # 9. Health Check Test
    print("\n9. ❤️ Testing System Health...")
    response = requests.get(f"{base_url}/health")
    if response.status_code == 200:
        health = response.json()
        print(f"✅ System health: {health['status']}")
        print(f"   Version: {health['version']}")
    else:
        print("❌ Health check failed")
        return False
    
    print("\n🎉 All Enhanced System Tests Passed Successfully!")
    print("\n📋 System Summary:")
    print(f"   • Authentication: Working")
    print(f"   • System Status: Working")
    print(f"   • Security Metrics: Working")
    print(f"   • Network Interface Detection: Enhanced & Working")
    print(f"   • Interface Health Monitoring: Working")
    print(f"   • Security Alerts: Working")
    print(f"   • Mitigation Actions: Working")
    print(f"   • Configuration Management: Working")
    print(f"   • System Health: Working")
    
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
    test_complete_system()