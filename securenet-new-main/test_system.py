#!/usr/bin/env python3
"""
Quick test script to verify the LAN Security System API is working correctly.
"""

import requests
import json

def test_api():
    """Test the main API endpoints."""
    base_url = "http://localhost:8000"
    
    print("🔍 Testing LAN Security System API...")
    
    # Test health endpoint
    try:
        response = requests.get(f"{base_url}/health")
        if response.status_code == 200:
            print("✅ Health check: PASSED")
            print(f"   Response: {response.json()}")
        else:
            print("❌ Health check: FAILED")
            return False
    except Exception as e:
        print(f"❌ Health check: ERROR - {e}")
        return False
    
    # Test authentication
    try:
        login_data = {"username": "admin", "password": "admin123"}
        response = requests.post(f"{base_url}/api/auth/login", json=login_data)
        if response.status_code == 200:
            print("✅ Authentication: PASSED")
            tokens = response.json()
            access_token = tokens["access_token"]
        else:
            print("❌ Authentication: FAILED")
            return False
    except Exception as e:
        print(f"❌ Authentication: ERROR - {e}")
        return False
    
    # Test protected endpoint
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(f"{base_url}/api/system/status", headers=headers)
        if response.status_code == 200:
            print("✅ System Status: PASSED")
            status = response.json()
            print(f"   System State: {status['system_state']}")
            print(f"   Deployment Mode: {status['deployment_mode']}")
            print(f"   Monitoring Active: {status['monitoring_active']}")
        else:
            print("❌ System Status: FAILED")
            return False
    except Exception as e:
        print(f"❌ System Status: ERROR - {e}")
        return False
    
    # Test metrics endpoint
    try:
        response = requests.get(f"{base_url}/api/system/metrics", headers=headers)
        if response.status_code == 200:
            print("✅ Security Metrics: PASSED")
            metrics = response.json()
            print(f"   Threats Detected: {metrics['total_threats_detected']}")
            print(f"   Successful Mitigations: {metrics['successful_mitigations']}")
            print(f"   Detection Accuracy: {metrics['detection_accuracy']:.1f}%")
        else:
            print("❌ Security Metrics: FAILED")
            return False
    except Exception as e:
        print(f"❌ Security Metrics: ERROR - {e}")
        return False
    
    print("\n🎉 All API tests PASSED! The LAN Security System is working correctly.")
    return True

if __name__ == "__main__":
    test_api()