#!/usr/bin/env python3
"""
Direct API test to see the raw response.
"""

import requests
import json

def test_direct_api():
    """Test direct API call."""
    base_url = "http://localhost:8000"
    
    # Login first
    login_data = {"username": "admin", "password": "admin123"}
    response = requests.post(f"{base_url}/api/auth/login", json=login_data)
    if response.status_code != 200:
        print("❌ Login failed")
        return
    
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Get interfaces
    response = requests.get(f"{base_url}/api/network/interfaces", headers=headers)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")

if __name__ == "__main__":
    test_direct_api()