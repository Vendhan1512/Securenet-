#!/usr/bin/env python3
"""
Debug interface name handling.
"""

import requests
import json
from urllib.parse import quote, unquote

def debug_interface_names():
    """Debug interface name encoding/decoding."""
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
    if response.status_code != 200:
        print("❌ Failed to get interfaces")
        return
    
    interfaces = response.json()["interfaces"]
    if not interfaces:
        print("❌ No interfaces found")
        return
    
    test_interface = interfaces[0]['name']
    print(f"Original interface name: {test_interface}")
    print(f"URL encoded: {quote(test_interface)}")
    print(f"URL decoded: {unquote(quote(test_interface))}")
    
    # Test health endpoint with different encodings
    encodings = [
        ("Raw", test_interface),
        ("URL encoded", quote(test_interface)),
        ("Double encoded", quote(quote(test_interface))),
    ]
    
    for name, encoded_name in encodings:
        url = f"{base_url}/api/network/interfaces/{encoded_name}/health"
        print(f"\nTesting {name}: {url}")
        response = requests.get(url, headers=headers)
        print(f"Status: {response.status_code}")
        if response.status_code != 200:
            print(f"Error: {response.text}")

if __name__ == "__main__":
    debug_interface_names()