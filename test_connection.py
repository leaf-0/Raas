#!/usr/bin/env python3
"""
Connection Test Script for FME-ABT Backend
Tests all API endpoints that FME Sentinel Watch expects
"""

import requests
import json
import time
from datetime import datetime

# Backend URL
BASE_URL = "http://127.0.0.1:5000"

def test_endpoint(endpoint, method="GET", data=None):
    """Test a single API endpoint"""
    url = f"{BASE_URL}{endpoint}"
    
    try:
        if method == "GET":
            response = requests.get(url, timeout=5)
        elif method == "POST":
            response = requests.post(url, json=data, timeout=5)
        
        print(f"✓ {method} {endpoint}: {response.status_code}")
        
        if response.status_code == 200:
            try:
                data = response.json()
                print(f"  Response: {json.dumps(data, indent=2)[:200]}...")
            except:
                print(f"  Response: {response.text[:100]}...")
        else:
            print(f"  Error: {response.text}")
            
        return response.status_code == 200
        
    except requests.exceptions.ConnectionError:
        print(f"✗ {method} {endpoint}: Connection refused - Backend not running")
        return False
    except Exception as e:
        print(f"✗ {method} {endpoint}: {str(e)}")
        return False

def main():
    """Test all FME Sentinel Watch API endpoints"""
    print("="*60)
    print("FME-ABT Backend Connection Test")
    print("="*60)
    
    # Test endpoints that FME Sentinel Watch expects
    endpoints = [
        ("/api/alerts", "GET"),
        ("/api/status", "GET"),
        ("/api/memory", "GET"),
        ("/api/mitigation", "POST", {"enabled": True}),
        ("/api/mitigation", "POST", {"enabled": False}),
    ]
    
    # Additional dashboard endpoints
    dashboard_endpoints = [
        ("/api/events", "GET"),
        ("/api/metrics", "GET"),
        ("/api/config", "GET"),
    ]
    
    print("\n1. Testing FME Sentinel Watch Endpoints:")
    print("-" * 40)
    
    success_count = 0
    for endpoint_data in endpoints:
        if len(endpoint_data) == 3:
            endpoint, method, data = endpoint_data
        else:
            endpoint, method = endpoint_data
            data = None
            
        if test_endpoint(endpoint, method, data):
            success_count += 1
        print()
    
    print(f"\nFME Sentinel Watch Endpoints: {success_count}/{len(endpoints)} working")
    
    print("\n2. Testing Dashboard Endpoints:")
    print("-" * 40)
    
    dashboard_success = 0
    for endpoint, method in dashboard_endpoints:
        if test_endpoint(endpoint, method):
            dashboard_success += 1
        print()
    
    print(f"\nDashboard Endpoints: {dashboard_success}/{len(dashboard_endpoints)} working")
    
    # Test CORS headers
    print("\n3. Testing CORS Headers:")
    print("-" * 40)
    
    try:
        response = requests.options(f"{BASE_URL}/api/alerts", headers={
            'Origin': 'http://localhost:5173',
            'Access-Control-Request-Method': 'GET'
        })
        
        if 'Access-Control-Allow-Origin' in response.headers:
            print("✓ CORS headers present")
        else:
            print("✗ CORS headers missing")
            
    except Exception as e:
        print(f"✗ CORS test failed: {e}")
    
    print("\n" + "="*60)
    total_success = success_count + dashboard_success
    total_endpoints = len(endpoints) + len(dashboard_endpoints)
    
    if total_success == total_endpoints:
        print("🎉 All endpoints working! Backend is ready for FME Sentinel Watch")
    else:
        print(f"⚠️  {total_endpoints - total_success} endpoints need attention")
        print("\nTo start the backend:")
        print("1. Install dependencies: pip install -r requirements.txt")
        print("2. Run the backend: python app.py")
    
    print("="*60)

if __name__ == "__main__":
    main()
