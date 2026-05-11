#!/usr/bin/env python3
"""Test Kerberos client login flow."""

import requests

def test_login():
    print("Testing Kerberos Client Login...")
    print("="*60)
    
    # Test login with form data
    url = "http://localhost:9884/api/login"
    data = {
        "username": "CLIENT_1",
        "password": "password"
    }
    
    print("POST " + url)
    print("Data: " + str(data))
    print()
    
    try:
        response = requests.post(url, data=data)
        print("Response Status: " + str(response.status_code))
        print("Response Headers: " + str(dict(response.headers)))
        print("Response Body: " + response.text)
        
        if response.status_code == 200:
            print("\nLogin successful!")
            result = response.json()
            print("Session ID: " + str(result.get('session_id')))
            print("State: " + str(result.get('state')))
        else:
            print("\nLogin failed with status " + str(response.status_code))
            
    except requests.exceptions.RequestException as e:
        print("Request failed: " + str(e))
    
    # Test state endpoint
    print("\n" + "="*60)
    print("Testing /api/state endpoint...")
    
    try:
        response = requests.get("http://localhost:9884/api/state")
        print("Response Status: " + str(response.status_code))
        print("Response Body: " + response.text)
    except requests.exceptions.RequestException as e:
        print("Request failed: " + str(e))

if __name__ == "__main__":
    test_login()
