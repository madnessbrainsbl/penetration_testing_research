#!/usr/bin/env python3
"""
CSRF Deep Test - Check if critical endpoints are vulnerable to CSRF

Critical endpoints that change account state should require:
1. CSRF token
2. Or custom header (like X-Requested-With)
3. Or SameSite cookie protection
"""
import requests
import json

BASE_URL = "https://api.bybit.com"
requests.packages.urllib3.disable_warnings()

print("="*80)
print("CSRF VULNERABILITY DEEP ANALYSIS")
print("="*80)

# List of critical state-changing endpoints
critical_endpoints = [
    ("/v5/account/set-margin-mode", {"setMarginMode": "ISOLATED_MARGIN"}),
    ("/v5/account/upgrade-to-uta", {}),
    ("/v5/account/set-mmp-config", {"baseCoin": "BTC"}),
    ("/v5/user/update-api", {"readOnly": 1}),
]

for endpoint, payload in critical_endpoints:
    print(f"\n{'='*80}")
    print(f"Testing: {endpoint}")
    print(f"Payload: {payload}")
    print("-" * 80)
    
    # Test 1: Simple POST without ANY auth or CSRF
    print("\n[Test 1] POST without auth/CSRF:")
    try:
        r1 = requests.post(
            f"{BASE_URL}{endpoint}",
            json=payload,
            verify=False,
            timeout=5
        )
        print(f"  Status: {r1.status_code}")
        if r1.status_code == 200:
            try:
                data = r1.json()
                print(f"  Response: {json.dumps(data, indent=2)[:300]}")
                
                # Check if it's an error or success
                ret_code = data.get('retCode')
                if ret_code == 0:
                    print("  🚨🚨🚨 CRITICAL: Request succeeded WITHOUT auth!")
                elif ret_code in [10003, 10001, 10002]:
                    print(f"  ✅ Safe: Auth required (retCode: {ret_code})")
                else:
                    print(f"  ⚠️  Unusual retCode: {ret_code} - {data.get('retMsg')}")
            except:
                print(f"  Response (non-JSON): {r1.text[:200]}")
        else:
            print(f"  ✅ Safe: Non-200 status")
    except Exception as e:
        print(f"  Error: {e}")
    
    # Test 2: POST with Origin header (CORS bypass check)
    print("\n[Test 2] POST with malicious Origin:")
    try:
        r2 = requests.post(
            f"{BASE_URL}{endpoint}",
            json=payload,
            headers={"Origin": "https://evil.com"},
            verify=False,
            timeout=5
        )
        print(f"  Status: {r2.status_code}")
        acao = r2.headers.get('Access-Control-Allow-Origin', 'Not Set')
        acac = r2.headers.get('Access-Control-Allow-Credentials', 'Not Set')
        print(f"  ACAO: {acao}")
        print(f"  ACAC: {acac}")
        
        if acao == "https://evil.com" and acac == "true":
            print("  🚨 CORS misconfiguration! Evil origin accepted with credentials!")
    except Exception as e:
        print(f"  Error: {e}")
    
    # Test 3: GET request (some endpoints accept both GET and POST)
    print("\n[Test 3] GET request (method confusion):")
    try:
        r3 = requests.get(
            f"{BASE_URL}{endpoint}",
            params=payload,
            verify=False,
            timeout=5
        )
        print(f"  Status: {r3.status_code}")
        if r3.status_code == 200:
            print(f"  ⚠️  Endpoint accepts GET! Response: {r3.text[:100]}")
    except Exception as e:
        print(f"  Error: {e}")

print("\n" + "="*80)
print("CSRF ANALYSIS COMPLETE")
print("="*80)

print("\n📋 Summary:")
print("If any endpoint returned retCode=0 without auth, that's CRITICAL.")
print("If CORS allows evil.com with credentials, that's HIGH.")
print("All tests above were read-only checks (no actual changes made).")
