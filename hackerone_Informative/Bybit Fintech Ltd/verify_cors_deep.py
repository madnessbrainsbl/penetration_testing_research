#!/usr/bin/env python3
"""
Deep CORS verification - checking if it's REALLY exploitable
"""
import requests
import json

BASE_URL = "https://api.bybit.com"
requests.packages.urllib3.disable_warnings()

print("="*80)
print("DEEP CORS VERIFICATION")
print("="*80)

# Test different scenarios
test_cases = [
    {
        "name": "Test 1: Reflect arbitrary origin",
        "origin": "https://totally-evil-site.com",
        "url": "/v5/market/time"
    },
    {
        "name": "Test 2: Null origin",
        "origin": "null",
        "url": "/v5/market/time"
    },
    {
        "name": "Test 3: File protocol",
        "origin": "file://",
        "url": "/v5/market/time"
    },
    {
        "name": "Test 4: Authenticated endpoint",
        "origin": "https://attacker.com",
        "url": "/v5/account/wallet-balance?accountType=UNIFIED"
    }
]

print("\n[1] Testing Origin Reflection")
print("-" * 80)

reflects_origin = False
allows_credentials = False

for test in test_cases:
    print(f"\n{test['name']}")
    print(f"  Origin: {test['origin']}")
    print(f"  URL: {test['url']}")
    
    try:
        r = requests.get(
            f"{BASE_URL}{test['url']}",
            headers={"Origin": test['origin']},
            verify=False,
            timeout=5
        )
        
        acao = r.headers.get('Access-Control-Allow-Origin', '')
        acac = r.headers.get('Access-Control-Allow-Credentials', '')
        
        print(f"  ACAO: {acao}")
        print(f"  ACAC: {acac}")
        
        if acao == test['origin']:
            print(f"  ⚠️  Origin is REFLECTED!")
            reflects_origin = True
            
        if acac == 'true':
            print(f"  ⚠️  Credentials are ALLOWED!")
            allows_credentials = True
            
    except Exception as e:
        print(f"  Error: {e}")

# Check for preflight
print("\n\n[2] Testing Preflight (OPTIONS)")
print("-" * 80)

try:
    r = requests.options(
        f"{BASE_URL}/v5/account/wallet-balance",
        headers={
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "content-type"
        },
        verify=False
    )
    
    print(f"Preflight Status: {r.status_code}")
    print(f"ACAO: {r.headers.get('Access-Control-Allow-Origin', 'Not Set')}")
    print(f"ACAC: {r.headers.get('Access-Control-Allow-Credentials', 'Not Set')}")
    print(f"ACAM: {r.headers.get('Access-Control-Allow-Methods', 'Not Set')}")
    
except Exception as e:
    print(f"Preflight error: {e}")

# Final analysis
print("\n\n[3] EXPLOITATION ANALYSIS")
print("=" * 80)

if reflects_origin and allows_credentials:
    print("⚠️⚠️⚠️ HEADERS SUGGEST VULNERABILITY")
    print("\nHowever, to confirm it's EXPLOITABLE, we need to check:")
    print("1. ✓ CORS headers present (CONFIRMED)")
    print("2. ? Browser allows reading response in JavaScript")
    print("3. ? Authentication works via cookies/headers that are sent")
    print("4. ? Sensitive data is actually returned")
    print("\n⚡ NEXT STEP: Open test_cors_real.html in browser while logged into Bybit")
    print("   If JavaScript can read wallet balance, then it's REAL.")
    print("   If browser blocks it, then it's FALSE POSITIVE.")
    
else:
    print("✅ No obvious CORS misconfiguration")

print("\n" + "="*80)
print("IMPORTANT: CORS headers in curl != exploitable vulnerability")
print("The browser has additional security checks that curl doesn't.")
print("="*80)
