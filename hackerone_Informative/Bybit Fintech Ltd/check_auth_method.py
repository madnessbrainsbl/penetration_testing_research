#!/usr/bin/env python3
"""
Check how Bybit authenticates web requests
- Cookies? (vulnerable to CORS)
- Headers? (safe from CORS)
"""
import requests

BASE_URL = "https://www.bybit.com"
API_URL = "https://api.bybit.com"

requests.packages.urllib3.disable_warnings()

print("="*80)
print("AUTHENTICATION METHOD ANALYSIS")
print("="*80)

# Check if web UI sets cookies
print("\n[1] Checking if Bybit sets cookies")
print("-" * 80)

try:
    r = requests.get(BASE_URL, verify=False)
    cookies = r.cookies
    
    if cookies:
        print(f"✓ Found {len(cookies)} cookies:")
        for cookie in cookies:
            print(f"  - {cookie.name}: {cookie.value[:20]}... (Domain: {cookie.domain})")
    else:
        print("✗ No cookies set by main page")
        
except Exception as e:
    print(f"Error: {e}")

# Check login page
print("\n[2] Checking login page cookies")
print("-" * 80)

try:
    r = requests.get(f"{BASE_URL}/login", verify=False)
    cookies = r.cookies
    
    if cookies:
        print(f"✓ Login page sets {len(cookies)} cookies:")
        for cookie in cookies:
            print(f"  - {cookie.name}")
    else:
        print("✗ No cookies from login page")
        
except Exception as e:
    print(f"Error: {e}")

# Check if API accepts cookie auth
print("\n[3] Testing if API accepts cookie authentication")
print("-" * 80)

# Create a fake session cookie
fake_cookies = {
    'session': 'test123',
    'token': 'test456',
    'auth': 'test789'
}

try:
    r = requests.get(
        f"{API_URL}/v5/account/wallet-balance?accountType=UNIFIED",
        cookies=fake_cookies,
        verify=False
    )
    
    print(f"Status: {r.status_code}")
    
    try:
        data = r.json()
        ret_code = data.get('retCode')
        ret_msg = data.get('retMsg', '')
        
        print(f"RetCode: {ret_code}")
        print(f"Message: {ret_msg}")
        
        if 'cookie' in ret_msg.lower() or 'session' in ret_msg.lower():
            print("\n✓ API mentions cookies/session in error!")
            print("  This suggests cookie-based auth might be used.")
        elif 'apiKey' in ret_msg or 'apiTimestamp' in ret_msg:
            print("\n✗ API requires header-based auth (X-BAPI-*)")
            print("  CORS attack won't work because:")
            print("  - Custom headers require preflight (OPTIONS)")
            print("  - Preflight doesn't automatically include credentials")
            print("  - JavaScript can't set X-BAPI-SIGN without knowing secret")
            
    except:
        pass
        
except Exception as e:
    print(f"Error: {e}")

print("\n\n[4] CRITICAL ANALYSIS")
print("="*80)

print("""
For CORS vulnerability to be EXPLOITABLE, ALL must be true:

1. ✓ CORS headers reflect origin (CONFIRMED)
2. ✓ CORS allows credentials (CONFIRMED)  
3. ? Web UI uses COOKIE-based authentication (UNKNOWN)
4. ? Browser sends cookies cross-origin (depends on SameSite)
5. ? JavaScript can read response (needs browser test)

If Bybit uses HEADER-based auth (X-BAPI-API-KEY, X-BAPI-SIGN):
  → CORS attack FAILS because:
    - Headers need preflight
    - Attacker can't generate X-BAPI-SIGN without API secret
    - Even if CORS headers are permissive
    
NEXT STEPS:
1. Check browser DevTools on www.bybit.com:
   - Network tab → Look for requests to api.bybit.com
   - Check if they use Cookies OR X-BAPI-* headers
   
2. Open test_cors_real.html while logged in:
   - If it reads wallet balance → VULNERABLE
   - If it gets auth error → NOT VULNERABLE (header-based auth)
""")

print("="*80)
