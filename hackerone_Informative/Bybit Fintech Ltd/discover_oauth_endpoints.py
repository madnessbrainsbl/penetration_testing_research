#!/usr/bin/env python3
import requests
import re

requests.packages.urllib3.disable_warnings()

print("="*80)
print("OAUTH ENDPOINT DISCOVERY")
print("="*80)

# Download login page to find OAuth URLs
print("\n[1] Analyzing Login Page for OAuth URLs")
print("-" * 80)

try:
    r = requests.get("https://www.bybit.com/login", verify=False, timeout=10)
    
    # Look for OAuth patterns
    oauth_patterns = [
        r'https://[^"]*google[^"]*oauth[^"]*',
        r'https://[^"]*apple[^"]*auth[^"]*',
        r'https://[^"]*telegram[^"]*auth[^"]*',
        r'https://accounts\.google\.com/o/oauth2/[^"]*',
        r'https://appleid\.apple\.com/auth/[^"]*',
        r'/api/auth/google[^"]*',
        r'/oauth/[^"]*',
        r'redirect_uri=([^&"]*)',
        r'callback[^"]*url=([^&"]*)',
    ]
    
    found_urls = set()
    
    for pattern in oauth_patterns:
        matches = re.findall(pattern, r.text)
        for match in matches:
            found_urls.add(match)
    
    if found_urls:
        print("✓ Found OAuth-related URLs:")
        for url in sorted(found_urls):
            print(f"  - {url}")
    else:
        print("✗ No OAuth URLs found in HTML")
    
    # Look for JavaScript OAuth init
    if 'GoogleAuth' in r.text or 'gapi.auth2' in r.text:
        print("\n✓ Google OAuth detected (JavaScript)")
    
    if 'AppleID' in r.text or 'appleid.auth' in r.text:
        print("✓ Apple Sign In detected (JavaScript)")
        
    if 'telegram' in r.text.lower() and 'login' in r.text.lower():
        print("✓ Telegram Login detected")
        
except Exception as e:
    print(f"Error: {e}")

# Test common OAuth endpoints
print("\n\n[2] Testing Common OAuth Endpoints")
print("-" * 80)

oauth_endpoints = [
    "https://www.bybit.com/oauth/google",
    "https://www.bybit.com/oauth/apple",
    "https://www.bybit.com/oauth/telegram",
    "https://www.bybit.com/api/oauth/google",
    "https://www.bybit.com/api/oauth/apple",
    "https://www.bybit.com/api/auth/google/callback",
    "https://www.bybit.com/api/auth/apple/callback",
    "https://api.bybit.com/oauth/authorize",
    "https://api.bybit.com/v5/oauth/authorize",
]

for endpoint in oauth_endpoints:
    try:
        r = requests.get(endpoint, verify=False, timeout=3, allow_redirects=False)
        
        if r.status_code not in [404, 403]:
            print(f"\n✓ {endpoint}")
            print(f"  Status: {r.status_code}")
            
            if 'Location' in r.headers:
                location = r.headers['Location']
                print(f"  Redirects to: {location[:100]}")
                
                # Check for redirect_uri parameter
                if 'redirect_uri=' in location:
                    print(f"  🎯 Found redirect_uri parameter!")
                    
                # Check for client_id
                if 'client_id=' in location:
                    client_id = re.search(r'client_id=([^&]*)', location)
                    if client_id:
                        print(f"  Client ID: {client_id.group(1)}")
                        
    except:
        pass

# Check for OAuth configuration in JS files
print("\n\n[3] Searching for OAuth Config in JavaScript")
print("-" * 80)

js_files = [
    "https://www.bybit.com/_next/static/chunks/pages/_app.js",
    "https://www.bybit.com/_next/static/chunks/main.js",
]

for js_url in js_files:
    try:
        r = requests.get(js_url, verify=False, timeout=5)
        
        # Look for client IDs and secrets
        google_client_id = re.search(r'[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com', r.text)
        if google_client_id:
            print(f"\n✓ Google Client ID: {google_client_id.group(0)}")
        
        # Look for redirect URIs
        redirect_uris = re.findall(r'redirect_uri["\s:=]+([^"&,\s]+)', r.text)
        if redirect_uris:
            print(f"✓ Redirect URIs found: {set(redirect_uris)}")
            
    except:
        pass

print("\n" + "="*80)
print("NEXT STEPS:")
print("1. Open Burp Suite and configure browser proxy")
print("2. Go to https://www.bybit.com/login")
print("3. Click 'Continue with Google' (or Apple)")
print("4. Intercept the request in Burp")
print("5. Look for redirect_uri parameter")
print("6. Try to change it to https://evil.com")
print("7. Check if you get redirected with authorization code")
print("="*80)
