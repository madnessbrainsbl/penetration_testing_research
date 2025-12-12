#!/usr/bin/env python3
"""Extract endpoints from JavaScript"""
import requests
import re
import json
from urllib.parse import urljoin
import urllib3
urllib3.disable_warnings()

base = "https://www.zooplus.de"
s = requests.Session()
s.headers.update({"User-Agent": "Mozilla/5.0"})

print("[*] Fetching pages and extracting endpoints...")

pages = [
    "/",
    "/account/overview",
    "/checkout/cart",
    "/shop",
]

all_endpoints = set()

for page in pages:
    try:
        resp = s.get(f"{base}{page}", timeout=10, verify=False)
        html = resp.text
        
        # Extract JS files
        js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html)
        
        # Extract endpoints from HTML
        patterns = [
            r'["\'](/[^"\']*api[^"\']*)["\']',
            r'["\'](/[^"\']*upload[^"\']*)["\']',
            r'["\'](/[^"\']*graphql[^"\']*)["\']',
            r'["\'](/[^"\']*import[^"\']*)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(get|post)\(["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[-1]
                if match.startswith('/') and len(match) < 200:
                    all_endpoints.add(match)
        
        # Analyze JS files
        for js_file in js_files[:5]:  # Limit
            if not js_file.startswith('http'):
                js_file = urljoin(base, js_file)
            try:
                js_resp = s.get(js_file, timeout=5, verify=False)
                js_content = js_resp.text
                
                for pattern in patterns:
                    matches = re.findall(pattern, js_content)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[-1]
                        if match.startswith('/') and len(match) < 200:
                            all_endpoints.add(match)
            except: pass
    except: pass

print(f"\n[+] Found {len(all_endpoints)} endpoints")
for ep in sorted(all_endpoints):
    if any(x in ep for x in ['upload', 'graphql', 'import', 'actuator', 'debug']):
        print(f"  {ep}")

# Save
with open("reports/extracted_endpoints.json", "w") as f:
    json.dump({"endpoints": sorted(list(all_endpoints))}, f, indent=2)

print(f"\n[+] Saved to reports/extracted_endpoints.json")

