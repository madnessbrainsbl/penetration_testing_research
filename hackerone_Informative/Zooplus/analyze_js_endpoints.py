#!/usr/bin/env python3
"""Analyze JavaScript for hidden endpoints"""
import requests
import re
import json
import urllib.parse
from urllib.parse import urljoin
import urllib3
urllib3.disable_warnings()

base = "https://www.zooplus.de"
s = requests.Session()
s.headers.update({"User-Agent": "Mozilla/5.0"})

print("[*] Fetching main page...")
try:
    resp = s.get(base, timeout=10, verify=False)
    html = resp.text
    
    # Extract JS files
    js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html)
    print(f"[+] Found {len(js_files)} JS files")
    
    endpoints_found = set()
    
    # Look for API endpoints in HTML
    api_patterns = [
        r'["\'](/api/[^"\']+)["\']',
        r'["\'](/[a-z-]+/api/[^"\']+)["\']',
        r'["\'](/semiprotected/[^"\']+)["\']',
        r'["\'](/protected/[^"\']+)["\']',
        r'["\'](/checkout/[^"\']+)["\']',
        r'["\'](/myaccount/[^"\']+)["\']',
    ]
    
    for pattern in api_patterns:
        matches = re.findall(pattern, html)
        for match in matches:
            if '/api/' in match or '/checkout/' in match:
                endpoints_found.add(match)
    
    # Fetch and analyze JS files
    for js_file in js_files[:10]:  # Limit to first 10
        if not js_file.startswith('http'):
            js_file = urljoin(base, js_file)
        
        try:
            js_resp = s.get(js_file, timeout=5, verify=False)
            js_content = js_resp.text
            
            # Look for endpoints
            for pattern in api_patterns:
                matches = re.findall(pattern, js_content)
                for match in matches:
                    if '/api/' in match or '/checkout/' in match:
                        endpoints_found.add(match)
            
            # Look for fetch/axios calls
            fetch_patterns = [
                r'fetch\(["\']([^"\']+)["\']',
                r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
                r'\.get\(["\']([^"\']+)["\']',
                r'\.post\(["\']([^"\']+)["\']',
            ]
            
            for pattern in fetch_patterns:
                matches = re.findall(pattern, js_content)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[-1]
                    if match.startswith('/') and ('api' in match or 'upload' in match or 'config' in match):
                        endpoints_found.add(match)
        except:
            pass
    
    print(f"\n[+] Found {len(endpoints_found)} potential endpoints")
    for ep in sorted(endpoints_found):
        if len(ep) < 100:  # Filter out very long strings
            print(f"  {ep}")
    
    # Save for testing
    with open("reports/js_endpoints.json", "w") as f:
        json.dump({"endpoints": sorted(list(endpoints_found))}, f, indent=2)
    print(f"\n[+] Saved to reports/js_endpoints.json")
    
except Exception as e:
    print(f"[!] Error: {e}")

