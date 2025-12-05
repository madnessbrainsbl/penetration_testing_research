#!/usr/bin/env python3
import os
import re

print("="*80)
print("EXTRACTING API ENDPOINTS FROM JS")
print("="*80)

js_dir = "/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data"
endpoints = set()
full_urls = set()

# Regex for endpoints
endpoint_pattern = re.compile(r'["\'](/v[0-9]+/[^"\']+|/api/[^"\']+)["\']')
url_pattern = re.compile(r'["\'](https?://[^"\']+)["\']')

for root, dirs, files in os.walk(js_dir):
    for file in files:
        if file.endswith(".js") or file.endswith(".html"):
            path = os.path.join(root, file)
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    # Find endpoints
                    matches = endpoint_pattern.findall(content)
                    for m in matches:
                        if len(m) < 100 and not m.startswith("//"):
                            endpoints.add(m)
                            
                    # Find full URLs
                    matches_url = url_pattern.findall(content)
                    for m in matches_url:
                        if "bybit.com" in m:
                            full_urls.add(m)
            except:
                pass

print("\n[FOUND ENDPOINTS]")
for ep in sorted(endpoints):
    print(ep)

print("\n[FOUND FULL URLS]")
for url in sorted(full_urls):
    print(url)
