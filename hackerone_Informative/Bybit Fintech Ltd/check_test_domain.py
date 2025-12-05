#!/usr/bin/env python3
import requests
import socket

TARGET = "www.bybit-test-1.bybit.com"
requests.packages.urllib3.disable_warnings()

print(f"Checking {TARGET}...")

# 1. Resolve DNS
try:
    ip = socket.gethostbyname(TARGET)
    print(f"✓ Resolved IP: {ip}")
except:
    print("✗ DNS Resolution failed (might be internal only)")

# 2. Check HTTP/HTTPS
protocols = ["http", "https"]
for proto in protocols:
    try:
        url = f"{proto}://{TARGET}"
        r = requests.get(url, verify=False, timeout=5)
        print(f"✓ {url} - {r.status_code}")
        print(f"  Title: {r.text.split('<title>')[1].split('</title>')[0] if '<title>' in r.text else 'No title'}")
    except Exception as e:
        print(f"✗ {url} - Error: {str(e)[:50]}")

# 3. Check common paths if accessible
paths = ["/admin", "/api", "/v5/market/time", "/.git/config", "/robots.txt"]
for path in paths:
    try:
        url = f"https://{TARGET}{path}"
        r = requests.get(url, verify=False, timeout=5)
        if r.status_code != 404:
            print(f"⚠️  {url} - {r.status_code}")
    except:
        pass
