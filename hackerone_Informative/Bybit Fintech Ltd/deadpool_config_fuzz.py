#!/usr/bin/env python3
import requests
import json

requests.packages.urllib3.disable_warnings()

BASE_URL = "https://api.bybit.com"

print("="*80)
print("CONFIG API FUZZING (Deadpool SDK)")
print("="*80)

endpoints = [
    "/v3/config/web",
    "/v3/config/banner"
]

payloads = [
    {},
    {"project_name": "bybit"},
    {"project_name": "admin"},
    {"project_name": "internal"},
    {"site": "jp"},
    {"site": "global"},
    {"country": "US"},
    {"country": "CN"},
    {"platform": "pc"},
    {"platform": "mobile"},
    {"version": "v1"},
    {"debug": True},
]

headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "platform": "pc",  # From JS analysis
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

for endpoint in endpoints:
    print(f"\n[Testing {endpoint}]")
    for payload in payloads:
        try:
            r = requests.post(
                f"{BASE_URL}{endpoint}",
                json={"data": payload, "ttl": 60000}, # Structure seen in JS
                headers=headers,
                verify=False,
                timeout=5
            )
            
            print(f"Payload: {payload} -> Status: {r.status_code}")
            if r.status_code == 200:
                try:
                    print(f"  Response: {str(r.json())[:200]}")
                except:
                    print(f"  Text: {r.text[:100]}")
                    
        except Exception as e:
            print(f"Error: {e}")

print("\n" + "="*80)
