#!/usr/bin/env python3
import subprocess
import time
import hmac
import hashlib
import json

# Configuration
API_KEY = "22JSr5zWpW0eReC6rE"
API_SECRET = "QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"

# We will test both environments
ENVIRONMENTS = {
    "TESTNET": "https://api-testnet.bybit.com",
    "MAINNET": "https://api.bybit.com"
}

def get_signature(payload, api_secret):
    return hmac.new(
        bytes(api_secret, "utf-8"), 
        bytes(payload, "utf-8"), 
        hashlib.sha256
    ).hexdigest()

def check_env(name, base_url):
    print(f"\nTesting {name} ({base_url})...")
    
    # Get server time first
    try:
        cmd = ["curl", "-s", f"{base_url}/v5/market/time"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        server_time = int(json.loads(res.stdout)['time'])
        offset = server_time - int(time.time() * 1000)
        print(f"  Time Offset: {offset}ms")
    except:
        print("  Failed to get time. Using local.")
        offset = 0

    timestamp = str(int(time.time() * 1000) + offset)
    recv_window = "10000"
    
    # POST to /v5/order/create (safest way to check auth without creating order if params invalid)
    # Wait, better to check /v5/user/query-api (read only)
    endpoint = "/v5/user/query-api"
    sign_payload = f"{timestamp}{API_KEY}{recv_window}"
    
    signature = get_signature(sign_payload, API_SECRET)
    
    headers = [
        "-H", f"X-BAPI-API-KEY: {API_KEY}",
        "-H", f"X-BAPI-SIGN: {signature}",
        "-H", "X-BAPI-SIGN-TYPE: 2",
        "-H", f"X-BAPI-TIMESTAMP: {timestamp}",
        "-H", f"X-BAPI-RECV-WINDOW: {recv_window}",
        "-H", "Content-Type: application/json"
    ]
    
    cmd = ["curl", "-s", "-v"] + headers + [f"{base_url}{endpoint}"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        try:
            data = json.loads(result.stdout)
            ret_code = data.get('retCode')
            ret_msg = data.get('retMsg')
            print(f"  Result: {ret_code} - {ret_msg}")
            
            if ret_code == 0:
                print(f"  ✅ SUCCESS! Keys are for {name}")
                return True
            elif ret_code == 10003:
                print(f"  ❌ Invalid Key for {name}")
            else:
                print(f"  ⚠️  Other error: {ret_msg}")
                
        except:
            print(f"  Failed to parse JSON.")
    except Exception as e:
        print(f"  Error: {e}")
    
    return False

print("="*80)
print("ENVIRONMENT CHECK")
print("="*80)

for name, url in ENVIRONMENTS.items():
    if check_env(name, url):
        break
