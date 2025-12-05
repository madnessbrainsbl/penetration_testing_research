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

requests.packages.urllib3.disable_warnings()

def get_signature(payload, api_secret):
    return hmac.new(
        bytes(api_secret, "utf-8"), 
        bytes(payload, "utf-8"), 
        hashlib.sha256
    ).hexdigest()

def send_request(method, endpoint, payload=None):
    # 1. Prepare params
    if payload is None:
        payload = {}
        
    timestamp = str(int(time.time() * 1000))
    recv_window = "5000"
    
    # 2. Sort params for GET (important for signature if passed in query)
    # For Bybit V5: 
    # GET: signature = hmac(timestamp + key + recv_window + queryString)
    # POST: signature = hmac(timestamp + key + recv_window + json_body)
    
    if method == "GET":
        # Sort params alphabetically
        # params_str = urllib.parse.urlencode(sorted(payload.items()))
        # Actually requests urlencode might not sort consistently, let's force sort
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
    
    print(f"DEBUG: {method} {endpoint}")
    # print(f"DEBUG: Sign Payload: {sign_payload}")
    # print(f"DEBUG: Signature: {signature}")
    
    try:
        if method == "GET":
            r = requests.get(full_url, headers=headers, verify=False, timeout=10)
        else:
            r = requests.post(full_url, headers=headers, data=data, verify=False, timeout=10)
            
        # print(f"DEBUG: Response Status: {r.status_code}")
        # print(f"DEBUG: Response Text: {r.text[:200]}")
        
        return r.json()
    except Exception as e:
        print(f"ERROR: {e}")
        if 'r' in locals():
            print(f"Response text was: {r.text}")
        return {"retCode": -1, "retMsg": str(e)}

print("="*80)
print("DEBUGGING AUTH")
print("="*80)

# Test 1: Simple Balance Check
res = send_request("GET", "/v5/account/wallet-balance", {"accountType": "UNIFIED"})
print(f"Result: {res}")

if res.get('retCode') == 0:
    print("\nSUCCESS! Auth is working.")
else:
    print("\nFAILED. Check keys or signature logic.")
