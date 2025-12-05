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

def send_request():
    endpoint = "/v5/account/wallet-balance"
    # Sort params: accountType=UNIFIED
    params = {"accountType": "UNIFIED"}
    params_str = "accountType=UNIFIED" # pre-sorted
    
    timestamp = str(int(time.time() * 1000))
    recv_window = "20000" # Increase window to be safe
    
    # Signature payload for GET
    sign_payload = f"{timestamp}{API_KEY}{recv_window}{params_str}"
    
    signature = get_signature(sign_payload, API_SECRET)
    
    headers = {
        "X-BAPI-API-KEY": API_KEY,
        "X-BAPI-SIGN": signature,
        "X-BAPI-SIGN-TYPE": "2",
        "X-BAPI-TIMESTAMP": timestamp,
        "X-BAPI-RECV-WINDOW": recv_window,
        # "Content-Type": "application/json" # Not strictly required for GET, but good practice
    }
    
    full_url = f"{BASE_URL}{endpoint}?{params_str}"
    
    print(f"Requesting: {full_url}")
    print(f"Timestamp: {timestamp}")
    
    try:
        r = requests.get(full_url, headers=headers, verify=False, timeout=10)
        print(f"Status: {r.status_code}")
        print(f"Response: {r.text}")
        return r.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    send_request()
