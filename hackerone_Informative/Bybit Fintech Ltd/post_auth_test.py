#!/usr/bin/env python3
import requests
import time
import hmac
import hashlib
import json

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

def test_post_auth():
    endpoint = "/v5/order/create"
    # Invalid order params to provoke validation error (but pass auth)
    params = {
        "category": "linear",
        "symbol": "BTCUSDT",
        "side": "Buy",
        "orderType": "Limit",
        "qty": "0.001"
        # Missing price, etc.
    }
    params_str = json.dumps(params)
    
    timestamp = str(int(time.time() * 1000))
    recv_window = "10000"
    
    # Signature payload for POST
    sign_payload = f"{timestamp}{API_KEY}{recv_window}{params_str}"
    
    signature = get_signature(sign_payload, API_SECRET)
    
    headers = {
        "X-BAPI-API-KEY": API_KEY,
        "X-BAPI-SIGN": signature,
        "X-BAPI-SIGN-TYPE": "2",
        "X-BAPI-TIMESTAMP": timestamp,
        "X-BAPI-RECV-WINDOW": recv_window,
        "Content-Type": "application/json" # Crucial for POST
    }
    
    full_url = f"{BASE_URL}{endpoint}"
    
    print(f"POST {full_url}")
    print(f"Payload: {params_str}")
    
    try:
        r = requests.post(full_url, headers=headers, data=params_str, verify=False, timeout=10)
        print(f"Status: {r.status_code}")
        print(f"Response: {r.text}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_post_auth()
