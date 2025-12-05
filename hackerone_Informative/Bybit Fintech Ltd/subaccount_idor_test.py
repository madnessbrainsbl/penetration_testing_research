#!/usr/bin/env python3
"""
Sub-Account IDOR Testing
INSTRUCTIONS: 
1. Create 2 sub-accounts in Bybit UI
2. Generate API keys for each sub-account
3. Fill in the keys below
4. Run this script
"""
import subprocess
import time
import hmac
import hashlib
import json

# FILL THESE IN:
MASTER_API_KEY = "22JSr5zWpW0eReC6rE"
MASTER_API_SECRET = "QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"

SUB1_API_KEY = ""  # TODO: Fill after creating sub1
SUB1_API_SECRET = ""

SUB2_API_KEY = ""  # TODO: Fill after creating sub2
SUB2_API_SECRET = ""

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

def send_request(endpoint, api_key, api_secret, params={}):
    timestamp = str(int(time.time() * 1000) + OFFSET)
    recv_window = "5000"
    
    params_str = "&".join([f"{k}={v}" for k, v in sorted(params.items())])
    sign_payload = f"{timestamp}{api_key}{recv_window}{params_str}"
    signature = hmac.new(bytes(api_secret, "utf-8"), bytes(sign_payload, "utf-8"), hashlib.sha256).hexdigest()
    
    headers = [
        "-H", f"X-BAPI-API-KEY: {api_key}",
        "-H", f"X-BAPI-SIGN: {signature}",
        "-H", "X-BAPI-SIGN-TYPE: 2",
        "-H", f"X-BAPI-TIMESTAMP: {timestamp}",
        "-H", f"X-BAPI-RECV-WINDOW: {recv_window}",
        "-H", "Content-Type: application/json"
    ]
    
    full_url = f"{BASE_URL}{endpoint}"
    if params_str:
        full_url += f"?{params_str}"
    
    cmd = ["curl", "-s"] + headers + [full_url]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return json.loads(result.stdout)
    except Exception as e:
        return {"error": str(e)}

print("="*80)
print("SUB-ACCOUNT IDOR TESTING")
print("="*80)

if not SUB1_API_KEY or not SUB2_API_KEY:
    print("\n❌ ERROR: You need to fill in SUB1 and SUB2 API keys!")
    print("\nSteps:")
    print("1. Go to Bybit → Account → Sub-Account")
    print("2. Create 2 sub-accounts (Sub1, Sub2)")
    print("3. For each sub-account:")
    print("   - Login as sub-account")
    print("   - Generate API key")
    print("   - Copy key & secret to this script")
    print("\n4. Run script again")
    exit(1)

# Get baseline data for each account
print("\n[1] Getting Baseline Data")
print("-" * 80)

print("\n1.1 Master Account Data:")
master_balance = send_request("/v5/account/wallet-balance", MASTER_API_KEY, MASTER_API_SECRET, {"accountType": "UNIFIED"})
master_uid = send_request("/v5/user/query-api", MASTER_API_KEY, MASTER_API_SECRET, {})
print(f"  Balance RetCode: {master_balance.get('retCode')}")
print(f"  UID RetCode: {master_uid.get('retCode')}")
if master_uid.get('retCode') == 0:
    print(f"  Master UID: {master_uid['result'].get('uid')}")

print("\n1.2 Sub1 Account Data:")
sub1_balance = send_request("/v5/account/wallet-balance", SUB1_API_KEY, SUB1_API_SECRET, {"accountType": "UNIFIED"})
sub1_uid = send_request("/v5/user/query-api", SUB1_API_KEY, SUB1_API_SECRET, {})
print(f"  Balance RetCode: {sub1_balance.get('retCode')}")
print(f"  UID RetCode: {sub1_uid.get('retCode')}")
if sub1_uid.get('retCode') == 0:
    print(f"  Sub1 UID: {sub1_uid['result'].get('uid')}")

print("\n1.3 Sub2 Account Data:")
sub2_balance = send_request("/v5/account/wallet-balance", SUB2_API_KEY, SUB2_API_SECRET, {"accountType": "UNIFIED"})
sub2_uid = send_request("/v5/user/query-api", SUB2_API_KEY, SUB2_API_SECRET, {})
print(f"  Balance RetCode: {sub2_balance.get('retCode')}")
print(f"  UID RetCode: {sub2_uid.get('retCode')}")
if sub2_uid.get('retCode') == 0:
    print(f"  Sub2 UID: {sub2_uid['result'].get('uid')}")

# IDOR Test 1: Sub1 tries to access Sub2 data
print("\n\n[2] IDOR Test: Sub1 → Sub2")
print("-" * 80)

print("\nUsing Sub1 API key to access Sub2 wallet:")
idor_test = send_request("/v5/account/wallet-balance", SUB1_API_KEY, SUB1_API_SECRET, {"accountType": "UNIFIED"})
print(f"  RetCode: {idor_test.get('retCode')}")
print(f"  RetMsg: {idor_test.get('retMsg', '')[:60]}")

if idor_test.get('retCode') == 0:
    result = idor_test.get('result', {})
    if result != sub1_balance.get('result', {}):
        print(f"  🚨🚨🚨 IDOR FOUND! Got different data!")
        print(f"  Sub1 balance: {sub1_balance.get('result', {})}")
        print(f"  IDOR result: {result}")
    else:
        print(f"  ✅ No IDOR - got own data")

# IDOR Test 2: Sub1 tries to modify Master
print("\n\n[3] Privilege Escalation Test: Sub1 → Master")
print("-" * 80)

print("\nSub1 tries to query Master API keys:")
priv_esc = send_request("/v5/user/query-api", SUB1_API_KEY, SUB1_API_SECRET, {})
print(f"  RetCode: {priv_esc.get('retCode')}")

if priv_esc.get('retCode') == 0:
    result = priv_esc.get('result', {})
    master_uid_val = master_uid.get('result', {}).get('uid')
    result_uid = result.get('uid')
    
    if result_uid != master_uid_val and result_uid != sub1_uid.get('result', {}).get('uid'):
        print(f"  🚨🚨🚨 PRIVILEGE ESCALATION! Got Master data!")
        print(f"  Result: {result}")

# IDOR Test 3: Sub tries to list all sub-accounts
print("\n\n[4] Information Disclosure: List All Subs")
print("-" * 80)

print("\nSub1 tries to list all sub-accounts:")
list_subs = send_request("/v5/user/query-sub-members", SUB1_API_KEY, SUB1_API_SECRET, {})
print(f"  RetCode: {list_subs.get('retCode')}")
print(f"  RetMsg: {list_subs.get('retMsg', '')[:60]}")

if list_subs.get('retCode') == 0:
    subs = list_subs.get('result', {}).get('subMembers', [])
    print(f"  🚨 INFORMATION DISCLOSURE! Got {len(subs)} sub-accounts:")
    for sub in subs:
        print(f"    - UID: {sub.get('uid')}, Username: {sub.get('username')}")

print("\n" + "="*80)
print("SUB-ACCOUNT IDOR TEST COMPLETE")
print("\nIf any 🚨 appeared → You found a vulnerability!")
print("="*80)
