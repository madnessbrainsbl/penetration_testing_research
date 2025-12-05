#!/usr/bin/env python3
"""
Referral/Affiliate Abuse Testing
"""
import requests
import time

BASE_URL = "https://api.bybit.com"
requests.packages.urllib3.disable_warnings()

print("="*80)
print("REFERRAL/AFFILIATE ABUSE TESTING")
print("="*80)

# Test 1: Get referral info from authenticated API
print("\n[1] Testing Referral API Endpoints")
print("-" * 80)

referral_endpoints = [
    "/v5/user/query-api",  # Should contain referral code
    "/v5/broker/referral-statistics",
    "/v5/broker/sub-member-info",
    "/v5/asset/query-bonus",
]

for endpoint in referral_endpoints:
    try:
        r = requests.get(f"{BASE_URL}{endpoint}", verify=False, timeout=3)
        
        if r.status_code not in [404, 403]:
            print(f"\n{endpoint} - {r.status_code}")
            try:
                data = r.json()
                print(f"  RetCode: {data.get('retCode')}")
                print(f"  Msg: {data.get('retMsg', '')[:60]}")
                
                if data.get('retCode') == 0:
                    print(f"  🚨 Returns data without auth!")
                    print(f"  Data: {str(data)[:200]}")
                    
            except:
                pass
    except:
        pass

# Test 2: Check for referral code validation
print("\n\n[2] Testing Referral Code Validation")
print("-" * 80)

fake_referral_codes = [
    "ADMIN",
    "TEST",
    "12345",
    "AAAAAA",
    "../../../etc/passwd",
    "<script>alert(1)</script>",
]

print("\nTrying to register with fake referral codes:")
print("(This will fail at auth, but we check for code validation)")

for code in fake_referral_codes:
    try:
        # Try to access referral page
        r = requests.get(
            f"https://www.bybit.com/invite?ref={code}",
            verify=False,
            timeout=3,
            allow_redirects=False
        )
        
        print(f"\nCode: {code}")
        print(f"  Status: {r.status_code}")
        
        if r.status_code == 200:
            if 'invalid' not in r.text.lower() and 'error' not in r.text.lower():
                print(f"  ⚠️  No validation error! Code might be accepted")
                
    except:
        pass

# Test 3: Rate limiting on registration
print("\n\n[3] Testing Rate Limiting on Registration")
print("-" * 80)

print("\nAttempting multiple registrations in quick succession:")
print("(Testing if we can mass-register for referral abuse)\n")

start_time = time.time()
success_count = 0
error_count = 0

for i in range(5):  # Try 5 times
    try:
        data = {
            "email": f"test{int(time.time())}+{i}@tempmail.com",
            "password": "TestPass123!@#",
            "referralCode": "YOUR_CODE_HERE"  # TODO: Fill with real code
        }
        
        r = requests.post(
            f"{BASE_URL}/user/v1/create",
            json=data,
            verify=False,
            timeout=3
        )
        
        try:
            resp = r.json()
            ret_code = resp.get('retCode')
            
            if ret_code == 0:
                success_count += 1
                print(f"  [{i+1}] ✓ Registration successful!")
            else:
                error_count += 1
                msg = resp.get('retMsg', '')
                print(f"  [{i+1}] ✗ {ret_code}: {msg[:50]}")
                
                if 'rate' in msg.lower() or 'limit' in msg.lower():
                    print(f"       → Rate limit detected")
                    break
        except:
            pass
            
        time.sleep(0.5)  # Small delay
        
    except Exception as e:
        print(f"  [{i+1}] Error: {str(e)[:50]}")

elapsed = time.time() - start_time
print(f"\nResults:")
print(f"  Time: {elapsed:.2f}s")
print(f"  Success: {success_count}")
print(f"  Errors: {error_count}")

if success_count >= 3:
    print(f"  🚨 High success rate! Possible mass registration abuse")

# Test 4: Check bonus requirements
print("\n\n[4] Checking Bonus Requirements")
print("-" * 80)

print("""
Manual steps to test bonus abuse:

1. Get your referral link from Bybit UI
2. Open incognito/private browser
3. Register new account with:
   - Temp email (temp-mail.org)
   - Your referral code
4. Check if bonus is granted immediately
5. Try to:
   a) Withdraw immediately
   b) Transfer to another account
   c) Trade minimal volume and withdraw

If any works → Business Logic Bug (bonus abuse)
""")

print("\n" + "="*80)
print("REFERRAL TESTING COMPLETE")
print("\nFor complete testing, follow manual steps in MANUAL_TESTING_GUIDE.md")
print("="*80)
