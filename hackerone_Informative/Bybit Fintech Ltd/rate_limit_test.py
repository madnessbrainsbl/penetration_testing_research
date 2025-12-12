#!/usr/bin/env python3
"""
Rate Limiting Testing
Checking if critical endpoints have proper rate limiting
"""
import requests
import time
from concurrent.futures import ThreadPoolExecutor

requests.packages.urllib3.disable_warnings()

print("="*80)
print("RATE LIMITING TESTING")
print("="*80)

# Test 1: Login rate limiting
print("\n[1] Testing Login Rate Limiting")
print("-" * 80)

login_url = "https://api.bybit.com/user/v1/login"
test_email = "ratelimit_test@test.com"

print(f"\nAttempting 20 failed logins in quick succession...")
print(f"Email: {test_email}")

start_time = time.time()
success_count = 0
blocked_count = 0
error_codes = {}

for i in range(20):
    try:
        r = requests.post(
            login_url,
            json={"email": test_email, "password": f"wrongpass{i}"},
            verify=False,
            timeout=3
        )
        
        try:
            data = r.json()
            ret_code = data.get('retCode')
            ret_msg = data.get('retMsg', '')
            
            if ret_code not in error_codes:
                error_codes[ret_code] = 0
            error_codes[ret_code] += 1
            
            if 'rate' in ret_msg.lower() or 'limit' in ret_msg.lower() or 'too many' in ret_msg.lower():
                blocked_count += 1
                print(f"  [{i+1:2d}] 🛑 Rate limited: {ret_msg[:50]}")
                break
            else:
                success_count += 1
                if i < 3 or i % 5 == 0:
                    print(f"  [{i+1:2d}] ✓ Request accepted (RetCode: {ret_code})")
                    
        except:
            pass
            
        time.sleep(0.1)  # 100ms between requests
        
    except Exception as e:
        print(f"  [{i+1:2d}] Error: {str(e)[:40]}")

elapsed = time.time() - start_time

print(f"\n📊 Results:")
print(f"  Time: {elapsed:.2f}s")
print(f"  Accepted: {success_count}/20")
print(f"  Blocked: {blocked_count}/20")
print(f"  Rate: {success_count/elapsed:.1f} req/s")
print(f"  Error codes: {error_codes}")

if success_count >= 15:
    print(f"\n  🚨 WEAK RATE LIMITING!")
    print(f"     Accepted {success_count} requests in {elapsed:.1f}s")
    print(f"     This allows brute force attacks!")

# Test 2: Password reset rate limiting
print("\n\n[2] Testing Password Reset Rate Limiting")
print("-" * 80)

reset_url = "https://api.bybit.com/user/v1/password/forgot"

print(f"\nSending 10 password reset requests...")

start_time = time.time()
success_count = 0

for i in range(10):
    try:
        r = requests.post(
            reset_url,
            json={"email": f"test{i}@test.com"},
            verify=False,
            timeout=3
        )
        
        try:
            data = r.json()
            ret_code = data.get('retCode')
            ret_msg = data.get('retMsg', '')
            
            if 'rate' in ret_msg.lower() or 'limit' in ret_msg.lower():
                print(f"  [{i+1:2d}] 🛑 Rate limited")
                break
            else:
                success_count += 1
                if i < 3:
                    print(f"  [{i+1:2d}] ✓ Request accepted")
                    
        except:
            pass
            
        time.sleep(0.5)
        
    except:
        pass

elapsed = time.time() - start_time

print(f"\n📊 Results:")
print(f"  Accepted: {success_count}/10")

if success_count >= 8:
    print(f"  🚨 Password reset flooding possible!")

# Test 3: Registration rate limiting
print("\n\n[3] Testing Registration Rate Limiting")
print("-" * 80)

reg_url = "https://api.bybit.com/user/v1/create"

print(f"\nTrying to create 5 accounts rapidly...")

start_time = time.time()
success_count = 0

for i in range(5):
    try:
        timestamp = int(time.time() * 1000)
        r = requests.post(
            reg_url,
            json={
                "email": f"rate{timestamp}_{i}@tempmail.com",
                "password": "TestPass123!"
            },
            verify=False,
            timeout=3
        )
        
        try:
            data = r.json()
            ret_code = data.get('retCode')
            ret_msg = data.get('retMsg', '')
            
            print(f"  [{i+1}] RetCode: {ret_code}, Msg: {ret_msg[:40]}")
            
            if ret_code == 0:
                success_count += 1
                print(f"      🚨 Registration successful!")
                
            if 'rate' in ret_msg.lower():
                break
                
        except:
            pass
            
        time.sleep(0.5)
        
    except:
        pass

if success_count >= 3:
    print(f"\n  🚨 Mass registration possible! ({success_count} accounts created)")

print("\n" + "="*80)
print("RATE LIMITING TEST COMPLETE")
print("\n💡 If rate limiting is weak:")
print("  - Login: Enables password brute force")
print("  - Reset: Enables email flooding/DoS")
print("  - Registration: Enables spam/referral abuse")
print("="*80)
