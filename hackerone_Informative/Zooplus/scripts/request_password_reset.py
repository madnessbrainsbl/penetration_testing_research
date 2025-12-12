#!/usr/bin/env python3
"""
Request password reset для обоих тестовых аккаунтов
Чтобы получить свежие tokens для IDOR тестирования
"""

import requests
import json

BASE_URL = "https://www.zooplus.de"
AUTH_URL = "https://login.zooplus.de"

ACCOUNTS = [
    {"email": "duststorm155@doncong.com", "name": "Account A"},
    {"email": "suobup@dunkos.xyz", "name": "Account B"}
]

def request_password_reset(email):
    """Запрашивает password reset для email"""
    print(f"\n[*] Requesting password reset for: {email}")
    
    # Try different possible endpoints
    endpoints = [
        f"{BASE_URL}/api/auth/password-reset",
        f"{BASE_URL}/api/password-reset",
        f"{BASE_URL}/forgot-password",
        f"{AUTH_URL}/auth/realms/zooplus/login-actions/reset-credentials",
        f"{AUTH_URL}/auth/realms/zooplus/password-reset",
    ]
    
    for endpoint in endpoints:
        try:
            # Method 1: JSON
            response = requests.post(
                endpoint,
                json={"email": email},
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            print(f"  Endpoint: {endpoint}")
            print(f"  Status: {response.status_code}")
            
            if response.status_code in [200, 201, 204]:
                print(f"  [+] Success! Check email for reset link")
                print(f"  Response: {response.text[:200]}")
                return True
            
            # Method 2: Form data
            response = requests.post(
                endpoint,
                data={"email": email, "username": email},
                timeout=10
            )
            
            if response.status_code in [200, 201, 204]:
                print(f"  [+] Success! Check email for reset link")
                return True
                
        except Exception as e:
            continue
    
    print(f"  [!] Could not find working endpoint")
    return False

def main():
    print("="*80)
    print("REQUEST PASSWORD RESET TOKENS")
    print("="*80)
    
    print("\n[*] This script will request password reset for both test accounts")
    print("[*] After running, check emails to get fresh tokens!")
    
    for account in ACCOUNTS:
        print(f"\n{'='*80}")
        print(f"{account['name']}: {account['email']}")
        print(f"{'='*80}")
        
        result = request_password_reset(account['email'])
        
        if not result:
            print(f"\n[!] Manual action required:")
            print(f"1. Go to https://www.zooplus.de")
            print(f"2. Click 'Forgot Password'")
            print(f"3. Enter: {account['email']}")
            print(f"4. Check email for reset link")
            print(f"5. Extract token from link")
    
    print("\n" + "="*80)
    print("NEXT STEPS")
    print("="*80)
    print("""
After getting both tokens:

1. Open both password reset emails
2. Extract tokens from URLs
3. Update real_attack_account_takeover.py with:
   - TOKEN_ACCOUNT_A = "..." 
   - TOKEN_ACCOUNT_B = "..."

4. Run IDOR test:
   - Try to reset Account A password using Account B's token
   - If successful → CRITICAL ACCOUNT TAKEOVER!

5. Test token reuse:
   - Use token, complete password reset
   - Try to use same token again
   - If works → HIGH severity vulnerability
""")

if __name__ == "__main__":
    main()

