#!/usr/bin/env python3
"""
Анализ Keycloak Action Token для поиска уязвимостей
"""

import base64
import json
from urllib.parse import unquote, urlparse, parse_qs

# URL из письма
email_link = """https://mailing.zooplus.de/lnk/EAAAB-1S0ykAAAAAAAAAAKCSMUEAAAADXuwAAAAAAAkK0ABpNwh9yY86kJtuSfO25U111ljIUAAISzM/2/qrHtKqPSTnOhhFYkOAnrVw/aHR0cHM6Ly9sb2dpbi56b29wbHVzLmRlL2F1dGgvcmVhbG1zL3pvb3BsdXMvbG9naW4tYWN0aW9ucy9hY3Rpb24tdG9rZW4_a2V5PWV5SmhiR2NpT2lKSVV6VXhNaUlzSW5SNWNDSWdPaUFpU2xkVUlpd2lhMmxrSWlBNklDSXhPVEZoT1dZMk9TMDFZMkl4TFRSbFkyTXRZakEyTUMwME5EVmpaamMxTURreU56UWlmUS5leUpsZUhBaU9qRTNOalV6TURBM016SXNJbWxoZENJNk1UYzJOVEl4TkRNek1pd2lhblJwSWpvaU16STRaVGxrWWpBdFltSTVNeTAwTkdJd0xUbGhOR1F0WXpNeFl6Z3hOR1UwWVRZNUlpd2lhWE56SWpvaWFIUjBjSE02THk5c2IyZHBiaTU2YjI5d2JIVnpMbVJsTDJGMWRHZ3ZjbVZoYkcxekwzcHZiM0JzZFhNaUxDSmhkV1FpT2lKb2RIUndjem92TDJ4dloybHVMbnB2YjNCc2RYTXVaR1V2WVhWMGFDOXlaV0ZzYldzdmVtOXZjR3gxY3lJc0luTjFZaUk2SWpZMk1EZGtPVEJtTFdaa1l6SXRORE00TnkwNVlqWXpMVEZqT0dabFlqY3hNalV3WVNJc0luUjVjQ0k2SW5KbGMyVjBMV055WldSbGJuUnBZV3h6SWl3aVlYcHdJam9pYzJodmNDMXRlWHB2YjNCc2RYTXRjSEp2WkMxNmIyOXdiSFZ6SWl3aWJtOXVZMlVpT2lJek1qaGxPV1JpTUMxaVlqa3pMVFEwWWpBdE9XRTBaQzFqTXpGak9ERTBaVFJoTmpraUxDSmhjMmxrSWpvaVpEVm1OelkwTUdJdE5tVTBPQzAwTXpZMExUbG1Zek10WW1WbFpHWTNZMkU1TkdZeUxuZ3RVRUZmTmt4MFJYZDNMalEwTm1RNE4yRTJMVFJtTTJZdE5EbGpaUzFpTUdaakxUQTRaV0l6TlRsa1lqRmtOeUlzSW1WdGJDSTZJbk4xYjJKMWNFQmtkVzVyYjNNdWVIbDZJbjAuOWhRUlhfejFuOGZqS2tYVEtmcHRpRUJqdlZyN2xJRVdLODFDLXZ3YUZMZl9QMGloVGg0X0hmRlc2ZHUydHdjTWtpQWpma2dzVHJ5d0xEVnNpaVVXT2cmZXhlY3V0aW9uPTQ5OGFkZjdjLTZlMTQtNDJmMi1hZWU5LWRhOTM3NzI3MmQ0MSZjbGllbnRfaWQ9c2hvcC1teXpvb3BsdXMtcHJvZC16b29wbHVzJnRhYl9pZD14LVBBXzZMdEV3dyZ1aV9sb2NhbGVzPWRlLURF"""

def decode_jwt(token):
    """Декодирует JWT token без проверки подписи"""
    try:
        # JWT состоит из трех частей: header.payload.signature
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        # Декодируем header
        header = parts[0]
        # Добавляем padding если нужно
        header += '=' * (4 - len(header) % 4)
        header_decoded = base64.urlsafe_b64decode(header)
        header_json = json.loads(header_decoded)
        
        # Декодируем payload
        payload = parts[1]
        payload += '=' * (4 - len(payload) % 4)
        payload_decoded = base64.urlsafe_b64decode(payload)
        payload_json = json.loads(payload_decoded)
        
        return {
            'header': header_json,
            'payload': payload_json,
            'signature': parts[2]
        }
    except Exception as e:
        print(f"Error decoding JWT: {e}")
        return None

# Декодируем base64 из tracking link
print("=" * 80)
print("KEYCLOAK ACTION TOKEN ANALYSIS")
print("=" * 80)

# Извлекаем JWT token из URL
# URL encoded в base64
import re
match = re.search(r'aHR0cHM6Ly9sb2dpbi56b29wbHVzLmRlL[A-Za-z0-9_-]+', email_link)
if match:
    encoded_url = match.group(0)
    # Добавляем padding
    encoded_url += '=' * (4 - len(encoded_url) % 4)
    try:
        decoded_url = base64.urlsafe_b64decode(encoded_url).decode('utf-8')
        print(f"\n[+] Decoded URL from tracking link:")
        print(decoded_url)
        
        # Парсим URL
        parsed = urlparse(decoded_url)
        params = parse_qs(parsed.query)
        
        if 'key' in params:
            jwt_token = params['key'][0]
            print(f"\n[+] Found JWT token in 'key' parameter:")
            print(f"Token: {jwt_token[:50]}...")
            
            # Декодируем JWT
            decoded = decode_jwt(jwt_token)
            if decoded:
                print("\n" + "=" * 80)
                print("JWT HEADER:")
                print("=" * 80)
                print(json.dumps(decoded['header'], indent=2))
                
                print("\n" + "=" * 80)
                print("JWT PAYLOAD:")
                print("=" * 80)
                print(json.dumps(decoded['payload'], indent=2))
                
                # Анализ уязвимостей
                print("\n" + "=" * 80)
                print("VULNERABILITY ANALYSIS:")
                print("=" * 80)
                
                payload = decoded['payload']
                
                # Check 1: Token expiration
                if 'exp' in payload and 'iat' in payload:
                    exp = payload['exp']
                    iat = payload['iat']
                    validity = exp - iat
                    print(f"\n[*] Token Validity: {validity} seconds ({validity//60} minutes)")
                    if validity > 900:  # 15 minutes
                        print(f"[!] FINDING: Token valid for {validity//60} minutes - too long for action token!")
                        print("[!] Recommendation: Should be 5-10 minutes maximum")
                
                # Check 2: User identifier
                if 'sub' in payload:
                    print(f"\n[*] User ID: {payload['sub']}")
                    print("[*] Test: Can we swap this user ID with another user's?")
                
                # Check 3: Email in token
                if 'eml' in payload or 'email' in payload:
                    email = payload.get('eml') or payload.get('email')
                    print(f"\n[*] Email in token: {email}")
                    print("[!] POTENTIAL ATTACK: Email parameter manipulation")
                
                # Check 4: Action type
                if 'typ' in payload:
                    print(f"\n[*] Action Type: {payload['typ']}")
                
                # Check 5: Session ID
                if 'asid' in payload:
                    print(f"\n[*] Session ID: {payload['asid']}")
                    print("[*] Test: Can this session ID be reused?")
                
                # Check 6: Nonce
                if 'nonce' in payload:
                    print(f"\n[*] Nonce: {payload['nonce']}")
                    print("[*] Test: Token replay protection")
                
                # Extract full URL for testing
                print("\n" + "=" * 80)
                print("ATTACK VECTORS TO TEST:")
                print("=" * 80)
                
                print("\n1. TOKEN REUSE")
                print("   - Use the same token multiple times")
                print("   - Expected: Token should be invalidated after first use")
                
                print("\n2. TOKEN MANIPULATION")
                print("   - Decode token, change 'sub' (user ID)")
                print("   - Decode token, change 'eml' (email)")
                print("   - Re-encode without signature (if not validated)")
                
                print("\n3. TIMING ATTACK")
                print("   - Use expired token")
                print("   - Use token after user changed password")
                
                print("\n4. IDOR ON ACTION TOKEN")
                print("   - Get reset token for Account A")
                print("   - Modify user ID to Account B")
                print("   - Complete action → Account takeover!")
                
                print("\n5. PARAMETER POLLUTION")
                print("   - Add multiple 'key' parameters")
                print("   - Add conflicting user identifiers")
                
                print("\n" + "=" * 80)
                print("DIRECT ATTACK URL (for testing):")
                print("=" * 80)
                print(decoded_url)
                
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

