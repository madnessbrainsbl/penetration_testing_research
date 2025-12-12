#!/usr/bin/env python3
"""
Rate Limiting Test для Zooplus
Проверяет наличие rate limiting на критичных endpoints
"""

import requests
import time
from datetime import datetime

BASE_URL = "https://www.zooplus.de"

def test_login_rate_limit():
    """Тест rate limiting на login endpoint"""
    print("\n[*] Testing login rate limiting...")
    
    login_url = f"{BASE_URL}/api/auth/login"
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    attempts = 0
    blocked = False
    
    for i in range(100):
        try:
            payload = {
                "email": "test@example.com",
                "password": f"wrong_password_{i}"
            }
            
            start_time = time.time()
            response = requests.post(login_url, json=payload, headers=headers, timeout=10)
            elapsed = time.time() - start_time
            
            attempts += 1
            
            print(f"Attempt {attempts}: Status {response.status_code}, Time: {elapsed:.2f}s")
            
            # Проверка на rate limiting
            if response.status_code == 429:
                print(f"[+] Rate limiting detected at attempt {attempts}!")
                blocked = True
                break
            elif "captcha" in response.text.lower():
                print(f"[+] CAPTCHA triggered at attempt {attempts}!")
                blocked = True
                break
            elif "too many" in response.text.lower():
                print(f"[+] Rate limit message detected at attempt {attempts}!")
                blocked = True
                break
            elif elapsed > 5:
                print(f"[+] Request delayed (>5s) - possible rate limiting")
                
            time.sleep(0.1)  # Small delay between requests
            
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed: {e}")
            continue
    
    if not blocked and attempts >= 50:
        print(f"\n[!] VULNERABILITY: No rate limiting detected after {attempts} attempts!")
        print("[!] This allows password brute-force attacks")
        return {
            "vulnerable": True,
            "description": f"No rate limiting on login after {attempts} attempts",
            "severity": "MEDIUM",
            "cvss": "6.5"
        }
    
    return {"vulnerable": False}


def test_password_reset_rate_limit():
    """Тест rate limiting на password reset"""
    print("\n[*] Testing password reset rate limiting...")
    
    reset_url = f"{BASE_URL}/api/auth/reset-password"
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0"
    }
    
    attempts = 0
    blocked = False
    
    for i in range(20):
        try:
            payload = {
                "email": f"test{i}@example.com"
            }
            
            response = requests.post(reset_url, json=payload, headers=headers, timeout=10)
            attempts += 1
            
            print(f"Attempt {attempts}: Status {response.status_code}")
            
            if response.status_code == 429:
                print(f"[+] Rate limiting detected at attempt {attempts}!")
                blocked = True
                break
            
            time.sleep(0.5)
            
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed: {e}")
            continue
    
    if not blocked and attempts >= 15:
        print(f"\n[!] VULNERABILITY: No rate limiting on password reset after {attempts} attempts!")
        print("[!] This allows email enumeration and DoS")
        return {
            "vulnerable": True,
            "description": f"No rate limiting on password reset after {attempts} attempts",
            "severity": "LOW",
            "cvss": "4.3"
        }
    
    return {"vulnerable": False}


def test_api_rate_limit(token):
    """Тест rate limiting на API endpoints"""
    print("\n[*] Testing API rate limiting...")
    
    api_url = f"{BASE_URL}/myaccount/api/customer-config/v1/customerconfiguration/123"
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "Mozilla/5.0"
    }
    
    attempts = 0
    blocked = False
    
    for i in range(1000):
        try:
            response = requests.get(api_url, headers=headers, timeout=5)
            attempts += 1
            
            if attempts % 100 == 0:
                print(f"Attempt {attempts}: Status {response.status_code}")
            
            if response.status_code == 429:
                print(f"[+] API rate limiting detected at attempt {attempts}!")
                blocked = True
                break
            
        except requests.exceptions.RequestException as e:
            if attempts % 100 == 0:
                print(f"[!] Request failed: {e}")
            continue
    
    if not blocked and attempts >= 500:
        print(f"\n[!] VULNERABILITY: No API rate limiting after {attempts} requests!")
        print("[!] This allows API abuse and resource exhaustion")
        return {
            "vulnerable": True,
            "description": f"No API rate limiting after {attempts} requests",
            "severity": "LOW",
            "cvss": "3.7"
        }
    
    return {"vulnerable": False}


def main():
    print("=" * 60)
    print("Zooplus Rate Limiting Test")
    print(f"Time: {datetime.now()}")
    print("=" * 60)
    
    findings = []
    
    # Test 1: Login rate limiting
    result = test_login_rate_limit()
    if result.get("vulnerable"):
        findings.append(result)
    
    # Test 2: Password reset rate limiting
    result = test_password_reset_rate_limit()
    if result.get("vulnerable"):
        findings.append(result)
    
    # Test 3: API rate limiting (требует token)
    # Uncomment when you have a valid token
    # token = "YOUR_TOKEN_HERE"
    # result = test_api_rate_limit(token)
    # if result.get("vulnerable"):
    #     findings.append(result)
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    if findings:
        print(f"\n[!] Found {len(findings)} vulnerability(ies):\n")
        for i, finding in enumerate(findings, 1):
            print(f"{i}. {finding['description']}")
            print(f"   Severity: {finding['severity']} (CVSS: {finding['cvss']})")
            print()
    else:
        print("\n[+] No rate limiting vulnerabilities found")
        print("[+] All endpoints have proper protection")
    
    return findings


if __name__ == "__main__":
    main()

