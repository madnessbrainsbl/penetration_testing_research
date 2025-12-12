#!/usr/bin/env python3
"""
Test cart modification endpoints - find correct endpoints for remove/update/coupon
"""

import requests
import json
import sys

BASE_URL = "https://www.zooplus.de"
CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"
ARTICLE_ID = 2966422  # First article from cart

SESSION_COOKIE = sys.argv[1] if len(sys.argv) > 1 else None

if not SESSION_COOKIE:
    print("[!] Usage: python3 test_cart_modify_endpoints.py <session_cookie>")
    sys.exit(1)

headers = {
    "Cookie": SESSION_COOKIE,
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

print(f"[*] Testing cart modification endpoints")
print(f"[*] Cart UUID: {CART_UUID}")
print(f"[*] Article ID: {ARTICLE_ID}")
print()

# First, get current cart state
print("[*] Step 1: Get current cart state")
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
if r.status_code == 200:
    cart = r.json()
    print(f"[+] Cart has {len(cart.get('articles', []))} items")
    print(f"[+] Total: {cart.get('summary', {}).get('grandTotal', 0)} EUR")
else:
    print(f"[!] Failed to read cart: {r.status_code}")
    sys.exit(1)

print()
print("[*] Step 2: Testing various modification endpoints...")
print()

# Test different endpoint patterns
endpoints_to_test = [
    # Remove/Delete patterns
    ("DELETE", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/{ARTICLE_ID}", None),
    ("DELETE", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/items/{ARTICLE_ID}", None),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/{ARTICLE_ID}/remove", None),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/remove", {"articleId": ARTICLE_ID}),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/remove", {"articleId": ARTICLE_ID}),
    
    # Update quantity patterns
    ("PUT", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/{ARTICLE_ID}", {"quantity": 0}),
    ("PUT", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/items/{ARTICLE_ID}", {"quantity": 0}),
    ("PATCH", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/{ARTICLE_ID}", {"quantity": 0}),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/{ARTICLE_ID}/update", {"quantity": 0}),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/update", {"articles": [{"id": ARTICLE_ID, "quantity": 0}]}),
    
    # State API patterns
    ("PUT", f"/checkout/api/cart-state-api/v2/cart/{CART_UUID}/articles/{ARTICLE_ID}", {"quantity": 0}),
    ("POST", f"/checkout/api/cart-state-api/v2/cart/{CART_UUID}/articles/{ARTICLE_ID}/remove", None),
    
    # Coupon patterns
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/coupon", {"code": "TEST"}),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/apply-coupon", {"code": "TEST"}),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/promo", {"code": "TEST"}),
]

successful_endpoints = []

for method, endpoint, payload in endpoints_to_test:
    print(f"[*] Testing {method} {endpoint}")
    
    try:
        if method == "DELETE":
            r = requests.delete(f"{BASE_URL}{endpoint}", headers=headers, timeout=5)
        elif method == "PUT":
            r = requests.put(f"{BASE_URL}{endpoint}", headers=headers, json=payload, timeout=5)
        elif method == "PATCH":
            r = requests.patch(f"{BASE_URL}{endpoint}", headers=headers, json=payload, timeout=5)
        else:  # POST
            r = requests.post(f"{BASE_URL}{endpoint}", headers=headers, json=payload, timeout=5)
        
        print(f"    HTTP {r.status_code}")
        
        if r.status_code == 200:
            print(f"    [!!!] SUCCESS! Endpoint works: {method} {endpoint}")
            print(f"    Response: {r.text[:200]}")
            successful_endpoints.append((method, endpoint, payload, r.status_code, r.text[:500]))
        elif r.status_code == 204:
            print(f"    [!!!] SUCCESS! Endpoint works (No Content): {method} {endpoint}")
            successful_endpoints.append((method, endpoint, payload, r.status_code, "No Content"))
        elif r.status_code == 403:
            print(f"    [X] Forbidden (may be protected)")
        elif r.status_code == 404:
            print(f"    [X] Not found")
        elif r.status_code == 400:
            print(f"    [!] Bad Request (endpoint exists but wrong payload): {r.text[:100]}")
        else:
            print(f"    Response: {r.text[:100]}")
            
    except Exception as e:
        print(f"    Error: {e}")

print()
print("[*] Step 3: Verify cart after modifications")
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
if r.status_code == 200:
    cart_after = r.json()
    after_count = len(cart_after.get("articles", []))
    after_total = cart_after.get("summary", {}).get("grandTotal", 0)
    print(f"[+] Cart now has {after_count} items")
    print(f"[+] Total: {after_total} EUR")

print()
if successful_endpoints:
    print("[!!!] ========================================")
    print("[!!!] FOUND WORKING ENDPOINTS:")
    print("[!!!] ========================================")
    for method, endpoint, payload, status, response in successful_endpoints:
        print(f"[!!!] {method} {endpoint}")
        if payload:
            print(f"      Payload: {payload}")
        print(f"      Status: {status}")
        print(f"      Response: {response}")
        print()
else:
    print("[!] No working modification endpoints found")
    print("[!] All tested endpoints returned 404 or errors")

