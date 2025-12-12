#!/usr/bin/env python3
"""
Advanced cart modification testing - try different approaches
"""

import requests
import json
import sys

BASE_URL = "https://www.zooplus.de"
CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"
CART_ID = 851483754  # From cart response
ARTICLE_ID = 2966422

SESSION_COOKIE = sys.argv[1] if len(sys.argv) > 1 else None

if not SESSION_COOKIE:
    print("[!] Usage: python3 test_cart_modify_advanced.py <session_cookie>")
    sys.exit(1)

headers = {
    "Cookie": SESSION_COOKIE,
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

print(f"[*] Advanced cart modification testing")
print(f"[*] Cart UUID: {CART_UUID}")
print(f"[*] Cart ID: {CART_ID}")
print(f"[*] Article ID: {ARTICLE_ID}")
print()

# Get current cart
print("[*] Getting current cart state...")
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
if r.status_code != 200:
    print(f"[!] Failed to read cart: {r.status_code}")
    sys.exit(1)

cart = r.json()
before_count = len(cart.get("articles", []))
before_total = cart.get("summary", {}).get("grandTotal", 0)
print(f"[+] Cart has {before_count} items, total: {before_total} EUR")
print()

# Try different approaches
endpoints_to_test = [
    # Using cartId instead of UUID
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_ID}/articles/{ARTICLE_ID}/remove", None),
    ("PUT", f"/checkout/api/cart-api/v2/cart/{CART_ID}/articles/{ARTICLE_ID}", {"quantity": 0}),
    ("DELETE", f"/checkout/api/cart-api/v2/cart/{CART_ID}/articles/{ARTICLE_ID}", None),
    
    # Using both UUID and cartId
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/update", {
        "articles": [{"id": ARTICLE_ID, "quantity": 0}]
    }),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/modify", {
        "articles": [{"id": ARTICLE_ID, "quantity": 0}]
    }),
    
    # Try with different payload structures
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}", {
        "action": "remove",
        "articleId": ARTICLE_ID
    }),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}", {
        "action": "update",
        "articleId": ARTICLE_ID,
        "quantity": 0
    }),
    
    # Try v1 API
    ("POST", f"/checkout/api/cart-api/v1/cart/{CART_UUID}/remove", {"articleId": ARTICLE_ID}),
    ("PUT", f"/checkout/api/cart-api/v1/cart/{CART_UUID}/articles/{ARTICLE_ID}", {"quantity": 0}),
    
    # Try state API
    ("POST", f"/checkout/api/cart-state-api/v2/cart/{CART_UUID}/update", {
        "articles": [{"id": ARTICLE_ID, "quantity": 0}]
    }),
    
    # Try with offerId
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/remove", {
        "offerId": "1P.2966422"
    }),
    
    # Try coupon endpoints
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/coupon/apply", {"code": "TEST"}),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/promocode", {"code": "TEST"}),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/voucher", {"code": "TEST"}),
]

successful = []

for method, endpoint, payload in endpoints_to_test:
    print(f"[*] Testing {method} {endpoint}")
    if payload:
        print(f"    Payload: {json.dumps(payload)}")
    
    try:
        if method == "DELETE":
            r = requests.delete(f"{BASE_URL}{endpoint}", headers=headers, timeout=5)
        elif method == "PUT":
            r = requests.put(f"{BASE_URL}{endpoint}", headers=headers, json=payload, timeout=5)
        else:  # POST
            r = requests.post(f"{BASE_URL}{endpoint}", headers=headers, json=payload, timeout=5)
        
        print(f"    HTTP {r.status_code}")
        
        if r.status_code in [200, 204]:
            print(f"    [!!!] SUCCESS!")
            print(f"    Response: {r.text[:300]}")
            successful.append((method, endpoint, payload, r.status_code, r.text[:500]))
        elif r.status_code == 400:
            print(f"    [!] Bad Request (endpoint may exist): {r.text[:200]}")
        elif r.status_code == 403:
            print(f"    [X] Forbidden")
        elif r.status_code == 404:
            print(f"    [X] Not found")
        else:
            print(f"    Response: {r.text[:200]}")
    except Exception as e:
        print(f"    Error: {e}")

print()
print("[*] Verifying cart after modifications...")
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
if r.status_code == 200:
    cart_after = r.json()
    after_count = len(cart_after.get("articles", []))
    after_total = cart_after.get("summary", {}).get("grandTotal", 0)
    print(f"[+] Cart now has {after_count} items, total: {after_total} EUR")
    
    if before_count != after_count or before_total != after_total:
        print()
        print("[!!!] ========================================")
        print("[!!!] CART WAS MODIFIED!")
        print("[!!!] ========================================")
        print(f"[!!!] Before: {before_count} items, {before_total} EUR")
        print(f"[!!!] After:  {after_count} items, {after_total} EUR")

print()
if successful:
    print("[!!!] ========================================")
    print("[!!!] FOUND WORKING ENDPOINTS:")
    print("[!!!] ========================================")
    for method, endpoint, payload, status, response in successful:
        print(f"[!!!] {method} {endpoint}")
        if payload:
            print(f"      Payload: {json.dumps(payload)}")
        print(f"      Status: {status}")
        print(f"      Response: {response}")
        print()
else:
    print("[!] No working modification endpoints found")
    print("[!] Note: Modification may require different authentication or use different API structure")

