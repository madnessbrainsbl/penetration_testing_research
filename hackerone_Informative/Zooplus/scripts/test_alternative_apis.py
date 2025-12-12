#!/usr/bin/env python3
"""
Test alternative API paths and GraphQL
"""

import requests
import json
import sys

BASE_URL = "https://www.zooplus.de"
CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"

SESSION_COOKIE = sys.argv[1] if len(sys.argv) > 1 else None

if not SESSION_COOKIE:
    print("[!] Usage: python3 test_alternative_apis.py <session_cookie>")
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
article_id = cart.get("articles", [{}])[0].get("id")
offer_id = cart.get("articles", [{}])[0].get("offerId", "")

print(f"[*] Testing alternative API paths")
print(f"[+] Article ID: {article_id}, Offer ID: {offer_id}")
print()

# Test alternative API paths
tests = [
    # Different API base paths
    ("POST", f"/api/cart/{CART_UUID}/articles/{article_id}/remove", None),
    ("PUT", f"/api/cart/{CART_UUID}/articles/{article_id}", {"quantity": 0}),
    ("POST", f"/api/v2/cart/{CART_UUID}/articles/{article_id}/remove", None),
    ("PUT", f"/api/v2/cart/{CART_UUID}/articles/{article_id}", {"quantity": 0}),
    
    # REST API paths
    ("POST", f"/rest/cart/{CART_UUID}/articles/{article_id}/remove", None),
    ("PUT", f"/rest/cart/{CART_UUID}/articles/{article_id}", {"quantity": 0}),
    
    # GraphQL
    ("POST", "/graphql", {
        "query": f'mutation {{ removeFromCart(cartId: "{CART_UUID}", articleId: {article_id}) }}'
    }),
    ("POST", "/graphql", {
        "query": f'mutation {{ updateCartItem(cartId: "{CART_UUID}", articleId: {article_id}, quantity: 0) }}'
    }),
    
    # Different checkout paths
    ("POST", f"/checkout/cart/{CART_UUID}/articles/{article_id}/remove", None),
    ("PUT", f"/checkout/cart/{CART_UUID}/articles/{article_id}", {"quantity": 0}),
    
    # My account paths
    ("POST", f"/myaccount/api/cart/{CART_UUID}/articles/{article_id}/remove", None),
    ("PUT", f"/myaccount/api/cart/{CART_UUID}/articles/{article_id}", {"quantity": 0}),
]

for method, endpoint, payload in tests:
    print(f"[*] {method} {endpoint}")
    try:
        if method == "PUT":
            r = requests.put(f"{BASE_URL}{endpoint}", headers=headers, json=payload, timeout=5)
        else:
            r = requests.post(f"{BASE_URL}{endpoint}", headers=headers, json=payload, timeout=5)
        
        print(f"    HTTP {r.status_code}")
        if r.status_code in [200, 204]:
            print(f"    [!!!] SUCCESS!")
            print(f"    {r.text[:200]}")
        elif r.status_code not in [404]:
            print(f"    Response: {r.text[:200]}")
    except Exception as e:
        print(f"    Error: {e}")

