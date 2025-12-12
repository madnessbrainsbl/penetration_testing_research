#!/usr/bin/env python3
"""
Try query parameters and form-data
"""

import requests
import sys

BASE_URL = "https://www.zooplus.de"
CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"

SESSION_COOKIE = sys.argv[1] if len(sys.argv) > 1 else None

if not SESSION_COOKIE:
    print("[!] Usage: python3 test_cart_modify_query_params.py <session_cookie>")
    sys.exit(1)

headers = {
    "Cookie": SESSION_COOKIE,
    "Accept": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

# Get cart
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
cart = r.json()
article_id = cart.get("articles", [{}])[0].get("id")
before_count = len(cart.get("articles", []))

print(f"[*] Testing query parameters and form-data")
print(f"[+] Article ID: {article_id}")
print()

# Test 1: Query parameters with GET
print("[*] Test 1: GET with query parameters")
tests = [
    f"/checkout/api/cart-api/v2/cart/{CART_UUID}?action=remove&articleId={article_id}",
    f"/checkout/api/cart-api/v2/cart/{CART_UUID}?remove={article_id}",
    f"/checkout/api/cart-api/v2/cart/{CART_UUID}?articleId={article_id}&quantity=0",
]

for url in tests:
    print(f"[*] GET {url}")
    try:
        r = requests.get(f"{BASE_URL}{url}", headers=headers, timeout=5)
        print(f"    HTTP {r.status_code}")
        if r.status_code == 200:
            print(f"    [!!!] SUCCESS!")
    except:
        pass

# Test 2: Form-data with POST
print()
print("[*] Test 2: POST with form-data")
headers_form = headers.copy()
headers_form["Content-Type"] = "application/x-www-form-urlencoded"

form_data_tests = [
    {"action": "remove", "articleId": str(article_id)},
    {"articleId": str(article_id), "quantity": "0"},
    {"remove": str(article_id)},
    {"id": str(article_id), "qty": "0"},
]

endpoint = f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/{article_id}"
for data in form_data_tests:
    print(f"[*] POST {endpoint} (form-data)")
    print(f"    Data: {data}")
    try:
        r = requests.post(f"{BASE_URL}{endpoint}", headers=headers_form, data=data, timeout=5)
        print(f"    HTTP {r.status_code}")
        if r.status_code in [200, 204]:
            print(f"    [!!!] SUCCESS!")
            print(f"    {r.text[:200]}")
    except Exception as e:
        print(f"    Error: {e}")

# Test 3: Try the 405 endpoint with form-data
print()
print("[*] Test 3: POST to 405 endpoint with form-data")
endpoint_405 = f"/checkout/cart/{CART_UUID}/articles/{article_id}"
for data in form_data_tests:
    print(f"[*] POST {endpoint_405} (form-data)")
    try:
        r = requests.post(f"{BASE_URL}{endpoint_405}", headers=headers_form, data=data, timeout=5)
        print(f"    HTTP {r.status_code}")
        if r.status_code in [200, 204]:
            print(f"    [!!!] SUCCESS!")
            print(f"    {r.text[:200]}")
        elif r.status_code not in [404, 405]:
            print(f"    Response: {r.text[:150]}")
    except Exception as e:
        print(f"    Error: {e}")

# Verify
print()
print("[*] Verifying cart...")
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
if r.status_code == 200:
    cart_after = r.json()
    after_count = len(cart_after.get("articles", []))
    if before_count != after_count:
        print(f"[!!!] CART MODIFIED! Before: {before_count}, After: {after_count}")

