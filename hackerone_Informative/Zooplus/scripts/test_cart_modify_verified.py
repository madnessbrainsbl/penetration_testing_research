#!/usr/bin/env python3
"""
Verify if GET with query parameters actually modifies cart
"""

import requests
import json
import sys
import time

BASE_URL = "https://www.zooplus.de"
CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"

SESSION_COOKIE = sys.argv[1] if len(sys.argv) > 1 else None

if not SESSION_COOKIE:
    print("[!] Usage: python3 test_cart_modify_verified.py <session_cookie>")
    sys.exit(1)

headers = {
    "Cookie": SESSION_COOKIE,
    "Accept": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

print(f"[*] Verifying cart modification via GET with query parameters")
print()

# Get initial cart state
print("[*] Step 1: Get initial cart state")
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
cart_before = r.json()
before_count = len(cart_before.get("articles", []))
before_total = cart_before.get("summary", {}).get("grandTotal", 0)
first_article = cart_before.get("articles", [{}])[0]
article_id = first_article.get("id")

print(f"[+] Cart before: {before_count} items, {before_total} EUR")
print(f"[+] First article ID: {article_id}")
print()

# Try GET with query parameters
print("[*] Step 2: Attempting modification via GET with query parameters")
test_urls = [
    f"/checkout/api/cart-api/v2/cart/{CART_UUID}?action=remove&articleId={article_id}",
    f"/checkout/api/cart-api/v2/cart/{CART_UUID}?remove={article_id}",
    f"/checkout/api/cart-api/v2/cart/{CART_UUID}?articleId={article_id}&quantity=0",
    f"/checkout/api/cart-api/v2/cart/{CART_UUID}?action=delete&articleId={article_id}",
]

for url in test_urls:
    print(f"[*] GET {url}")
    try:
        r = requests.get(f"{BASE_URL}{url}", headers=headers, timeout=5)
        print(f"    HTTP {r.status_code}")
        
        if r.status_code == 200:
            response_cart = r.json()
            response_count = len(response_cart.get("articles", []))
            response_total = response_cart.get("summary", {}).get("grandTotal", 0)
            
            print(f"    Response cart: {response_count} items, {response_total} EUR")
            
            if response_count != before_count or abs(response_total - before_total) > 0.01:
                print(f"    [!!!] CART WAS MODIFIED!")
                print(f"    Before: {before_count} items, {before_total} EUR")
                print(f"    After:  {response_count} items, {response_total} EUR")
                
                # Verify by reading cart again
                print()
                print("[*] Step 3: Verifying by reading cart again...")
                time.sleep(1)
                r2 = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
                if r2.status_code == 200:
                    cart_final = r2.json()
                    final_count = len(cart_final.get("articles", []))
                    final_total = cart_final.get("summary", {}).get("grandTotal", 0)
                    print(f"[+] Final cart: {final_count} items, {final_total} EUR")
                    
                    if final_count != before_count:
                        print()
                        print("[!!!] ========================================")
                        print("[!!!] MODIFICATION CONFIRMED!")
                        print("[!!!] ========================================")
                        print(f"[!!!] Working endpoint: GET {url}")
                        print(f"[!!!] Before: {before_count} items, {before_total} EUR")
                        print(f"[!!!] After:  {final_count} items, {final_total} EUR")
                        sys.exit(0)
    except Exception as e:
        print(f"    Error: {e}")

print()
print("[!] No modification detected - GET with query params may just return cart without modifying")

