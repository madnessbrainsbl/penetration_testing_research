#!/usr/bin/env python3
"""
Final attempt - try POST to endpoints that returned 405
"""

import requests
import json
import sys

BASE_URL = "https://www.zooplus.de"
CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"

SESSION_COOKIE = sys.argv[1] if len(sys.argv) > 1 else None

if not SESSION_COOKIE:
    print("[!] Usage: python3 test_cart_modify_final_attempt.py <session_cookie>")
    sys.exit(1)

headers = {
    "Cookie": SESSION_COOKIE,
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Referer": "https://www.zooplus.de/warenkorb",
    "Origin": "https://www.zooplus.de"
}

# Get cart
r = requests.get(f"{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}", headers=headers)
cart = r.json()
before_count = len(cart.get("articles", []))
before_total = cart.get("summary", {}).get("grandTotal", 0)

first_article = cart.get("articles", [{}])[0]
article_id = first_article.get("id")
offer_id = first_article.get("offerId", "")

print(f"[*] Final attempt - testing POST to 405 endpoints")
print(f"[+] Cart: {before_count} items, {before_total} EUR")
print(f"[+] Article ID: {article_id}, Offer ID: {offer_id}")
print()

# Endpoints that returned 405 - try POST instead
endpoints_405 = [
    f"/api/cart/{CART_UUID}/articles/{article_id}",
    f"/api/v2/cart/{CART_UUID}/articles/{article_id}",
    f"/rest/cart/{CART_UUID}/articles/{article_id}",
    f"/checkout/cart/{CART_UUID}/articles/{article_id}",
    f"/myaccount/api/cart/{CART_UUID}/articles/{article_id}",
]

# Try different payload structures with POST
payloads = [
    {"quantity": 0},
    {"action": "remove", "articleId": article_id},
    {"action": "update", "articleId": article_id, "quantity": 0},
    {"articleId": article_id, "quantity": 0},
    {"id": article_id, "quantity": 0},
    {"offerId": offer_id, "quantity": 0},
    {"remove": True, "articleId": article_id},
]

successful = []

for endpoint in endpoints_405:
    for payload in payloads:
        print(f"[*] POST {endpoint}")
        print(f"    Payload: {json.dumps(payload)}")
        try:
            r = requests.post(f"{BASE_URL}{endpoint}", headers=headers, json=payload, timeout=5)
            print(f"    HTTP {r.status_code}")
            
            if r.status_code in [200, 204]:
                print(f"    [!!!] SUCCESS!")
                print(f"    Response: {r.text[:300]}")
                successful.append((endpoint, payload, r.status_code, r.text[:500]))
                break
            elif r.status_code == 400:
                print(f"    [!] Bad Request: {r.text[:150]}")
            elif r.status_code not in [404, 405]:
                print(f"    Response: {r.text[:150]}")
        except Exception as e:
            print(f"    Error: {e}")

# Also try the main cart endpoint with different actions
print()
print("[*] Testing main cart endpoint with actions...")
main_endpoint = f"/checkout/api/cart-api/v2/cart/{CART_UUID}"

actions = [
    {"action": "removeArticle", "articleId": article_id},
    {"action": "updateArticle", "articleId": article_id, "quantity": 0},
    {"action": "remove", "articleId": article_id},
    {"method": "removeArticle", "articleId": article_id},
    {"op": "remove", "articleId": article_id},
]

for action in actions:
    print(f"[*] POST {main_endpoint}")
    print(f"    Payload: {json.dumps(action)}")
    try:
        r = requests.post(f"{BASE_URL}{main_endpoint}", headers=headers, json=action, timeout=5)
        print(f"    HTTP {r.status_code}")
        
        if r.status_code in [200, 204]:
            print(f"    [!!!] SUCCESS!")
            print(f"    Response: {r.text[:300]}")
            successful.append((main_endpoint, action, r.status_code, r.text[:500]))
        elif r.status_code == 400:
            print(f"    [!] Bad Request: {r.text[:150]}")
        elif r.status_code not in [404, 405]:
            print(f"    Response: {r.text[:150]}")
    except Exception as e:
        print(f"    Error: {e}")

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
        print(f"[!!!] Before: {before_count} items, {before_total} EUR")
        print(f"[!!!] After:  {after_count} items, {after_total} EUR")

if successful:
    print()
    print("[!!!] WORKING ENDPOINTS FOUND:")
    for endpoint, payload, status, response in successful:
        print(f"[!!!] POST {endpoint}")
        print(f"      Payload: {json.dumps(payload)}")
        print(f"      Status: {status}")
        print(f"      Response: {response[:200]}")
        print()
else:
    print()
    print("[!] No working endpoints found")
    print("[!] Modification may be handled client-side or require different authentication")

