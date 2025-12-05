#!/bin/bash
# Check existing orders and test with them

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE="https://api.bybit.com"

SERVER_TIME=$(curl -s "$BASE/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4)
LOCAL_TIME=$(date +%s)
OFFSET=$((SERVER_TIME - LOCAL_TIME))

sign_request() {
    local payload=$1
    local ts=$(($(date +%s) + OFFSET))000
    local recv="60000"
    local str="${ts}${API_KEY}${recv}${payload}"
    local sig=$(echo -n "$str" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')
    echo "$ts|$sig|$recv"
}

echo "=========================================="
echo "CHECKING EXISTING ORDERS"
echo "=========================================="

# Check open orders
QUERY="category=linear"
IFS='|' read -r ts sig recv <<< $(sign_request "$QUERY")

orders_response=$(curl -s "$BASE/v5/order/realtime?$QUERY" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "X-BAPI-SIGN: $sig" \
    -H "X-BAPI-SIGN-TYPE: 2" \
    -H "X-BAPI-TIMESTAMP: $ts" \
    -H "X-BAPI-RECV-WINDOW: $recv")

echo "Orders Response:"
echo "$orders_response"

# Try SPOT if linear doesn't work
echo ""
echo "Trying SPOT category..."

QUERY2="category=spot"
IFS='|' read -r ts sig recv <<< $(sign_request "$QUERY2")

spot_response=$(curl -s "$BASE/v5/order/realtime?$QUERY2" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "X-BAPI-SIGN: $sig" \
    -H "X-BAPI-SIGN-TYPE: 2" \
    -H "X-BAPI-TIMESTAMP: $ts" \
    -H "X-BAPI-RECV-WINDOW: $recv")

echo "$spot_response"

echo ""
echo "=========================================="
echo "CRITICAL ANALYSIS"
echo "=========================================="
echo ""
echo "If account has NO trading permissions (retCode 10024),"
echo "then the 'vulnerability' is NOT exploitable because:"
echo ""
echo "1. Can't create orders to test"
echo "2. Can't modify orders (even own)"
echo "3. Other users likely have same restrictions"
echo ""
echo "🔍 REVISED CONCLUSION:"
echo "The '110001 order not exists' response is likely:"
echo "- Standard API behavior for batch operations"
echo "- NOT a vulnerability, just informational"
echo ""
echo "WITHOUT ability to:"
echo "- Create real orders"
echo "- Obtain real orderIDs from other users"
echo "- Test cross-user modification"
echo ""
echo "This is NOT a confirmed vulnerability."
echo ""
echo "It's just API returning standard error codes."
echo "=========================================="
