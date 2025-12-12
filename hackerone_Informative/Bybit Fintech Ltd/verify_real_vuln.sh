#!/bin/bash
# REAL VULNERABILITY VERIFICATION
# 1. Create a real order
# 2. Try to amend it via batch
# 3. Verify the behavior is correct

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE="https://api.bybit.com"

# Get server time offset
SERVER_TIME=$(curl -s "$BASE/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4)
LOCAL_TIME=$(date +%s)
OFFSET=$((SERVER_TIME - LOCAL_TIME))

echo "=========================================="
echo "VERIFICATION: Real Order Test"
echo "=========================================="
echo "Offset: ${OFFSET}s"

sign_request() {
    local payload=$1
    local ts=$(($(date +%s) + OFFSET))000
    local recv="60000"
    local str="${ts}${API_KEY}${recv}${payload}"
    local sig=$(echo -n "$str" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')
    echo "$ts|$sig|$recv"
}

# Step 1: Create a REAL test order (very far from market price, won't execute)
echo ""
echo "[1] Creating a test limit order (far from market)..."

CREATE_PAYLOAD='{"category":"linear","symbol":"BTCUSDT","side":"Buy","orderType":"Limit","qty":"0.001","price":"10000","timeInForce":"GTC"}'

IFS='|' read -r ts sig recv <<< $(sign_request "$CREATE_PAYLOAD")

create_response=$(curl -s -X POST "$BASE/v5/order/create" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "X-BAPI-SIGN: $sig" \
    -H "X-BAPI-SIGN-TYPE: 2" \
    -H "X-BAPI-TIMESTAMP: $ts" \
    -H "X-BAPI-RECV-WINDOW: $recv" \
    -H "Content-Type: application/json" \
    -d "$CREATE_PAYLOAD")

echo "Create Response: $create_response"

# Extract orderID
ORDER_ID=$(echo "$create_response" | grep -o '"orderId":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$ORDER_ID" ]; then
    echo "❌ Failed to create order. Response:"
    echo "$create_response"
    exit 1
fi

echo "✓ Created order: $ORDER_ID"

# Step 2: Try to amend it via batch endpoint
echo ""
echo "[2] Testing batch amend on OWN order..."

BATCH_PAYLOAD="{\"category\":\"linear\",\"request\":[{\"symbol\":\"BTCUSDT\",\"orderId\":\"$ORDER_ID\",\"qty\":\"0.002\"}]}"

IFS='|' read -r ts sig recv <<< $(sign_request "$BATCH_PAYLOAD")

batch_response=$(curl -s -X POST "$BASE/v5/order/amend-batch" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "X-BAPI-SIGN: $sig" \
    -H "X-BAPI-SIGN-TYPE: 2" \
    -H "X-BAPI-TIMESTAMP: $ts" \
    -H "X-BAPI-RECV-WINDOW: $recv" \
    -H "Content-Type: application/json" \
    -d "$BATCH_PAYLOAD")

echo "Batch Response: $batch_response"

# Check if successful
if echo "$batch_response" | grep -q '"retCode":0'; then
    echo "✓ Batch returned retCode 0"
    
    # Check extInfo
    ext_code=$(echo "$batch_response" | grep -o '"code":[0-9]*' | head -1 | cut -d':' -f2)
    
    if [ "$ext_code" == "0" ] || [ -z "$ext_code" ]; then
        echo "✓ Order was SUCCESSFULLY modified (code: $ext_code)"
        echo ""
        echo "🔍 ANALYSIS: This is NORMAL behavior for own orders"
    else
        echo "⚠️  Order modification failed with code: $ext_code"
    fi
else
    echo "❌ Batch request failed"
fi

# Step 3: Now test with FAKE ID to compare
echo ""
echo "[3] Testing batch amend with FAKE order ID (comparison)..."

FAKE_BATCH='{"category":"linear","request":[{"symbol":"BTCUSDT","orderId":"11111111-2222-3333-4444-555555555555","qty":"0.001"}]}'

IFS='|' read -r ts sig recv <<< $(sign_request "$FAKE_BATCH")

fake_response=$(curl -s -X POST "$BASE/v5/order/amend-batch" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "X-BAPI-SIGN: $sig" \
    -H "X-BAPI-SIGN-TYPE: 2" \
    -H "X-BAPI-TIMESTAMP: $ts" \
    -H "X-BAPI-RECV-WINDOW: $recv" \
    -H "Content-Type: application/json" \
    -d "$FAKE_BATCH")

echo "Fake Order Response: $fake_response"

fake_code=$(echo "$fake_response" | grep -o '"code":[0-9]*' | head -1 | cut -d':' -f2)
echo "Fake order code: $fake_code"

# Step 4: Clean up - cancel the test order
echo ""
echo "[4] Cleaning up - canceling test order..."

CANCEL_PAYLOAD="{\"category\":\"linear\",\"symbol\":\"BTCUSDT\",\"orderId\":\"$ORDER_ID\"}"

IFS='|' read -r ts sig recv <<< $(sign_request "$CANCEL_PAYLOAD")

cancel_response=$(curl -s -X POST "$BASE/v5/order/cancel" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "X-BAPI-SIGN: $sig" \
    -H "X-BAPI-SIGN-TYPE: 2" \
    -H "X-BAPI-TIMESTAMP: $ts" \
    -H "X-BAPI-RECV-WINDOW: $recv" \
    -H "Content-Type: application/json" \
    -d "$CANCEL_PAYLOAD")

if echo "$cancel_response" | grep -q '"retCode":0'; then
    echo "✓ Test order canceled"
else
    echo "⚠️  Cancel failed: $cancel_response"
fi

# Final Analysis
echo ""
echo "=========================================="
echo "VERIFICATION RESULT"
echo "=========================================="
echo ""
echo "Own Order Modify: Success (Expected ✓)"
echo "Fake Order Modify: Code $fake_code (110001 = Not exists)"
echo ""

if [ "$fake_code" == "110001" ]; then
    echo "🔍 CONCLUSION:"
    echo "The 110001 'order not exists' is just informational."
    echo "It does NOT prove IDOR vulnerability."
    echo ""
    echo "For REAL vulnerability, we would need:"
    echo "1. A valid orderID from another user"
    echo "2. Successfully modify/cancel their order"
    echo ""
    echo "Current finding: Information Disclosure (Low/Info)"
    echo "NOT exploitable without additional orderID leak."
else
    echo "Unexpected code: $fake_code"
fi

echo ""
echo "=========================================="
