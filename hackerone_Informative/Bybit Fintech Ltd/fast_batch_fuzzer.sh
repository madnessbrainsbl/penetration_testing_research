#!/bin/bash
# FAST BATCH FUZZER - Pure Bash
# Tests all batch endpoints with fake IDs to find information disclosure

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE="https://api.bybit.com"

# Get server time offset
SERVER_TIME=$(curl -s "$BASE/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4)
LOCAL_TIME=$(date +%s)
OFFSET=$((SERVER_TIME - LOCAL_TIME))

echo "Server offset: ${OFFSET}s"

# Helper function to sign request
sign_request() {
    local payload=$1
    local ts=$(($(date +%s) + OFFSET))000
    local recv="60000"
    local str="${ts}${API_KEY}${recv}${payload}"
    local sig=$(echo -n "$str" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')
    
    echo "$ts|$sig|$recv"
}

# Test endpoints
ENDPOINTS=(
    "/v5/order/create-batch"
    "/v5/order/amend-batch"
    "/v5/order/cancel-batch"
    "/v5/asset/transfer/inter-transfer-batch"
    "/v5/position/set-leverage-batch"
)

echo ""
echo "=========================================="
echo "FUZZING BATCH ENDPOINTS"
echo "=========================================="

for endpoint in "${ENDPOINTS[@]}"; do
    echo ""
    echo "Testing: $endpoint"
    
    # Different payloads for different endpoints
    if [[ $endpoint == *"order"* ]]; then
        PAYLOAD='{"category":"linear","request":[{"symbol":"BTCUSDT","orderId":"00000000-1111-2222-3333-444444444444","qty":"0.001"}]}'
    elif [[ $endpoint == *"transfer"* ]]; then
        PAYLOAD='{"transfers":[{"fromMemberId":"1","toMemberId":"2","coin":"USDT","amount":"1"}]}'
    else
        PAYLOAD='{"category":"linear","list":[{"symbol":"BTCUSDT","leverage":"1"}]}'
    fi
    
    IFS='|' read -r ts sig recv <<< $(sign_request "$PAYLOAD")
    
    response=$(curl -s -X POST "$BASE$endpoint" \
        -H "X-BAPI-API-KEY: $API_KEY" \
        -H "X-BAPI-SIGN: $sig" \
        -H "X-BAPI-SIGN-TYPE: 2" \
        -H "X-BAPI-TIMESTAMP: $ts" \
        -H "X-BAPI-RECV-WINDOW: $recv" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" 2>&1)
    
    retCode=$(echo "$response" | grep -o '"retCode":[0-9]*' | cut -d':' -f2)
    
    if [ "$retCode" == "0" ]; then
        echo "  ✓ STATUS: SUCCESS (retCode 0)"
        
        # Check for order not exists
        if echo "$response" | grep -q "110001"; then
            echo "  🚨 FOUND: 'order not exists' - Information Disclosure!"
            echo "  Response: $response" | head -c 200
            echo ""
        fi
        
        # Check for permission denied
        if echo "$response" | grep -qi "permission\|access denied"; then
            echo "  ✓ Secure: Permission check works"
        fi
    elif [ "$retCode" == "10001" ]; then
        echo "  ⚠️  Auth error (check keys)"
    else
        echo "  ✗ RetCode: $retCode"
        echo "  Msg: $(echo "$response" | grep -o '"retMsg":"[^"]*"' | cut -d'"' -f4)"
    fi
done

echo ""
echo "=========================================="
echo "FUZZING COMPLETE"
echo "=========================================="
