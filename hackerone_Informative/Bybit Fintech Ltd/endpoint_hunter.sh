#!/bin/bash
# ENDPOINT HUNTER: Earn & Transfer
# Fuzzes for hidden/legacy endpoints that might bypass checks

BASE="https://api.bybit.com"
API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"

# Sync Time
OFFSET=$(($(curl -s "$BASE/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4) - $(date +%s)))

sign() {
    local p=$1
    local t=$(($(date +%s) + OFFSET))000
    local s=$(echo -n "${t}${API_KEY}5000${p}" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')
    echo "$t|$s"
}

# Payload doesn't matter much for 404 vs 403/200 check, but valid JSON helps
PAYLOAD='{"test":"1"}'
IFS='|' read -r ts sig <<< $(sign "$PAYLOAD")

echo "=========================================="
echo "HUNTING FOR LIVE ENDPOINTS"
echo "=========================================="

TARGETS=(
    # Earn / Lending
    "/v5/earn/order/create"
    "/v5/earn/lend/order"
    "/v5/lending/purchase"
    "/v5/ins-loan/product-info"
    "/v5/spot-cross-margin-trade/loan"
    "/v5/earn/flexible/subscribe"
    "/v5/earn/fixed/subscribe"
    "/v5/institution/loan"
    # Legacy Transfer
    "/v5/asset/transfer/inter-transfer"
    "/v5/asset/transfer/save-transfer"
    "/v1/asset/transfer"
    "/v3/asset/transfer"
    "/v5/account/transfer"
    # Legacy Subaccount
    "/v3/user/create-sub-member"
    "/v1/user/create-sub-member"
    "/v5/user/sub-apikeys"
)

for path in "${TARGETS[@]}"; do
    # Check POST
    resp=$(curl -s -w "%{http_code}" -X POST "$BASE$path" \
        -H "X-BAPI-API-KEY: $API_KEY" \
        -H "X-BAPI-SIGN: $sig" \
        -H "X-BAPI-SIGN-TYPE: 2" \
        -H "X-BAPI-TIMESTAMP: $ts" \
        -H "X-BAPI-RECV-WINDOW: 5000" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD")
    
    code=${resp: -3}
    body=${resp::-3}
    
    if [ "$code" != "404" ]; then
        echo "✅ FOUND: $path (Code: $code)"
        echo "   Response: ${body:0:100}..."
        
        # If we found the Earn endpoint, mark it!
        if [[ $path == *"/earn/"* ]]; then
             echo "   🎯 POTENTIAL EARN VECTOR!"
        fi
    else
        # echo "   (404) $path" 
        :
    fi
done

echo "=========================================="
