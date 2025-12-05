#!/bin/bash
# FIX: Reliable parsing

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE="https://api.bybit.com"
UID="527465456"

OFFSET=$(($(curl -s "$BASE/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4) - $(date +%s)))

sign() {
    local p=$1
    local t=$(($(date +%s) + OFFSET))000
    local s=$(echo -n "${t}${API_KEY}5000${p}" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')
    echo "$t|$s"
}

test_req() {
    local name=$1
    local payload=$2
    
    echo "--- $name ---"
    IFS='|' read -r ts sig <<< $(sign "$payload")
    
    resp=$(curl -s -X POST "$BASE/v5/asset/transfer/inter-transfer" \
        -H "X-BAPI-API-KEY: $API_KEY" \
        -H "X-BAPI-SIGN: $sig" \
        -H "X-BAPI-SIGN-TYPE: 2" \
        -H "X-BAPI-TIMESTAMP: $ts" \
        -H "X-BAPI-RECV-WINDOW: 5000" \
        -H "Content-Type: application/json" \
        -d "$payload")
    
    echo "Body: $resp"
    
    if echo "$resp" | grep -q "10016"; then
        echo "Result: 🚨 10016 SYSTEM ERROR"
    else
        echo "Result: Normal / Other Error"
    fi
    echo ""
}

echo "VERIFICATION RELOADED"
UUID=$(cat /proc/sys/kernel/random/uuid)
test_req "Self Transfer" "{\"transferId\":\"$UUID\",\"coin\":\"USDT\",\"amount\":\"0.01\",\"fromMemberId\":$UID,\"toMemberId\":$UID}"

UUID=$(cat /proc/sys/kernel/random/uuid)
test_req "Negative Amount" "{\"transferId\":\"$UUID\",\"coin\":\"USDT\",\"amount\":\"-100\",\"fromMemberId\":$UID,\"toMemberId\":$UID}"
