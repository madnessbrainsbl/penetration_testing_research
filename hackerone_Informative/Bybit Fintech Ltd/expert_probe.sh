#!/bin/bash
# MANUAL CURL PROBE FOR EXPERT VECTORS

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE="https://api.bybit.com"

# Helper to sign
sign() {
    params=$1
    ts=$(date +%s)000
    # Simple python one-liner to sign because bash hmac is pain
    sig=$(python3 -c "import hmac, hashlib; print(hmac.new(b'$API_SECRET', b'$ts$API_KEY5000$params', hashlib.sha256).hexdigest())")
    echo "$ts $sig"
}

echo "=========================================="
echo "EXPERT VECTOR PROBE"
echo "=========================================="

# 1. Trading Stop Probe (Non-existent ID)
echo -e "\n[1] /v5/position/trading-stop (Random PositionIdx)"
payload='{"category":"linear","symbol":"BTCUSDT","takeProfit":"100000","positionIdx":999}'
read ts sig <<< $(sign "$payload")

curl -s -X POST "$BASE/v5/position/trading-stop" \
  -H "X-BAPI-API-KEY: $API_KEY" \
  -H "X-BAPI-SIGN: $sig" \
  -H "X-BAPI-SIGN-TYPE: 2" \
  -H "X-BAPI-TIMESTAMP: $ts" \
  -H "X-BAPI-RECV-WINDOW: 5000" \
  -H "Content-Type: application/json" \
  -d "$payload"
echo ""

# 2. Order Amend Probe (Random UUID)
echo -e "\n[2] /v5/order/amend (Random OrderId)"
payload='{"category":"linear","symbol":"BTCUSDT","orderId":"11111111-1111-1111-1111-111111111111","qty":"0.1"}'
read ts sig <<< $(sign "$payload")

curl -s -X POST "$BASE/v5/order/amend" \
  -H "X-BAPI-API-KEY: $API_KEY" \
  -H "X-BAPI-SIGN: $sig" \
  -H "X-BAPI-SIGN-TYPE: 2" \
  -H "X-BAPI-TIMESTAMP: $ts" \
  -H "X-BAPI-RECV-WINDOW: 5000" \
  -H "Content-Type: application/json" \
  -d "$payload"
echo ""

# 3. Transfer Query (Random ID) - GET Request
echo -e "\n[3] /v5/asset/transfer/query-inter-transfer-list-by-id (Random TransferId)"
# For GET, params are sorted. transferId=...
tid="11111111-1111-1111-1111-111111111111"
params="transferId=$tid"
read ts sig <<< $(sign "$params")

curl -s "$BASE/v5/asset/transfer/query-inter-transfer-list-by-id?transferId=$tid" \
  -H "X-BAPI-API-KEY: $API_KEY" \
  -H "X-BAPI-SIGN: $sig" \
  -H "X-BAPI-SIGN-TYPE: 2" \
  -H "X-BAPI-TIMESTAMP: $ts" \
  -H "X-BAPI-RECV-WINDOW: 5000"
echo ""

# 4. Mobile Spoofing
echo -e "\n[4] Mobile Header Spoofing"
payload='{}'
read ts sig <<< $(sign "$payload") # empty payload for GET logic usually but let's try standard endpoint
# Signing empty param string for GET /v5/user/query-api?
read ts sig <<< $(sign "")

curl -s "$BASE/v5/user/query-api" \
  -H "X-BAPI-API-KEY: $API_KEY" \
  -H "X-BAPI-SIGN: $sig" \
  -H "X-BAPI-SIGN-TYPE: 2" \
  -H "X-BAPI-TIMESTAMP: $ts" \
  -H "User-Agent: Bybit/4.32.0 (Android 13; Pixel 7)" \
  -H "platform: android" \
  -H "X-App-Version: 4.32.0"
echo ""
