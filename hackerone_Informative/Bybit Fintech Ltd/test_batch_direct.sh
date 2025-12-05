#!/bin/bash
# Direct CURL test for batch endpoint

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"

# Payload with fake IDs
PAYLOAD='{"category":"linear","request":[{"symbol":"BTCUSDT","orderId":"fake-id-1","qty":"0.001"},{"symbol":"BTCUSDT","orderId":"fake-id-2","qty":"0.001"}]}'

# Get timestamp
TS=$(date +%s)000

# Sign
SIG=$(echo -n "${TS}${API_KEY}5000${PAYLOAD}" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

echo "Testing /v5/order/amend-batch"
echo "Timestamp: $TS"
echo "Signature: $SIG"
echo ""

curl -v -X POST "https://api.bybit.com/v5/order/amend-batch" \
  -H "X-BAPI-API-KEY: $API_KEY" \
  -H "X-BAPI-SIGN: $SIG" \
  -H "X-BAPI-SIGN-TYPE: 2" \
  -H "X-BAPI-TIMESTAMP: $TS" \
  -H "X-BAPI-RECV-WINDOW: 5000" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" 2>&1 | grep -A 20 "HTTP"
