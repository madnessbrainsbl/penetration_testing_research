#!/bin/bash
# API BRUTE FORCE FOR ACCESS
# Target: Find ANY working endpoint with current keys

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE="https://api.bybit.com"

# Sync Time
SERVER_TIME=$(curl -s "$BASE/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4)
OFFSET=$((SERVER_TIME - $(date +%s)))

sign() {
    local p=$1
    local t=$(($(date +%s) + OFFSET))000
    local s=$(echo -n "${t}${API_KEY}5000${p}" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')
    echo "$t|$s"
}

call() {
    local ep=$1
    local pay=$2 # Empty for GET usually, but V5 POSTs often need empty json
    local method=$3
    
    IFS='|' read -r ts sig <<< $(sign "$pay")
    
    resp=$(curl -s -X $method "$BASE$ep" \
        -H "X-BAPI-API-KEY: $API_KEY" \
        -H "X-BAPI-SIGN: $sig" \
        -H "X-BAPI-SIGN-TYPE: 2" \
        -H "X-BAPI-TIMESTAMP: $ts" \
        -H "X-BAPI-RECV-WINDOW: 5000" \
        -H "Content-Type: application/json" \
        -d "$pay")
        
    code=$(echo "$resp" | grep -o '"retCode":[0-9]*' | cut -d':' -f2)
    msg=$(echo "$resp" | grep -o '"retMsg":"[^"]*"' | cut -d'"' -f4)
    
    if [ "$code" == "0" ]; then
        echo "✅ [OPEN] $ep"
        echo "   -> $resp"
    elif [ "$code" == "10005" ]; then
        echo "🔒 [DENIED] $ep"
    elif [ "$code" == "" ]; then
        echo "❓ [404/ERR] $ep"
    else
        echo "⚠️  [$code] $ep ($msg)"
    fi
}

echo "=== BRUTE FORCING API ENDPOINTS ==="

# LIST OF TARGETS
# Asset
call "/v5/asset/transfer/query-asset-info" "" "GET"
call "/v5/asset/deposit/query-record" "" "GET"
call "/v5/asset/withdraw/query-record" "" "GET"
call "/v5/asset/coin/query-info" "" "GET"

# User
call "/v5/user/query-api" "" "GET"
call "/v5/user/get-member-type" "" "GET"
call "/v5/user/affiliate/info" "" "GET"

# Account
call "/v5/account/info" "" "GET"
call "/v5/account/wallet-balance" "accountType=UNIFIED" "GET"
call "/v5/account/fee-rate" "category=linear&symbol=BTCUSDT" "GET"

# Broker / Partner (Often weak auth)
call "/v5/broker/earning-record" "" "GET"
call "/v5/broker/account-info" "" "GET"

# Spot
call "/v5/spot-margin-trade/interest-quota" "token=USDT" "GET"

echo "=== DONE ==="
