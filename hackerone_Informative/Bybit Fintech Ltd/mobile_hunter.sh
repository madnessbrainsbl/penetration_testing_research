#!/bin/bash
# MOBILE API HUNTER - Tests /app/ endpoints

BASE="https://api.bybit.com"

echo "=========================================="
echo "MOBILE ENDPOINT DISCOVERY"
echo "=========================================="

# Common mobile paths
PATHS=(
    "/app/v1/user/info"
    "/app/v1/user/referral"
    "/app/v1/user/referral/update"
    "/app/v1/user/profile"
    "/app/v1/asset/balance"
    "/app/v1/asset/transfer"
    "/app/v1/order/create"
    "/app/v2/user/info"
    "/app/v2/user/referral"
    "/app/config/version"
    "/app/earn/products"
)

for path in "${PATHS[@]}"; do
    # Try GET first
    response=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
        -H "User-Agent: Bybit/4.32.0 (Android 13)" \
        -H "platform: android" \
        -H "X-App-Version: 4.32.0" \
        "$BASE$path" 2>&1)
    
    http_code=$(echo "$response" | grep "HTTP_CODE" | cut -d':' -f2)
    
    if [ "$http_code" != "404" ] && [ "$http_code" != "403" ]; then
        echo ""
        echo "✓ FOUND: $path (HTTP $http_code)"
        echo "$response" | head -5
    fi
done

echo ""
echo "=========================================="
echo "MOBILE SCAN COMPLETE"
echo "=========================================="
