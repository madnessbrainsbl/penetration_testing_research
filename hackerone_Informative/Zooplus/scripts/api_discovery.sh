#!/bin/bash

# API Discovery и Testing для Zooplus

TARGET="www.zooplus.de"
BASE_URL="https://$TARGET"
OUTPUT="reports/api_discovery.txt"

echo "================================================================================"
echo "API DISCOVERY & TESTING"
echo "================================================================================"

mkdir -p reports

# Common API endpoints to test
API_ENDPOINTS=(
    "/api"
    "/api/v1"
    "/api/v2"
    "/api/v3"
    "/graphql"
    "/rest"
    "/rest/v1"
    "/rest/v2"
    "/api/auth"
    "/api/user"
    "/api/users"
    "/api/customer"
    "/api/customers"
    "/api/orders"
    "/api/order"
    "/api/products"
    "/api/product"
    "/api/cart"
    "/api/checkout"
    "/api/payment"
    "/api/profile"
    "/api/admin"
    "/api/config"
    "/api/settings"
    "/api/swagger"
    "/api/docs"
    "/api-docs"
    "/swagger"
    "/swagger.json"
    "/swagger/v1/swagger.json"
    "/api/swagger.json"
    "/openapi.json"
    "/v2/api-docs"
    "/v3/api-docs"
)

echo "[*] Testing common API endpoints..." | tee "$OUTPUT"

for endpoint in "${API_ENDPOINTS[@]}"; do
    URL="$BASE_URL$endpoint"
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$URL")
    
    if [ "$RESPONSE" != "404" ] && [ "$RESPONSE" != "000" ]; then
        echo "[+] $endpoint - Status: $RESPONSE" | tee -a "$OUTPUT"
        
        # Get full response for interesting endpoints
        if [ "$RESPONSE" = "200" ]; then
            echo "    Fetching content..."
            curl -s "$URL" | head -20 >> "$OUTPUT"
        fi
    fi
done

echo "" | tee -a "$OUTPUT"
echo "[*] Testing GraphQL introspection..." | tee -a "$OUTPUT"

# GraphQL introspection query
GRAPHQL_QUERY='{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"}'

for endpoint in "/graphql" "/api/graphql" "/v1/graphql"; do
    echo "[*] Testing: $BASE_URL$endpoint"
    RESPONSE=$(curl -s -X POST "$BASE_URL$endpoint" \
        -H "Content-Type: application/json" \
        -d "$GRAPHQL_QUERY" 2>/dev/null)
    
    if echo "$RESPONSE" | grep -q "__schema"; then
        echo "[!!!] GraphQL introspection ENABLED at $endpoint" | tee -a "$OUTPUT"
        echo "$RESPONSE" | jq '.' 2>/dev/null | head -100 >> "$OUTPUT"
    fi
done

echo "" | tee -a "$OUTPUT"
echo "[+] API Discovery complete. Results in: $OUTPUT"

