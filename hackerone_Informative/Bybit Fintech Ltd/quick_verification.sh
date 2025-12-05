#!/bin/bash
# Quick verification script for CORS vulnerability
# Run this to get proof screenshot

echo "=========================================="
echo "CORS VULNERABILITY VERIFICATION"
echo "=========================================="
echo ""
echo "Testing with evil.com origin..."
echo ""

curl -v -H "Origin: https://evil.com" \
  "https://api.bybit.com/v5/account/wallet-balance?accountType=UNIFIED" 2>&1 | \
  grep -i "access-control"

echo ""
echo "=========================================="
echo "If you see:"
echo "  Access-Control-Allow-Origin: https://evil.com"
echo "  Access-Control-Allow-Credentials: true"
echo ""
echo "Then vulnerability is CONFIRMED!"
echo "=========================================="
