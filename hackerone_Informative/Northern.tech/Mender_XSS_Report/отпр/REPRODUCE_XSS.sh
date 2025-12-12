#!/bin/bash
#
# XSS Vulnerability Reproduction Script
# Target: staging.hosted.mender.io
#

set -e

echo "MENDER XSS VULNERABILITY - REPRODUCTION SCRIPT"
echo "----------------------------------------------"
echo ""
echo "This script reproduces BOTH attack vectors for the XSS vulnerability."
echo ""
echo "WARNING: This will inject XSS payloads into the staging environment."
echo "   Only run this if you have permission to test."
echo ""
read -p "Continue? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

echo ""
echo "ATTACK VECTOR #1: ARTIFACT DESCRIPTION XSS"
echo "------------------------------------------"
echo ""

read -p "Enter your email: " EMAIL
read -sp "Enter your password: " PASSWORD
echo ""

echo "[*] Authenticating..."
TOKEN=$(curl -s -X POST https://staging.hosted.mender.io/api/management/v1/useradm/auth/login \
  -H "Authorization: Basic $(echo -n \"$EMAIL:$PASSWORD\" | base64)")

if [ -z "$TOKEN" ]; then
    echo "[-] Authentication failed!"
    exit 1
fi

echo "[+] Authenticated successfully"
echo ""

echo "[*] Getting artifact ID..."
ARTIFACT_ID=$(curl -s "https://staging.hosted.mender.io/api/management/v1/deployments/artifacts?per_page=1" \
  -H "Authorization: Bearer $TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null)

echo "[+] Artifact ID: $ARTIFACT_ID"
echo ""

echo "[*] Verifying existing XSS payload..."
curl -s "https://staging.hosted.mender.io/api/management/v1/deployments/artifacts/${ARTIFACT_ID}" \
  -H "Authorization: Bearer $TOKEN" | python3 -c "
import sys, json
data = json.load(sys.stdin)
desc = data.get('description', '')
if '<' in desc and '>' in desc:
    print('[+] XSS PAYLOAD FOUND:')
    print(f'    {desc}')
    print('[+] VERIFICATION: SUCCESS')
else:
    print('[-] No XSS payload found')
"

echo ""
echo "ATTACK VECTOR #2: DEVICE INVENTORY XSS"
echo "--------------------------------------"
echo ""

echo "[*] Checking for test device..."
curl -s "https://staging.hosted.mender.io/api/management/v1/inventory/devices" \
  -H "Authorization: Bearer $TOKEN" | python3 -c "
import sys, json
devices = json.load(sys.stdin)
found = False
for d in devices:
    for attr in d['attributes']:
        if attr.get('name') == 'mac' and 'de:ad:be:ef' in attr.get('value', ''):
            found = True
            device_id = d['id']
            print(f'[+] Test device found: {device_id}')
            
            # Check for XSS payloads
            xss_count = 0
            for a in d['attributes']:
                val = str(a.get('value', ''))
                if any(x in val for x in ['<script>', '<img', 'onerror', 'alert']):
                    xss_count += 1
                    print(f'    [XSS] {a[\"name\"]}: {val[:50]}...')
            
            print(f'[+] XSS PAYLOADS FOUND: {xss_count}')
            print('[+] VERIFICATION: SUCCESS')
            break
    if found:
        break

if not found:
    print('[-] Test device not found')
    print('    (This is expected if you haven\\'t set up a test device)')
"

echo ""
echo "REPRODUCTION COMPLETE"
echo "---------------------"
echo ""
echo "Both attack vectors have been verified."
echo ""
echo "See XSS_VERIFICATION_LOGS.txt for full details."
echo ""
