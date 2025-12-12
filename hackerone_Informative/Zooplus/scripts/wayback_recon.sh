#!/bin/bash

# Wayback Machine Reconnaissance
# Находит исторические endpoints и sensitive files

DOMAIN="zooplus.de"
OUTPUT="reports/wayback_urls.txt"

echo "================================================================================"
echo "WAYBACK MACHINE RECONNAISSANCE"
echo "================================================================================"

mkdir -p reports

echo "[*] Fetching URLs from Wayback Machine..."

# Get all URLs from Wayback
curl -s "http://web.archive.org/cdx/search/cdx?url=*.$DOMAIN/*&output=text&fl=original&collapse=urlkey" | \
    sort -u > "$OUTPUT"

TOTAL=$(wc -l < "$OUTPUT")
echo "[+] Found $TOTAL unique URLs"

echo "" 
echo "[*] Filtering interesting endpoints..."

# Filter API endpoints
echo "API Endpoints:" | tee reports/wayback_api.txt
grep -iE "/api/|/rest/|/graphql" "$OUTPUT" | tee -a reports/wayback_api.txt

# Admin panels
echo "" | tee -a reports/wayback_admin.txt
echo "Admin Panels:" | tee -a reports/wayback_admin.txt
grep -iE "/admin|/dashboard|/panel|/manage" "$OUTPUT" | tee -a reports/wayback_admin.txt

# Config/sensitive files
echo "" | tee -a reports/wayback_sensitive.txt
echo "Sensitive Files:" | tee -a reports/wayback_sensitive.txt
grep -iE "\.env|config\.|\.sql|\.bak|\.zip|\.tar|\.gz|backup|\.git" "$OUTPUT" | tee -a reports/wayback_sensitive.txt

# Authentication endpoints
echo "" | tee -a reports/wayback_auth.txt
echo "Auth Endpoints:" | tee -a reports/wayback_auth.txt
grep -iE "/login|/auth|/oauth|/sso|/signin|/signup|/register|/password" "$OUTPUT" | tee -a reports/wayback_auth.txt

echo ""
echo "[+] Results saved:"
echo "  - All URLs: reports/wayback_urls.txt"
echo "  - API endpoints: reports/wayback_api.txt"
echo "  - Admin panels: reports/wayback_admin.txt"
echo "  - Sensitive files: reports/wayback_sensitive.txt"
echo "  - Auth endpoints: reports/wayback_auth.txt"

