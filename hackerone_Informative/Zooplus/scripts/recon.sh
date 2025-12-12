#!/bin/bash

# Full Reconnaissance Script для Zooplus
# Быстрая разведка с использованием стандартных Unix утилит

TARGET="www.zooplus.de"
DOMAIN="zooplus.de"
OUTPUT_DIR="reports/recon"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "================================================================================"
echo "ZOOPLUS RECONNAISSANCE"
echo "Target: $TARGET"
echo "Date: $(date)"
echo "================================================================================"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# PHASE 1: Basic HTTP Info
echo -e "\n${YELLOW}[*] PHASE 1: HTTP Headers & Server Info${NC}"
echo "--------------------------------------------------------------------------------"

curl -s -I "https://$TARGET" | tee "$OUTPUT_DIR/headers.txt"

echo -e "\n${GREEN}[+] Detecting technologies from headers...${NC}"
curl -s -I "https://$TARGET" | grep -iE "server|x-powered-by|x-aspnet|via|x-cache|cf-ray" | tee -a "$OUTPUT_DIR/tech_stack.txt"

# PHASE 2: Technology Detection
echo -e "\n${YELLOW}[*] PHASE 2: Technology Stack Detection${NC}"
echo "--------------------------------------------------------------------------------"

echo "[*] Downloading homepage..."
curl -s "https://$TARGET" > "$OUTPUT_DIR/homepage.html"

echo "[*] Searching for JavaScript frameworks..."
grep -oiE "(react|vue\.js|angular|jquery|next\.js|nuxt)" "$OUTPUT_DIR/homepage.html" | sort -u | tee -a "$OUTPUT_DIR/tech_stack.txt"

echo -e "\n[*] Searching for CMS/Platform..."
if grep -qi "wp-content\|wp-includes" "$OUTPUT_DIR/homepage.html"; then
    echo -e "${GREEN}[+] WordPress detected${NC}" | tee -a "$OUTPUT_DIR/tech_stack.txt"
fi

if grep -qi "drupal\|/sites/default" "$OUTPUT_DIR/homepage.html"; then
    echo -e "${GREEN}[+] Drupal detected${NC}" | tee -a "$OUTPUT_DIR/tech_stack.txt"
fi

if grep -qi "magento\|mage\." "$OUTPUT_DIR/homepage.html"; then
    echo -e "${GREEN}[+] Magento detected${NC}" | tee -a "$OUTPUT_DIR/tech_stack.txt"
fi

# PHASE 3: JavaScript Files Discovery
echo -e "\n${YELLOW}[*] PHASE 3: JavaScript Files Discovery${NC}"
echo "--------------------------------------------------------------------------------"

echo "[*] Extracting JavaScript URLs..."
grep -oE 'src="[^"]+\.js[^"]*"' "$OUTPUT_DIR/homepage.html" | cut -d'"' -f2 | tee "$OUTPUT_DIR/js_files.txt"

echo -e "\n[*] Interesting JS files:"
grep -iE "(main|app|bundle|vendor|config|api)" "$OUTPUT_DIR/js_files.txt" | head -20

# Download main JS file for analysis
MAIN_JS=$(grep -iE "(main|app|bundle)" "$OUTPUT_DIR/js_files.txt" | head -1)
if [ ! -z "$MAIN_JS" ]; then
    echo -e "\n[*] Downloading main JS file: $MAIN_JS"
    
    if [[ "$MAIN_JS" == http* ]]; then
        curl -s "$MAIN_JS" > "$OUTPUT_DIR/main.js"
    else
        curl -s "https://$TARGET$MAIN_JS" > "$OUTPUT_DIR/main.js"
    fi
    
    echo "[*] Searching for API endpoints in JS..."
    grep -oE '["'"'"']/api/[^"'"'"']+["'"'"']' "$OUTPUT_DIR/main.js" | sort -u | head -50 | tee "$OUTPUT_DIR/api_endpoints.txt"
    
    echo -e "\n[*] Searching for interesting strings in JS..."
    grep -oiE '["'"'"']\w*(token|key|secret|password|admin)["'"'"']' "$OUTPUT_DIR/main.js" | sort -u | head -30 | tee "$OUTPUT_DIR/interesting_strings.txt"
fi

# PHASE 4: Subdomain Enumeration
echo -e "\n${YELLOW}[*] PHASE 4: Subdomain Enumeration${NC}"
echo "--------------------------------------------------------------------------------"

echo "[*] Testing known subdomains..."
SUBDOMAINS=("www" "api" "m" "mobile" "login" "auth" "admin" "dev" "staging" "test" "mail" "shop" "cdn" "static" "media" "blog" "support" "docs" "mailing")

for sub in "${SUBDOMAINS[@]}"; do
    URL="https://$sub.$DOMAIN"
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "$URL" 2>/dev/null)
    
    if [ "$STATUS" != "000" ] && [ "$STATUS" != "" ]; then
        echo -e "${GREEN}[+] $sub.$DOMAIN - Status: $STATUS${NC}" | tee -a "$OUTPUT_DIR/subdomains_found.txt"
    fi
done

# PHASE 5: robots.txt and sitemap.xml
echo -e "\n${YELLOW}[*] PHASE 5: robots.txt & Sitemap Discovery${NC}"
echo "--------------------------------------------------------------------------------"

echo "[*] Checking robots.txt..."
curl -s "https://$TARGET/robots.txt" > "$OUTPUT_DIR/robots.txt"

if [ -s "$OUTPUT_DIR/robots.txt" ]; then
    echo -e "${GREEN}[+] robots.txt found:${NC}"
    grep -E "Disallow|Allow|Sitemap" "$OUTPUT_DIR/robots.txt" | head -30
    
    # Extract sitemaps
    grep -oE "Sitemap: .+" "$OUTPUT_DIR/robots.txt" | cut -d' ' -f2 | tee "$OUTPUT_DIR/sitemaps.txt"
fi

# PHASE 6: Common Files Discovery
echo -e "\n${YELLOW}[*] PHASE 6: Common Files Discovery${NC}"
echo "--------------------------------------------------------------------------------"

COMMON_FILES=(
    "/.git/HEAD"
    "/.git/config"
    "/.env"
    "/.env.local"
    "/config.json"
    "/package.json"
    "/.well-known/security.txt"
    "/swagger.json"
    "/api-docs"
    "/openapi.json"
    "/graphql"
    "/admin"
    "/debug"
    "/phpinfo.php"
    "/info.php"
    "/.DS_Store"
    "/backup"
    "/backup.zip"
    "/backup.tar.gz"
    "/database.sql"
)

echo "[*] Testing for common files..."
for file in "${COMMON_FILES[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "https://$TARGET$file")
    
    if [ "$STATUS" = "200" ]; then
        echo -e "${RED}[!!!] FOUND: $file - Status: $STATUS${NC}" | tee -a "$OUTPUT_DIR/sensitive_files.txt"
    fi
done

# PHASE 7: SSL/TLS Info
echo -e "\n${YELLOW}[*] PHASE 7: SSL/TLS Information${NC}"
echo "--------------------------------------------------------------------------------"

echo "[*] SSL Certificate info:"
echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null | openssl x509 -noout -text | grep -E "Subject:|Issuer:|Not Before|Not After|DNS:" | tee "$OUTPUT_DIR/ssl_info.txt"

# PHASE 8: DNS Records
echo -e "\n${YELLOW}[*] PHASE 8: DNS Records${NC}"
echo "--------------------------------------------------------------------------------"

echo "[*] A Records:"
dig +short "$DOMAIN" A | tee -a "$OUTPUT_DIR/dns_records.txt"

echo -e "\n[*] MX Records:"
dig +short "$DOMAIN" MX | tee -a "$OUTPUT_DIR/dns_records.txt"

echo -e "\n[*] TXT Records:"
dig +short "$DOMAIN" TXT | tee -a "$OUTPUT_DIR/dns_records.txt"

echo -e "\n[*] NS Records:"
dig +short "$DOMAIN" NS | tee -a "$OUTPUT_DIR/dns_records.txt"

# PHASE 9: WAF Detection
echo -e "\n${YELLOW}[*] PHASE 9: WAF/CDN Detection${NC}"
echo "--------------------------------------------------------------------------------"

echo "[*] Checking for WAF/CDN..."
HEADERS=$(curl -s -I "https://$TARGET")

if echo "$HEADERS" | grep -qi "cloudflare"; then
    echo -e "${GREEN}[+] Cloudflare detected${NC}"
fi

if echo "$HEADERS" | grep -qi "incapsula"; then
    echo -e "${GREEN}[+] Incapsula detected${NC}"
fi

if echo "$HEADERS" | grep -qi "akamai"; then
    echo -e "${GREEN}[+] Akamai detected${NC}"
fi

# PHASE 10: Quick XSS/SQLi Test
echo -e "\n${YELLOW}[*] PHASE 10: Quick Vulnerability Scan${NC}"
echo "--------------------------------------------------------------------------------"

echo "[*] Testing for reflected parameters..."
curl -s "https://$TARGET/?test=INJECTIONTEST" | grep -o "INJECTIONTEST" > /dev/null
if [ $? -eq 0 ]; then
    echo -e "${YELLOW}[!] Parameter reflection detected - XSS testing recommended${NC}"
fi

echo "[*] Testing error handling..."
curl -s "https://$TARGET/?id='" | grep -iE "sql|mysql|postgresql|error" > /dev/null
if [ $? -eq 0 ]; then
    echo -e "${RED}[!!!] Possible SQL error detected - SQLi testing needed${NC}"
fi

# Summary
echo -e "\n================================================================================"
echo "RECONNAISSANCE COMPLETE"
echo "================================================================================"

echo -e "\n${GREEN}[+] Results saved to: $OUTPUT_DIR/${NC}"
echo ""
echo "Generated files:"
ls -lh "$OUTPUT_DIR/"

echo -e "\n${YELLOW}[*] Next Steps:${NC}"
echo "1. Review: $OUTPUT_DIR/tech_stack.txt"
echo "2. Check API endpoints: $OUTPUT_DIR/api_endpoints.txt"
echo "3. Review JS for secrets: $OUTPUT_DIR/interesting_strings.txt"
echo "4. Test found subdomains: $OUTPUT_DIR/subdomains_found.txt"
echo ""
echo "Run with authentication for deeper testing!"

