#!/bin/bash
# Deep subdomain enumeration using multiple sources

echo "=========================================="
echo "DEEP SUBDOMAIN ENUMERATION"
echo "=========================================="

DOMAIN="bybit.com"

echo -e "\n[1] Certificate Transparency Logs (crt.sh)"
echo "------------------------------------------"
curl -s "https://crt.sh/?q=%.${DOMAIN}&output=json" | \
    jq -r '.[].name_value' 2>/dev/null | \
    sort -u | \
    grep -v "*" | \
    head -20

echo -e "\n[2] DNS Bruteforce (common subdomains)"
echo "------------------------------------------"

COMMON_SUBS="admin api api2 app beta blog cdn connect dashboard dev developer developers docs ftp git help internal m mail mobile old panel partner sandbox smtp staging static status support test testnet vpn www"

for sub in $COMMON_SUBS; do
    host "${sub}.${DOMAIN}" 2>/dev/null | grep "has address" && echo "  ✓ ${sub}.${DOMAIN}"
done

echo -e "\n[3] Checking for cloud storage buckets"
echo "------------------------------------------"

BUCKETS="bybit bybit-prod bybit-staging bybit-dev bybit-backup bybit-data bybit-static"

for bucket in $BUCKETS; do
    # S3
    curl -s -I "https://${bucket}.s3.amazonaws.com" 2>/dev/null | grep -q "200 OK" && echo "  🚨 S3: ${bucket}"
    
    # Google Cloud Storage
    curl -s -I "https://storage.googleapis.com/${bucket}" 2>/dev/null | grep -q "200 OK" && echo "  🚨 GCS: ${bucket}"
done

echo -e "\n[4] Checking for open ports on main domain"
echo "------------------------------------------"

for port in 21 22 3306 5432 6379 8080 8443 9200 27017; do
    nc -zv -w1 ${DOMAIN} ${port} 2>&1 | grep -q "succeeded" && echo "  ⚠️  Port ${port} open"
done

echo -e "\n=========================================="
