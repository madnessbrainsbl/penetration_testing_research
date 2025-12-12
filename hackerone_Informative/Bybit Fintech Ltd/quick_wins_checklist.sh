#!/bin/bash
# Quick wins checklist - easy bugs to find manually

echo "=========================================="
echo "QUICK WINS CHECKLIST FOR BYBIT"
echo "=========================================="

echo -e "\n📋 High Priority Manual Tests:\n"

echo "✓ 1. OAuth Open Redirect (30 min)"
echo "   → Open Burp, intercept Google login, modify redirect_uri"
echo "   → Expected: Find in 30% of OAuth implementations"
echo ""

echo "✓ 2. Account Pre-Takeover (45 min)"
echo "   → Create account with victim email (no verify)"
echo "   → Link your Google OAuth"
echo "   → Have victim login via Google"
echo "   → Expected: 20% chance to find"
echo ""

echo "✓ 3. Email Enumeration (5 min)"
echo "   → Password reset with existing vs non-existing email"
echo "   → Different messages = enumeration"
echo ""

echo "✓ 4. Rate Limiting on Login (10 min)"
echo "   → Try 100+ failed logins"
echo "   → No lockout = vulnerability"
echo ""

echo "✓ 5. Referral Self-Abuse (20 min)"
echo "   → Get referral link"
echo "   → Register new account with your link"
echo "   → Get bonus on both accounts = abuse"
echo ""

echo -e "\n🔍 Quick Automated Checks:\n"

echo "[Test 1] Email Enumeration via Password Reset"
curl -s -X POST https://api.bybit.com/user/v1/password/forgot \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@bybit.com"}' | head -50

echo -e "\n[Test 2] Checking for exposed .git"
curl -s -I https://www.bybit.com/.git/config | grep "HTTP"

echo -e "\n[Test 3] Checking for robots.txt secrets"
curl -s https://www.bybit.com/robots.txt | grep -i "disallow"

echo -e "\n[Test 4] Checking for exposed admin panels"
for path in /admin /administrator /phpmyadmin /adminer /wp-admin; do
    status=$(curl -s -o /dev/null -w "%{http_code}" https://www.bybit.com$path)
    if [ "$status" != "404" ] && [ "$status" != "403" ]; then
        echo "  ⚠️  $path - HTTP $status"
    fi
done

echo -e "\n=========================================="
echo "Start with OAuth test - highest ROI!"
echo "Open: https://www.bybit.com/login"
echo "=========================================="
