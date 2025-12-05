# 🔥 HARDCORE MODE - Action Plan for Next 2-3 Hours

## Текущая ситуация
- **300+ автоматических тестов** выполнено
- **0 уязвимостей** найдено автоматически
- **Причина:** Bybit имеет enterprise security
- **Решение:** Переходим на ручное тестирование high-value targets

---

## 🎯 Top 5 Targets (prioritized by success probability)

### 1. OAuth Open Redirect (⏱️ 30 min, 🎲 30% chance)

**Why it works:**
- OAuth redirect validation часто слабая
- Даже у больших компаний находят (Google, Facebook)
- Bybit использует OAuth (Google/Apple/Telegram)

**How to test:**
```
1. Install Burp Suite Community (free)
2. Configure browser proxy: 127.0.0.1:8080
3. Go to: https://www.bybit.com/login
4. Click "Continue with Google"
5. Intercept request in Burp
6. Find parameter: redirect_uri or callback_url
7. Change value to: https://evil.com
8. Forward request
9. Check if redirected to evil.com with ?code=...
```

**Vulnerable if:**
- Redirects to evil.com
- Authorization code visible in URL
- No error about invalid redirect_uri

**Report template:**
```
Title: OAuth Open Redirect Allows Account Takeover
Severity: High
Impact: Attacker can steal authorization code and takeover victim account
Steps: [paste your Burp history]
```

---

### 2. Account Pre-Takeover (⏱️ 45 min, 🎲 20% chance)

**Why it works:**
- Complex race condition between registration and OAuth
- Many platforms don't handle this correctly
- Recent bugs: Microsoft, Dropbox, Grammarly

**How to test:**
```
1. Go to: https://www.bybit.com/register
2. Create account with: victim@gmail.com
3. DON'T verify email
4. Go to Settings → Security → Link Google Account
5. Link YOUR Google (attacker@gmail.com)
6. Logout
7. NEW BROWSER: Click "Continue with Google"
8. Login with DIFFERENT Google that has victim@gmail.com
9. Check: Which account did you land in?
```

**Vulnerable if:**
- You land in the account created in step 2
- This means attacker can pre-create account and capture victim

**Report template:**
```
Title: Account Pre-Takeover via OAuth Email Confusion
Severity: Critical
Impact: Attacker can takeover any account before victim registers
Steps: [detailed reproduction]
PoC Video: [record screen]
```

---

### 3. Referral Self-Abuse (⏱️ 20 min, 🎲 15% chance)

**Why it works:**
- Business logic bugs common in referral systems
- Bonus without proper validation
- Recent: Coinbase, Robinhood had referral bugs

**How to test:**
```
1. Login to your Bybit account
2. Go to: Rewards → Referral Program
3. Copy your referral link: https://www.bybit.com/invite?ref=YOURCODE
4. Logout
5. Open Incognito/Private browser
6. Register NEW account using YOUR referral link
7. Use temp email: https://temp-mail.org
8. Complete registration
9. Check BOTH accounts for bonus
```

**Vulnerable if:**
- Both accounts get bonus
- No KYC required
- Can withdraw or trade immediately

**Exploitation:**
- Create 100 accounts with your link
- Get 100x bonus
- Profit

**Report template:**
```
Title: Referral System Allows Self-Referral for Unlimited Bonuses
Severity: High
Impact: Attacker can generate unlimited referral bonuses
Steps: [show 2 accounts with bonus]
Financial Impact: $X per account × unlimited accounts
```

---

### 4. Sub-Account IDOR (⏱️ 60 min, 🎲 10% chance)

**Why it works:**
- Complex permission model between Master/Sub
- Authorization checks easy to miss
- Recent: Binance had sub-account bugs

**How to test:**
```
1. In your Master account, create 2 sub-accounts:
   - Go to: Account → Sub-Accounts → Create
   - Create Sub1
   - Create Sub2

2. For Sub1, generate API key:
   - Login as Sub1
   - API Management → Create Key
   - Save: KEY1 and SECRET1

3. For Sub2, generate API key:
   - Save: KEY2 and SECRET2

4. Run script: subaccount_idor_test.py
   - Fill in API keys
   - Script tests if Sub1 can access Sub2 data
```

**Vulnerable if:**
- Sub1 API key returns Sub2 wallet balance
- Sub1 can modify Sub2 settings
- Sub1 can access Master account data

**Report template:**
```
Title: Sub-Account IDOR Allows Cross-Account Data Access
Severity: Critical  
Impact: Sub-account can access/modify other sub-accounts or master
Steps: [API calls with different keys]
```

---

### 5. 2FA Bypass via Backup Codes (⏱️ 30 min, 🎲 5% chance)

**Why it works:**
- Backup code logic sometimes has race conditions
- Can generate unlimited codes
- Can use without 2FA enabled

**How to test:**
```
1. Login to your account
2. Enable 2FA (Google Authenticator)
3. Generate backup codes
4. Save codes
5. Logout
6. Try these attacks:

Attack A: Code Reuse
- Login with password
- Enter 2FA code: 123456
- Complete login
- Logout
- Login again
- Try SAME code: 123456
- If works → vulnerability

Attack B: Brute Force
- Login with password
- Try codes: 000000, 000001, 000002...
- Check if rate limited after N attempts
- If not → vulnerability

Attack C: Backup Code without 2FA
- Disable 2FA
- Try to use old backup codes
- If works → vulnerability
```

**Report template:**
```
Title: 2FA Bypass via [Code Reuse/Brute Force/Backup Codes]
Severity: High
Impact: Attacker can bypass 2FA protection
Steps: [detailed reproduction]
```

---

## 📋 Quick Reference Checklist

```
□ OAuth Open Redirect (30 min) - START HERE
□ Account Pre-Takeover (45 min) - SECOND
□ Referral Self-Abuse (20 min) - THIRD  
□ Sub-Account IDOR (60 min) - IF TIME
□ 2FA Bypass (30 min) - IF TIME

Total: ~3 hours of focused manual testing
```

---

## 🛠️ Tools You Need

1. **Burp Suite Community** (free)
   - Download: https://portswigger.net/burp/communitydownload
   - Use for: OAuth testing, request interception

2. **Temp Email Service**
   - Use: https://temp-mail.org
   - For: Creating test accounts

3. **Private/Incognito Browser**
   - For: Testing as different user

4. **Screen Recording**
   - Use: OBS Studio (free)
   - For: PoC videos for report

---

## 📝 Reporting Template

When you find something, use this structure:

```markdown
## Summary
[One sentence: what is the vulnerability]

## Severity
[High/Critical based on impact]

## Description
[Technical explanation of the bug]

## Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Proof of Concept
[Screenshots, video, or code]

## Impact
[What attacker can do]
- Account takeover
- Financial loss
- Data theft

## Affected Users
[How many users can be impacted]

## Remediation
[How to fix it]
```

---

## ⏰ Time Management

- **First 30 min:** OAuth testing (highest ROI)
- **Next 45 min:** Account Pre-Takeover
- **Next 20 min:** Referral abuse
- **Remaining:** Sub-Account or 2FA

**Set timer for each task!** Don't spend too long on one thing.

---

## 🎬 Start Now!

1. Open Burp Suite
2. Configure proxy
3. Go to https://www.bybit.com/login
4. Click "Continue with Google"
5. **Find that redirect_uri parameter!**

---

Good luck! 🍀

Remember: Even if you don't find anything, this is valuable experience.
Bybit is HARD, but that's why the bounties are good when you DO find something.
