# Zooplus Reconnaissance Summary

**Date:** 2025-12-09  
**Target:** www.zooplus.de  
**Status:** Initial reconnaissance completed

---

## 🎯 Technology Stack Detected

### Frontend
- **Framework:** Next.js
- **JavaScript:** React + jQuery  
- **Build:** Webpack

### Backend/Infrastructure
- **Service Mesh:** Istio Envoy
- **CDN:** AWS CloudFront  
- **Compute:** AWS Lambda (eu-central-1)
- **SSL:** Amazon RSA 2048 M02

### Security
- **HSTS:** ✅ Enabled (max-age=31536000; includeSubDomains; preload)
- **Cookies:** ✅ Secure, HttpOnly, SameSite=Lax
- **WAF:** CloudFront (AWS)

---

## 🌐 Discovered Subdomains

| Subdomain | Status | Notes |
|-----------|--------|-------|
| `www.zooplus.de` | 200 | Main site |
| `m.zooplus.de` | 301 | Mobile redirect |
| `login.zooplus.de` | 403 | **Interesting!** Auth service |
| `support.zooplus.de` | 302 | Support redirect |
| `mailing.zooplus.de` | 200 | **Active** - Email tracking |

---

## 🔍 Interesting Findings

### 1. ⚠️ CORS Configuration

```http
access-control-allow-origin: *
```

**Status:** Needs verification  
**Potential Impact:** If applied to sensitive endpoints → Data theft  
**Test Required:** Check if authenticated endpoints allow wildcard CORS

---

### 2. 🔴 Parameter Reflection Detected

The recon script detected parameter values being reflected in responses.

**Test URLs:**
```
https://www.zooplus.de/?test=INJECTIONTEST
→ "INJECTIONTEST" reflected in response
```

**Potential Vulnerabilities:**
- Reflected XSS
- Open Redirect
- HTML Injection

**Next Step:** Manual XSS testing with real payloads

---

### 3. 🔴 Possible SQL Error Detection

Initial testing detected potential SQL error patterns in responses.

**Status:** Requires manual verification  
**Test Required:** Craft proper SQL injection payloads with authentication

---

## 📁 Files & Directories Discovered

### robots.txt
```
Sitemap: https://www.zooplus.de/sitemap.xml
Disallow: /ov?
Disallow: /detailedQuestion.htm$
Disallow: /
```

**Note:** Very restrictive robots.txt - most paths disallowed

### Sitemap
- Found: `https://www.zooplus.de/sitemap.xml`
- Can be crawled for full URL enumeration

---

## 🔐 SSL/TLS Information

```
Issuer: Amazon RSA 2048 M02
Valid: Apr 18 2025 - May 18 2026
Domains: zooplus.de, *.zooplus.de
```

**Status:** ✅ Valid certificate, wildcard coverage

---

## 📦 JavaScript Analysis

### Main JS Bundles Found:
```
/_next/static/chunks/main-app-89838dfd418e076b.js
/_next/static/chunks/app/layout-083b427a9d7c43f4.js
/_next/static/chunks/webpack-60527969c203d0b0.js
```

**Analysis Status:** Downloaded but requires deep inspection for:
- API endpoints
- Authentication tokens
- Internal endpoints
- Development artifacts

---

## 🚫 Not Found / Secured

- ✅ No `.git` exposure
- ✅ No `.env` files accessible
- ✅ No `backup` files
- ✅ No `phpinfo.php`
- ✅ No `/admin` panel publicly accessible
- ✅ No GraphQL introspection enabled
- ✅ No Swagger/OpenAPI docs exposed

---

## 🎯 Critical Next Steps for Real Vulnerabilities

### Phase 1: Authenticated Testing Required

**Need:**
1. Valid session cookies for both test accounts
2. Fresh password reset tokens

**Will Test:**
- IDOR on orders, invoices, addresses
- Stored XSS in profile/reviews
- CSRF on state-changing operations
- Business logic in checkout

### Phase 2: Manual Verification

**Found Issues That Need Manual Testing:**

1. **CORS Misconfiguration**
   - Test: Access authenticated endpoints from evil.com origin
   - Impact: If successful → High severity data theft

2. **Parameter Reflection**
   - Test: Manual XSS payloads in all reflected parameters
   - Impact: If unescaped → Medium-High XSS

3. **SQL Error Patterns**
   - Test: Proper SQL injection with time-based/boolean payloads
   - Impact: If exploitable → Critical SQL injection

### Phase 3: Deep JavaScript Analysis

**Action:** Download and analyze all main JS bundles for:
```bash
# Extract from main.js:
- API endpoints not in HTML
- Hardcoded tokens/keys
- Development/debug endpoints
- Client-side validation bypasses
```

---

## 📊 Risk Assessment (Current)

| Category | Risk Level | Reason |
|----------|-----------|--------|
| Information Disclosure | Low | Good security headers, no sensitive files exposed |
| Authentication | Unknown | Requires authenticated testing |
| Authorization (IDOR) | Unknown | Cannot test without valid sessions |
| XSS | Medium | Parameter reflection detected |
| SQL Injection | Low-Medium | Error patterns detected, need verification |
| CORS | Medium | Wildcard detected, impact depends on endpoints |

---

## 🛠️ Tools Used

- `curl` - HTTP requests
- `grep` - Pattern matching
- `openssl` - SSL analysis
- Bash scripting

---

## 📝 Generated Reports

All reconnaissance data saved in: `reports/recon/`

```
reports/recon/
├── headers.txt                    # HTTP headers analysis
├── homepage.html                  # Downloaded homepage
├── tech_stack.txt                # Technology detection
├── js_files.txt                  # JavaScript file list
├── main.js                       # Main JS bundle
├── subdomains_found.txt          # Active subdomains
├── robots.txt                    # robots.txt content
├── sitemaps.txt                  # Sitemap URLs
├── ssl_info.txt                  # SSL certificate info
└── api_endpoints.txt             # API endpoints (if found in JS)
```

---

## ⚡ What's Blocking Further Testing

### Cannot Test Without:

1. **Session Cookies** - For IDOR, XSS in authenticated forms, CSRF
2. **Password Reset Tokens** - For account takeover testing
3. **Bearer Tokens** - For API authorization testing

### Can Test Now (Limited Impact):

- ✅ Public endpoint enumeration
- ✅ Technology fingerprinting
- ✅ SSL/TLS configuration
- ✅ robots.txt/sitemap analysis
- ⚠️ Basic XSS/SQLi (limited without auth)

---

## 🎯 Recommended Next Actions

1. **Provide Authentication Data** (see `WHAT_I_NEED_FOR_REAL_TESTING.md`)
2. **Deep JS Analysis** - Extract all API endpoints
3. **Wayback Machine** - Historical endpoint discovery
4. **Manual CORS Testing** - Verify wildcard impact
5. **Subdomain Takeover** - Check DNS for unused subdomains

---

## 📈 Progress

- [x] Technology stack identified
- [x] Subdomains enumerated
- [x] Security headers analyzed
- [x] SSL/TLS verified
- [x] JavaScript files discovered
- [x] robots.txt analyzed
- [ ] Deep JS analysis (API extraction)
- [ ] CORS exploitation verified
- [ ] XSS manually tested
- [ ] SQLi manually tested
- [ ] IDOR testing (blocked - need auth)
- [ ] CSRF testing (blocked - need auth)
- [ ] Business logic testing (blocked - need auth)

---

**Next:** Provide session cookies to unlock 80% more attack surface! 🚀

