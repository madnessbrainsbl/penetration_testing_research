# Databricks Reconnaissance Findings

**Date**: 2025-12-05
**Status**: Unauthenticated Testing Phase

---

## 🎯 Target Infrastructure

### Active Endpoints
| Domain | Status | Notes |
|--------|--------|-------|
| `community.cloud.databricks.com` | 404 on root, API requires auth | Community Edition |
| `accounts.cloud.databricks.com` | 303 → /login | Account management |
| `dbc-9a3f8ed1-7608.cloud.databricks.com` | 404 | Org-ID: 8789365059946363 |
| **`dbc-4b448b2e-59b6.cloud.databricks.com`** | **ACTIVE** | **Org-ID: 3047257800510966** |
| `login.databricks.com` | 200 | Login portal |
| `partners.databricks.com` | 301 → /s/ | Partner portal (Salesforce) |

### Active Workspace Details
- **URL**: `https://dbc-4b448b2e-59b6.cloud.databricks.com`
- **Org-ID**: `3047257800510966`
- **CSRF Token observed**: `5360e295-9a11-485f-a2b5-115f2c4ba2d3`
- **WebSocket**: `/websocket?o=3047257800510966`
- **GraphQL-WS**: `/graphql-ws?o=3047257800510966`

### Discovered Subdomains (303 redirects to main)
- jenkins.databricks.com
- ci.databricks.com  
- internal.databricks.com
- admin.databricks.com
- qa.databricks.com
- uat.databricks.com
- beta.databricks.com
- auth.databricks.com
- oauth.databricks.com

### Infrastructure Details
- **CDN**: CloudFront + AmazonS3
- **UI Assets**: `ui-assets.cloud.databricks.com` (S3 bucket, us-west-2)
- **Server**: `databricks` (custom)
- **Security Headers**: HSTS enabled, X-Content-Type-Options: nosniff

---

## 🔍 OIDC/OAuth Discovery

### OpenID Configuration
**Endpoint**: `https://accounts.cloud.databricks.com/oidc/.well-known/openid-configuration`

```json
{
  "authorization_endpoint": "https://accounts.cloud.databricks.com/oidc/v1/authorize",
  "token_endpoint": "https://accounts.cloud.databricks.com/oidc/v1/token",
  "issuer": "https://accounts.cloud.databricks.com/oidc",
  "jwks_uri": "https://accounts.cloud.databricks.com/oidc/jwks.json",
  "scopes_supported": ["all-apis", "email", "offline_access", "openid", "profile", "sql"],
  "response_types_supported": ["code", "id_token"],
  "grant_types_supported": ["client_credentials", "authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"]
}
```

### JWKS Public Key
- **Algorithm**: RS256
- **Key ID**: `646befd4f966017b69524c94e27179ccf2fded55dbb3497e0f103a039cf26857`

---

## 📊 Information Disclosure Findings

### 1. Version Information (Low)
**Location**: Login page HTML
```
servedVersion: ".monolith-ui_2025-12-04_10.31.38Z_master_394b9983_1644835590"
commitHash: "394b9983ab67e878c60ea4de8c6dfacdcc970af5"
```

### 2. Internal Java Class Names (Low)
**Location**: `/telemetry-unauth` error responses
```
com.databricks.common.web.LogErrorType
```

### 3. Org-ID Disclosure (Low)
**Location**: Response headers on workspace requests
```
x-databricks-org-id: 8789365059946363
```

### 4. Request ID Pattern (Informative)
All requests return unique request IDs in `x-request-id` header.

---

## 🛡️ Security Controls Observed

### Authentication
- All API endpoints require Bearer token
- `www-authenticate: Bearer realm="DatabricksRealm"`
- No unauthenticated API access

### CORS
- No permissive CORS headers detected
- Origin header not reflected

### Headers
- HSTS with preload
- X-Content-Type-Options: nosniff
- No X-Frame-Options observed

### Rate Limiting
- Not tested without credentials

---

## ❌ Tested Vectors (No Findings)

- [ ] Open Redirect in login (`next_url` parameter) - validated
- [ ] CORS misconfiguration - not vulnerable
- [ ] Path traversal via API - requires auth
- [ ] SSRF via DBFS - requires auth
- [ ] Source maps - empty/sanitized
- [ ] Subdomain takeover - all resolve

---

## 🔑 Next Steps (Requires Credentials)

1. **Request HackerOne Credentials**
   - Use "Request Credential" feature
   - Need 2 accounts for IDOR testing

2. **Priority Tests with Auth**
   - IDOR on notebooks, jobs, clusters
   - Permission escalation
   - DBFS file enumeration
   - Secret scope access
   - Cross-workspace access

3. **Container Escape (Advanced)**
   - Requires cluster access
   - Check kernel version
   - LXC configuration

---

## 📁 Files Created

- `PENTEST_PLAN.md` - Detailed testing plan
- `test_databricks.py` - Automated testing script
- `RECON_FINDINGS.md` - This file

---

*Next action: Request test credentials from HackerOne to continue authenticated testing.*

