# Databricks Pentest - Current Status

**Date**: 2025-12-05
**Time Spent**: ~30 minutes
**Phase**: Unauthenticated Reconnaissance

---

## ✅ Completed Tests

### Infrastructure Mapping
- [x] Main domains checked (community, accounts, workspace)
- [x] Subdomain enumeration (~20 subdomains found)
- [x] Server fingerprinting (CloudFront, S3, custom Databricks server)
- [x] OIDC/OAuth endpoints discovered
- [x] JWKS public key extracted

### Security Tests (Unauthenticated)
- [x] CORS misconfiguration - **NOT VULNERABLE**
- [x] Open Redirect in login - **NOT VULNERABLE**  
- [x] API endpoints without auth - **ALL PROTECTED**
- [x] Path traversal - **REQUIRES AUTH**
- [x] Source map exposure - **EMPTY/SANITIZED**
- [x] Subdomain takeover - **NOT VULNERABLE**

---

## 📊 Findings Summary

| Finding | Severity | Status |
|---------|----------|--------|
| Version/Commit disclosure in HTML | Low/Info | Documented |
| Internal Java class names in errors | Low/Info | Documented |
| Org-ID disclosure in headers | Low/Info | Documented |
| OIDC configuration public | Expected | N/A |

**Note**: All findings so far are LOW/INFORMATIVE. No bounty-worthy vulnerabilities found in unauthenticated testing.

---

## 🔒 Blockers

### Need Credentials
All high-value tests require authentication:
- IDOR testing (notebooks, jobs, clusters, secrets)
- Permission escalation
- DBFS file enumeration
- Cross-tenant access
- Container escape (requires cluster access)

### How to Get Credentials
1. **HackerOne Request Credential** - Use the feature on Databricks program page
2. **Community Edition** - Register at https://www.databricks.com/try-databricks
3. **Second Account** - Needed for IDOR verification

---

## 🎯 Priority Actions

### Immediate (After Getting Credentials)

1. **IDOR Testing** (+25% bounty)
   ```bash
   python3 test_databricks.py
   ```
   - Test notebook ID manipulation
   - Test job ID manipulation
   - Test cross-user access

2. **Secret Enumeration**
   - List all secret scopes
   - Check for leaked credentials in DBFS
   - Check workspace files

3. **Permission Escalation**
   - Test self-assign admin
   - Test ACL bypass
   - Test group manipulation

### Advanced (Requires Cluster)

4. **Container Escape** ($3000 guaranteed)
   - Check kernel version
   - Test LXC escape vectors
   - Check namespace isolation

---

## 📁 Files Created

| File | Purpose |
|------|---------|
| `PENTEST_PLAN.md` | Detailed attack plan |
| `test_databricks.py` | Automated testing script |
| `RECON_FINDINGS.md` | Reconnaissance results |
| `TESTING_STATUS.md` | This status file |

---

## 📝 Key Learnings from Other Projects

### Ripio (INFORMATIVE)
- CSS Injection + JWT leak was rejected because JWT in URL was "expected behavior"
- **Lesson**: Must cross security boundary, not just demonstrate theoretical risk

### Kong (CRITICAL - $$$)
- pre-function plugin → env vault → cluster keys
- Full exploitation chain with real impact
- **Lesson**: Need to show complete path to impact

### What Works for Bounty
1. Actual unauthorized access to other user's data
2. Privilege escalation with proof
3. Secret/credential exfiltration
4. Container/isolation bypass

---

## ⏭️ Next Steps

```
1. Get test credentials from HackerOne
2. Run test_databricks.py with token
3. Focus on IDOR/ACL bypass (highest bounty potential)
4. Document any findings with full PoC
5. If cluster access available, test container escape
```

---

*Status: WAITING FOR CREDENTIALS*

