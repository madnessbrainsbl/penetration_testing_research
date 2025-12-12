# Databricks Aggressive Penetration Testing Results
**Date:** December 6, 2025
**Techniques Used:** Internet research, CVE analysis, aggressive API fuzzing

---

## Research Sources

1. **SEC Consult - Cluster Isolation Bypass** (CVE not assigned)
   - DBFS init script poisoning for RCE
   - **Status on our target:** MITIGATED - Public DBFS root is disabled

2. **CVE-2024-49194 - JDBC JNDI Injection**
   - JNDI injection via JDBC URL parameters
   - **Status:** NOT APPLICABLE - requires JDBC driver < 2.6.40

3. **CVE-2025-53763 - Azure Databricks Privilege Escalation** (CVSS 9.8)
   - Improper access control allowing privilege escalation
   - **Status:** UNTESTABLE - Azure-specific, we're on AWS

4. **MLflow Vulnerabilities (CVE-2024-0520, CVE-2023-6709, etc.)**
   - Path traversal and RCE in MLflow
   - **Status:** NOT EXPLOITABLE - no MLflow experiments/models in workspace

---

## Attack Vectors Tested

### ❌ Blocked Attacks

| Attack | Technique | Result |
|--------|-----------|--------|
| DBFS Init Script Poisoning | Write to /databricks/init | PERMISSION_DENIED - Public DBFS disabled |
| Apache Spark doAs Injection | CVE-2022-33891 | Parameter ignored |
| JNDI Injection | ${jndi:ldap://...} in parameters | Not processed |
| Path Traversal | /../../../etc/passwd | Invalid request path |
| SQL Stacked Queries | SELECT 1; SELECT * | PARSE_SYNTAX_ERROR |
| SSRF via Webhook | webhook_notifications with IMDS | Requires environment config |
| Template Injection (SSTI) | {{7*7}} in cluster name | Treated as literal string |
| MLflow Path Traversal | ../../../etc/passwd in artifact_location | No experiments to target |
| Git Repo SSRF | http://169.254.169.254 as repo URL | Validation blocked |
| Cross-Account External Location | Point to other S3 bucket | AWS IAM blocks at runtime |

### ⚠️ Information Disclosure (Low Severity)

| Finding | Non-Admin Access | Impact |
|---------|-----------------|--------|
| External Location S3 URLs | YES | Can see internal bucket structure |
| User List | YES | Can enumerate all workspace users |
| Serving Endpoints | YES | Can see AI model configurations |
| Cluster Policies | Partial | Can see policy names and some config |
| Storage Credential Names | YES | Can see credential names (not secrets) |

### ⚠️ Design Issues (Not Vulnerabilities)

| Issue | Description | Databricks Position |
|-------|-------------|---------------------|
| Python UDF RCE | os.popen() works in sandbox | Expected behavior - sandbox isolates |
| Row Filter Replacement | Owner can replace SQL UDF with Python | Expected - owner has full control |
| skip_validation | Can create credentials without validation | Validation happens at runtime |
| Wildcard in LIKE UDF | % returns all rows | User error in UDF design |

---

## Critical Mitigations Found

1. **Public DBFS Root Disabled** - Blocks SEC Consult attack
2. **Serverless-Only Workspace** - No classic clusters = no init script attacks
3. **External Data Access Disabled** - Blocks credential vending abuse
4. **Delta Sharing Disabled** - Blocks OIDC token attacks
5. **Network Isolation in UDF Sandbox** - Blocks IMDS and external access
6. **AWS IAM Runtime Validation** - Even skip_validation doesn't bypass IAM

---

## Conclusion

**No exploitable vulnerabilities found** after aggressive testing.

The workspace has strong security configurations:
- Modern (Dec 2025) metastore with new security requirements
- Serverless-only compute
- Disabled legacy features (public DBFS, Delta Sharing external)
- Proper access controls at API and AWS IAM levels

### Recommendations for Databricks Security Team

1. Consider restricting external location visibility for non-admin users
2. Consider adding alerts for Python UDF creation with os/subprocess imports
3. Consider implementing function immutability for security-critical UDFs

---

**Report Generated:** December 6, 2025
**Testing Duration:** ~3 hours
**Techniques Applied:** 17+ attack vectors
**CVEs Researched:** 5+
**Result:** No critical/high vulnerabilities confirmed

