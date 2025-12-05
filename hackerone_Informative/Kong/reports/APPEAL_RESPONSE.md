## Key Distinction: Self-hosted Kong vs Konnect Cloud

The GitHub discussion you referenced (https://github.com/Kong/kong/discussions/10194) discusses Lua sandbox limitations in **self-hosted Kong** deployments. This is fundamentally different from **Konnect Cloud Serverless Gateway**:

| Aspect                              | Self-hosted Kong    | Konnect Cloud (This Report) |
| ----------------------------------- | ------------------- | --------------------------- |
| **Who manages infrastructure?**     | Customer            | Kong Inc.                   |
| **Who sets environment variables?** | Customer            | Kong Inc.                   |
| **Who owns KONG_CLUSTER_CERT_KEY?** | Customer            | **Kong Inc.**               |
| **Is env var access a risk?**       | Customer's decision | **Kong's responsibility**   |
| **Multi-tenant?**                   | No                  | **Yes**                     |

---

## The Critical Difference

In **self-hosted Kong**, the customer:

- Deploys Kong on their own infrastructure
- Sets their own environment variables
- Accepts the risk of pre-function accessing those variables
- Only affects their own environment

In **Konnect Cloud Serverless**, Kong Inc.:

- Manages shared infrastructure
- Sets `KONG_CLUSTER_CERT_KEY` as an environment variable
- **Did not expect** users to be able to read it via `kong.vault.get()`
- This key is **Kong's infrastructure secret**, not the customer's

---

## What Was Actually Leaked

This is not about a customer reading their own secrets. The leaked `KONG_CLUSTER_CERT_KEY` is:

```
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCgg8P6wDI+v2s6xl
6s6kCVkK59Kl0euyPOPGmRb7MjWhRANCAARI3iNSohdOCWtmRFoUFMvDM3s4XKX2
sthcquKZPkZaARmKTgbbkjoopklOri3wxJWNa+qvq+/Rx05aHT7rJpBp
-----END PRIVATE KEY-----
```

**This is Kong's Control Plane ↔ Data Plane mTLS private key.**

This key is used for:

- Mutual TLS authentication between CP and DP
- Encrypting cluster configuration sync
- Validating Data Plane identity

**This key should NEVER be accessible to customers.**

---

## Practical Exploitation Scenarios

### Scenario 1: Rogue Data Plane Registration

With the stolen cluster key + certificate, an attacker could potentially:

1. Register a rogue Data Plane to the Control Plane
2. Receive all configuration updates (routes, services, plugins)
3. Intercept a copy of all API traffic patterns

### Scenario 2: Cross-tenant Impact (if keys are shared)

If Kong uses shared infrastructure keys across tenants:

1. Attacker in Tenant A exfiltrates cluster key
2. Uses key to access Tenant B's configuration
3. Complete multi-tenant isolation bypass

### Scenario 3: Man-in-the-Middle (if attacker has network position)

With the private key:

1. Attacker can decrypt CP↔DP communication
2. Modify configuration in transit
3. Inject malicious plugins

---

## Why This Is Different From the GitHub Discussion

The GitHub discussion says:

> "There is no way to restrict access to environment variables in a Lua sandbox"

This is true for **self-hosted Kong** where:

- The customer controls the environment
- The customer sets the env vars
- The customer accepts this risk

But in **Konnect Cloud**:

- **Kong sets the env vars** (not the customer)
- **Kong stores secrets in env vars** (KONG_CLUSTER_CERT_KEY)
- **Kong should NOT expose these to customer code**

The fix is simple: **Don't store sensitive infrastructure keys in environment variables accessible to customer-supplied Lua code.**

---

## Remediation Suggestions

1. **Move cluster keys out of env vars** - Use mounted secrets at restricted paths
2. **Block kong.vault.get("env/KONG\_\*")** - Deny access to Kong's internal variables
3. **Use separate key namespaces** - Customer env vault vs Kong internal secrets
4. **Implement allowlist** - Only allow vault access to customer-defined secrets

---

## Summary

| Claim                      | Reality                                                                   |
| -------------------------- | ------------------------------------------------------------------------- |
| "No security impact"       | **KONG_CLUSTER_CERT_KEY leaked** - this is Kong's infrastructure key      |
| "Known sandbox limitation" | **Konnect Cloud should not store secrets in sandbox-accessible env vars** |
| "Customer's own env vars"  | **This is KONG'S key, not customer's**                                    |
| "Acceptable risk"          | **Not acceptable in multi-tenant cloud environment**                      |

---

## Request

I respectfully request that this report be re-evaluated as **Critical** based on:

1. **The leaked key is Kong's infrastructure secret**, not a customer-defined variable
2. **Konnect Cloud is multi-tenant** - different security model than self-hosted
3. **The private key enables cluster compromise** - not just information disclosure
4. **Kong's responsibility** to not expose infrastructure secrets to customer code

If you need additional proof of exploitability (e.g., successful rogue DP connection), I am happy to work with your security team to demonstrate this in a controlled environment.

Thank you for reconsidering.

---

**Key Evidence:**

1. `KONG_CLUSTER_CERT_KEY` = Full ECDSA P-256 private key
2. `KONG_CLUSTER_CERT` = Corresponding certificate
3. These are **Kong-managed secrets**, not customer-defined
4. Accessed via `kong.vault.get("{vault://env/KONG_CLUSTER_CERT_KEY}")`
5. This works in **Konnect Cloud Serverless** - a managed, multi-tenant service
