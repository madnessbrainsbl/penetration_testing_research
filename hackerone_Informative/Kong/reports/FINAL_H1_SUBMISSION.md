# Kong Konnect High Severity Vulnerability Report

## 1. Executive Summary

We have identified two significant vulnerabilities in the Kong Konnect platform:
1.  **Server-Side Request Forgery (SSRF)** in the Serverless Gateway, allowing internal network scanning and potential cloud metadata exposure.
2.  **Cross-Service Access Control Flaw** (IDOR/Privilege Escalation), where a Gateway-scoped token allows full administrative access to the Mesh Control Plane.

## 2. Vulnerability 1: High-Impact SSRF in Serverless Gateway

**Severity:** High
**CVSS Score:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) - *Assumes potential for data leak*

### Description
The `v2/control-planes/{ID}/core-entities/services` API endpoint lacks input validation for the `url` parameter. It allows users to configure Services pointing to internal IP addresses, including:
- `127.0.0.1` (Localhost / Admin API)
- `169.254.169.254` (Cloud Metadata Services)

While network policies currently return a `502 Bad Gateway` for these requests, the **Gateway actively attempts the connection**, as evidenced by the `x-kong-upstream-latency` header.

### Exploitation & Impact
1.  **Internal Port Scanning:** Attackers can map internal infrastructure by analyzing `x-kong-upstream-latency`.
2.  **External Proxying (Anonymization):** Using the `http-log` plugin, attackers can proxy malicious traffic through Kong's infrastructure, masking their origin IP.
3.  **Cloud Credential Theft Risk:** If network egress policies are ever misconfigured (e.g., during debugging or updates), AWS/GCP credentials will be instantly exposed.
4.  **Admin API Attack Surface:** Exposure of `127.0.0.1:8001` creates a path for Remote Code Execution (RCE) via Lua plugin injection if network protections fail.

---

## 3. Vulnerability 2: Mesh Control Plane Privilege Escalation

**Severity:** Medium/High
**Status:** Successfully Exploited

### Description
A JWT token issued for a user's session (intended for Gateway management) grants **full read/write access** to the Mesh Control Plane API (`v1/mesh/control-planes/...`).

### Exploitation Steps (Confirmed)
Using the Gateway token, we successfully:
1.  Created a new Mesh named `malicious`.
2.  Created an `ExternalService` pointing to `webhook.site` (and internal IPs).
3.  Created a `HealthCheck` policy to force the Control Plane to initiate outbound connections.

### Impact
- **Violation of Least Privilege:** Gateway users should not implicitly control Mesh infrastructure.
- **Blind SSRF via Mesh CP:** The Control Plane itself can be coerced into sending HTTP requests (Health Checks) to arbitrary targets.

---

## 4. Recommendations

1.  **Input Validation (Critical):**
    - Implement a "Deny List" for `service.url` preventing:
        - `127.0.0.0/8`
        - `169.254.0.0/16`
        - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
    - Resolve hostnames server-side before accepting them to prevent DNS rebinding.

2.  **Token Scoping:**
    - Restrict JWT tokens to specific scopes (e.g., `gateway:write`, `mesh:read`). A Gateway token should not write to Mesh APIs.

3.  **Network Hardening:**
    - Ensure `http-log` and other outbound plugins obey the same egress restrictions as Proxy traffic.

---

## 5. Artifacts

All exploitation logs, curl commands, and tool outputs have been saved to:
`/media/sf_vremen/hackerone/Kong/reports/artifacts/exploitation_logs.txt`

**Validated By:**
- User: marisa2@doncong.com
- Date: Nov 26, 2025
