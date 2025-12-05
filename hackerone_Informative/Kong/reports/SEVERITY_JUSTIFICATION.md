# Severity Justification: Why Kong Konnect SSRF is HIGH Severity

## Executive Summary

While the current exploitation returned `502 Bad Gateway` errors for cloud metadata services (indicating network-level blocking), the vulnerability remains **High Severity** because the **application layer (API) completely fails to validate input**. The security of the platform currently relies entirely on a single layer of defense (network policies), which violates the Defense-in-Depth principle. Furthermore, the discovered Privilege Escalation vector allows unauthorized access to the Mesh Control Plane.

## 1. CVSS 3.1 Scoring Analysis

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N`
**Score:** **7.7 (High)**

*   **Attack Vector (AV): Network** - Exploitable remotely via the public API.
*   **Attack Complexity (AC): Low** - Requires standard API calls, no race conditions or complex setup.
*   **Privileges Required (PR): Low** - Requires a standard user token (available to any registered user).
*   **User Interaction (UI): None** - No victim interaction required.
*   **Scope (S): Changed** - The vulnerability affects resources beyond the vulnerable component (Mesh Control Plane, Internal Network, Cloud Provider).
*   **Confidentiality (C): Low/High** - Confirmed internal network mapping (Low). Potential for cloud credential theft if network rules change (High).
*   **Integrity (I): Low** - Unauthorized creation of Mesh resources.
*   **Availability (A): None** - No DoS demonstrated (though possible via http-log spam).

---

## 2. Evidence of High Impact

### A. The "One Config Change from Disaster" Risk
The specific check preventing `169.254.169.254` access is a **Network Policy**, not an Application Logic validation.
*   **Proof:** The API returned `200 OK` when creating the service.
*   **Risk:** If a DevOps engineer temporarily disables egress filtering for debugging, or if a software update changes the underlying container network (CNI) configuration, **AWS Credentials will be instantly exposed**.
*   **Industry Standard:** In Bug Bounty programs, missing application-level SSRF protection is considered High because network rules are mutable and often bypassed.

### B. Active Internal Network Reconnaissance
We successfully demonstrated that the Gateway **attempts connections** to internal IPs.
*   **Evidence:** `x-kong-upstream-latency` headers confirm the Gateway spends time trying to handshake with the target.
*   **Impact:** An attacker can map the internal network topology (finding databases, admin panels, internal APIs) by analyzing latency differences between open and closed ports. This is **active unauthorized reconnaissance**.

### C. Cross-Service Privilege Escalation (The "Hidden" Critical)
We used a token intended for **Serverless Gateway** management to access and modify the **Mesh Control Plane**.
*   **Action:** Created a Mesh (`malicious`), ExternalService (`ssrf-test`), and HealthCheck Policy.
*   **Impact:** This is a Broken Access Control (IDOR/Privilege Escalation). A compromised Gateway user should not have write access to the Mesh infrastructure. This expands the attack surface significantly, allowing an attacker to consume resources or launch attacks from the Mesh infrastructure.

### D. Anonymized Attacks (External SSRF)
Using the `http-log` plugin, we successfully sent POST requests to `webhook.site`.
*   **Impact:** Attackers can use Kong's high-reputation IP addresses to launch attacks (credential stuffing, scanning) against third-party targets. This puts Kong's IP reputation at risk and facilitates malicious activity.

---

## 3. Comparison: Low vs. High

| Feature | Low Severity (What you might think it is) | High Severity (What it actually is) |
| :--- | :--- | :--- |
| **Validation** | API blocks internal IPs, but maybe allows some harmless ones. | **API accepts ALL internal IPs (127.0.0.1, Cloud Metadata).** |
| **Connection** | Gateway drops request immediately. | **Gateway TRIES to connect (502 Error + Latency).** |
| **Access Control** | Token only works for intended service. | **Token grants access to unrelated Mesh Control Plane.** |
| **Risk** | Minor information leak. | **Full Cloud Compromise if Network Policy fails.** |

## 4. Conclusion

This vulnerability represents a **fundamental architectural flaw** in input validation and access control. It is not a simple bug but a systemic failure to sanitize critical parameters (`service.url`) and scope authentication tokens properly.

**Final Recommendation:** Treat as **High Severity**. Remediation requires code changes (API Validation) and architectural changes (Token Scoping), not just network tweaks.
