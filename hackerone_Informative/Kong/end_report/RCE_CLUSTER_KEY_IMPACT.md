## Summary

The vulnerability allows a Konnect tenant with plugin‑management rights on Serverless Gateway to:

1. Execute arbitrary Lua code on the shared Konnect Serverless Gateway infrastructure.
2. Use `kong.vault.get()` with the `env` backend to read any environment variable.
3. Exfiltrate `KONG_CLUSTER_CERT_KEY` (cluster mTLS private key) and attach a rogue data plane trusted by the control plane.

This results in a complete compromise of the Konnect Serverless cluster.

---

## Technical impact

- **Cluster key disclosure**

  - Full disclosure of `KONG_CLUSTER_CERT_KEY` (ECDSA P‑256 private key).
  - Ability to connect arbitrary rogue data planes and observe/modify traffic.

- **Remote Code Execution**

  - Arbitrary Lua execution in `pre-function` on all requests.

- **Sensitive data exposure**

  - Theft of request headers/cookies/bodies.
  - Disclosure of internal configuration and infrastructure (Prometheus metrics, Kubernetes service account token path, SSL certificate locations, internal services like k8s‑api, aws‑metadata, localhost Admin API).

- **Multi‑tenant risk**
  - Serverless Gateway is a shared SaaS environment; a malicious tenant could potentially impact other tenants using the same Serverless cluster.

---

## Business impact

- Cross‑tenant traffic interception and modification.
- Compromise of the Konnect control‑plane / data‑plane trust model.
- Potential non‑compliance with PCI‑DSS / SOC2 / GDPR due to key and data exposure.
- High reputational risk if abused in the wild.

---

## Safe testing

All testing was performed only against my own Konnect organization and Serverless Gateway instance. I did not attempt to access other customers’ Dedicated Cloud Gateways or production environments, and all tokens/keys used for testing will be revoked.
