# Testing Session - Initial Setup & Reconnaissance

## Session Info
- **Date**: 2025-11-23
- **Duration**: Planning stage
- **Focus Area**: Initial setup + reconnaissance (Blocks 0-3)
- **Tools Used**: Browser, Burp Suite, curl

## Key Updates
- ✅ Program is now PUBLIC (Nov 17, 2025)
- ✅ CFEngine Community & Enterprise now IN SCOPE
- ✅ Gold Standard Safe Harbor applies

## Objectives
- [x] Update documentation with latest program info
- [ ] Create 2 test accounts on staging.hosted.mender.io
- [ ] Configure Burp Suite
- [ ] Map Mender SaaS application structure
- [ ] Identify all API endpoints
- [ ] Get org IDs, user IDs, device IDs for testing
- [ ] Run initial IDOR tests

---

## STEP 1: Create Test Accounts ⚡ NEXT

### Account 1 (Attacker)
```
URL: https://staging.hosted.mender.io
Email: [your_h1_username]@wearehackerone.com
Password: [generate strong password]

After registration:
- User ID: [to fill]
- Org ID: [to fill]
- API Token: [to fill]
```

### Account 2 (Victim)
```
Email: [your_h1_username]+victim@wearehackerone.com
Password: [generate strong password]

After registration:
- User ID: [to fill]
- Org ID: [to fill]
- API Token: [to fill]
```

### Commands to get token:
```bash
# Login and get token
curl -X POST https://staging.hosted.mender.io/api/management/v1/useradm/auth/login \
  -H "Content-Type: application/json" \
  -H "X-HackerOne-Research: [your_username]" \
  -d '{"email":"email@example.com","password":"password"}' \
  -v

# Save tokens
export TOKEN_A="<token_account_1>"
export TOKEN_B="<token_account_2>"
export H1_USER="[your_h1_username]"
```

---

## STEP 2: Configure Burp Suite

- [ ] Start Burp Suite Professional/Community
- [ ] Configure browser proxy (127.0.0.1:8080)
- [ ] Import CA certificate
- [ ] Set scope filter: `.*staging\.hosted\.mender\.io.*`
- [ ] Enable HTTP history logging
- [ ] Configure match/replace rule for X-HackerOne-Research header

### Burp Match/Replace Rule:
```
Type: Request header
Match: ^X-HackerOne-Research:.*
Replace: X-HackerOne-Research: [your_h1_username]
```

---

## STEP 3: Application Mapping (Account 1)

### UI Walkthrough Checklist
- [ ] Registration flow
- [ ] Login/Logout
- [ ] Dashboard
- [ ] Devices section
  - [ ] List devices
  - [ ] Add device (get tenant token)
  - [ ] Device details
  - [ ] Accept/Reject device
  - [ ] Decommission device
- [ ] Device groups
  - [ ] Create group
  - [ ] Manage group
- [ ] Releases/Artifacts
  - [ ] Upload artifact
  - [ ] View artifacts
  - [ ] Delete artifact
- [ ] Deployments
  - [ ] Create deployment
  - [ ] View deployment details
  - [ ] Abort deployment
- [ ] Users & Permissions
  - [ ] List users
  - [ ] Invite user
  - [ ] Change role
  - [ ] Remove user
- [ ] Settings/Organization
  - [ ] View org settings
  - [ ] Modify settings
  - [ ] API keys

### Extract IDs from Account 1:
```bash
# Current user
curl -X GET https://staging.hosted.mender.io/api/management/v1/useradm/users/me \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER"

# Devices
curl -X GET https://staging.hosted.mender.io/api/management/v2/devauth/devices \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER"

# Deployments
curl -X GET https://staging.hosted.mender.io/api/management/v1/deployments/deployments \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER"

# Users
curl -X GET https://staging.hosted.mender.io/api/management/v1/useradm/users \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER"
```

**Save all IDs for IDOR testing**

---

## STEP 4: Export and Parse Burp Requests

After completing UI walkthrough:

```bash
# In Burp Suite:
# 1. HTTP History → Filter by staging.hosted.mender.io
# 2. Select all requests
# 3. Right-click → Copy requests
# 4. Save to file

# Parse requests
cd /media/sf_vremen/hackerone/Northern.tech
python3 scripts/burp_request_parser.py burp_requests_export.txt

# Check results
ls endpoint_tests/
cat endpoint_tests/api_catalog.md
```

---

## STEP 5: Initial IDOR Testing ⚡ PRIORITY

### Prepare victim resources (Account 2):

```bash
# Login as Account 2 and create some resources:
# - Add at least 1 device (pending is OK)
# - Create 1 deployment (if possible)
# - Note the IDs

# Extract victim IDs:
curl -X GET https://staging.hosted.mender.io/api/management/v1/useradm/users/me \
  -H "Authorization: Bearer $TOKEN_B" \
  -H "X-HackerOne-Research: $H1_USER"
# Save: victim_user_id, victim_org_id

curl -X GET https://staging.hosted.mender.io/api/management/v2/devauth/devices \
  -H "Authorization: Bearer $TOKEN_B" \
  -H "X-HackerOne-Research: $H1_USER"
# Save: victim_device_id
```

### Run automated IDOR tests:

```bash
python3 scripts/test_idor.py

# Input when prompted:
# - H1 username: [your_username]
# - Token A: $TOKEN_A
# - Token B: $TOKEN_B
# - Victim device ID: [from above]
# - Victim deployment ID: [if available]
# - Victim user ID: [from above]
```

### Manual IDOR tests (critical endpoints):

```bash
# Test 1: View victim's devices
curl -X GET https://staging.hosted.mender.io/api/management/v2/devauth/devices \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER"
# Expected: Only Account A devices
# If sees Account B devices → CRITICAL VULNERABILITY!

# Test 2: Access victim's device by ID
curl -X GET "https://staging.hosted.mender.io/api/management/v2/devauth/devices/$VICTIM_DEVICE_ID" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER" \
  -v
# Expected: 403 or 404
# If 200 → CRITICAL VULNERABILITY!

# Test 3: Accept victim's device
curl -X PUT "https://staging.hosted.mender.io/api/management/v2/devauth/devices/$VICTIM_DEVICE_ID/auth/$AUTH_ID/status" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER" \
  -H "Content-Type: application/json" \
  -d '{"status":"accepted"}' \
  -v
# Expected: 403
# If 200/204 → CRITICAL VULNERABILITY!

# Test 4: View victim's users
curl -X GET https://staging.hosted.mender.io/api/management/v1/useradm/users \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER"
# Expected: Only Account A users
# If sees Account B users → CRITICAL VULNERABILITY!
```

---

## STEP 6: Test Authentication & Session Management

### JWT Analysis (if using JWT tokens):

```bash
# Decode JWT token
echo "$TOKEN_A" | cut -d'.' -f2 | base64 -d | jq

# Check for:
# - Weak algorithms (alg: none, HS256)
# - Missing expiration
# - Predictable structure
# - Sensitive data in payload
```

### Session tests:

```bash
# Test 1: Token after logout
# 1. Login, save token
# 2. Logout
# 3. Try using old token
curl -X GET https://staging.hosted.mender.io/api/management/v1/useradm/users/me \
  -H "Authorization: Bearer $OLD_TOKEN" \
  -H "X-HackerOne-Research: $H1_USER"
# Expected: 401
# If 200 → Session not invalidated!

# Test 2: Token after password change
# 1. Change password
# 2. Try using old token
# Expected: 401
```

---

## STEP 7: Test Critical Business Logic

### Device enrollment attacks:

```bash
# Get tenant token (all users can access this - known behavior)
curl -X GET https://staging.hosted.mender.io/api/management/v2/devauth/tenant/token \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER"

# Try to register device with modified org_id/tenant_id
# (Check if can hijack devices to another org)
```

### Mass assignment tests:

```bash
# Test 1: Create user with elevated role
curl -X POST https://staging.hosted.mender.io/api/management/v1/useradm/users \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "Password123!",
    "roles": ["RBAC_ROLE_PERMIT_ALL"]
  }'
# Expected: Reject or assign default role
# If accepts admin role → PRIVILEGE ESCALATION!

# Test 2: Modify own user with admin role
curl -X PUT "https://staging.hosted.mender.io/api/management/v1/useradm/users/$MY_USER_ID" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER" \
  -H "Content-Type: application/json" \
  -d '{
    "roles": ["RBAC_ROLE_PERMIT_ALL"]
  }'
# Expected: 403
# If 200 → PRIVILEGE ESCALATION!

# Test 3: Change org_id in requests
# Try adding org_id parameter to various endpoints
```

---

## Results Summary

### Critical Tests Completed:
- [ ] Cross-tenant device IDOR
- [ ] Cross-tenant deployment IDOR
- [ ] Cross-tenant user IDOR
- [ ] Privilege escalation via mass assignment
- [ ] Session invalidation
- [ ] Device enrollment attacks

### Vulnerabilities Found:
```
Count: 0

[Will fill as testing progresses]
```

### Interesting Observations:
```
- 
- 
```

### Blocked/Questions:
```
- 
- 
```

---

## Next Session Plan

**Focus**: Complete reconnaissance + IDOR testing, then move to:
- XSS testing (device names, deployment descriptions)
- CSRF testing
- API deep dive
- Source code review

**Preparation**:
- Review Burp HTTP history
- Analyze JWT tokens
- Check previous CVEs (mender.io/blog/tag/cve)
- Read source code authorization logic

---

## Commands Reference Sheet

```bash
# Quick token test
curl -s https://staging.hosted.mender.io/api/management/v1/useradm/users/me \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER" | jq

# Quick device list
curl -s https://staging.hosted.mender.io/api/management/v2/devauth/devices \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER" | jq

# Quick IDOR test template
curl -v -X GET "https://staging.hosted.mender.io/api/management/v2/devauth/devices/$VICTIM_ID" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER"

# Interactive API client
python3 scripts/mender_api_client.py
```

---

**Status**: 🟡 Ready to begin testing  
**Next action**: Create accounts and start STEP 1
