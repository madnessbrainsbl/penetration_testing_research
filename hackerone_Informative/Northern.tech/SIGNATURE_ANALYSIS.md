# 🔍 DEEP ANALYSIS: Signature Verification in Mender

## Date: 2025-11-23
## Objective: Determine if signature bypass is 100% critical vulnerability

---

## 📚 FINDINGS FROM DOCUMENTATION

### Official Mender Documentation (docs.mender.io)

**Key Quote from Sign and Verify page:**
> "If the Mender Client is configured to enable signature verification, **it will reject any unsigned Artifacts**. This is necessary because otherwise an attacker could simply inject unsigned Artifacts to bypass the signature verification."

**Architecture:**
1. **Signing happens**: On signing system (offline, secure)
2. **Artifacts stored**: On Mender Server (can be signed or unsigned)
3. **Verification happens**: On Mender Client (device) - **NOT on server**
4. **Client config**: `ArtifactVerifyKey(s)` option enables verification

**Security Model:**
- Server acts as **storage/distribution** for artifacts
- Client is responsible for **verification**
- If client has `ArtifactVerifyKey` configured → rejects unsigned
- If client does NOT have key configured → accepts any artifact

---

## 🔬 FINDINGS FROM CODE ANALYSIS

### Location: `deployments/app/app.go:980-985`

```go
// There is no signature verification here.
// It is just simple check if artifact is signed or not.
aReader.VerifySignatureCallback = func(message, sig []byte) error {
    metaArtifact.Signed = true
    return nil
}
```

**Analysis:**
1. ✅ Comment explicitly states: "There is no signature verification here"
2. ✅ Callback always returns `nil` (success)
3. ✅ Only sets `metaArtifact.Signed = true` if signature present
4. ✅ Does NOT verify signature cryptographically
5. ✅ Field `Signed` is NEVER checked/enforced anywhere in server code

**Conclusion:** Server does NOT verify signatures. This is CONFIRMED.

---

## ❓ CRITICAL QUESTION: Is This By Design or a Bug?

### Evidence FOR "By Design" (NOT a vulnerability):

1. **Documentation clearly states:**
   - Verification happens on CLIENT, not server
   - Server is just storage
   - This is the documented architecture

2. **Use case:**
   - Demo/test artifacts may be unsigned (like current "mender-demo-artifact")
   - Production clients configured with `ArtifactVerifyKey` will reject unsigned
   - This gives flexibility

3. **Scope interpretation:**
   - "Bypassing the signature check" might mean:
     - Bypassing CLIENT-side verification (not server)
     - Or finding a way to make client accept invalid signature

### Evidence FOR "Bug" (IS a vulnerability):

1. **Attack scenario:**
   - Attacker compromises server account
   - Uploads unsigned/malicious artifact
   - If any client is misconfigured (no `ArtifactVerifyKey`)
   - Client will accept malicious artifact
   - RCE achieved

2. **Defense in depth:**
   - Server SHOULD validate artifacts even if client also validates
   - Reject unsigned artifacts by default
   - Allow unsigned only if explicitly enabled

3. **Scope explicitly mentions:**
   - "Bypassing the signature check for verifying signed artifacts"
   - This is listed as HIGH value target
   - Would be strange to list if it's "working as designed"

---

## 🎯 REAL ATTACK VECTOR

### Scenario 1: Misconfigured Client
**Prerequisites:**
- Attacker has valid server account (created via signup)
- Target device does NOT have `ArtifactVerifyKey` configured

**Attack:**
1. Upload malicious unsigned artifact to server ✅ (possible)
2. Create deployment to target device ✅ (possible)
3. Device downloads artifact ✅ (will happen)
4. Device accepts unsigned artifact ✅ (if not configured to verify)
5. Execute malicious payload ✅ (RCE)

**Impact:** Critical - Full RCE on device

**Likelihood:** Medium - Depends on client configuration

### Scenario 2: Signature Forgery
**Prerequisites:**
- Device HAS `ArtifactVerifyKey` configured
- Need to bypass verification

**Attack:**
1. Upload artifact with fake/invalid signature
2. If server accepts it (which it does)
3. Device should reject it (client-side verification)

**Status:** Server accepts, but client SHOULD reject. Not a bypass.

---

## 🔐 COMPARISON: What SHOULD Happen vs What HAPPENS

### Expected (Secure) Behavior:

```
1. User uploads artifact
2. Server checks if signed (optional policy)
3. Server stores artifact
4. Client downloads artifact
5. Client verifies signature (if ArtifactVerifyKey set)
6. Client installs if valid
```

### Actual Current Behavior:

```
1. User uploads artifact
2. Server does NOT check signature ❌
3. Server stores artifact (signed or unsigned)
4. Client downloads artifact
5. Client verifies signature (if ArtifactVerifyKey set)
6. Client installs if valid OR if no key configured
```

**The Gap:** Server has NO policy to enforce signed artifacts

---

## 💡 FINAL ASSESSMENT

### Is This a Vulnerability? 

**Answer: DEPENDS ON INTERPRETATION**

#### Interpretation A: "Working as Designed" (NOT a bug)
- Mender architecture delegates verification to client
- Server is intentionally "dumb storage"
- Clients protect themselves via configuration
- **Verdict:** Not a vulnerability, just flexible design

#### Interpretation B: "Defense in Depth Failure" (IS a bug)
- Server should offer OPTION to reject unsigned artifacts
- Lack of server-side policy enables attacks on misconfigured clients
- Scope explicitly lists this as high-value target
- **Verdict:** Medium to High severity vulnerability

---

## 🎯 WHAT WOULD MAKE IT 100% CRITICAL?

For this to be **CRITICAL ($3000)**, we would need:

### Option 1: Bypass Client-Side Verification
- Find a way to make client accept INVALID signature
- Or bypass `ArtifactVerifyKey` check on client
- **This would be Critical**
- But requires access to client code/device

### Option 2: Prove Real-World Impact
- Show that production deployments commonly misconfigured
- Demonstrate actual Hosted Mender instances without verification
- Prove this is exploitable in realistic scenario
- **This would elevate severity**

### Option 3: Policy Bypass
- Find a setting/policy that SHOULD enforce signatures
- Prove we can bypass it
- **This would be Critical**
- But no such policy exists in code

---

## 📊 SEVERITY ASSESSMENT

### Current Finding: "Server accepts unsigned artifacts"

**IF reported as:**
- "Server does not verify signatures" → Response: "Working as designed"
- "Missing defense-in-depth: no policy to enforce signed artifacts" → Maybe Low/Medium
- "Signature verification bypass" → Need to prove actual bypass (not just acceptance)

**Estimated Severity:**
- **Best case:** Low to Medium ($200-$500)
- **Worst case:** Out of scope (intended behavior)
- **Critical scenario:** Only if we prove client bypass or real exploitation

---

## 🎭 COMPARISON TO SCOPE

**Scope says:** "Bypassing the signature check for verifying signed artifacts in Mender"

**Our finding:** "Server stores unsigned artifacts, client decides to verify"

**Match?** 
- ❌ We haven't BYPASSED anything
- ✅ We found that server doesn't CHECK
- ⚠️ Ambiguous if this counts as "bypass"

---

## 🚨 RECOMMENDATION

### For Bug Bounty Report:

**DO NOT** report as "Critical Signature Bypass" because:
1. No actual bypass - just absence of server-side check
2. Documented architecture delegates to client
3. Risk of "Informative" or "N/A" response

**INSTEAD:**
1. Test if there's a way to bypass CLIENT verification
2. Or look for policy/config that should enforce but doesn't
3. Or find different critical bug

### Next Steps:

**Priority 1:** Look for OTHER critical bugs
- IDOR in different endpoints
- Auth bypass
- Privilege escalation
- SQL injection

**Priority 2:** Test Stored XSS in UI
- Already confirmed in API
- Need browser verification

**Priority 3:** Explore CFEngine
- Newly in scope
- "Taking over CFEngine Hub from host"
- Potentially critical

---

## 💰 BOUNTY POTENTIAL REASSESSMENT

### Original Hope: $3,000 (Critical)
### Realistic Estimate: $0-$500 (Informative to Medium)
### Risk Level: HIGH (might be "working as designed")

**Conclusion:** This is NOT the $3,000 bug we're looking for.

**Action:** Continue hunting for real Critical vulnerabilities.

---

## 📝 KEY LEARNINGS

1. ✅ Always check documentation before claiming "missing security control"
2. ✅ Understand system architecture (client vs server responsibilities)
3. ✅ "Accepts unsigned" ≠ "Signature bypass"
4. ✅ Critical bugs need demonstrable exploitation, not just missing features
5. ✅ Read scope carefully - "bypass" implies circumvention, not absence

---

**Status:** Signature verification analysis COMPLETE
**Finding:** Likely by design, not critical vulnerability
**Next:** Focus on finding real critical bugs

🎯 **BACK TO THE HUNT!**
