# Databricks – Final Comprehensive Pentest Report

**Target:** `dbc-4b448b2e-59b6.cloud.databricks.com`

**Workspace ID:** `3047257800510966`

**Cloud / Region:** AWS, `us-east-2`

**Period:** ~7+ hours of active testing (one session)

**Tester:** Security Researcher (HackerOne)

**Program:** Databricks Bug Bounty

---

## 1. Executive Summary

During an intensive, focused penetration test against a Databricks workspace (Serverless SQL Warehouse + Unity Catalog), I attempted to:

- Break **sandbox isolation** of Python UDFs and the SQL runtime
- Escalate privileges inside the workspace and Unity Catalog
- Exfiltrate data across boundaries (RLS bypass, cross-tenant, secrets, tokens)
- Trigger client-side issues (XSS) with security impact

**Result:**

- **No critical, exploitable vulnerabilities confirmed.**
- **No successful sandbox escape** from the UDF environment to the underlying host or other tenants.
- **Row-level security (RLS) and Unity Catalog ACLs held** under realistic attacker capabilities.
- Several **low‑severity / defense-in-depth findings** were identified, most notably:
  - Seccomp disabled (`Seccomp: 0`) in the UDF sandbox (kernel attack surface is large, but mitigated by other controls)
  - Ability for non-admins to enumerate **user list, groups, secret scope names, system catalog metadata, external location URLs**
  - MSG_OOB available on AF_UNIX sockets (relevant to some kernel CVEs, but not directly exploitable here)

At the end of testing, the Databricks environment **refused to start the warehouse** with:

```json
{
  "error_code": "BAD_REQUEST",
  "message": "Sorry, cannot run the resource because you've exhausted your available credits. Please add a payment method to upgrade your account.",
  "details": [
    {
      "@type": "type.googleapis.com/google.rpc.ErrorInfo",
      "reason": "DENY_NEW_AND_EXISTING_RESOURCES",
      "domain": "resource-gatekeeper",
      "metadata": {
        "scope": "WorkspaceId(3047257800510966)",
        "denyReason": "CREDIT_EXHAUSTED"
      }
    }
  ]
}
```

so **further runtime exploitation tests are blocked** until new credits or a new workspace are available.

---

## 2. Test Environment

### 2.1 High-Level Architecture

- **Workspace URL:** `https://dbc-4b448b2e-59b6.cloud.databricks.com`
- **Metastore ID:** `8510a0a1-dcbd-483f-8dfd-3ec964685259`
- **Unity Catalog:** enabled (system catalog present: `system`)
- **Compute:**
  - Primary: **Serverless SQL Warehouse** `c38a578e1ced2494` (type `PRO`)
- **DBR Version:** 17.x (serverless runtime, Python UDFs available)

### 2.2 Accounts and Roles

Two accounts/tokens were involved:

| Identity                        | Role        | Usage                                     |
|---------------------------------|------------|-------------------------------------------|
| `tanyia45@doncong.com`         | Admin      | Setup, admin-level probing, audit views   |
| `sarasofia3@doncong.com`       | Non-admin  | Real attacker model for access tests      |

### 2.3 Runtime / Sandbox (Python UDF) – Observed

From multiple `py_exec_test`-style UDFs:

```text
Architecture:      aarch64
Kernel reported:   Linux sandbox 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016 aarch64 GNU/Linux
User:              ubuntu (UID=1000, GID=1000)
Filesystem:        9p-mounted, read-only root, /databricks tree present
Memory:            ~300 MB
CPUs:              8 vCPUs
Isolation:         Firecracker microVM (inferred from behavior and /databricks layout)
```

Cgroups:

```text
7:pids:/
6:memory:/
5:job:/
4:devices:/
3:cpuset:/
2:cpuacct:/
1:cpu:/
```

No Docker socket, no `/dev/vsock`, no LXC-specific paths.

---

## 3. Sandbox Security – Detailed Analysis

### 3.1 Process Status (`/proc/self/status`)

Representative output inside the UDF sandbox:

```text
Uid:    1000    1000    1000    1000
Gid:    1000    1000    1000    1000
CapInh: 00000000000000c0
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 00000000000000c0
Seccomp:        0
```

Interpretation:

- **Seccomp: 0** → **no seccomp filter applied** (all syscalls allowed by the kernel itself)
- **CapEff = 0x0** → process currently has **no effective capabilities**
- **CapPrm = 0x0** → process has **no permitted capabilities**
- **CapBnd = 0xc0** → bounding set includes bits 6 and 7 → 
  - `CAP_SETGID` and `CAP_SETUID` are present only in **bounding set**, not in effective/permitted sets.

### 3.2 NoNewPrivs Verification

Directly checked in two ways:

1. Via `/proc/self/status` (in extended dumps): line `NoNewPrivs: 1` (where present)
2. Via `prctl(PR_GET_NO_NEW_PRIVS)` inside a Python UDF:

```python
import ctypes
libc = ctypes.CDLL(None)
PR_GET_NO_NEW_PRIVS = 39
result = libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
# Observed: result = 1
```

**Conclusion:** `NoNewPrivs` is **enabled** (1) for the sandbox process.

### 3.3 Attempted Privilege Escalation – `setuid(0)` PoC

A concrete exploitation attempt:

```python
import ctypes, os
libc = ctypes.CDLL(None)
results = []

ret = libc.setuid(0)
results.append(f"setuid(0): {ret}, errno: {ctypes.get_errno()}")
results.append(f"uid after: {os.getuid()}")

try:
    with open("/etc/shadow") as f:
        results.append("shadow: " + f.read()[:100])
except Exception as e:
    results.append(f"shadow error: {e}")

try:
    with open("/etc/passwd") as f:
        results.append("passwd: " + f.read()[:100])
except Exception as e:
    results.append(f"passwd error: {e}")

return str(results)
```

**Observed result:**

```text
['setuid(0): -1, errno: 0',
 'uid after: 1000',
 "shadow error: [Errno 13] Permission denied: '/etc/shadow'",
 'passwd: root:x:0:0:root:/root:/bin/bash\n...
']
```

- `setuid(0)` **fails** (returns -1)
- UID remains **1000** (non-root)
- `/etc/shadow` is **not readable** (Permission denied)

### 3.4 Why Seccomp=0 Is Still Not an Exploit

**Risk:**

- With seccomp disabled, **all kernel syscalls are potentially reachable**, subject only to normal kernel permission checks.
- This **dramatically enlarges the kernel attack surface** (e.g., `perf_event_open`, `userfaultfd`, `keyctl`, etc.).
- Many modern Linux kernel privilege escalation exploits start from such syscalls.

**Mitigations present in Databricks sandbox:**

1. **NoNewPrivs = 1**
   - Blocks privilege escalation via SUID binaries and certain exec-based tricks
   - Prevents acquiring new capabilities across `execve()` boundaries

2. **CapEff = CapPrm = 0x0**
   - The process has **no effective or permitted capabilities**, so even dangerous syscalls that require `CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_NET_RAW`, etc. will be denied.

3. **CapBnd = 0xc0** (Bounding Set)
   - The presence of `CAP_SETUID`/`CAP_SETGID` in the bounding set means **theoretical maximum**, not actual rights.
   - Since `CapPrm=0x0` and `NoNewPrivs=1`, there is **no legitimate path** to elevate to those capabilities.

4. **Firecracker microVM isolation**
   - Even if a kernel privilege escalation in the guest were found, it would be constrained to the guest microVM, not the physical host or other tenants.

**Bottom line:**

- **Seccomp=0** is a **defense-in-depth gap**, not a direct privilege escalation by itself.
- Real exploitation would require a **new kernel 0‑day** that:
  - Bypasses `NoNewPrivs`
  - Works with `CapEff=0x0`
  - Gives control *within* the Firecracker VM (and potentially finds a second escape from VM to host).

At present, **no such exploit was identified** in this testing.

---

## 4. Dangerous Syscalls and Attack Surface

Several tests were done to evaluate whether “interesting” syscalls are reachable and how they behave.

### 4.1 AF_UNIX MSG_OOB (CVE-2025-38236 Vector)

A PoC Python UDF:

```python
import socket
s1, s2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s1.send(b"test", socket.MSG_OOB)
    return "MSG_OOB works!"
except Exception as e:
    return str(e)
```

**Observed:** `MSG_OOB works!`

- This confirms that the runtime **allows MSG_OOB on AF_UNIX sockets**.
- Some kernel UAF vulnerabilities target exactly this behavior.
- However, **no specific kernel bug was found or exploited**.

### 4.2 Direct Syscalls via `libc.syscall`

Several syscall numbers were tested, e.g.:

- `keyctl` (250)
- `perf_event_open` (298)
- `unshare` with `CLONE_NEWUSER`
- `setns` (308)

Typical results:

```text
['keyctl: -1', 'perf_event: -1']
['unshare NEWUSER: -1, errno: 0', 'setns: -1']
```

Indicating that the **kernel rejects these operations** (likely due to lack of capabilities / permissions), not because of seccomp.

### 4.3 ptrace and Yama

Check:

```bash
cat /proc/sys/kernel/yama/ptrace_scope
# Observed: 1
```

- `ptrace_scope=1` → restricted to tracing children / own subtree, **still constrained**.
- Combined with no capabilities and NoNewPrivs, ptrace-based host escapes are unlikely.

### 4.4 KASLR / `/proc/kallsyms`

Access attempt:

```bash
cat /proc/kallsyms
# Result: No such file or directory
```

- KASLR symbol information is **not exposed** in this environment.

### 4.5 `/proc/kcore` / Kernel Memory

Direct reading of `/proc/kcore` was **not successfully performed** (blocked), meaning there is **no trivial direct kernel memory dump** from the sandbox.

---

## 5. Filesystem and Environment

### 5.1 Filesystem Paths

Observations:

- `/databricks/` present with:

```text
/databricks/
├── .pyenv/
├── python -> /databricks/python3
├── python3/
├── safespark/
└── spark/
```

- Root filesystem is effectively **read-only** for the UDF process.
- Attempts to write to system files such as `/etc/passwd`, `/etc/shadow`, or perform `mount` operations consistently failed with `Permission denied` / `must be superuser`.

### 5.2 Secrets and Tokens on Disk

Searches like:

```bash
find / -type f | grep -iE 'token|secret|credential|password|key' | head -10
```

resulted in **no clearly sensitive credentials** visible in accessible paths. Databricks appears to avoid storing access tokens or secret material in readable locations inside the UDF sandbox.

---

## 6. Network Isolation

All attempts to perform outbound network communication from Python UDFs failed:

- HTTP requests (e.g. `requests.get('https://example.com')`)
- Direct socket connections (TCP/UDP), including to cloud metadata (`169.254.169.254`)

Conclusion: UDF sandbox is **network-isolated**, eliminating straightforward exfiltration via HTTP/DNS or cloud metadata abuse.

---

## 7. Unity Catalog, RLS, and Access Control

### 7.1 Row-Level Security (RLS) and Function Replacement

The classic RLS bypass via function replacement was tested:

- Target: a security function (e.g., row filter) with `RETURNS BOOLEAN`.
- Attack idea: `CREATE OR REPLACE FUNCTION` that returns `TRUE` for everything.

Access checks:

- Non-admin **cannot** grant themselves `MANAGE` on that function.
- Without `MANAGE`, cannot replace the function.
- Even with `EXECUTE` or `CREATE FUNCTION`, replacement is blocked.

**Result:** RLS bypass via function replacement **only works if the attacker already has `MANAGE` on the function**, which is expected behavior and does **not** cross a new security boundary.

### 7.2 Unity Catalog & System Catalog

- Non-admin can see some metadata about the `system` catalog (e.g. via `GET /api/2.1/unity-catalog/catalogs/system`), but **not sensitive data**.
- Attempts to read privileged system tables (billing, internal logs) were blocked by RBAC.

### 7.3 IDOR Attempts

Several attempts were made to access admin content using the non-admin token:

- `GET /api/2.0/workspace/get-status?path=/Users/tanyia45@doncong.com`
- `GET /api/2.0/workspace/list?path=/Users/tanyia45@doncong.com`

Observed:

- Responses were empty / access denied → **no IDOR on workspace paths**.

---

## 8. Secrets, Tokens, and Audit Logs

### 8.1 Secret Scopes

Using non-admin token (`sarasofia3`):

```http
GET /api/2.0/secrets/scopes/list
```

Response (example):

```json
{
  "scopes": [
    {"name": "exploit-scope", "backend_type": "DATABRICKS"},
    {"name": "nonadmin-scope", "backend_type": "DATABRICKS"},
    {"name": "test-secret-scope", "backend_type": "DATABRICKS"}
  ]
}
```

- Non-admin can **enumerate secret scope names** (information disclosure).
- Attempt to list or read secrets:

```http
GET /api/2.0/secrets/list?scope=test-secret-scope
```

Result:

```json
{"error_code":"PERMISSION_DENIED", ...}
```

**No secret values were accessible**.

### 8.2 Token Management APIs

Attempt with non-admin token:

```http
GET /api/2.0/token-management/tokens
```

Response:

```json
{
  "error_code": "PERMISSION_DENIED",
  "message": "Requesting user 'sarasofia3@doncong.com' is not an admin."
}
```

Thus token management is **admin-only**, as expected.

### 8.3 Audit Logs and Token Leakage

Queries against `system.access.audit` looked for `dapi`-like patterns in `request_params` or `response`.

- No direct, full token values were observed in audit logs.
- Some **token-related action names** were visible:
  - `generateDbToken`
  - `changeDbTokenAcl`
  - `mintOAuthToken`

But **not the tokens themselves**.

---

## 9. XSS and UI-Side Attacks

### 9.1 Stored XSS in Metadata

Multiple attempts to inject HTML/JS payloads into table/column/function comments:

- Payloads like `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>` were stored in metadata.
- In the Databricks web UI, these values were **properly escaped and displayed as text**.

Result:

- **Stored XSS payloads are persisted**, but **not executed** by the React frontend.
- This is essentially **informational / low** severity, not an exploitable XSS.

---

## 10. Billing / Credits Exhaustion

Towards the end of testing, every attempt to start or use the SQL warehouse failed with:

```json
{
  "error_code": "BAD_REQUEST",
  "message": "Sorry, cannot run the resource because you've exhausted your available credits. Please add a payment method to upgrade your account.",
  "details": [
    {
      "@type": "type.googleapis.com/google.rpc.ErrorInfo",
      "reason": "DENY_NEW_AND_EXISTING_RESOURCES",
      "domain": "resource-gatekeeper",
      "metadata": {
        "scope": "WorkspaceId(3047257800510966)",
        "denyReason": "CREDIT_EXHAUSTED"
      }
    }
  ]
}
```

Interpretation:

- Databricks uses **credits/DBU** per workspace.
- Intensive testing (especially serverless warehouses + UDFs) consumed the allowance.
- Further runtime testing is impossible on this workspace until credits are replenished.

This is **not a vulnerability**, but an **operational limit** that stopped additional PoC work.

---

## 11. Findings Summary

### 11.1 Confirmed, Low/Informational

1. **Seccomp disabled in UDF sandbox**
   - **Severity:** Medium (defense-in-depth)
   - **Impact:** Full kernel syscall surface exposed to unprivileged UDF code.
   - **Mitigations:** NoNewPrivs=1, CapEff=0, Firecracker VM.
   - **Status:** Not directly exploitable in current tests.

2. **MSG_OOB available on AF_UNIX sockets**
   - **Severity:** Low/Medium (depends on kernel state)
   - **Impact:** Can be used as a vector for known/unknown kernel UAF bugs.
   - **Status:** No kernel exploit identified; just an available primitive.

3. **User / Group enumeration via SCIM and/or APIs**
   - **Severity:** Low
   - **Impact:** Aids reconnaissance and targeted attacks.

4. **Secret scope names visible to non-admins**
   - **Severity:** Low
   - **Impact:** Reveals naming of internal secret scopes; no secret values exposed.

5. **External location URLs and S3 paths visible**
   - **Severity:** Low
   - **Impact:** Exposes internal S3 bucket paths, helpful for cloud recon, but no credentials.

6. **Stored but escaped XSS payloads in metadata**
   - **Severity:** Informational
   - **Impact:** Payloads are stored but safely rendered.

### 11.2 Not Found / Not Confirmed

- No **sandbox escape** from UDF to host.
- No **cross-tenant data access**.
- No **critical RLS/ACL bypass** achievable by a normal non-admin.
- No **token or secret leaks** from runtime or APIs that bypass documented boundaries.
- No exploitable **XSS** or client-side issues with security impact.

---

## 12. Overall Assessment

**Security posture:**

- Databricks shows a **strong, multi-layered security model**:
  - Firecracker microVM isolation
  - NoNewPrivs + zero effective capabilities
  - Read-only filesystem, restricted writes
  - Network isolation from UDFs
  - Strict RBAC for tokens, secrets, system catalogs
  - Modern web security headers and CSP

**Key observation:**

- `Seccomp: 0` is a notable deviation from common **best practices** for production sandboxes. It does not, by itself, lead to an exploit in this environment, but:
  - Expands the kernel attack surface
  - Makes future kernel 0-days more dangerous in this context

**From a bug bounty perspective:**

- Current evidence supports **defense-in-depth / Medium** severity for seccomp being disabled.
- Without a working kernel 0-day or a clear escalation path, Databricks is likely to treat this as **hardening advice**, not a critical vulnerability.

---

## 13. Recommendations

1. **Enable seccomp filters** for UDF sandbox processes
   - Adopt a restrictive default profile, blocking rarely needed syscalls.
   - This would significantly reduce the impact of future kernel bugs.

2. **Review exposure of secret scope names and external location URLs**
   - Consider limiting visibility of scope names / bucket paths to admins or owners.

3. **Continue to avoid storing sensitive tokens in sandbox-readable paths**
   - Current behavior is good; maintain this discipline.

4. **Maintain strict RBAC on SCIM and workspace APIs**
   - If possible, allow user enumeration only for admins.

5. **Consider explicit security documentation for the UDF sandbox model**
   - Clarify that isolation is provided via Firecracker + NoNewPrivs + capabilities, not seccomp.

---

## 14. Next Steps (If Credits/Workspace Are Restored)

If a new workspace or additional credits become available, next logical research directions would be:

1. **Focused kernel exploit research** (only if realistic):
   - Target syscalls like `perf_event_open`, `userfaultfd`, or AF_UNIX/MSG_OOB.
   - Attempt to find/port a PoC that bypasses NoNewPrivs.

2. **Further Unity Catalog / IDOR investigations:**
   - Cross-catalog or cross-schema privilege escalation.
   - Subtle RLS bypass patterns in multi-function setups.

3. **More advanced data exfiltration and covert channels:**
   - Side channels via CPU/cache timing (between tenants).
   - Creative use of logs/metadata as an exfiltration path.

At the time of this report, however, **no exploitable path has been demonstrated**.

---

**Report generated:** 2025‑12‑06 (final session)

**Classification:** Confidential – Databricks Bug Bounty

**Author:** Security Researcher

