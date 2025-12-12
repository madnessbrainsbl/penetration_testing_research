# Databricks UDF Sandbox - Critical Security Vulnerabilities PoC

## Summary

Multiple critical security misconfigurations in Databricks Python UDF sandbox that dramatically increase kernel attack surface and enable potential container escape.

## Vulnerability Details

### 1. Seccomp Completely Disabled

**Severity**: CRITICAL
**CVSS 3.1**: 9.1 (CRITICAL)
**CVE Potential**: CVE-2025-XXXXX

#### Description
The Python UDF sandbox has seccomp syscall filtering completely disabled (Seccomp: 0), exposing the full Linux kernel attack surface to unprivileged user code.

#### Proof of Concept

```sql
-- PoC 1: Check Seccomp status
CREATE OR REPLACE FUNCTION workspace.default.check_seccomp()
RETURNS STRING
LANGUAGE PYTHON
AS $$
with open('/proc/self/status') as f:
    for line in f:
        if 'Seccomp:' in line or 'NoNewPrivs:' in line or 'Cap' in line:
            print(line.strip())
    return "Seccomp check complete"
$$;

SELECT check_seccomp();
```

**Expected Output**:
```
Seccomp:        0       ← DISABLED! All syscalls accessible
NoNewPrivs:     1       ← Only traditional privesc blocked
CapEff:         0000000000000000
```

#### Impact

With seccomp disabled, attackers can invoke dangerous syscalls that are normally blocked:

- `perf_event_open` (298) - CVE-2023-0386, CVE-2021-4154 exploitation
- `keyctl` (250) - Kernel keyring attacks
- `userfaultfd` (282) - Race condition primitives for kernel exploits
- `bpf` (280) - eBPF privilege escalation
- `ptrace` (157) - Process debugging attacks
- `memfd_create` (279) - Fileless malware execution

---

### 2. Full Compiler Suite Available

**Severity**: HIGH
**CVSS 3.1**: 7.5 (HIGH)

#### Description
Production sandbox includes full C/C++ compiler toolchain (gcc, g++, cc), enabling on-demand compilation of kernel exploits.

#### Proof of Concept

```sql
SELECT workspace.default.shell_exec('which gcc && gcc --version');
```

**Output**:
```
/usr/bin/gcc
gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0
```

#### Exploit Demo: Compile Custom Syscall Test

```sql
SELECT workspace.default.shell_exec('
cat > /tmp/exploit.c << "CEOF"
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main() {
    // Test dangerous syscalls
    printf("perf_event_open: %ld\\n", syscall(298, 0, 0, 0, 0, 0));
    printf("keyctl: %ld\\n", syscall(250, 0, 0, 0, 0, 0));
    printf("userfaultfd: %ld\\n", syscall(282, 0));
    printf("memfd_create: %ld\\n", syscall(279, "exploit", 0));
    return 0;
}
CEOF

gcc -o /tmp/exploit /tmp/exploit.c 2>&1
/tmp/exploit
');
```

**Impact**: Attacker can:
- Compile public kernel exploits (Dirty Pipe, DirtyCOW variants, etc.)
- Adapt PoC code to target kernel 4.4.0
- Build multi-stage exploitation chains
- Create fileless attacks using memfd_create

---

### 3. Extremely Outdated Kernel

**Severity**: HIGH
**CVSS 3.1**: 8.1 (HIGH)

#### Description
Sandbox runs on Linux kernel 4.4.0 from January 2016 - **9+ years old** without security updates.

#### Proof of Concept

```sql
SELECT workspace.default.shell_exec('uname -a');
```

**Output**:
```
Linux sandbox 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016 aarch64 GNU/Linux
```

#### Known Vulnerabilities in Kernel 4.4.0

| CVE | Description | Impact |
|-----|-------------|--------|
| CVE-2016-5195 | DirtyCOW | Privilege escalation |
| CVE-2017-1000112 | UFO exploit | Memory corruption |
| CVE-2017-16995 | eBPF verifier bug | Arbitrary read/write |
| CVE-2017-7308 | packet_set_ring overflow | Local privilege escalation |
| CVE-2016-8655 | Race condition in packet socket | Root access |
| CVE-2016-9793 | SO_{SND|RCV}BUFFORCE socket option | Root access |

**Note**: While some exploits require `/proc/self/mem` write (which is blocked), many kernel bugs can be exploited through accessible syscalls with seccomp disabled.

---

### 4. memfd_create Accessible for Fileless Attacks

**Severity**: MEDIUM
**CVSS 3.1**: 6.5 (MEDIUM)

#### Proof of Concept

```sql
SELECT workspace.default.shell_exec('python3 << EOF
import ctypes
libc = ctypes.CDLL(None)
# memfd_create syscall (279 on aarch64)
fd = libc.syscall(279, b"malware", 0)
print(f"memfd_create returned fd: {fd}")
if fd > 0:
    print("[SUCCESS] Anonymous memory file created")
    import os
    os.close(fd)
EOF
');
```

**Impact**: Enables fileless exploitation - attacker can compile exploit, load it into memory-only fd, execute without touching disk.

---

### 5. MSG_OOB on AF_UNIX Sockets (UAF Vector)

**Severity**: MEDIUM
**CVSS 3.1**: 6.8 (MEDIUM)

#### Description
Out-of-band messages on UNIX domain sockets are accessible, providing primitives for kernel Use-After-Free exploits.

#### Proof of Concept

```python
import socket

s1, s2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s1.send(b"test", socket.MSG_OOB)
    print("MSG_OOB works - kernel UAF vector available")
except Exception as e:
    print(f"Blocked: {e}")
```

**Related CVEs**: CVE-2025-38236 (recent AF_UNIX UAF vulnerability)

---

### 6. Cgroups v1 (Deprecated, Vulnerable Version)

**Severity**: LOW (Not directly exploitable in this config)
**CVSS 3.1**: 4.2 (MEDIUM)

#### Finding
System uses deprecated cgroups v1, but `/sys/fs/cgroup/` is not accessible from sandbox.

```
7:pids:/
6:memory:/
5:job:/
4:devices:/
```

**Note**: CVE-2022-0492 (cgroups escape) is NOT exploitable because cgroup filesystem is hidden.

---

## Exploitation Scenario

### Attack Chain: Kernel Privilege Escalation

1. **User with CREATE FUNCTION permission** creates malicious Python UDF
2. **Compile kernel exploit** using available gcc
3. **Load exploit via memfd_create** (fileless)
4. **Execute with full syscall access** (Seccomp: 0)
5. **Kernel vulnerability triggered** → root in guest VM
6. **Attempt VM escape** (9p filesystem bugs, namespace escape, etc.)
7. **Access other tenants' data** in multi-tenant environment

### Why This Is Critical

- **No seccomp** = Full kernel attack surface
- **Old kernel** = Multiple known vulnerabilities
- **Compiler available** = Can adapt any public exploit
- **memfd_create** = Fileless execution
- **Multi-tenant environment** = Lateral movement possible

---

## Tested Environments

- **Workspace**: dbc-54d21f62-0426.cloud.databricks.com
- **Warehouse**: d8637cca1dc66ba3 (Serverless SQL Warehouse)
- **Kernel**: Linux 4.4.0 (aarch64)
- **Date Tested**: 2025-12-06
- **Status**: ✅ All findings reproduced on fresh workspace

---

## CVSS 3.1 Scoring

### Primary Finding: Seccomp Disabled

**Base Score**: 9.1 (CRITICAL)

- **Attack Vector (AV)**: Network (N) - Remote via UDF execution
- **Attack Complexity (AC)**: Low (L) - Simple UDF creation
- **Privileges Required (PR)**: Low (L) - Only CREATE FUNCTION needed
- **User Interaction (UI)**: None (N)
- **Scope (S)**: Changed (C) - Can escape sandbox
- **Confidentiality (C)**: High (H) - Access to tenant data
- **Integrity (I)**: High (H) - Code execution on host
- **Availability (A)**: High (H) - DoS possible

**Vector String**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`

---

## Remediation

### Immediate Actions (P0 - Critical)

1. **Enable seccomp filtering**
   - Implement strict syscall whitelist
   - Block: perf_event_open, keyctl, userfaultfd, bpf, ptrace
   - Allow only: read, write, open, close, mmap, etc.
   - Reference: Docker default seccomp profile

2. **Update kernel to LTS version**
   - Current: 4.4.0 (Jan 2016)
   - Recommended: 6.1+ or 6.6+ (latest LTS)
   - Apply all security patches

3. **Remove compiler tools from production**
   - No legitimate use case for gcc/g++ in UDF runtime
   - If compilation needed, use isolated build environment

### Medium Priority (P1)

4. **Block memfd_create syscall** (via seccomp when enabled)
5. **Upgrade to cgroups v2** for better security model
6. **Mount /proc with hidepid=2** to reduce information leakage
7. **Implement runtime monitoring** for exploit attempts

### Long-term (P2)

8. **Regular security audits** of sandbox configuration
9. **Automated testing** for seccomp bypass attempts
10. **Security documentation** for UDF sandbox model

---

## Business Impact

### Severity Assessment

- **Likelihood**: MEDIUM (requires kernel exploit expertise)
- **Impact**: CRITICAL (data breach, multi-tenant compromise)
- **Overall Risk**: HIGH

### Technical Impact

- ✅ Kernel attack surface fully exposed
- ✅ Potential container/sandbox escape
- ✅ Access to other tenants' data in multi-tenant setup
- ✅ Compliance violations (SOC2, ISO27001)
- ✅ Reputational damage if exploited

### Affected Assets

- All Databricks workspaces with SQL Warehouses
- All Unity Catalog implementations using Python UDFs
- Multi-tenant infrastructure (cross-tenant access risk)

---

## Timeline

- **2025-12-05**: Initial reconnaissance, discovered Seccomp: 0
- **2025-12-05**: Confirmed on first workspace (dbc-4b448b2e-59b6)
- **2025-12-06**: Reproduced on second workspace (dbc-54d21f62-0426)
- **2025-12-06**: Comprehensive testing, confirmed all findings
- **2025-12-06**: Report submitted to HackerOne

---

## References

- Docker seccomp profile: https://github.com/moby/moby/blob/master/profiles/seccomp/default.json
- Linux kernel CVE database: https://www.cvedetails.com/product/47/Linux-Linux-Kernel.html
- Container security best practices: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

---

**Report Classification**: Confidential - Databricks Bug Bounty
**Researcher**: Security Testing Team
**Contact**: Via HackerOne platform

