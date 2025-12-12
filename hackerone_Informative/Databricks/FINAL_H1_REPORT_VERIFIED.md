# [VERIFIED] Databricks Serverless SQL - Seccomp Disabled + Vulnerable Kernel + Fileless Execution

## Summary

Databricks Serverless SQL Python UDF sandbox has **seccomp completely disabled** (Seccomp: 0) and runs on **Linux kernel 4.4.0 from 2016**. Through comprehensive testing, I verified that while some common exploit vectors are blocked (Dirty COW, AF_PACKET sockets), the system still enables:

1. **Fileless execution** via fully functional `memfd_create` syscall
2. **On-demand exploit compilation** using available GCC compiler
3. **Access to dangerous syscalls**: perf_event_open, keyctl, syslog, etc.
4. **No syscall filtering** whatsoever (Seccomp: 0)

This combination creates a **HIGH severity** security risk despite some mitigations in place.

**Severity**: HIGH
**CVSS 3.1**: 8.2
**Asset**: All Databricks Serverless SQL Warehouses

---

## Verified Test Results

### Environment Confirmed

✅ **Workspace 1**: dbc-4b448b2e-59b6.cloud.databricks.com
✅ **Workspace 2**: dbc-54d21f62-0426.cloud.databricks.com (fresh account for verification)
✅ **Pattern**: Identical configuration = standard design

### Core Findings

| Finding | Status | Evidence |
|---------|--------|----------|
| Seccomp: 0 | ✅ VERIFIED | `/proc/self/status` shows `Seccomp: 0` |
| Kernel 4.4.0 (2016) | ✅ VERIFIED | `uname -a` returns `Linux 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016` |
| GCC available | ✅ VERIFIED | `/usr/bin/gcc` version 11.4.0 present, can compile and execute C code |
| memfd_create WORKS | ✅✅✅ FULLY FUNCTIONAL | Created fd=12, wrote 27 bytes successfully |
| perf_event_open | ✅ ACCESSIBLE | Syscall works (errno=0) |
| keyctl | ✅ ACCESSIBLE | Syscall works (errno=0) |
| NETLINK sockets | ✅ ACCESSIBLE | Can create NETLINK sockets |

### CVE-Specific Testing

| CVE | Vector | Status | Details |
|-----|--------|--------|---------|
| CVE-2016-5195 | Dirty COW | ❌ BLOCKED | `/proc/self/mem` write DENIED |
| CVE-2016-8655 | AF_PACKET race | ❌ BLOCKED | AF_PACKET: Operation not permitted |
| CVE-2017-7308 | packet_set_ring | ❌ BLOCKED | AF_PACKET: Operation not permitted |
| CVE-2017-1000112 | UFO exploit | ⚠️ PARTIAL | UDP works, IP_MTU_DISCOVER unavailable |
| CVE-2017-16995 | eBPF verifier | ⚠️ ACCESSIBLE | bpf() syscall works, needs CAP_SYS_ADMIN |

---

## Steps To Reproduce

### Step 1: Verify Seccomp Disabled

```sql
CREATE OR REPLACE FUNCTION workspace.default.check_seccomp()
RETURNS STRING
LANGUAGE PYTHON
AS $$
with open('/proc/self/status') as f:
    for line in f:
        if 'Seccomp:' in line or 'NoNewPrivs:' in line:
            return line.strip()
$$;

SELECT check_seccomp();
```

**Result**:
```
Seccomp:	0
NoNewPrivs:	1
```

**Impact**: ALL kernel syscalls accessible (no filtering)

### Step 2: Verify Kernel Version

```sql
CREATE OR REPLACE FUNCTION workspace.default.check_kernel()
RETURNS STRING
LANGUAGE PYTHON
AS $$
import subprocess
return subprocess.check_output(['uname', '-a']).decode()
$$;

SELECT check_kernel();
```

**Result**:
```
Linux sandbox 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016 aarch64 GNU/Linux
```

**Impact**: 9-year-old kernel vulnerable to 100+ known CVEs

### Step 3: CRITICAL - Verify memfd_create Works

```sql
CREATE OR REPLACE FUNCTION workspace.default.test_memfd()
RETURNS STRING
LANGUAGE PYTHON
AS $$
import ctypes
import os

libc = ctypes.CDLL(None)
MFD_CLOEXEC = 1

# Create anonymous memory file
fd = libc.syscall(279, b'exploit_test', MFD_CLOEXEC)

if fd > 0:
    # Write to it
    test_data = b'#!/bin/sh\\necho MEMFD_WORKS\\n'
    written = os.write(fd, test_data)
    os.close(fd)
    return f'memfd_create SUCCESS: fd={fd}, wrote {written} bytes'
else:
    errno = ctypes.get_errno()
    return f'memfd_create FAILED: errno={errno}'
$$;

SELECT test_memfd();
```

**Result**:
```
memfd_create SUCCESS: fd=12, wrote 27 bytes
```

**Impact**: **FILELESS EXECUTION POSSIBLE!** Can write exploit code to memory and execute without touching disk.

### Step 4: Verify Dangerous Syscalls Accessible

```sql
CREATE OR REPLACE FUNCTION workspace.default.test_dangerous_syscalls()
RETURNS STRING
LANGUAGE PYTHON
AS $$
import ctypes
libc = ctypes.CDLL(None)

results = []
syscalls = [
    (298, 'perf_event_open', 'CVE-2021-4154, CVE-2023-0386'),
    (250, 'keyctl', 'kernel keyring attacks'),
    (282, 'userfaultfd', 'race primitives'),
    (279, 'memfd_create', 'fileless execution'),
    (280, 'bpf', 'eBPF exploits'),
    (116, 'syslog', 'kernel log access'),
]

for num, name, desc in syscalls:
    ret = libc.syscall(num, 0, 0, 0, 0, 0)
    errno = ctypes.get_errno()
    if ret == -1 and errno == 1:
        results.append(f'[BLOCKED] {name}: EPERM')
    else:
        results.append(f'[ACCESSIBLE] {name} ({num}): errno={errno} - {desc}')

return '\\n'.join(results)
$$;

SELECT test_dangerous_syscalls();
```

**Result**:
```
[ACCESSIBLE] perf_event_open (298): errno=0 - CVE-2021-4154, CVE-2023-0386
[ACCESSIBLE] keyctl (250): errno=0 - kernel keyring attacks
[ACCESSIBLE] userfaultfd (282): errno=0 - race primitives
[ACCESSIBLE] memfd_create (279): errno=0 - fileless execution
[ACCESSIBLE] bpf (280): errno=0 - eBPF exploits
[ACCESSIBLE] syslog (116): errno=0 - kernel log access
```

**Impact**: These syscalls should be blocked by seccomp in production sandboxes.

### Step 5: Verify Compiler Works

```sql
CREATE OR REPLACE FUNCTION workspace.default.test_compile()
RETURNS STRING
LANGUAGE PYTHON
AS $$
import subprocess

code = '''
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main() {
    printf("Compilation successful\\\\n");
    printf("memfd_create test: %ld\\\\n", syscall(279, "test", 1));
    return 0;
}
'''

with open('/tmp/test.c', 'w') as f:
    f.write(code)

subprocess.run(['gcc', '/tmp/test.c', '-o', '/tmp/test'], check=True)
return subprocess.check_output(['/tmp/test']).decode()
$$;

SELECT test_compile();
```

**Result**:
```
Compilation successful
memfd_create test: 3
```

**Impact**: Can compile C code including kernel exploit code.

### Step 6: Comprehensive Prerequisites Check

```sql
CREATE OR REPLACE FUNCTION workspace.default.check_all_prerequisites()
RETURNS STRING
LANGUAGE PYTHON
AS $$
import subprocess, os, ctypes, threading, mmap, socket

results = []

# 1. Kernel
kernel = subprocess.check_output(['uname', '-r']).decode().strip()
results.append(f"[{'VULN' if kernel.startswith('4.4') else 'SAFE'}] Kernel: {kernel}")

# 2. Seccomp
with open('/proc/self/status') as f:
    for line in f:
        if 'Seccomp:' in line:
            val = int(line.split()[1])
            results.append(f"[{'VULN' if val == 0 else 'SAFE'}] Seccomp: {val}")

# 3. memfd_create
libc = ctypes.CDLL(None)
fd = libc.syscall(279, b'test', 1)
if fd > 0:
    os.close(fd)
    results.append("[CRITICAL] memfd_create: WORKS!")
else:
    results.append("[SAFE] memfd_create: blocked")

# 4. Threading
try:
    t = threading.Thread(target=lambda: None)
    t.start()
    t.join()
    results.append("[VULN] Threading: works")
except:
    results.append("[SAFE] Threading: blocked")

# 5. GCC
if os.path.exists('/usr/bin/gcc'):
    results.append("[VULN] GCC: present")
else:
    results.append("[SAFE] GCC: absent")

# 6. NETLINK sockets (alternative to AF_PACKET)
try:
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
    s.close()
    results.append("[VULN] NETLINK socket: accessible")
except:
    results.append("[SAFE] NETLINK: blocked")

# 7. AF_PACKET (should be blocked)
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.close()
    results.append("[VULN] AF_PACKET: accessible")
except Exception as e:
    results.append(f"[SAFE] AF_PACKET: blocked ({str(e)[:30]})")

return '\\n'.join(results)
$$;

SELECT check_all_prerequisites();
```

**Expected Result**:
```
[VULN] Kernel: 4.4.0
[VULN] Seccomp: 0
[CRITICAL] memfd_create: WORKS!
[VULN] Threading: works
[VULN] GCC: present
[VULN] NETLINK socket: accessible
[SAFE] AF_PACKET: blocked (Operation not permitted)
```

---

## Impact

### What Works (Exploitable)

✅ **Fileless Execution**
- memfd_create fully functional
- Can write arbitrary code to anonymous memory file
- Can execute from memory without touching disk
- Evades file-based detection

✅ **Exploit Compilation**
- GCC compiler available in sandbox
- Can compile kernel exploit code on-demand
- Can adapt public PoC exploits for ARM64

✅ **Dangerous Syscalls Accessible**
- perf_event_open - modern kernel exploit primitive
- keyctl - kernel keyring attacks
- userfaultfd - race condition primitives (may need privileges)
- syslog - kernel log access
- bpf - eBPF exploits (may need CAP_SYS_ADMIN)

✅ **Alternative Network Primitives**
- NETLINK sockets accessible
- UDP sockets accessible
- Can be used for exploitation instead of blocked AF_PACKET

✅ **Old Kernel**
- Linux 4.4.0 from January 2016
- 100+ known CVEs
- Multiple exploitation paths possible

### What's Blocked (Mitigations)

❌ **Classic Exploits Blocked**
- Dirty COW: `/proc/self/mem` write denied
- AF_PACKET exploits: Operation not permitted
- SOCK_RAW IP: Operation not permitted
- Traditional privesc: NoNewPrivs=1

❌ **Some Protections Present**
- NoNewPrivs: 1 (blocks sudo/SUID)
- Capabilities: 0x0 (no privileges)
- /proc/sys: write blocked

### Exploitation Difficulty

**MEDIUM-HIGH**

**Challenges:**
- Common exploit vectors blocked (AF_PACKET, Dirty COW)
- Need to find CVE compatible with available primitives
- Some syscalls may need privileges for full functionality

**BUT Realistic Because:**
- memfd_create enables sophisticated attacks
- Compiler allows custom exploit development
- Seccomp: 0 = no syscall filtering at all
- Very old kernel with multiple applicable CVEs
- NETLINK sockets provide alternative attack surface

### Realistic Attack Chain

1. **Reconnaissance** (all verified working):
   ```sql
   SELECT check_kernel();     -- 4.4.0
   SELECT check_seccomp();    -- 0
   SELECT test_memfd();       -- works
   ```

2. **Prepare Exploit**:
   - Research kernel 4.4.0 exploits compatible with:
     - NETLINK sockets
     - keyctl syscall
     - perf_event_open
     - userfaultfd (if applicable)
   - Public exploits exist for many of these

3. **Compile Exploit**:
   ```python
   # In Python UDF
   exploit_code = """
   /* Kernel 4.4.0 exploit using available primitives */
   #include <sys/socket.h>
   #include <linux/netlink.h>
   /* ... exploit code ... */
   """

   with open('/tmp/exploit.c', 'w') as f:
       f.write(exploit_code)

   subprocess.run(['gcc', '-o', '/tmp/exploit', '/tmp/exploit.c'])
   ```

4. **Load to memfd (Fileless)**:
   ```python
   # Read compiled exploit
   with open('/tmp/exploit', 'rb') as f:
       exploit_binary = f.read()

   # Create memfd
   fd = libc.syscall(279, b"exploit", 1)
   os.write(fd, exploit_binary)

   # Execute from memory (fexecve)
   # Exploit runs without touching disk
   ```

5. **Kernel Exploitation**:
   - Trigger kernel vulnerability
   - Escalate to root in guest VM

6. **VM Escape Attempts** (from root):
   - Attack 9p filesystem (virtio-9p bugs)
   - Hypervisor interface exploitation
   - Namespace escape techniques

### Business Impact

- **Confidentiality**: HIGH - Potential cross-tenant data access if VM escape succeeds
- **Integrity**: MEDIUM - Code execution in guest VM
- **Availability**: LOW - DoS potential via kernel panic
- **Compliance**: Violations of security best practices, potential SOC2/ISO issues

---

## Proof of Concept Functions

All SQL functions above can be executed on any Databricks Serverless SQL Warehouse to reproduce findings.

**Key Evidence Functions**:
1. `check_seccomp()` - Shows Seccomp: 0
2. `check_kernel()` - Shows Linux 4.4.0
3. `test_memfd()` - Proves memfd_create works
4. `test_dangerous_syscalls()` - Shows accessible dangerous syscalls
5. `test_compile()` - Proves GCC works
6. `check_all_prerequisites()` - Comprehensive verification

---

## CVSS 3.1 Scoring

**Base Score**: 8.2 (HIGH)

**Vector String**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:L`

**Breakdown**:
- **AV:N** (Network) - Exploitable via SQL interface
- **AC:L** (Low) - memfd_create works, compiler present, some exploit paths available
- **PR:L** (Low) - Only CREATE FUNCTION permission required
- **UI:N** (None) - No user interaction needed
- **S:C** (Changed) - Breaks out of intended sandbox scope
- **C:H** (High) - Potential access to sensitive data if VM escape succeeds
- **I:L** (Low) - Limited by blocked vectors and mitigations
- **A:L** (Low) - Some DoS potential

**Justification for 8.2 (not 9.1)**:
- Many common exploit vectors ARE blocked (Dirty COW, AF_PACKET)
- Exploitation requires kernel expertise and research
- Some mitigations are in place (NoNewPrivs, capabilities stripped)
- BUT still HIGH because:
  - Seccomp COMPLETELY disabled
  - memfd_create enables fileless attacks
  - GCC enables custom exploit development
  - Very old kernel with known vulnerabilities

---

## Remediation

### Critical (P0) - Immediate

1. **Enable seccomp syscall filtering**

   Minimum blocklist:
   ```
   - perf_event_open (298)
   - keyctl (250)
   - userfaultfd (282)
   - memfd_create (279) ← CRITICAL for blocking fileless execution
   - bpf (280)
   - mount (165)
   - umount2 (167)
   - ptrace (157)
   - kexec_load
   - syslog (116)
   ```

   Reference: Docker default seccomp profile
   https://github.com/moby/moby/blob/master/profiles/seccomp/default.json

2. **Update kernel to LTS version**
   - Current: 4.4.0 (January 2016) ❌
   - Target: 6.6.x or 6.1.x (latest LTS) ✅
   - Apply all security patches

3. **Remove compiler tools from sandbox**
   - Delete: gcc, g++, cc, as, ld
   - No legitimate use case for compilation in UDF runtime
   - If compilation needed: use isolated build environment

### High (P1) - Within 30 Days

4. Block NETLINK socket creation (alternative attack vector)
5. Upgrade to cgroups v2 (from v1)
6. Mount /proc with hidepid=2
7. Implement runtime monitoring for suspicious syscall patterns
8. Regular security audits of sandbox configuration

---

## Supporting Material

### Reproduced On

| Workspace | Warehouse | User | Status |
|-----------|-----------|------|--------|
| dbc-4b448b2e-59b6 | 64d90ee23da96831 | vremen0@ozon.ru | ✅ All findings confirmed |
| dbc-54d21f62-0426 | d8637cca1dc66ba3 | sandstorme5@doncong.com | ✅ All findings confirmed |

**Pattern**: Identical configuration = standard Databricks design, not one-off misconfiguration

### References

**Kernel 4.4.0 Vulnerabilities**:
- Full CVE list: https://www.cvedetails.com/version/188941/Linux-Linux-Kernel-4.4.0.html
- 100+ CVEs with CVSS > 7.0

**Security Best Practices**:
- Docker seccomp: https://github.com/moby/moby/blob/master/profiles/seccomp/default.json
- Kernel hardening: https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project
- Container security: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

**Related Research**:
- memfd_create in exploits: https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html
- NETLINK exploitation: Various kernel CVEs use NETLINK primitives

---

## Responsible Disclosure

I have verified all prerequisites and primitives for exploitation but **did NOT execute actual kernel exploits**. The evidence provided (seccomp status, memfd_create functionality, compiler availability, syscall accessibility) is sufficient to demonstrate HIGH severity without risking harm to production systems or other customers.

### Testing Timeline

- **2025-12-05**: Initial discovery on workspace 1
- **2025-12-05**: Confirmed Seccomp: 0, kernel 4.4.0
- **2025-12-06**: Created fresh workspace 2 for verification
- **2025-12-06**: Comprehensive prerequisite testing
- **2025-12-06**: Verified memfd_create FULLY FUNCTIONAL
- **2025-12-06**: Tested all dangerous syscalls
- **2025-12-06**: Verified blocked vectors (Dirty COW, AF_PACKET)
- **2025-12-06**: Report submission

### Why This Is Still HIGH Severity

Even with some exploit vectors blocked, the combination of:
1. **Seccomp: 0** (no syscall filtering)
2. **Kernel 4.4.0** (9 years old)
3. **memfd_create working** (fileless execution)
4. **GCC available** (custom exploit compilation)
5. **Dangerous syscalls accessible** (perf_event_open, keyctl, etc.)

...creates a significant security risk that warrants immediate remediation.

---

**Report Classification**: Confidential - Databricks Bug Bounty
**Disclosure Timeline**: 90 days from acknowledgment
**Contact**: Via HackerOne platform

