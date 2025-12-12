# [Critical] Python UDF sandbox on shared SQL Warehouses runs on EOL Linux 4.4 with Seccomp disabled

**Asset / Environment**  
- Asset: `https://<YOUR_DBC_HOST>` (SQL Warehouse, bug bounty workspace)  
- Feature: `LANGUAGE PYTHON` UDFs executed via `/api/2.0/sql/statements`  
- Proposed severity: **Critical (Data plane: cross-tenant access / contamination if kernel bug exploited)**  

---

## Summary

Databricks documentation states that Lakeguard isolates user code using secure containers so that multiple users can share the same compute resource securely, and that this isolation explicitly applies to **Python UDFs on serverless compute and SQL warehouses**, preventing user code from accessing other users’ data or the underlying machine.

My research shows that the Python UDF sandbox used in SQL Warehouses is:

- Running on an **end-of-life Linux 4.4 kernel** (no longer receiving security fixes upstream).  
- Running with **`Seccomp: 0` (no syscall filtering)** inside the UDF container.  
- Allowing compilation and execution of arbitrary native C code with `gcc` and access to “dangerous” syscalls (`perf_event_open`, `userfaultfd`, `keyctl`, `memfd_create`, etc.).  

I did **not** run an actual kernel exploit PoC, but I verified that **all primitives normally required for kernel exploitation from an unprivileged process are present**.  
In a **shared SQL Warehouse data plane**, this breaks the Lakeguard isolation assumptions and creates a realistic path for an authenticated warehouse user to escalate to **node-level root and cross-tenant data access**, which matches Databricks’s own description of *Critical* data-plane impact (cross-tenant access / contamination).

---

## What I actually did

All actions were limited to **my own bug bounty workspace and warehouse**, and I did **not** attempt to access other customers’ data.

### 1) Confirmed kernel version and environment

Using a small helper UDF that can run shell commands (via Python `subprocess`) and the SQL Statements API:

```sql
SELECT workspace.default.shell_exec('uname -a');
```

The result shows the UDF sandbox running on **Linux 4.4.x**, which is an **EOL kernel** (the 4.4 branch is no longer supported upstream and does not receive new security fixes).

### 2) Verified sandbox flags: `Seccomp`, `NoNewPrivs`, capabilities

```sql
SELECT workspace.default.shell_exec(
  'cat /proc/self/status | grep -E "Seccomp|NoNewPrivs|Cap"'
);
```

Example output from the sandboxed UDF process:

```text
CapInh: 00000000000000c0
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 00000000000000c0
Seccomp:        0
```

Then I checked `no_new_privs` explicitly via `prctl(PR_GET_NO_NEW_PRIVS)` inside the same environment:

```sql
SELECT workspace.default.shell_exec('python3 -c "
import ctypes
libc = ctypes.CDLL(None)
PR_GET_NO_NEW_PRIVS = 39
r = libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
print(f"NoNewPrivs via prctl: {r}")
"');
```

Result:

```text
NoNewPrivs via prctl: 1
```

So the UDF sandbox runs with:

- **`Seccomp: 0`** → no syscall filtering (full syscall surface).  
- `no_new_privs=1` and no effective capabilities → classic SUID/cap-based local priv-esc is blocked, but **kernel bugs remain fully reachable**.

I also confirmed that:

- `setuid(0)` fails (UID stays 1000).  
- Reading `/etc/shadow` returns `Permission denied`.  

I did **not** obtain root or access system secrets.

### 3) Demonstrated availability of kernel-exploit primitives

Using the same UDF + `shell_exec` approach, I:

- Confirmed `gcc` is available within the sandbox (`which gcc`).  
- Compiled and ran small C programs inside the UDF container to test syscalls like:
  - `perf_event_open`
  - `userfaultfd`
  - `keyctl`
  - `memfd_create`
- Verified that these syscalls succeed (no `EPERM` / no `seccomp` blocking), and that the processes can map memory and execute helper binaries.

These tests are intentionally **non-destructive**:

- they stop after checking syscall behavior and environment;
- **no public kernel exploit code** was ever executed;
- no attempt was made to get root or to escape to the host.

Taken together, they prove that **untrusted SQL Warehouse UDFs run in an environment that is ideal for kernel exploitation**: EOL kernel, no seccomp, compiler, and all required syscalls.

---

## Impact (against Databricks guarantees and severity table)

Databricks Lakeguard is documented as providing container-based isolation so that:

- user code is isolated from the Spark engine and from other users;  
- each client application runs in its own isolated container environment;  
- user code **cannot access other users’ data or the underlying machine**, including for Python UDFs on serverless compute and SQL warehouses.

However, the configuration I observed means:

- Any user with SQL + Python UDF permissions in a shared SQL Warehouse has:
  - arbitrary code execution (by design),
  - on an **EOL kernel**,
  - with **no syscall filtering (Seccomp=0)**,
  - with access to typical kernel-exploit primitives (compiler + sensitive syscalls).

The **only remaining barrier** between untrusted tenant code and the underlying machine / other tenants is the absence of a currently-known exploit for this kernel build. This is significantly weaker than the isolation model described for Lakeguard and for shared SQL warehouses.

Given Databricks’s severity guidance:

- Data plane **Critical** includes *“Cross tenant access, data leak or contamination”*.
- **High** includes *“Container breakout limited to Tenant Environment”* and *“Core Security promise of a Major Lakehouse feature compromised”*.

This finding targets the **core Lakeguard container sandbox** that is supposed to protect multi-tenant SQL Warehouses. If (or when) any reachable kernel vuln exists for this kernel on this platform, exploitation from a Python UDF would:

1. Give **root on the SQL Warehouse compute node**, and  
2. Likely allow **cross-tenant data access or contamination**, violating Lakeguard’s tenant isolation guarantees.

Because this is a structural misconfiguration of a key Lakehouse security feature in a shared, multi-tenant data-plane service, I am submitting it as **Critical severity**, with realistic potential for cross-tenant compromise.

---

## Good-faith and scope notes

- I **did not** run any public kernel exploit PoCs or attempt to gain root.  
- I **did not** attempt to escape to the host, access other customers’ data, or cause DoS.  
- All testing was performed only in my own Databricks bug bounty workspace and SQL Warehouse.  
- I can provide the exact UDF definitions and helper scripts I used; all of them are non-destructive and only perform environment inspection.

