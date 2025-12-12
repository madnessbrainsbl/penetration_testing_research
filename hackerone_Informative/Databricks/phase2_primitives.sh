#!/bin/bash

TOKEN="REDACTED_DATABRICKS_TOKEN"
WORKSPACE="https://dbc-54d21f62-0426.cloud.databricks.com"
WAREHOUSE_ID="d8637cca1dc66ba3"

exec_sql() {
    local statement="$1"
    curl -s -X POST "$WORKSPACE/api/2.0/sql/statements" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
        \"warehouse_id\": \"$WAREHOUSE_ID\",
        \"statement\": $(echo "$statement" | python3 -c "import sys, json; print(json.dumps(sys.stdin.read()))"),
        \"wait_timeout\": \"30s\"
      }" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    result = data.get('result', {}).get('data_array', [[]])
    if result and result[0]:
        print(result[0][0])
    else:
        print('[empty]')
except:
    print('[error]')
"
}

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║          DEEP SANDBOX SECURITY RESEARCH - Phase 2             ║"
echo "║                  Security Primitives Check                     ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

echo "═══ [1/8] PROCESS STATUS (Seccomp, NoNewPrivs, Capabilities) ═══"
exec_sql "SELECT workspace.default.shell_exec('cat /proc/self/status | grep -E \"(Seccomp|NoNewPrivs|Cap)\"')"
echo ""

echo "═══ [2/8] VERIFY NoNewPrivs VIA PRCTL ═══"
exec_sql "SELECT workspace.default.shell_exec('python3 -c \"
import ctypes
libc = ctypes.CDLL(None)
PR_GET_NO_NEW_PRIVS = 39
result = libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
print(f\\\"NoNewPrivs via prctl: {result} (1=enabled)\\\")
\"')"
echo ""

echo "═══ [3/8] ATTEMPT setuid(0) - Should FAIL ═══"
exec_sql "SELECT workspace.default.shell_exec('python3 -c \"
import ctypes, os
libc = ctypes.CDLL(None)
before = os.getuid()
ret = libc.setuid(0)
after = os.getuid()
print(f\\\"UID before: {before}, setuid(0) returned: {ret}, UID after: {after}\\\")
if ret == 0:
    print(\\\"WARNING: setuid(0) SUCCEEDED!\\\")
else:
    print(\\\"✓ setuid(0) blocked (expected)\\\")
\"')"
echo ""

echo "═══ [4/8] KERNEL SYMBOLS (KASLR bypass check) ═══"
exec_sql "SELECT workspace.default.shell_exec('cat /proc/kallsyms 2>&1 | head -5 || echo \"[no kallsyms access]\"')"
echo ""

echo "═══ [5/8] PTRACE SCOPE ═══"
exec_sql "SELECT workspace.default.shell_exec('cat /proc/sys/kernel/yama/ptrace_scope 2>&1 || echo \"[no ptrace_scope]\"')"
echo ""

echo "═══ [6/8] AVAILABLE SYSCALLS TEST ═══"
exec_sql "SELECT workspace.default.shell_exec('python3 -c \"
import ctypes
libc = ctypes.CDLL(None)

# Test dangerous syscalls
syscalls = {
    \\\"keyctl\\\": 250,
    \\\"perf_event_open\\\": 298,
    \\\"userfaultfd\\\": 282,
    \\\"bpf\\\": 280
}

for name, num in syscalls.items():
    ret = libc.syscall(num, 0, 0, 0, 0, 0)
    print(f\\\"{name}({num}): {ret}\\\")
\"')"
echo ""

echo "═══ [7/8] MEMORY LIMITS & RLIMITS ═══"
exec_sql "SELECT workspace.default.shell_exec('cat /proc/self/limits | head -15')"
echo ""

echo "═══ [8/8] CHECK FOR SUID BINARIES ═══"
exec_sql "SELECT workspace.default.shell_exec('find / -perm -4000 2>/dev/null | head -10 || echo \"[no suid binaries]\"')"
echo ""

echo "═══ PHASE 2 COMPLETE ═══"

