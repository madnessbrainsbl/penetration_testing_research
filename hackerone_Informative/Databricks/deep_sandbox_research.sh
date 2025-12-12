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
        print('[empty result]')
except:
    print('[parse error]')
"
}

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║          DEEP SANDBOX SECURITY RESEARCH - Phase 1             ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

echo "═══ [1/10] KERNEL & VIRTUALIZATION TYPE ═══"
exec_sql "SELECT workspace.default.shell_exec('uname -a')"
echo ""

echo "═══ [2/10] CHECKING FOR FIRECRACKER SIGNATURES ═══"
exec_sql "SELECT workspace.default.shell_exec('dmesg 2>&1 | grep -i firecracker | head -5 || echo \"[no firecracker in dmesg]\"')"
echo ""

echo "═══ [3/10] HYPERVISOR DETECTION ═══"
exec_sql "SELECT workspace.default.shell_exec('cat /proc/cpuinfo | grep -i hypervisor || echo \"[no hypervisor flag]\"')"
echo ""

echo "═══ [4/10] CGROUP VERSION & HIERARCHY ═══"
exec_sql "SELECT workspace.default.shell_exec('cat /proc/self/cgroup')"
echo ""

echo "═══ [5/10] NAMESPACE ISOLATION ═══"
exec_sql "SELECT workspace.default.shell_exec('ls -la /proc/self/ns/')"
echo ""

echo "═══ [6/10] PROCESS 1 INFO (init) ═══"
exec_sql "SELECT workspace.default.shell_exec('cat /proc/1/cmdline 2>&1 | tr \"\\000\" \" \" || echo \"[cannot read]\"')"
echo ""

echo "═══ [7/10] VSOCK DEVICE CHECK ═══"
exec_sql "SELECT workspace.default.shell_exec('ls -la /dev/vsock 2>&1 || echo \"[no vsock device]\"')"
exec_sql "SELECT workspace.default.shell_exec('ls -la /dev/vhost-vsock 2>&1 || echo \"[no vhost-vsock]\"')"
echo ""

echo "═══ [8/10] LXC-SPECIFIC FILES ═══"
exec_sql "SELECT workspace.default.shell_exec('ls -la /dev/lxc/ 2>&1 || echo \"[no /dev/lxc/]\"')"
exec_sql "SELECT workspace.default.shell_exec('cat /proc/1/environ 2>&1 | grep -i lxc | head -3 || echo \"[no LXC in environ]\"')"
echo ""

echo "═══ [9/10] MOUNT POINTS & FILESYSTEM ═══"
exec_sql "SELECT workspace.default.shell_exec('mount | grep -E \"(9p|virtiofs|lxc|firecracker)\" || echo \"[no special mounts]\"')"
echo ""

echo "═══ [10/10] DEVICE LIST ═══"
exec_sql "SELECT workspace.default.shell_exec('ls -la /dev/ | head -20')"
echo ""

echo "═══ PHASE 1 COMPLETE ═══"

