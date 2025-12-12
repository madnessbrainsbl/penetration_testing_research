import requests
import json

target = "https://api.ffbbbdc6d3c353211fe2ba39c9f744cd.com/p/admin"
# Also try /p/back as it gave 500 too
targets = [target, "https://api.ffbbbdc6d3c353211fe2ba39c9f744cd.com/p/back"]

params = [
    "action", "method", "cmd", "command", "query", "q", 
    "id", "uid", "user", "username", "email", 
    "data", "payload", "config", "type", "event",
    "key", "token", "auth", "sign", "signature"
]

values = [
    "test", 
    1, 
    True, 
    {"test": 1}, 
    ["test"]
]

headers = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0"
}

print(f"Fuzzing params on {targets}...")

for url in targets:
    print(f"\nTarget: {url}")
    # Baseline
    try:
        base = requests.post(url, json={}, verify=False, timeout=5)
        print(f"Baseline {{}}: {base.status_code} (len: {len(base.content)})")
    except:
        print("Baseline failed")
        continue

    for p in params:
        for v in values:
            payload = {p: v}
            try:
                r = requests.post(url, json=payload, verify=False, timeout=3)
                # If length differs significantly or status changes
                if r.status_code != base.status_code or abs(len(r.content) - len(base.content)) > 10:
                    print(f"[!] FOUND DIFF: {json.dumps(payload)} -> {r.status_code} (len: {len(r.content)})")
                # else:
                #     print(f".", end="", flush=True)
            except Exception as e:
                pass
