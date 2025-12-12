import requests
import time

base_url = "https://api.ffbbbdc6d3c353211fe2ba39c9f744cd.com/p/"
paths = [
    "front", "front-testnet", "back", "backend", "admin", "logs", 
    "metrics", "health", "status", "config", "dashboard", "user", "v1", "v2"
]

print(f"Fuzzing {base_url}...")

for p in paths:
    url = base_url + p
    try:
        r = requests.get(url, verify=False, timeout=5)
        print(f"/{p}: {r.status_code} (len: {len(r.content)})")
        if r.status_code != 404 and r.status_code != 403:
             print(f"  -> Content: {r.text[:100]}")
    except Exception as e:
        print(f"/{p}: Error {e}")
    time.sleep(0.5)
