import requests
import time

url = "https://api.ffbbbdc6d3c353211fe2ba39c9f744cd.com/p/admin"
payloads = [
    {},
    {"test": 1},
    [],
    "string",
    "<?xml version='1.0'?><root>test</root>"
]

headers = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0"
}

print(f"Probing {url} with POST...")

for p in payloads:
    try:
        r = requests.post(url, json=p if isinstance(p, (dict, list)) else None, data=p if isinstance(p, str) else None, headers=headers, verify=False, timeout=5)
        print(f"Payload: {str(p)[:20]} -> {r.status_code} (len: {len(r.content)})")
        if r.status_code != 500:
             print(f"  -> Content: {r.text[:200]}")
    except Exception as e:
        print(f"Error: {e}")
    time.sleep(0.5)
