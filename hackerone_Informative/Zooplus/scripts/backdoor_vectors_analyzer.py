#!/usr/bin/env python3
"""
Backdoor Vectors Analyzer для Zooplus
Анализирует возможные векторы для создания бэкдора в кластерной инфраструктуре
ВАЖНО: Только для легитимного пентестинга!
"""

import requests
import json
import sys
from urllib.parse import urljoin, urlparse
from datetime import datetime
import re

class BackdoorVectorAnalyzer:
    def __init__(self, target="www.zooplus.de"):
        self.target = target
        self.base_url = f"https://{target}"
        self.vectors = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def log_vector(self, severity, title, description, vector_type, endpoint=None, exploit_path=None):
        """Логирует найденный вектор"""
        vector = {
            "severity": severity,
            "title": title,
            "description": description,
            "type": vector_type,
            "endpoint": endpoint,
            "exploit_path": exploit_path,
            "timestamp": datetime.now().isoformat()
        }
        self.vectors.append(vector)
        print(f"[{severity}] {title}")
        if endpoint:
            print(f"    Endpoint: {endpoint}")
        if exploit_path:
            print(f"    Exploit Path: {exploit_path}")
    
    def check_webhook_endpoints(self):
        """Проверяет webhook endpoints для инъекции"""
        print("\n[*] Checking webhook endpoints...")
        
        webhook_paths = [
            "/webhook",
            "/webhooks",
            "/api/webhook",
            "/api/webhooks",
            "/hooks",
            "/callback",
            "/callbacks",
            "/notify",
            "/notification"
        ]
        
        for path in webhook_paths:
            try:
                url = urljoin(self.base_url, path)
                # Try GET
                resp = self.session.get(url, timeout=5, verify=False)
                if resp.status_code in [200, 405]:  # 405 = method not allowed but endpoint exists
                    self.log_vector(
                        "HIGH",
                        f"Webhook Endpoint Found: {path}",
                        "Webhook endpoint may allow injection of malicious payloads or callbacks to attacker-controlled servers.",
                        "webhook_injection",
                        endpoint=url,
                        exploit_path="POST malicious payload → callback to attacker server"
                    )
            except Exception as e:
                pass
    
    def check_file_upload(self):
        """Проверяет endpoints для загрузки файлов"""
        print("\n[*] Checking file upload endpoints...")
        
        upload_paths = [
            "/upload",
            "/api/upload",
            "/file/upload",
            "/api/file/upload",
            "/media/upload",
            "/images/upload"
        ]
        
        for path in upload_paths:
            try:
                url = urljoin(self.base_url, path)
                resp = self.session.get(url, timeout=5, verify=False)
                if resp.status_code in [200, 405]:
                    self.log_vector(
                        "HIGH",
                        f"File Upload Endpoint: {path}",
                        "File upload endpoint may allow uploading malicious files (webshells, backdoors).",
                        "file_upload",
                        endpoint=url,
                        exploit_path="Upload malicious file → Execute on server"
                    )
            except Exception as e:
                pass
    
    def check_code_execution(self):
        """Проверяет endpoints для выполнения кода"""
        print("\n[*] Checking code execution endpoints...")
        
        execution_paths = [
            "/api/execute",
            "/api/eval",
            "/api/run",
            "/api/script",
            "/admin/execute",
            "/console"
        ]
        
        for path in execution_paths:
            try:
                url = urljoin(self.base_url, path)
                resp = self.session.get(url, timeout=5, verify=False)
                if resp.status_code in [200, 405]:
                    self.log_vector(
                        "CRITICAL",
                        f"Code Execution Endpoint: {path}",
                        "Endpoint may allow arbitrary code execution - potential backdoor vector.",
                        "code_execution",
                        endpoint=url,
                        exploit_path="POST code → Execute on server"
                    )
            except Exception as e:
                pass
    
    def check_template_injection(self):
        """Проверяет template injection векторы"""
        print("\n[*] Checking template injection vectors...")
        
        template_paths = [
            "/api/render",
            "/api/template",
            "/render",
            "/template",
            "/api/preview"
        ]
        
        for path in template_paths:
            try:
                url = urljoin(self.base_url, path)
                resp = self.session.get(url, timeout=5, verify=False)
                if resp.status_code in [200, 405]:
                    self.log_vector(
                        "HIGH",
                        f"Template Endpoint: {path}",
                        "Template rendering endpoint may be vulnerable to SSTI (Server-Side Template Injection).",
                        "template_injection",
                        endpoint=url,
                        exploit_path="Inject template code → Execute on server"
                    )
            except Exception as e:
                pass
    
    def check_ssrf_vectors(self):
        """Проверяет SSRF векторы для доступа к внутренним сервисам"""
        print("\n[*] Checking SSRF vectors...")
        
        ssrf_paths = [
            "/api/fetch",
            "/api/proxy",
            "/api/request",
            "/api/url",
            "/api/import",
            "/api/export"
        ]
        
        for path in ssrf_paths:
            try:
                url = urljoin(self.base_url, path)
                resp = self.session.get(url, timeout=5, verify=False)
                if resp.status_code in [200, 405]:
                    self.log_vector(
                        "HIGH",
                        f"SSRF Vector: {path}",
                        "Endpoint may allow SSRF to access internal cluster services (metadata, admin APIs).",
                        "ssrf",
                        endpoint=url,
                        exploit_path="Request internal service → Access cluster metadata/admin"
                    )
            except Exception as e:
                pass
    
    def check_config_endpoints(self):
        """Проверяет endpoints для изменения конфигурации"""
        print("\n[*] Checking configuration endpoints...")
        
        config_paths = [
            "/api/config",
            "/api/settings",
            "/admin/config",
            "/api/admin/config"
        ]
        
        for path in config_paths:
            try:
                url = urljoin(self.base_url, path)
                resp = self.session.get(url, timeout=5, verify=False)
                if resp.status_code in [200, 405]:
                    self.log_vector(
                        "CRITICAL",
                        f"Config Endpoint: {path}",
                        "Configuration endpoint may allow modifying cluster settings or injecting malicious config.",
                        "config_injection",
                        endpoint=url,
                        exploit_path="Modify config → Inject backdoor settings"
                    )
            except Exception as e:
                pass
    
    def check_api_key_exposure(self):
        """Проверяет утечки API ключей в JavaScript"""
        print("\n[*] Checking for API key exposure in JavaScript...")
        
        try:
            resp = self.session.get(self.base_url, timeout=10, verify=False)
            # Extract JavaScript file URLs
            js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', resp.text)
            
            for js_file in js_files[:10]:  # Limit to first 10
                if not js_file.startswith('http'):
                    js_file = urljoin(self.base_url, js_file)
                
                try:
                    js_resp = self.session.get(js_file, timeout=5, verify=False)
                    js_content = js_resp.text
                    
                    # Look for API keys, tokens, secrets
                    patterns = {
                        "api[_-]?key": r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                        "api[_-]?token": r'["\']?api[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                        "secret": r'["\']?secret["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
                        "access[_-]?token": r'["\']?access[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']'
                    }
                    
                    for pattern_name, pattern in patterns.items():
                        matches = re.findall(pattern, js_content, re.IGNORECASE)
                        if matches:
                            self.log_vector(
                                "HIGH",
                                f"API Key Exposure in JS: {pattern_name}",
                                f"JavaScript file contains exposed {pattern_name}.",
                                "credential_exposure",
                                endpoint=js_file,
                                exploit_path=f"Extract {pattern_name} → Use for API access"
                            )
                            break
                except:
                    pass
        except Exception as e:
            pass
    
    def check_graphql_introspection(self):
        """Проверяет GraphQL introspection"""
        print("\n[*] Checking GraphQL introspection...")
        
        graphql_endpoints = [
            "/graphql",
            "/api/graphql",
            "/graphql/v1",
            "/graphql/v2"
        ]
        
        introspection_query = {
            "query": "query IntrospectionQuery { __schema { queryType { name } } }"
        }
        
        for endpoint in graphql_endpoints:
            try:
                url = urljoin(self.base_url, endpoint)
                resp = self.session.post(url, json=introspection_query, timeout=5, verify=False)
                
                if resp.status_code == 200 and "__schema" in resp.text:
                    self.log_vector(
                        "MEDIUM",
                        f"GraphQL Introspection Enabled: {endpoint}",
                        "GraphQL introspection is enabled, exposing API schema.",
                        "information_disclosure",
                        endpoint=url,
                        exploit_path="Query introspection → Discover endpoints → Exploit"
                    )
            except Exception as e:
                pass
    
    def check_jwt_manipulation(self):
        """Проверяет векторы для манипуляции JWT"""
        print("\n[*] Checking JWT manipulation vectors...")
        
        auth_endpoints = [
            "/api/auth",
            "/auth",
            "/api/login",
            "/login",
            "/api/token"
        ]
        
        for endpoint in auth_endpoints:
            try:
                url = urljoin(self.base_url, endpoint)
                resp = self.session.get(url, timeout=5, verify=False)
                if resp.status_code in [200, 401, 405]:
                    self.log_vector(
                        "HIGH",
                        f"Auth Endpoint: {endpoint}",
                        "Authentication endpoint may be vulnerable to JWT manipulation (algorithm confusion, weak secret).",
                        "jwt_manipulation",
                        endpoint=url,
                        exploit_path="Manipulate JWT → Escalate privileges → Backdoor access"
                    )
            except Exception as e:
                pass
    
    def check_persistent_storage(self):
        """Проверяет векторы для персистентного хранения бэкдора"""
        print("\n[*] Checking persistent storage vectors...")
        
        storage_paths = [
            "/api/storage",
            "/api/cache",
            "/api/session",
            "/api/data"
        ]
        
        for path in storage_paths:
            try:
                url = urljoin(self.base_url, path)
                resp = self.session.get(url, timeout=5, verify=False)
                if resp.status_code in [200, 405]:
                    self.log_vector(
                        "MEDIUM",
                        f"Storage Endpoint: {path}",
                        "Storage endpoint may allow persisting malicious data that survives restarts.",
                        "persistent_storage",
                        endpoint=url,
                        exploit_path="Store malicious payload → Survives cluster restart"
                    )
            except Exception as e:
                pass
    
    def generate_report(self):
        """Генерирует отчет"""
        report = {
            "target": self.target,
            "scan_date": datetime.now().isoformat(),
            "total_vectors": len(self.vectors),
            "vectors_by_severity": {
                "CRITICAL": len([v for v in self.vectors if v["severity"] == "CRITICAL"]),
                "HIGH": len([v for v in self.vectors if v["severity"] == "HIGH"]),
                "MEDIUM": len([v for v in self.vectors if v["severity"] == "MEDIUM"]),
                "LOW": len([v for v in self.vectors if v["severity"] == "LOW"])
            },
            "vectors_by_type": {},
            "vectors": self.vectors
        }
        
        # Count by type
        for vector in self.vectors:
            vtype = vector["type"]
            report["vectors_by_type"][vtype] = report["vectors_by_type"].get(vtype, 0) + 1
        
        return report

def main():
    import warnings
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    
    print("=" * 70)
    print("ZOOPLUS BACKDOOR VECTORS ANALYZER")
    print("=" * 70)
    print("ВАЖНО: Этот инструмент предназначен ТОЛЬКО для легитимного")
    print("пентестинга в рамках программы Bug Bounty!")
    print("=" * 70)
    
    analyzer = BackdoorVectorAnalyzer()
    
    print(f"Target: {analyzer.target}")
    print(f"Start Time: {datetime.now()}")
    print("=" * 70)
    
    # Run all checks
    analyzer.check_webhook_endpoints()
    analyzer.check_file_upload()
    analyzer.check_code_execution()
    analyzer.check_template_injection()
    analyzer.check_ssrf_vectors()
    analyzer.check_config_endpoints()
    analyzer.check_api_key_exposure()
    analyzer.check_graphql_introspection()
    analyzer.check_jwt_manipulation()
    analyzer.check_persistent_storage()
    
    # Generate report
    report = analyzer.generate_report()
    
    # Save report
    import os
    os.makedirs("reports", exist_ok=True)
    report_file = "reports/backdoor_vectors.json"
    
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)
    
    print("\n" + "=" * 70)
    print("ANALYSIS SUMMARY")
    print("=" * 70)
    print(f"Total Vectors Found: {report['total_vectors']}")
    print(f"  CRITICAL: {report['vectors_by_severity']['CRITICAL']}")
    print(f"  HIGH: {report['vectors_by_severity']['HIGH']}")
    print(f"  MEDIUM: {report['vectors_by_severity']['MEDIUM']}")
    print(f"  LOW: {report['vectors_by_severity']['LOW']}")
    
    print("\nVectors by Type:")
    for vtype, count in report['vectors_by_type'].items():
        print(f"  {vtype}: {count}")
    
    print(f"\n[+] Report saved to: {report_file}")
    print("\n[!] REMINDER: Use findings only for legitimate security testing!")

if __name__ == "__main__":
    main()

