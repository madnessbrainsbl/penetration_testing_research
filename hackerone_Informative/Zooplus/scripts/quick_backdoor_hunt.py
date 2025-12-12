#!/usr/bin/env python3
"""
Quick Backdoor Hunter - быстрая версия без зависаний
"""

import requests
import json
from urllib.parse import urljoin
from datetime import datetime
import urllib3
urllib3.disable_warnings()

class QuickBackdoorHunter:
    def __init__(self, target="www.zooplus.de"):
        self.target = target
        self.base_url = f"https://{target}"
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0'
        })
    
    def quick_test(self, path, method='GET', payload=None):
        """Быстрый тест endpoint"""
        try:
            url = urljoin(self.base_url, path)
            if method == 'GET':
                resp = self.session.get(url, timeout=1, verify=False, allow_redirects=False)
            else:
                resp = self.session.post(url, json=payload, timeout=1, verify=False, allow_redirects=False)
            
            if resp.status_code not in [404, 403, 405]:
                return {
                    "path": path,
                    "method": method,
                    "status": resp.status_code,
                    "response_length": len(resp.text) if resp.text else 0
                }
        except:
            pass
        return None
    
    def hunt_envoy_admin(self):
        """Быстрый поиск Envoy admin"""
        print("\n[*] Envoy admin endpoints...")
        paths = ["/stats", "/clusters", "/config_dump", "/admin/stats", "/envoy/stats"]
        for path in paths:
            result = self.quick_test(path)
            if result and result['status'] == 200:
                self.findings.append({
                    "severity": "CRITICAL",
                    "type": "envoy_admin",
                    "path": path,
                    "status": result['status']
                })
                print(f"  [CRITICAL] Found: {path}")
    
    def hunt_file_upload(self):
        """Быстрый поиск file upload"""
        print("\n[*] File upload endpoints...")
        paths = ["/upload", "/api/upload", "/file/upload"]
        for path in paths:
            result = self.quick_test(path, method='POST', payload={})
            if result and result['status'] in [200, 201]:
                self.findings.append({
                    "severity": "HIGH",
                    "type": "file_upload",
                    "path": path
                })
                print(f"  [HIGH] Found: {path}")
    
    def hunt_code_exec(self):
        """Быстрый поиск code execution"""
        print("\n[*] Code execution endpoints...")
        paths = ["/api/execute", "/api/eval", "/api/run", "/console"]
        for path in paths:
            result = self.quick_test(path, method='POST', payload={"code": "test"})
            if result and result['status'] == 200:
                self.findings.append({
                    "severity": "CRITICAL",
                    "type": "code_execution",
                    "path": path
                })
                print(f"  [CRITICAL] Found: {path}")
    
    def hunt_ssrf(self):
        """Быстрый поиск SSRF"""
        print("\n[*] SSRF vectors...")
        paths = ["/api/fetch", "/api/proxy", "/api/request"]
        for path in paths:
            result = self.quick_test(path, method='POST', payload={"url": "http://127.0.0.1"})
            if result:
                self.findings.append({
                    "severity": "HIGH",
                    "type": "ssrf",
                    "path": path
                })
                print(f"  [HIGH] Found: {path}")
    
    def hunt_config(self):
        """Быстрый поиск config"""
        print("\n[*] Config endpoints...")
        paths = ["/api/config", "/api/settings", "/admin/config"]
        for path in paths:
            result = self.quick_test(path)
            if result and result['status'] == 200:
                self.findings.append({
                    "severity": "HIGH",
                    "type": "config",
                    "path": path
                })
                print(f"  [HIGH] Found: {path}")
    
    def hunt_webhook(self):
        """Быстрый поиск webhook"""
        print("\n[*] Webhook endpoints...")
        paths = ["/webhook", "/api/webhook", "/callback"]
        for path in paths:
            result = self.quick_test(path, method='POST', payload={"url": "https://test.com"})
            if result:
                self.findings.append({
                    "severity": "HIGH",
                    "type": "webhook",
                    "path": path
                })
                print(f"  [HIGH] Found: {path}")
    
    def hunt_template(self):
        """Быстрый поиск template injection"""
        print("\n[*] Template injection...")
        paths = ["/api/render", "/api/template", "/render"]
        for path in paths:
            result = self.quick_test(path, method='POST', payload={"template": "{{7*7}}"})
            if result and "49" in (result.get('response', '') or ''):
                self.findings.append({
                    "severity": "CRITICAL",
                    "type": "template_injection",
                    "path": path
                })
                print(f"  [CRITICAL] Found: {path}")
    
    def run(self):
        """Запуск всех проверок"""
        print("=" * 70)
        print("QUICK BACKDOOR HUNTER")
        print("=" * 70)
        print(f"Target: {self.target}")
        print("=" * 70)
        
        self.hunt_envoy_admin()
        self.hunt_file_upload()
        self.hunt_code_exec()
        self.hunt_ssrf()
        self.hunt_config()
        self.hunt_webhook()
        self.hunt_template()
        
        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print(f"Total findings: {len(self.findings)}")
        
        if self.findings:
            critical = len([f for f in self.findings if f['severity'] == 'CRITICAL'])
            high = len([f for f in self.findings if f['severity'] == 'HIGH'])
            print(f"  CRITICAL: {critical}")
            print(f"  HIGH: {high}")
            
            # Save report
            import os
            os.makedirs("reports", exist_ok=True)
            with open("reports/quick_backdoor_hunt.json", "w") as f:
                json.dump({
                    "target": self.target,
                    "scan_date": datetime.now().isoformat(),
                    "findings": self.findings
                }, f, indent=2)
            print(f"\n[+] Report saved to: reports/quick_backdoor_hunt.json")
        else:
            print("  No findings")
        
        return self.findings

if __name__ == "__main__":
    hunter = QuickBackdoorHunter()
    hunter.run()

