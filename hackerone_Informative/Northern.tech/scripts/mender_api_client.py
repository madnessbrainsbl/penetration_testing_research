#!/usr/bin/env python3
"""
Mender API Client для тестирования
Упрощает взаимодействие с Mender API
"""

import requests
import json
from typing import Dict, List, Optional

class MenderAPIClient:
    def __init__(self, base_url: str, token: str, h1_username: str):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.h1_username = h1_username
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'X-HackerOne-Research': h1_username
        })
    
    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        """Базовый метод для запросов"""
        url = f"{self.base_url}{path}"
        return self.session.request(method, url, **kwargs)
    
    def _get(self, path: str, **kwargs) -> requests.Response:
        return self._request('GET', path, **kwargs)
    
    def _post(self, path: str, **kwargs) -> requests.Response:
        return self._request('POST', path, **kwargs)
    
    def _put(self, path: str, **kwargs) -> requests.Response:
        return self._request('PUT', path, **kwargs)
    
    def _delete(self, path: str, **kwargs) -> requests.Response:
        return self._request('DELETE', path, **kwargs)
    
    # ===== AUTHENTICATION =====
    
    @staticmethod
    def login(base_url: str, email: str, password: str, h1_username: str) -> Optional[str]:
        """Получить токен через логин"""
        url = f"{base_url}/api/management/v1/useradm/auth/login"
        headers = {
            'Content-Type': 'application/json',
            'X-HackerOne-Research': h1_username
        }
        data = {
            'email': email,
            'password': password
        }
        
        resp = requests.post(url, json=data, headers=headers)
        
        if resp.status_code == 200:
            return resp.text.strip()
        else:
            print(f"[!] Login failed: {resp.status_code} {resp.text}")
            return None
    
    def whoami(self) -> Dict:
        """Получить информацию о текущем пользователе"""
        resp = self._get('/api/management/v1/useradm/users/me')
        return resp.json() if resp.status_code == 200 else {}
    
    # ===== DEVICES =====
    
    def list_devices(self, page: int = 1, per_page: int = 20) -> List[Dict]:
        """Список устройств"""
        resp = self._get(
            '/api/management/v2/devauth/devices',
            params={'page': page, 'per_page': per_page}
        )
        return resp.json() if resp.status_code == 200 else []
    
    def get_device(self, device_id: str) -> Optional[Dict]:
        """Получить устройство по ID"""
        resp = self._get(f'/api/management/v2/devauth/devices/{device_id}')
        return resp.json() if resp.status_code == 200 else None
    
    def accept_device(self, device_id: str, auth_id: str) -> bool:
        """Принять устройство"""
        resp = self._put(
            f'/api/management/v2/devauth/devices/{device_id}/auth/{auth_id}/status',
            json={'status': 'accepted'}
        )
        return resp.status_code in [200, 204]
    
    def reject_device(self, device_id: str, auth_id: str) -> bool:
        """Отклонить устройство"""
        resp = self._put(
            f'/api/management/v2/devauth/devices/{device_id}/auth/{auth_id}/status',
            json={'status': 'rejected'}
        )
        return resp.status_code in [200, 204]
    
    def decommission_device(self, device_id: str) -> bool:
        """Удалить устройство"""
        resp = self._delete(f'/api/management/v2/devauth/devices/{device_id}')
        return resp.status_code in [200, 204]
    
    # ===== DEPLOYMENTS =====
    
    def list_deployments(self, page: int = 1, per_page: int = 20) -> List[Dict]:
        """Список deployments"""
        resp = self._get(
            '/api/management/v1/deployments/deployments',
            params={'page': page, 'per_page': per_page}
        )
        return resp.json() if resp.status_code == 200 else []
    
    def get_deployment(self, deployment_id: str) -> Optional[Dict]:
        """Получить deployment по ID"""
        resp = self._get(f'/api/management/v1/deployments/deployments/{deployment_id}')
        return resp.json() if resp.status_code == 200 else None
    
    def create_deployment(self, name: str, artifact_name: str, devices: List[str]) -> Optional[Dict]:
        """Создать deployment"""
        data = {
            'name': name,
            'artifact_name': artifact_name,
            'devices': devices
        }
        resp = self._post('/api/management/v1/deployments/deployments', json=data)
        return resp.json() if resp.status_code == 201 else None
    
    def abort_deployment(self, deployment_id: str) -> bool:
        """Отменить deployment"""
        resp = self._put(
            f'/api/management/v1/deployments/deployments/{deployment_id}/status',
            json={'status': 'aborted'}
        )
        return resp.status_code in [200, 204]
    
    # ===== ARTIFACTS =====
    
    def list_artifacts(self) -> List[Dict]:
        """Список артефактов"""
        resp = self._get('/api/management/v1/deployments/artifacts')
        return resp.json() if resp.status_code == 200 else []
    
    def get_artifact(self, artifact_id: str) -> Optional[Dict]:
        """Получить артефакт по ID"""
        resp = self._get(f'/api/management/v1/deployments/artifacts/{artifact_id}')
        return resp.json() if resp.status_code == 200 else None
    
    def upload_artifact(self, filepath: str, description: str = "") -> Optional[Dict]:
        """Загрузить артефакт"""
        with open(filepath, 'rb') as f:
            files = {'artifact': f}
            data = {'description': description}
            # Remove Content-Type for multipart
            headers = {k: v for k, v in self.session.headers.items() 
                      if k != 'Content-Type'}
            resp = requests.post(
                f"{self.base_url}/api/management/v1/deployments/artifacts",
                files=files,
                data=data,
                headers=headers
            )
        return resp.json() if resp.status_code == 201 else None
    
    # ===== USERS =====
    
    def list_users(self) -> List[Dict]:
        """Список пользователей"""
        resp = self._get('/api/management/v1/useradm/users')
        return resp.json() if resp.status_code == 200 else []
    
    def get_user(self, user_id: str) -> Optional[Dict]:
        """Получить пользователя по ID"""
        resp = self._get(f'/api/management/v1/useradm/users/{user_id}')
        return resp.json() if resp.status_code == 200 else None
    
    def create_user(self, email: str, password: str) -> Optional[Dict]:
        """Создать пользователя"""
        data = {
            'email': email,
            'password': password
        }
        resp = self._post('/api/management/v1/useradm/users', json=data)
        return resp.json() if resp.status_code == 201 else None
    
    def update_user_roles(self, user_id: str, roles: List[str]) -> bool:
        """Изменить роли пользователя"""
        resp = self._put(
            f'/api/management/v1/useradm/users/{user_id}',
            json={'roles': roles}
        )
        return resp.status_code in [200, 204]
    
    def delete_user(self, user_id: str) -> bool:
        """Удалить пользователя"""
        resp = self._delete(f'/api/management/v1/useradm/users/{user_id}')
        return resp.status_code in [200, 204]
    
    # ===== ORGANIZATION =====
    
    def get_tenant_token(self) -> Optional[str]:
        """Получить tenant token"""
        resp = self._get('/api/management/v2/devauth/tenant/token')
        return resp.text if resp.status_code == 200 else None
    
    # ===== UTILITY =====
    
    def print_summary(self):
        """Вывести summary текущего аккаунта"""
        print("\n" + "="*60)
        print("ACCOUNT SUMMARY")
        print("="*60)
        
        me = self.whoami()
        if me:
            print(f"User: {me.get('email', 'N/A')}")
            print(f"ID: {me.get('id', 'N/A')}")
            print(f"Roles: {', '.join(me.get('roles', []))}")
        
        devices = self.list_devices()
        print(f"\nDevices: {len(devices)}")
        if devices:
            for dev in devices[:3]:
                print(f"  - {dev.get('id', 'N/A')[:20]}... ({dev.get('status', 'N/A')})")
        
        deployments = self.list_deployments()
        print(f"\nDeployments: {len(deployments)}")
        if deployments:
            for dep in deployments[:3]:
                print(f"  - {dep.get('name', 'N/A')} ({dep.get('status', 'N/A')})")
        
        artifacts = self.list_artifacts()
        print(f"\nArtifacts: {len(artifacts)}")
        
        print("="*60 + "\n")


def main():
    print("""
    ╔════════════════════════════════════════════════════╗
    ║   Mender API Client                                ║
    ║   Interactive API testing tool                    ║
    ╚════════════════════════════════════════════════════╝
    """)
    
    BASE_URL = "https://staging.hosted.mender.io"
    H1_USERNAME = input("Enter your H1 username: ").strip()
    
    print("\nLogin options:")
    print("1. Use existing token")
    print("2. Login with email/password")
    choice = input("Choice (1/2): ").strip()
    
    if choice == "1":
        token = input("Enter token: ").strip()
    else:
        email = input("Email: ").strip()
        password = input("Password: ").strip()
        print("[*] Logging in...")
        token = MenderAPIClient.login(BASE_URL, email, password, H1_USERNAME)
        if not token:
            print("[!] Login failed")
            return
        print(f"[+] Token: {token[:20]}...")
    
    # Initialize client
    client = MenderAPIClient(BASE_URL, token, H1_USERNAME)
    
    # Print summary
    client.print_summary()
    
    # Interactive mode
    while True:
        print("\nCommands:")
        print("  devices - List devices")
        print("  deployments - List deployments")
        print("  users - List users")
        print("  whoami - Current user info")
        print("  quit - Exit")
        
        cmd = input("\n> ").strip().lower()
        
        if cmd == 'quit':
            break
        elif cmd == 'devices':
            devices = client.list_devices()
            print(json.dumps(devices, indent=2))
        elif cmd == 'deployments':
            deps = client.list_deployments()
            print(json.dumps(deps, indent=2))
        elif cmd == 'users':
            users = client.list_users()
            print(json.dumps(users, indent=2))
        elif cmd == 'whoami':
            me = client.whoami()
            print(json.dumps(me, indent=2))
        else:
            print("[!] Unknown command")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
