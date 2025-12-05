#!/usr/bin/env python3
"""
Burp Suite Request Parser for Northern.tech
Парсит сохраненные запросы из Burp и создает каталог endpoints
"""

import re
import json
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set

class BurpRequestParser:
    def __init__(self):
        self.endpoints = defaultdict(lambda: {
            'methods': set(),
            'params': set(),
            'auth_required': None,
            'examples': []
        })
        
    def parse_burp_request(self, request_text: str) -> Dict:
        """Парсинг одного HTTP запроса из Burp"""
        lines = request_text.strip().split('\n')
        
        if not lines:
            return None
            
        # Parse request line
        request_line = lines[0]
        match = re.match(r'(\w+)\s+([^\s]+)\s+HTTP', request_line)
        if not match:
            return None
            
        method = match.group(1)
        path = match.group(2)
        
        # Parse headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # Parse body
        body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ''
        
        # Extract query parameters
        query_params = []
        if '?' in path:
            path_base, query = path.split('?', 1)
            query_params = [p.split('=')[0] for p in query.split('&')]
            path = path_base
        else:
            path_base = path
        
        # Normalize path (replace IDs with {id})
        normalized_path = self._normalize_path(path_base)
        
        return {
            'method': method,
            'path': path,
            'normalized_path': normalized_path,
            'query_params': query_params,
            'headers': headers,
            'body': body,
            'has_auth': 'Authorization' in headers or 'Cookie' in headers
        }
    
    def _normalize_path(self, path: str) -> str:
        """Нормализация пути - замена ID на {id}"""
        # Replace UUIDs
        path = re.sub(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '{id}',
            path,
            flags=re.IGNORECASE
        )
        # Replace numeric IDs
        path = re.sub(r'/\d+/', '/{id}/', path)
        path = re.sub(r'/\d+$', '/{id}', path)
        
        return path
    
    def add_request(self, request_text: str):
        """Добавить запрос в каталог"""
        parsed = self.parse_burp_request(request_text)
        if not parsed:
            return
            
        endpoint = parsed['normalized_path']
        self.endpoints[endpoint]['methods'].add(parsed['method'])
        self.endpoints[endpoint]['params'].update(parsed['query_params'])
        
        if self.endpoints[endpoint]['auth_required'] is None:
            self.endpoints[endpoint]['auth_required'] = parsed['has_auth']
        
        # Limit examples
        if len(self.endpoints[endpoint]['examples']) < 3:
            self.endpoints[endpoint]['examples'].append({
                'method': parsed['method'],
                'path': parsed['path'],
                'query_params': parsed['query_params']
            })
    
    def parse_burp_file(self, filepath: str):
        """Парсинг файла с запросами из Burp (разделенные ===)"""
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Split by separator
        requests = content.split('\n===\n')
        
        print(f"[*] Found {len(requests)} requests in file")
        
        for req in requests:
            if req.strip():
                self.add_request(req)
        
        print(f"[*] Identified {len(self.endpoints)} unique endpoints")
    
    def generate_api_catalog(self) -> str:
        """Генерация каталога API"""
        output = []
        output.append("# API Endpoints Catalog\n")
        output.append(f"Total endpoints: {len(self.endpoints)}\n")
        output.append("\n---\n")
        
        # Group by base path
        grouped = defaultdict(list)
        for endpoint in sorted(self.endpoints.keys()):
            base = endpoint.split('/')[1] if endpoint.startswith('/') else 'root'
            grouped[base].append(endpoint)
        
        for base, endpoints in sorted(grouped.items()):
            output.append(f"\n## /{base}\n")
            
            for endpoint in endpoints:
                data = self.endpoints[endpoint]
                methods = ', '.join(sorted(data['methods']))
                auth = "🔒" if data['auth_required'] else "🔓"
                
                output.append(f"\n### {auth} {endpoint}\n")
                output.append(f"**Methods**: {methods}\n")
                
                if data['params']:
                    params = ', '.join(sorted(data['params']))
                    output.append(f"**Query params**: {params}\n")
                
                output.append("\n**Test checklist**:")
                output.append("\n- [ ] IDOR test (change {id})")
                output.append("\n- [ ] Authorization test (different roles)")
                output.append("\n- [ ] Authentication bypass (remove token)")
                output.append("\n- [ ] Method tampering")
                if data['params']:
                    output.append("\n- [ ] Parameter injection")
                output.append("\n")
        
        return ''.join(output)
    
    def generate_test_matrix(self) -> str:
        """Генерация матрицы тестирования"""
        output = []
        output.append("| Endpoint | Methods | Auth | IDOR | AuthZ | Bypass | Injection | Status |\n")
        output.append("|----------|---------|------|------|-------|--------|-----------|--------|\n")
        
        for endpoint in sorted(self.endpoints.keys()):
            data = self.endpoints[endpoint]
            methods = ', '.join(sorted(data['methods']))
            auth = "Yes" if data['auth_required'] else "No"
            
            output.append(f"| {endpoint} | {methods} | {auth} | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |\n")
        
        return ''.join(output)
    
    def export_for_testing(self, output_dir: str = "endpoint_tests"):
        """Экспорт для тестирования"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # API Catalog
        catalog_file = output_path / "api_catalog.md"
        with open(catalog_file, 'w') as f:
            f.write(self.generate_api_catalog())
        print(f"[+] API catalog saved to: {catalog_file}")
        
        # Test Matrix
        matrix_file = output_path / "test_matrix.md"
        with open(matrix_file, 'w') as f:
            f.write(self.generate_test_matrix())
        print(f"[+] Test matrix saved to: {matrix_file}")
        
        # JSON export
        json_file = output_path / "endpoints.json"
        json_data = {
            endpoint: {
                'methods': list(data['methods']),
                'params': list(data['params']),
                'auth_required': data['auth_required'],
                'examples': data['examples']
            }
            for endpoint, data in self.endpoints.items()
        }
        with open(json_file, 'w') as f:
            json.dump(json_data, f, indent=2)
        print(f"[+] JSON export saved to: {json_file}")


def main():
    print("""
    ╔════════════════════════════════════════════════════╗
    ║   Burp Request Parser                              ║
    ║   Extract and catalog API endpoints               ║
    ╚════════════════════════════════════════════════════╝
    """)
    
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python burp_request_parser.py <burp_requests_file>")
        print("\nExport requests from Burp:")
        print("  1. Select requests in HTTP history")
        print("  2. Right-click -> Copy requests")
        print("  3. Paste into a text file")
        print("  4. Run this script on that file")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    parser = BurpRequestParser()
    parser.parse_burp_file(input_file)
    parser.export_for_testing()
    
    print("\n[✓] Done! Check 'endpoint_tests' directory for outputs")


if __name__ == '__main__':
    main()
