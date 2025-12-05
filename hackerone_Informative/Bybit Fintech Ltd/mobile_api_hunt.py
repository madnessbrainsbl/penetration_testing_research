#!/usr/bin/env python3
"""
Mobile API Discovery & Testing
Mobile apps often have separate APIs with different security
"""
import requests
import json

requests.packages.urllib3.disable_warnings()

print("="*80)
print("MOBILE API DISCOVERY")
print("="*80)

# Mobile API endpoints (common patterns)
mobile_bases = [
    "https://api-mobile.bybit.com",
    "https://m.bybit.com",
    "https://mobile-api.bybit.com",
    "https://app-api.bybit.com",
    "https://api.bybit.com/app",
    "https://api.bybit.com/mobile",
]

print("\n[1] Testing Mobile API Domains")
print("-" * 80)

active_domains = []

for base in mobile_bases:
    try:
        r = requests.get(f"{base}/v5/market/time", verify=False, timeout=3)
        
        if r.status_code == 200:
            print(f"✓ Active: {base}")
            active_domains.append(base)
            try:
                data = r.json()
                print(f"  Response: {data}")
            except:
                pass
        else:
            print(f"✗ Not found: {base} ({r.status_code})")
            
    except Exception as e:
        print(f"✗ Error: {base} - {str(e)[:50]}")

# Test mobile-specific endpoints
print("\n\n[2] Testing Mobile-Specific Endpoints")
print("-" * 80)

mobile_endpoints = [
    "/app/v1/user/profile",
    "/mobile/v1/config",
    "/app/version",
    "/app/config",
    "/mobile/settings",
    "/app/init",
    "/mobile/bootstrap",
]

for base in ["https://api.bybit.com"] + active_domains:
    for endpoint in mobile_endpoints:
        try:
            r = requests.get(f"{base}{endpoint}", verify=False, timeout=2)
            
            if r.status_code not in [404, 403]:
                print(f"\n✓ Found: {base}{endpoint}")
                print(f"  Status: {r.status_code}")
                try:
                    data = r.json()
                    print(f"  Data: {str(data)[:150]}")
                except:
                    print(f"  Text: {r.text[:100]}")
                    
        except:
            pass

# Test User-Agent based endpoints
print("\n\n[3] Testing User-Agent Based Access")
print("-" * 80)

mobile_user_agents = [
    "BybitApp/Android/1.0",
    "BybitApp/iOS/1.0", 
    "Bybit/1.0 (iPhone; iOS 16.0)",
]

for ua in mobile_user_agents:
    try:
        r = requests.get(
            "https://api.bybit.com/v5/market/time",
            headers={"User-Agent": ua},
            verify=False,
            timeout=3
        )
        
        # Check if different response
        print(f"\nUA: {ua}")
        print(f"  Status: {r.status_code}")
        
        # Check for special headers
        for header in ['X-Mobile-Version', 'X-App-Version', 'X-Force-Update']:
            if header in r.headers:
                print(f"  {header}: {r.headers[header]}")
                
    except:
        pass

# Test version endpoints (often leak info)
print("\n\n[4] Testing Version Info Endpoints")
print("-" * 80)

version_endpoints = [
    "/version",
    "/v1/version",
    "/app/version",
    "/api/version",
    "/version.json",
    "/app-version.json",
]

for endpoint in version_endpoints:
    try:
        r = requests.get(
            f"https://www.bybit.com{endpoint}",
            verify=False,
            timeout=3
        )
        
        if r.status_code == 200:
            print(f"\n✓ {endpoint}")
            try:
                data = r.json()
                print(f"  {json.dumps(data, indent=2)}")
            except:
                print(f"  {r.text[:200]}")
                
    except:
        pass

print("\n" + "="*80)
