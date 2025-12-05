#!/usr/bin/env python3
"""
Test for CORS misconfigurations that could lead to data theft
"""
import requests

requests.packages.urllib3.disable_warnings()

targets = [
    "https://testnet.bybit.com",
    "https://api-testnet.bybit.com",
    "https://api2-testnet.bybit.com",
    "https://api.ffbbbdc6d3c353211fe2ba39c9f744cd.com",
]

print("="*80)
print("TESTING CORS MISCONFIGURATIONS")
print("="*80)

malicious_origins = [
    "https://evil.com",
    "https://bybit.com.evil.com",
    "https://testnet.bybit.com.evil.com",
    "null",
    "http://localhost",
]

for target in targets:
    print(f"\n\nTARGET: {target}")
    print("-"*80)
    
    for origin in malicious_origins:
        try:
            r = requests.get(target, 
                           headers={"Origin": origin},
                           timeout=5, verify=False)
            
            acao = r.headers.get('Access-Control-Allow-Origin', '')
            acac = r.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao:
                print(f"\nOrigin: {origin}")
                print(f"  ACAO: {acao}")
                print(f"  ACAC: {acac}")
                
                # Check for vulnerabilities
                if acao == origin and acac == 'true':
                    print(f"  🚨🚨🚨 CRITICAL CORS MISCONFIGURATION!")
                    print(f"  Reflects attacker origin with credentials!")
                elif acao == '*' and acac == 'true':
                    print(f"  🚨 CORS misconfiguration - wildcard with credentials")
                elif acao == origin:
                    print(f"  ⚠️  Reflects origin (check if sensitive data accessible)")
                    
        except Exception as e:
            pass

print("\n" + "="*80)
