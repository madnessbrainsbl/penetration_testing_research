#!/usr/bin/env python3
"""
Check interesting subdomains found via CT logs
"""
import requests

requests.packages.urllib3.disable_warnings()

interesting_domains = [
    "https://git.bybit.com",
    "https://admin-testnet.bybit.com",
    "https://api-pre.bybit.com",
    "https://card.bybit.com",
    "https://card-prod.bybit.com",
    "https://card-testnet.bybit.com",
    "https://biz.bybit.com",
    "https://biz-testnet.bybit.com",
    "https://api.test.bybit.com",
    "https://asset-test-1.bybit.com",
]

print("="*80)
print("CHECKING INTERESTING SUBDOMAINS")
print("="*80)

for domain in interesting_domains:
    print(f"\n{'='*80}")
    print(f"Domain: {domain}")
    print("-"*80)
    
    try:
        r = requests.get(domain, verify=False, timeout=5, allow_redirects=True)
        
        print(f"Status: {r.status_code}")
        print(f"Final URL: {r.url}")
        print(f"Title: ", end="")
        
        # Extract title
        if '<title>' in r.text:
            title = r.text.split('<title>')[1].split('</title>')[0]
            print(title[:100])
        else:
            print("No title")
        
        # Check for interesting strings
        interesting_strings = [
            "GitLab", "GitHub", "Bitbucket",
            "admin", "dashboard", "login",
            "Unauthorized", "Forbidden",
            "swagger", "api-docs",
            "phpMyAdmin", "grafana", "jenkins",
        ]
        
        for string in interesting_strings:
            if string.lower() in r.text.lower():
                print(f"  ✓ Found: {string}")
        
        # Check headers
        interesting_headers = ['Server', 'X-Powered-By', 'X-GitLab-Version', 'X-Frame-Options']
        for header in interesting_headers:
            if header in r.headers:
                print(f"  {header}: {r.headers[header]}")
        
        # Check for .git exposure
        if domain == "https://git.bybit.com":
            git_check = requests.get(f"{domain}/.git/config", verify=False, timeout=3)
            if git_check.status_code == 200:
                print(f"  🚨🚨🚨 .git/config EXPOSED!")
                print(f"  Content: {git_check.text[:200]}")
        
        # Check for directory listing
        if 'Index of' in r.text or 'Directory listing' in r.text:
            print(f"  🚨 DIRECTORY LISTING ENABLED!")
        
        # Check for default credentials page
        if 'default password' in r.text.lower() or 'admin:admin' in r.text.lower():
            print(f"  ⚠️  Mentions default credentials!")
            
    except requests.exceptions.SSLError as e:
        print(f"❌ SSL Error: {str(e)[:100]}")
    except requests.exceptions.ConnectionError as e:
        print(f"❌ Connection Error: {str(e)[:100]}")
    except Exception as e:
        print(f"❌ Error: {str(e)[:100]}")

# Test specific endpoints on pre-production API
print(f"\n\n{'='*80}")
print("TESTING api-pre.bybit.com ENDPOINTS")
print("="*80)

pre_endpoints = [
    "/v5/market/time",
    "/v5/account/wallet-balance?accountType=UNIFIED",
    "/swagger",
    "/api-docs",
    "/health",
    "/status",
]

for endpoint in pre_endpoints:
    try:
        r = requests.get(f"https://api-pre.bybit.com{endpoint}", verify=False, timeout=3)
        
        if r.status_code not in [404, 403]:
            print(f"\n✓ {endpoint} - {r.status_code}")
            try:
                data = r.json()
                print(f"  Response: {str(data)[:150]}")
                
                # Check if less protected than production
                if data.get('retCode') == 0:
                    print(f"  🚨 Returns data! (Production requires auth)")
                    
            except:
                print(f"  Text: {r.text[:100]}")
                
    except:
        pass

print("\n" + "="*80)
