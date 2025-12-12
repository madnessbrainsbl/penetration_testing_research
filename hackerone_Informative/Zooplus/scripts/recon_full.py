#!/usr/bin/env python3
"""
Полная разведка Zooplus
- Технологический стек
- Серверы и инфраструктура
- API endpoints
- JavaScript анализ
- Subdomains
"""

import requests
import re
import json
from urllib.parse import urlparse
from datetime import datetime

TARGET = "www.zooplus.de"
BASE_URL = f"https://{TARGET}"

print("="*80)
print(f"FULL RECONNAISSANCE: {TARGET}")
print(f"Time: {datetime.now()}")
print("="*80)

# PHASE 1: HTTP Headers Analysis
print("\n" + "="*80)
print("PHASE 1: HTTP HEADERS & SERVER INFO")
print("="*80)

try:
    resp = requests.get(BASE_URL, timeout=10)
    
    print(f"\n[+] Status Code: {resp.status_code}")
    print(f"[+] Response Time: {resp.elapsed.total_seconds():.2f}s")
    
    print("\n[*] Response Headers:")
    interesting_headers = [
        'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
        'X-Frame-Options', 'X-Content-Type-Options', 'Content-Security-Policy',
        'Strict-Transport-Security', 'Set-Cookie', 'X-Generator',
        'X-Drupal-Cache', 'X-Varnish', 'Via', 'X-Cache', 'CF-Ray'
    ]
    
    tech_stack = []
    
    for header in interesting_headers:
        value = resp.headers.get(header)
        if value:
            print(f"  {header}: {value}")
            
            # Detect technologies
            if header == 'Server':
                tech_stack.append(f"Server: {value}")
            if 'cloudflare' in value.lower():
                tech_stack.append("CDN: Cloudflare")
            if 'varnish' in value.lower():
                tech_stack.append("Cache: Varnish")
    
    # Check cookies
    print("\n[*] Cookies:")
    for cookie in resp.cookies:
        print(f"  {cookie.name} = {cookie.value[:50]}...")
        print(f"    Domain: {cookie.domain}")
        print(f"    Path: {cookie.path}")
        print(f"    Secure: {cookie.secure}")
        print(f"    HttpOnly: {cookie.has_nonstandard_attr('HttpOnly')}")
        
except Exception as e:
    print(f"[!] Error: {e}")

# PHASE 2: Technology Detection from HTML
print("\n" + "="*80)
print("PHASE 2: TECHNOLOGY DETECTION")
print("="*80)

try:
    resp = requests.get(BASE_URL, timeout=10)
    html = resp.text
    
    # JavaScript frameworks
    print("\n[*] JavaScript Frameworks:")
    frameworks = {
        'React': ['react', '_react', 'reactDOM'],
        'Vue.js': ['vue.js', '__vue__', 'Vue.'],
        'Angular': ['ng-version', 'angular', 'ng-app'],
        'jQuery': ['jquery', 'jQuery'],
        'Next.js': ['__NEXT_DATA__', '_next/'],
        'Nuxt.js': ['__NUXT__'],
    }
    
    for framework, patterns in frameworks.items():
        for pattern in patterns:
            if pattern in html:
                print(f"  [+] {framework} detected")
                tech_stack.append(f"Frontend: {framework}")
                break
    
    # CMS Detection
    print("\n[*] CMS/Platform Detection:")
    cms_patterns = {
        'WordPress': ['wp-content', 'wp-includes'],
        'Drupal': ['drupal', '/sites/default/'],
        'Magento': ['Mage.', 'magento'],
        'Shopify': ['cdn.shopify.com'],
        'WooCommerce': ['woocommerce'],
    }
    
    for cms, patterns in cms_patterns.items():
        for pattern in patterns:
            if pattern in html:
                print(f"  [+] {cms} detected")
                tech_stack.append(f"CMS: {cms}")
                break
    
    # Analytics & Tracking
    print("\n[*] Analytics & Tracking:")
    analytics = {
        'Google Analytics': ['google-analytics.com', 'gtag', 'ga.js'],
        'Google Tag Manager': ['googletagmanager.com', 'gtm.js'],
        'Facebook Pixel': ['facebook.net/en_US/fbevents.js', 'fbq('],
        'Hotjar': ['hotjar.com'],
        'Mixpanel': ['mixpanel.com'],
    }
    
    for tool, patterns in analytics.items():
        for pattern in patterns:
            if pattern in html:
                print(f"  [+] {tool}")
                break
    
    # Find meta tags
    print("\n[*] Meta Information:")
    meta_patterns = [
        r'<meta name="generator" content="([^"]+)"',
        r'<meta name="version" content="([^"]+)"',
        r'<meta property="og:site_name" content="([^"]+)"',
    ]
    
    for pattern in meta_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        if matches:
            print(f"  {matches[0]}")
    
except Exception as e:
    print(f"[!] Error: {e}")

# PHASE 3: JavaScript Files Discovery
print("\n" + "="*80)
print("PHASE 3: JAVASCRIPT FILES DISCOVERY")
print("="*80)

try:
    js_files = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html)
    
    print(f"\n[*] Found {len(js_files)} JavaScript files")
    
    # Analyze interesting JS files
    interesting_js = []
    for js_url in js_files[:20]:  # First 20
        if any(keyword in js_url.lower() for keyword in ['main', 'app', 'bundle', 'vendor', 'config', 'api']):
            interesting_js.append(js_url)
            print(f"  [+] {js_url}")
    
    # Download and analyze main JS
    if interesting_js:
        print("\n[*] Analyzing main JavaScript file...")
        try:
            if not interesting_js[0].startswith('http'):
                js_url = BASE_URL + interesting_js[0]
            else:
                js_url = interesting_js[0]
            
            js_resp = requests.get(js_url, timeout=10)
            js_content = js_resp.text
            
            # Find API endpoints in JS
            print("\n[*] API Endpoints found in JavaScript:")
            api_patterns = [
                r'["\']/(api/[^"\']+)["\']',
                r'["\']https?://[^"\']+/(api/[^"\']+)["\']',
                r'["\']/(graphql[^"\']*)["\']',
            ]
            
            api_endpoints = set()
            for pattern in api_patterns:
                matches = re.findall(pattern, js_content)
                api_endpoints.update(matches)
            
            for endpoint in sorted(api_endpoints)[:30]:  # First 30
                print(f"  {endpoint}")
            
            # Find interesting strings
            print("\n[*] Interesting strings in JS:")
            interesting_patterns = [
                r'["\'](\w+_token)["\']',
                r'["\'](\w+_key)["\']',
                r'["\'](\w+_secret)["\']',
                r'["\']/(admin[^"\']*)["\']',
                r'["\']/(internal[^"\']*)["\']',
            ]
            
            interesting_strings = set()
            for pattern in interesting_patterns:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                interesting_strings.update(matches)
            
            for string in sorted(interesting_strings)[:20]:
                print(f"  {string}")
                
        except Exception as e:
            print(f"[!] Error analyzing JS: {e}")
            
except Exception as e:
    print(f"[!] Error: {e}")

# PHASE 4: Subdomain Enumeration
print("\n" + "="*80)
print("PHASE 4: SUBDOMAIN ENUMERATION")
print("="*80)

common_subdomains = [
    'www', 'api', 'm', 'mobile', 'dev', 'staging', 'test', 'admin',
    'login', 'auth', 'sso', 'mail', 'webmail', 'shop', 'store',
    'blog', 'support', 'help', 'docs', 'cdn', 'static', 'assets',
    'img', 'images', 'media', 'files', 'download', 'upload',
    'portal', 'dashboard', 'app', 'internal', 'vpn', 'remote',
    'git', 'jenkins', 'ci', 'grafana', 'kibana', 'elastic'
]

print("\n[*] Testing common subdomains...")
found_subdomains = []

for subdomain in common_subdomains:
    url = f"https://{subdomain}.zooplus.de"
    try:
        resp = requests.get(url, timeout=3, allow_redirects=False)
        if resp.status_code < 400:
            print(f"  [+] {subdomain}.zooplus.de - {resp.status_code}")
            found_subdomains.append(subdomain)
    except:
        pass

# Test known subdomains from scope
known_subs = ['www', 'login', 'mailing', 'api', 'm']
print("\n[*] Known subdomains from scope:")
for sub in known_subs:
    url = f"https://{sub}.zooplus.de"
    try:
        resp = requests.get(url, timeout=5)
        print(f"  [+] {sub}.zooplus.de")
        print(f"      Status: {resp.status_code}")
        print(f"      Server: {resp.headers.get('Server', 'Unknown')}")
    except Exception as e:
        print(f"  [-] {sub}.zooplus.de - {e}")

# PHASE 5: robots.txt and sitemap
print("\n" + "="*80)
print("PHASE 5: ROBOTS.TXT & SITEMAP")
print("="*80)

try:
    robots = requests.get(f"{BASE_URL}/robots.txt", timeout=5)
    if robots.status_code == 200:
        print("\n[*] robots.txt found:")
        lines = robots.text.split('\n')[:30]  # First 30 lines
        for line in lines:
            if 'Disallow' in line or 'Allow' in line:
                print(f"  {line}")
                
        # Find sitemaps
        sitemap_urls = re.findall(r'Sitemap:\s*(.+)', robots.text)
        if sitemap_urls:
            print("\n[*] Sitemaps found:")
            for sitemap in sitemap_urls:
                print(f"  {sitemap}")
except:
    pass

# PHASE 6: Common Files Discovery
print("\n" + "="*80)
print("PHASE 6: COMMON FILES DISCOVERY")
print("="*80)

common_files = [
    '/.git/HEAD',
    '/.env',
    '/config.json',
    '/package.json',
    '/.well-known/security.txt',
    '/swagger.json',
    '/api-docs',
    '/openapi.json',
    '/graphql',
    '/admin',
    '/debug',
    '/.DS_Store',
    '/backup',
    '/~backup',
]

print("\n[*] Testing for common files...")
for file in common_files:
    try:
        resp = requests.get(BASE_URL + file, timeout=3)
        if resp.status_code == 200:
            print(f"  [+] {file} - FOUND (Status: {resp.status_code})")
    except:
        pass

# PHASE 7: Technology Stack Summary
print("\n" + "="*80)
print("TECHNOLOGY STACK SUMMARY")
print("="*80)

print("\n[*] Detected Technologies:")
for tech in set(tech_stack):
    print(f"  • {tech}")

# Save results
results = {
    "target": TARGET,
    "scan_date": datetime.now().isoformat(),
    "technology_stack": list(set(tech_stack)),
    "found_subdomains": found_subdomains,
    "status": "completed"
}

with open("reports/recon_results.json", "w") as f:
    json.dump(results, f, indent=2)

print("\n[+] Reconnaissance complete!")
print("[+] Results saved to: reports/recon_results.json")

