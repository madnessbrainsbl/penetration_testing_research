#!/usr/bin/env python3
"""
Security Headers Testing для Zooplus
Проверяет наличие и правильность security headers
"""

import requests
from datetime import datetime

BASE_URL = "https://www.zooplus.de"


def analyze_security_headers(url):
    """Анализирует security headers для URL"""
    
    print(f"\n[*] Analyzing security headers for: {url}")
    
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        
        findings = []
        
        # Check HSTS
        hsts = headers.get('Strict-Transport-Security')
        if not hsts:
            print("[!] Missing: Strict-Transport-Security (HSTS)")
            findings.append({
                "header": "Strict-Transport-Security",
                "status": "MISSING",
                "impact": "Site vulnerable to SSL stripping attacks",
                "severity": "MEDIUM",
                "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
            })
        else:
            print(f"[+] HSTS present: {hsts}")
            if "max-age" not in hsts.lower():
                findings.append({
                    "header": "Strict-Transport-Security",
                    "status": "WEAK",
                    "value": hsts,
                    "impact": "HSTS without max-age is ineffective",
                    "severity": "MEDIUM"
                })
        
        # Check CSP
        csp = headers.get('Content-Security-Policy')
        if not csp:
            print("[!] Missing: Content-Security-Policy (CSP)")
            findings.append({
                "header": "Content-Security-Policy",
                "status": "MISSING",
                "impact": "No protection against XSS and data injection attacks",
                "severity": "MEDIUM",
                "recommendation": "Add CSP header with restrictive policy"
            })
        else:
            print(f"[+] CSP present: {csp[:100]}...")
            
            # Check for unsafe CSP directives
            if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                findings.append({
                    "header": "Content-Security-Policy",
                    "status": "WEAK",
                    "value": csp,
                    "impact": "CSP contains unsafe-inline or unsafe-eval, weakening XSS protection",
                    "severity": "LOW"
                })
        
        # Check X-Frame-Options
        xfo = headers.get('X-Frame-Options')
        if not xfo:
            print("[!] Missing: X-Frame-Options")
            findings.append({
                "header": "X-Frame-Options",
                "status": "MISSING",
                "impact": "Site vulnerable to clickjacking attacks",
                "severity": "MEDIUM",
                "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN"
            })
        else:
            print(f"[+] X-Frame-Options present: {xfo}")
        
        # Check X-Content-Type-Options
        xcto = headers.get('X-Content-Type-Options')
        if not xcto or xcto.lower() != 'nosniff':
            print("[!] Missing or weak: X-Content-Type-Options")
            findings.append({
                "header": "X-Content-Type-Options",
                "status": "MISSING",
                "impact": "Browser may MIME-sniff responses, leading to XSS",
                "severity": "LOW",
                "recommendation": "Add: X-Content-Type-Options: nosniff"
            })
        else:
            print(f"[+] X-Content-Type-Options present: {xcto}")
        
        # Check Referrer-Policy
        rp = headers.get('Referrer-Policy')
        if not rp:
            print("[!] Missing: Referrer-Policy")
            findings.append({
                "header": "Referrer-Policy",
                "status": "MISSING",
                "impact": "Referrer may leak sensitive URLs to third parties",
                "severity": "LOW",
                "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
            })
        else:
            print(f"[+] Referrer-Policy present: {rp}")
        
        # Check X-XSS-Protection (deprecated but still useful)
        xxp = headers.get('X-XSS-Protection')
        if xxp and xxp == "0":
            print("[!] X-XSS-Protection is disabled (set to 0)")
            findings.append({
                "header": "X-XSS-Protection",
                "status": "DISABLED",
                "impact": "XSS filter is explicitly disabled",
                "severity": "LOW",
                "recommendation": "Remove or set to: X-XSS-Protection: 1; mode=block"
            })
        
        # Check Permissions-Policy / Feature-Policy
        pp = headers.get('Permissions-Policy') or headers.get('Feature-Policy')
        if not pp:
            print("[!] Missing: Permissions-Policy")
            findings.append({
                "header": "Permissions-Policy",
                "status": "MISSING",
                "impact": "No control over browser features (camera, microphone, etc.)",
                "severity": "INFO",
                "recommendation": "Add: Permissions-Policy with appropriate restrictions"
            })
        
        return findings
        
    except Exception as e:
        print(f"[!] Error analyzing headers: {e}")
        return []


def check_cookie_security():
    """Проверяет security флаги cookies"""
    print("\n[*] Checking cookie security...")
    
    findings = []
    
    try:
        response = requests.get(BASE_URL, timeout=10)
        
        for cookie in response.cookies:
            print(f"\n[*] Cookie: {cookie.name}")
            
            # Check Secure flag
            if not cookie.secure:
                print(f"[!] Cookie '{cookie.name}' missing Secure flag")
                findings.append({
                    "type": "Insecure Cookie",
                    "cookie": cookie.name,
                    "issue": "Missing Secure flag",
                    "impact": "Cookie can be transmitted over HTTP",
                    "severity": "MEDIUM"
                })
            else:
                print(f"[+] Secure flag present")
            
            # Check HttpOnly flag
            if not cookie.has_nonstandard_attr('HttpOnly'):
                print(f"[!] Cookie '{cookie.name}' missing HttpOnly flag")
                findings.append({
                    "type": "Insecure Cookie",
                    "cookie": cookie.name,
                    "issue": "Missing HttpOnly flag",
                    "impact": "Cookie accessible via JavaScript (XSS risk)",
                    "severity": "HIGH"
                })
            else:
                print(f"[+] HttpOnly flag present")
            
            # Check SameSite attribute
            samesite = cookie.get_nonstandard_attr('SameSite')
            if not samesite:
                print(f"[!] Cookie '{cookie.name}' missing SameSite attribute")
                findings.append({
                    "type": "Insecure Cookie",
                    "cookie": cookie.name,
                    "issue": "Missing SameSite attribute",
                    "impact": "Cookie vulnerable to CSRF attacks",
                    "severity": "MEDIUM"
                })
            else:
                print(f"[+] SameSite: {samesite}")
                if samesite.lower() == 'none':
                    findings.append({
                        "type": "Weak Cookie Configuration",
                        "cookie": cookie.name,
                        "issue": "SameSite=None",
                        "impact": "Cookie sent in cross-site requests (CSRF risk)",
                        "severity": "LOW"
                    })
        
        return findings
        
    except Exception as e:
        print(f"[!] Error checking cookies: {e}")
        return []


def test_https_enforcement():
    """Проверяет принудительное использование HTTPS"""
    print("\n[*] Testing HTTPS enforcement...")
    
    findings = []
    
    try:
        # Try HTTP
        http_url = BASE_URL.replace("https://", "http://")
        response = requests.get(http_url, allow_redirects=False, timeout=10)
        
        if response.status_code in [301, 302, 307, 308]:
            location = response.headers.get('Location', '')
            if location.startswith('https://'):
                print("[+] HTTP redirects to HTTPS")
            else:
                print("[!] HTTP redirects but not to HTTPS")
                findings.append({
                    "type": "Weak HTTPS Enforcement",
                    "issue": "HTTP redirects to non-HTTPS URL",
                    "severity": "MEDIUM"
                })
        elif response.status_code == 200:
            print("[!] HTTP request accepted without redirect!")
            findings.append({
                "type": "No HTTPS Enforcement",
                "issue": "Site accessible over HTTP",
                "impact": "Traffic can be intercepted (MITM attacks)",
                "severity": "HIGH"
            })
        
        return findings
        
    except Exception as e:
        print(f"[+] HTTP not accessible (good): {e}")
        return []


def check_mixed_content():
    """Проверяет наличие mixed content"""
    print("\n[*] Checking for mixed content...")
    
    findings = []
    
    try:
        response = requests.get(BASE_URL, timeout=10)
        html = response.text.lower()
        
        # Look for http:// resources in HTTPS page
        if 'http://' in html and 'https://' in html:
            print("[!] Possible mixed content detected")
            print("[!] Manual inspection required")
            findings.append({
                "type": "Possible Mixed Content",
                "issue": "HTTP resources may be loaded in HTTPS page",
                "impact": "Weakens HTTPS protection",
                "severity": "LOW",
                "note": "Manual verification required"
            })
        else:
            print("[+] No obvious mixed content")
        
        return findings
        
    except Exception as e:
        print(f"[!] Error checking mixed content: {e}")
        return []


def main():
    print("=" * 60)
    print("Zooplus Security Headers Testing")
    print(f"Time: {datetime.now()}")
    print("=" * 60)
    
    all_findings = []
    
    # Test main pages
    pages_to_test = [
        BASE_URL,
        f"{BASE_URL}/myaccount",
        f"{BASE_URL}/checkout",
    ]
    
    for page in pages_to_test:
        findings = analyze_security_headers(page)
        all_findings.extend(findings)
    
    # Test cookie security
    findings = check_cookie_security()
    all_findings.extend(findings)
    
    # Test HTTPS enforcement
    findings = test_https_enforcement()
    all_findings.extend(findings)
    
    # Test mixed content
    findings = check_mixed_content()
    all_findings.extend(findings)
    
    # Summary
    print("\n" + "=" * 60)
    print("SECURITY HEADERS SUMMARY")
    print("=" * 60)
    
    if all_findings:
        # Group by severity
        critical = [f for f in all_findings if f.get('severity') == 'CRITICAL']
        high = [f for f in all_findings if f.get('severity') == 'HIGH']
        medium = [f for f in all_findings if f.get('severity') == 'MEDIUM']
        low = [f for f in all_findings if f.get('severity') == 'LOW']
        info = [f for f in all_findings if f.get('severity') == 'INFO']
        
        print(f"\nTotal findings: {len(all_findings)}")
        print(f"  Critical: {len(critical)}")
        print(f"  High: {len(high)}")
        print(f"  Medium: {len(medium)}")
        print(f"  Low: {len(low)}")
        print(f"  Info: {len(info)}\n")
        
        # Print details
        for severity_name, severity_findings in [
            ("CRITICAL", critical),
            ("HIGH", high),
            ("MEDIUM", medium),
            ("LOW", low),
            ("INFO", info)
        ]:
            if severity_findings:
                print(f"\n{severity_name} Severity:")
                for finding in severity_findings:
                    if 'header' in finding:
                        print(f"  - {finding['header']}: {finding['status']}")
                        print(f"    Impact: {finding.get('impact', 'N/A')}")
                        if 'recommendation' in finding:
                            print(f"    Fix: {finding['recommendation']}")
                    elif 'cookie' in finding:
                        print(f"  - Cookie '{finding['cookie']}': {finding['issue']}")
                        print(f"    Impact: {finding['impact']}")
                    elif 'type' in finding:
                        print(f"  - {finding['type']}: {finding['issue']}")
                        if 'impact' in finding:
                            print(f"    Impact: {finding['impact']}")
                    print()
        
        # Save findings
        import json
        with open("reports/security_headers_findings.json", "w") as f:
            json.dump(all_findings, f, indent=2)
        print("[+] Findings saved to reports/security_headers_findings.json")
        
    else:
        print("\n[+] No security header issues found")
        print("[+] All headers properly configured")
    
    return all_findings


if __name__ == "__main__":
    main()

