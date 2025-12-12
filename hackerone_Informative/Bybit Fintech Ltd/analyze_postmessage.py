#!/usr/bin/env python3
import re

files_with_postmessage = [
    '/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data/chunk_3924.js',
    '/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data/page.js',
]

print("="*80)
print("ANALYZING postMessage HANDLERS FOR DOM XSS")
print("="*80)

for filepath in files_with_postmessage:
    with open(filepath, 'r', errors='ignore') as f:
        content = f.read()
    
    print(f"\n\nFILE: {filepath.split('/')[-1]}")
    print("="*80)
    
    # Find all postMessage listeners
    patterns = [
        r'addEventListener\s*\(\s*["\']message["\'][^}]{50,2000}',
        r'window\.onmessage\s*=[^;]{50,500}',
        r'\.onmessage\s*=\s*function[^}]{50,2000}'
    ]
    
    for pattern in patterns:
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for i, match in enumerate(list(matches)[:5]):
            snippet_start = max(0, match.start() - 500)
            snippet_end = min(len(content), match.end() + 1000)
            snippet = content[snippet_start:snippet_end]
            
            print(f"\n--- postMessage Handler {i+1} ---")
            print(snippet[:1500])
            
            # Security checks
            checks = {
                'origin validation': bool(re.search(r'\.origin\s*[!=]=|event\.origin|e\.origin', snippet)),
                'uses eval': bool(re.search(r'\beval\s*\(', snippet)),
                'uses Function': bool(re.search(r'\bFunction\s*\(', snippet)),
                'uses innerHTML': bool(re.search(r'\.innerHTML\s*=', snippet)),
                'uses document.write': bool(re.search(r'document\.write', snippet)),
                'uses location': bool(re.search(r'location\.(href|assign|replace)', snippet)),
            }
            
            print(f"\n🔍 SECURITY ANALYSIS:")
            for check, result in checks.items():
                status = "✓" if result else "✗"
                if check == 'origin validation':
                    if not result:
                        print(f"  🚨 {status} {check} - VULNERABLE!")
                    else:
                        print(f"  {status} {check}")
                elif result and check != 'origin validation':
                    print(f"  ⚠️  {status} {check} - DANGEROUS!")
                else:
                    print(f"  {status} {check}")
            
            # Try to find what data is accessed
            data_access = re.findall(r'(data|event\.data|e\.data|message\.data)', snippet)
            if data_access:
                print(f"\n  📨 Accesses message data: {set(data_access)}")
                
                # Check if data is used in dangerous sinks
                if any(x in snippet for x in ['innerHTML', 'eval', 'Function', 'location']):
                    print(f"  🚨🚨🚨 MESSAGE DATA USED IN DANGEROUS SINK!")
                    print(f"  THIS IS LIKELY A DOM XSS VULNERABILITY!")
                    
            print("\n" + "-"*80)

print("\n" + "="*80)
print("ANALYSIS COMPLETE")
print("="*80)
