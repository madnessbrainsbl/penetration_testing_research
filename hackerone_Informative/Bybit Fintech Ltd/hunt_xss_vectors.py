#!/usr/bin/env python3
"""
Hunt for XSS vectors: postMessage, prototype pollution, unsafe DOM manipulation
"""
import re
import os

recon_dir = '/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data'

print("="*80)
print("HUNTING FOR XSS VECTORS")
print("="*80)

# Find all JS files
js_files = [f for f in os.listdir(recon_dir) if f.endswith('.js')]

print(f"\nAnalyzing {len(js_files)} JavaScript files...\n")

# Pattern 1: postMessage listeners (can be vulnerable)
print("[1] SEARCHING FOR postMessage HANDLERS")
print("-"*80)

postmessage_pattern = r'addEventListener\(["\']message["\']|window\.on\s*=|\.onmessage\s*='
proto_pollution_pattern = r'__proto__|constructor\[.*prototype|Object\.assign\(|\.prototype\['

for js_file in js_files:
    filepath = os.path.join(recon_dir, js_file)
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        # Check for postMessage
        if re.search(postmessage_pattern, content, re.IGNORECASE):
            print(f"\n✓ {js_file} - Has postMessage handler")
            
            # Find the handler code
            matches = re.finditer(r'addEventListener\(["\']message["\'][^}]+\}', content, re.IGNORECASE)
            for i, match in enumerate(list(matches)[:3]):  # Show first 3
                snippet_start = max(0, match.start() - 200)
                snippet_end = min(len(content), match.end() + 300)
                print(f"\n  Handler {i+1}:")
                print(f"  {content[snippet_start:snippet_end][:500]}")
                
                # Check if it validates origin
                handler_code = content[snippet_start:snippet_end]
                if 'origin' not in handler_code.lower():
                    print(f"  🚨 NO ORIGIN VALIDATION - Potential XSS!")
                    
    except Exception as e:
        pass

# Pattern 2: Unsafe eval/Function usage
print("\n\n[2] SEARCHING FOR eval/Function/setTimeout WITH USER INPUT")
print("-"*80)

dangerous_funcs = [
    (r'eval\s*\(', 'eval()'),
    (r'Function\s*\(', 'Function()'),
    (r'setTimeout\s*\([^,]+,', 'setTimeout with string'),
    (r'setInterval\s*\([^,]+,', 'setInterval with string'),
]

for js_file in js_files:
    filepath = os.path.join(recon_dir, js_file)
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        for pattern, desc in dangerous_funcs:
            matches = list(re.finditer(pattern, content))
            if matches:
                print(f"\n✓ {js_file} - Found {len(matches)}x {desc}")
                # Check if near user input sources
                for match in matches[:2]:
                    start = max(0, match.start() - 300)
                    end = min(len(content), match.end() + 200)
                    snippet = content[start:end]
                    
                    # Check for user input nearby
                    user_input_indicators = [
                        'location.', 'window.location', 'document.URL',
                        'URLSearchParams', 'searchParams', 'query',
                        'localStorage', 'sessionStorage', 'postMessage'
                    ]
                    
                    for indicator in user_input_indicators:
                        if indicator in snippet:
                            print(f"  🚨 {desc} near {indicator}:")
                            print(f"  {snippet[:400]}")
                            break
    except:
        pass

# Pattern 3: innerHTML/outerHTML with concatenation
print("\n\n[3] SEARCHING FOR UNSAFE innerHTML WITH CONCATENATION")
print("-"*80)

innerHTML_pattern = r'\.innerHTML\s*[+]?=|\.outerHTML\s*[+]?='

for js_file in js_files:
    filepath = os.path.join(recon_dir, js_file)
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        matches = list(re.finditer(innerHTML_pattern, content))
        if matches:
            print(f"\n✓ {js_file} - Found {len(matches)}x innerHTML assignment")
            
            for match in matches[:5]:
                start = max(0, match.start() - 200)
                end = min(len(content), match.end() + 300)
                snippet = content[start:end]
                
                # Check if it's string concatenation (dangerous)
                if '+' in snippet[match.start()-start:match.end()-start+50]:
                    print(f"  ⚠️  String concatenation detected:")
                    print(f"  {snippet[:400]}")
                    
                    # Check for user input
                    user_sources = ['location', 'URL', 'search', 'hash', 'localStorage', 'postMessage']
                    for source in user_sources:
                        if source in snippet.lower():
                            print(f"  🚨 POTENTIAL DOM XSS via {source}!")
                            break
    except:
        pass

# Pattern 4: document.write with user input
print("\n\n[4] SEARCHING FOR document.write WITH USER INPUT")
print("-"*80)

doc_write_pattern = r'document\.write\('

for js_file in js_files:
    filepath = os.path.join(recon_dir, js_file)
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        matches = list(re.finditer(doc_write_pattern, content))
        if matches:
            for match in matches[:3]:
                start = max(0, match.start() - 300)
                end = min(len(content), match.end() + 200)
                snippet = content[start:end]
                
                if any(x in snippet.lower() for x in ['location', 'search', 'hash', 'localstorage']):
                    print(f"\n🚨 {js_file} - document.write with user input:")
                    print(f"  {snippet[:400]}")
    except:
        pass

print("\n" + "="*80)
print("XSS VECTOR SCAN COMPLETE")
print("="*80)
