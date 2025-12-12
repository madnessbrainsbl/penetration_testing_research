#!/usr/bin/env python3
import re

with open('/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data/login-entry.js', 'r', errors='ignore') as f:
    content = f.read()

# Find where 'he' variable is defined
idx = content.find('complianceSDKApi2Host')
context = content[max(0, idx-500):min(len(content), idx+3000)]

print("="*80)
print("TRACING 'he' VARIABLE TO CONFIRM EXPLOITATION")
print("="*80)

# Extract the exact assignment
assignment_pattern = r'const\s+(\w+)=\w+\?\w+:"undefined"!=typeof window&&localStorage\.getItem\("complianceSDKApi2Host"\)\|\|\w+'
match = re.search(assignment_pattern, context)

if match:
    var_name = match.group(1)
    print(f"\n✓ Variable name: '{var_name}'")
    print(f"  Assignment: {match.group()}")
else:
    print("✗ Could not find variable assignment")
    # Try alternative pattern
    alt_pattern = r'(\w+)=\w+\?\w+:"undefined".*complianceSDKApi2Host'
    alt_match = re.search(alt_pattern, context)
    if alt_match:
        var_name = alt_match.group(1)
        print(f"\n✓ Alternative found: '{var_name}'")
    else:
        print("Trying to find manually...")
        # Manual extraction
        lines = context.split(',')
        for i, line in enumerate(lines):
            if 'complianceSDKApi2Host' in line:
                print(f"\nLine {i}: {line[:200]}")
                # Try to extract variable before =
                eq_idx = line.rfind('=', 0, line.find('complianceSDKApi2Host'))
                if eq_idx > 0:
                    var_part = line[:eq_idx].strip()
                    tokens = re.findall(r'\b\w+\b', var_part)
                    if tokens:
                        var_name = tokens[-1]
                        print(f"✓ Extracted variable: '{var_name}'")
                        break

# Now search for usage of this variable in API calls
print(f"\n\nSEARCHING FOR '{var_name}' USAGE IN API CALLS:")
print("-"*80)

# Common patterns for API usage
api_patterns = [
    (rf'baseURL:\s*{var_name}', 'Used as baseURL in config'),
    (rf'url:\s*{var_name}', 'Used as URL'),
    (rf'{var_name}\+', 'String concatenation'),
    (r'`.*\$\{' + var_name + r'\}', 'Template literal'),
    (r'new\s+\w+\(\{[^\}]*' + var_name, 'Passed to constructor'),
]

found_usage = False
for pattern, description in api_patterns:
    matches = list(re.finditer(pattern, content))
    if matches:
        found_usage = True
        print(f"\n✓ {description}")
        print(f"  Found {len(matches)} occurrence(s)")
        for m in matches[:2]:
            start = max(0, m.start() - 200)
            end = min(len(content), m.end() + 200)
            print(f"  Context: ...{content[start:end][:400]}...")

if not found_usage:
    # Search more broadly
    print(f"\n\nBROADER SEARCH (all references to '{var_name}'):")
    print("-"*80)
    # Find all mentions
    mentions = []
    for m in re.finditer(rf'\b{var_name}\b', content):
        mentions.append(m.start())
    
    print(f"Found {len(mentions)} total references")
    # Show first 10
    for i, pos in enumerate(mentions[:10]):
        start = max(0, pos - 150)
        end = min(len(content), pos + 150)
        print(f"\n{i+1}. Position {pos}:")
        print(f"   {content[start:end][:300]}")

# Check if there's validation AFTER reading from localStorage
print("\n\n" + "="*80)
print("CHECKING FOR VALIDATION AFTER LOCALSTORAGE READ")
print("="*80)

# Look for validation between localStorage read and usage
localStorage_idx = content.find('localStorage.getItem("complianceSDKApi2Host")')
if localStorage_idx > 0:
    # Check next 2000 chars for validation
    validation_zone = content[localStorage_idx:localStorage_idx+2000]
    
    validation_indicators = [
        'whitelist', 'allowlist', 'allowed', 'valid',
        'test(', 'match(', 'includes(', 'indexOf(',
        'startsWith(', 'endsWith(',
        'bybit.com', 'bycsi.com'
    ]
    
    found = []
    for indicator in validation_indicators:
        if indicator in validation_zone:
            found.append(indicator)
    
    if found:
        print(f"⚠️  Found potential validation keywords: {found}")
        print("\nExtract from validation zone:")
        print(validation_zone[:500])
    else:
        print("✗ NO VALIDATION KEYWORDS FOUND")
        print("🚨 VULNERABILITY CONFIRMED: localStorage value used without validation!")

print("\n" + "="*80)
