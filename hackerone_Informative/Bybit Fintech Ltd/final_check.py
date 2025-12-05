#!/usr/bin/env python3
import re

with open('/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data/login-entry.js', 'r', errors='ignore') as f:
    content = f.read()

print("="*80)
print("FINAL VULNERABILITY VERIFICATION")
print("="*80)

# Find the localStorage read
idx = content.find('localStorage.getItem("complianceSDKApi2Host")')
if idx == -1:
    print("ERROR: complianceSDKApi2Host not found!")
    exit(1)

# Extract context
context_before = content[max(0, idx-1000):idx]
context_after = content[idx:min(len(content), idx+2000)]

print("\n1. CODE CONTEXT:")
print("-"*80)
print("BEFORE:", context_before[-300:])
print("\n>>> localStorage.getItem('complianceSDKApi2Host') <<<\n")
print("AFTER:", context_after[:500])

# Find variable name
var_match = re.search(r'(\w+)\s*=\s*\w+\s*\?\s*\w+\s*:\s*"undefined".*complianceSDKApi2Host', context_before + context_after[:200])
if var_match:
    var_name = var_match.group(1)
    print(f"\n2. VARIABLE NAME: '{var_name}'")
else:
    print("\n2. Could not extract variable name precisely")
    var_name = "he"  # from our earlier findings

# Check if there's validation
print(f"\n3. VALIDATION CHECK:")
print("-"*80)

# Look in the zone after localStorage read
validation_zone = context_after[:1000]
validation_terms = ['test(', 'match(', 'includes(', 'whitelist', 'allowlist', 'indexOf', 'bybit']
found_validations = []

for term in validation_terms:
    if term in validation_zone.lower():
        found_validations.append(term)

if found_validations:
    print(f"⚠️  Found validation-like terms: {found_validations}")
    print("Need manual review to check if they apply to this variable")
else:
    print("✗ NO VALIDATION FOUND immediately after localStorage read")

# Check how variable is used
print(f"\n4. SEARCHING FOR USAGE OF VARIABLE:")
print("-"*80)

# Search for the variable in axios/fetch config
usage_patterns = [
    'baseURL',
    'url:',
    'host:',
    'fetch(',
    'axios(',
    'request('
]

for pattern in usage_patterns:
    # Find pattern occurrences after our variable definition
    pattern_idx = content.find(pattern, idx)
    if pattern_idx > idx and pattern_idx < idx + 5000:
        snippet_start = max(0, pattern_idx - 100)
        snippet_end = min(len(content), pattern_idx + 200)
        snippet = content[snippet_start:snippet_end]
        if var_name in snippet or 'he' in snippet:
            print(f"\n✓ Found '{pattern}' near variable:")
            print(f"  {snippet[:300]}")

# Final check: is there HTTPS prefix validation?
print(f"\n5. SECURITY CHECK - HTTPS VALIDATION:")
print("-"*80)

if 'https://' in context_after[:500]:
    print("⚠️  Found 'https://' in nearby code")
    print("Checking if it's a prefix or concatenation...")
    if '+' in context_after[:500] or '`' in context_after[:500]:
        print("✓ Possible string concatenation - variable might be used as subdomain/path")
    else:
        print("⚠️  Hard to determine usage pattern")
else:
    print("✗ No 'https://' prefix found - variable may be full URL")

print("\n" + "="*80)
print("CONCLUSION:")
print("="*80)

# Analyze the conditional S?T:localStorage
s_check = 'S?T:' in context_before[-200:]
if s_check:
    print("✓ Code uses conditional: S ? default : localStorage")
    print("  This means localStorage only used when S=false")
    print("  S appears to be hostname regex check")
    print("  On production domains (bybit.com), S=true, so localStorage NOT used")
    print("  BUT: On localhost/dev, S=false, localStorage IS used")
    print("\n🎯 VERDICT: VULNERABILITY EXISTS BUT LIMITED SCOPE")
    print("   - Only exploitable on localhost/non-standard domains")
    print("   - NOT exploitable on production testnet.bybit.com")
    print("   - Severity: LOW / INFORMATIONAL")
else:
    print("⚠️  Conditional pattern not clearly detected")

print("="*80)
