#!/usr/bin/env python3
import re

# Read the minified file
with open('/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data/login-entry.js', 'r', errors='ignore') as f:
    content = f.read()

print("="*80)
print("CRITICAL VERIFICATION: Is complianceSDKApi2Host really exploitable?")
print("="*80)

# Find the exact code
idx = content.find('complianceSDKApi2Host')
if idx == -1:
    print("NOT FOUND!")
    exit(1)

# Extract large context
context_size = 3000
start = max(0, idx - context_size)
end = min(len(content), idx + context_size)
snippet = content[start:end]

print("\n1. FULL CODE CONTEXT:")
print("-"*80)
print(snippet)
print("-"*80)

# Check if variable 'he' is actually used for API requests
print("\n2. TRACING VARIABLE USAGE:")
print("-"*80)

# The pattern in the context we saw: const he=S?T:"undefined"!=typeof window&&localStorage.getItem("complianceSDKApi2Host")||T
# Find what 'he' is used for

# Look for 'he' being used in URL construction or fetch/axios calls
patterns_to_check = [
    (r'he[,\s\)]', 'Variable "he" reference'),
    (r'baseURL:\s*he', 'Used as baseURL'),
    (r'url:\s*he', 'Used as URL'),
    (r'host:\s*he', 'Used as host'),
    (r'"https?://"\s*\+\s*he', 'String concatenation with he'),
    (r'`https?://\$\{he\}', 'Template literal with he'),
]

for pattern, description in patterns_to_check:
    matches = list(re.finditer(pattern, snippet))
    if matches:
        print(f"\n✓ FOUND: {description}")
        for m in matches[:3]:
            ctx_start = max(0, m.start() - 100)
            ctx_end = min(len(snippet), m.end() + 100)
            print(f"  Context: ...{snippet[ctx_start:ctx_end]}...")

# Most important: check if there's ANY validation
print("\n3. CHECKING FOR VALIDATION/WHITELIST:")
print("-"*80)

validation_keywords = ['whitelist', 'allowlist', 'includes', 'test(', 'match(', 'bybit.com', 'endsWith', 'startsWith']
found_validation = False

for keyword in validation_keywords:
    # Search in wider context around he variable
    wider_start = max(0, idx - 5000)
    wider_end = min(len(content), idx + 5000)
    wider_context = content[wider_start:wider_end]
    
    if keyword in wider_context.lower():
        print(f"⚠️  Found '{keyword}' near complianceSDKApi2Host")
        # Find exact location
        kw_idx = wider_context.lower().find(keyword.lower())
        kw_ctx_start = max(0, kw_idx - 150)
        kw_ctx_end = min(len(wider_context), kw_idx + 150)
        print(f"   Context: ...{wider_context[kw_ctx_start:kw_ctx_end]}...")
        found_validation = True

if not found_validation:
    print("✗ NO VALIDATION FOUND - Vulnerability likely REAL")
else:
    print("⚠️  VALIDATION EXISTS - Need to check if it can be bypassed")

print("\n" + "="*80)
print("4. FINAL VERDICT:")
print("="*80)

# Check if this is only for dev/test environment
if 'S?T:' in snippet:
    print("⚠️  Code pattern: he = S ? T : localStorage.getItem(...) || T")
    print("   This means:")
    print("   - If S is true, use T (default)")
    print("   - If S is false, try localStorage, fallback to T")
    print("   - Need to check what 'S' is (likely environment flag)")
    
    # Try to find S definition
    s_pattern = r'[,;\s]S\s*=\s*[^,;]+[,;]'
    s_matches = list(re.finditer(s_pattern, content[:idx+10000]))
    if s_matches:
        print(f"\n   Found {len(s_matches)} potential 'S' assignments:")
        for m in s_matches[-3:]:  # Last 3
            print(f"   {m.group()}")

print("\n" + "="*80)
