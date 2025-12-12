import re

def extract_with_context(filepath, search_term, context_size=500):
    with open(filepath, 'r', errors='ignore') as f:
        content = f.read()
    
    positions = []
    idx = 0
    while True:
        idx = content.find(search_term, idx)
        if idx == -1:
            break
        positions.append(idx)
        idx += 1
    
    print(f"\n=== Searching '{search_term}' in {filepath} ===")
    print(f"Found {len(positions)} occurrences\n")
    
    for i, pos in enumerate(positions):
        start = max(0, pos - context_size)
        end = min(len(content), pos + len(search_term) + context_size)
        snippet = content[start:end]
        print(f"--- Occurrence {i+1} at position {pos} ---")
        print(snippet)
        print("\n" + "="*80 + "\n")

# Analyze tmp_token usage
extract_with_context('/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data/login.html', 'tmp_token', 600)

# Analyze complianceSDKApi2Host usage
extract_with_context('/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data/vendors.js', 'complianceSDKApi2Host', 600)
extract_with_context('/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data/login-entry.js', 'complianceSDKApi2Host', 600)

# Also check for isQuickLogin to see what happens next
extract_with_context('/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data/login.html', 'isQuickLogin', 600)
