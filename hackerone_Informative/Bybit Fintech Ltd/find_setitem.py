# Extract all localStorage.setItem calls with context
import re

def find_setItem_calls(filepath):
    with open(filepath, 'r', errors='ignore') as f:
        content = f.read()
    
    # Find all localStorage.setItem calls
    pattern = r'localStorage\.setItem\([^)]+\)'
    matches = re.finditer(pattern, content)
    
    print(f"\n=== localStorage.setItem calls in {filepath} ===\n")
    for match in matches:
        start = max(0, match.start() - 300)
        end = min(len(content), match.end() + 300)
        context = content[start:end]
        print(f"Match: {match.group()}")
        print(f"Context:\n{context}\n")
        print("="*80)

find_setItem_calls('/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data/page.js')
find_setItem_calls('/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data/login.html')
find_setItem_calls('/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data/login_page.js')
