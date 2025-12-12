import os
import re

# Patterns to look for
patterns = {
    'dangerouslySetInnerHTML': r'dangerouslySetInnerHTML\s*[:=]',
    'innerHTML': r'\.innerHTML\s*=',
    'outerHTML': r'\.outerHTML\s*=',
    'document.write': r'document\.write\(',
    'location.href': r'location\.href\s*=',
    'location.replace': r'location\.replace\(',
    'window.open': r'window\.open\(',
    'eval': r'eval\(',
    'setTimeout_string': r'setTimeout\s*\(\s*["\']',
    'postMessage': r'\.postMessage\(',
    'message_listener': r'addEventListener\s*\(\s*["\']message["\']'
}

def scan_file(filepath):
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        found = False
        for name, pattern in patterns.items():
            matches = list(re.finditer(pattern, content))
            if matches:
                if not found:
                    print(f"\n--- {os.path.basename(filepath)} ---")
                    found = True
                print(f"  Found {name}: {len(matches)} times")
                
                # Print context for first few matches
                for m in matches[:3]:
                    start = max(0, m.start() - 50)
                    end = min(len(content), m.end() + 100)
                    snippet = content[start:end].replace('\n', ' ')
                    print(f"    ...{snippet}...")
    except Exception as e:
        print(f"Error reading {filepath}: {e}")

target_dir = '/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data'
for filename in os.listdir(target_dir):
    if filename.endswith('.js'):
        scan_file(os.path.join(target_dir, filename))
