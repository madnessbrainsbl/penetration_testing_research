import re
import os

def analyze_file(path):
    with open(path, 'r', errors='ignore') as f:
        content = f.read()
    
    # Look for localStorage/sessionStorage usage
    storage = re.findall(r'(localStorage|sessionStorage)\.(setItem|getItem)\(["\']([^"\']+)["\']', content)
    
    # Look for debug flags
    debug = re.findall(r'(debug|test|dev|mock)[a-zA-Z0-9_]*\s*[:=]\s*(!?0|!?1|true|false)', content, re.IGNORECASE)
    
    # Look for headers being set
    headers = re.findall(r'["\'](X-[a-zA-Z0-9\-]+)["\']\s*[:=]', content)
    
    return storage, debug, headers

target_dir = '/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data'
for filename in os.listdir(target_dir):
    if filename.endswith('.js'):
        s, d, h = analyze_file(os.path.join(target_dir, filename))
        if s or d or h:
            print(f"\nFile: {filename}")
            if s: print(f"  Storage: {s[:5]}")
            if d: print(f"  Debug/Flags: {d[:5]}")
            if h: print(f"  Headers: {h[:5]}")
