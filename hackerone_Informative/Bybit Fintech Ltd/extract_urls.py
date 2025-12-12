import re
import os

def extract_strings(file_path):
    with open(file_path, 'r', errors='ignore') as f:
        content = f.read()
    
    # Regex for URLs
    urls = re.findall(r'https?://[^\s"\'<>]+', content)
    
    # Regex for API paths (looser)
    # Matches strings starting with /v1, /api, /w1, etc inside quotes
    api_paths = re.findall(r'["\'](/v\d+/[\w\-/]+|/api/[\w\-/]+|/private/[\w\-/]+|/internal/[\w\-/]+)["\']', content)
    
    # Regex for script src
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', content)
    
    return urls, api_paths, script_srcs

target_dir = '/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data'
print(f"Scanning {target_dir}...")

for filename in os.listdir(target_dir):
    if filename.endswith('.js') or filename.endswith('.html'):
        path = os.path.join(target_dir, filename)
        print(f"\nFile: {filename}")
        urls, apis, scripts = extract_strings(path)
        
        if scripts:
            print(f"  Scripts found ({len(scripts)}):")
            for s in sorted(set(scripts))[:10]:
                 print(f"    {s}")
        
        if urls:
            print(f"  URLs found ({len(urls)}):")
            for u in sorted(set(urls))[:5]: 
                print(f"    {u}")
                
        if apis:
            print(f"  API Paths found ({len(apis)}):")
            for a in sorted(set(apis)):
                print(f"    {a}")
