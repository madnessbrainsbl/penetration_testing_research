import re

with open('/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data/buildManifest.js', 'r') as f:
    content = f.read()

# Regex to find page mappings like "/login":["static/chunks/...", ...]
# This is approximate, as the format is minified JSON-like structure
mappings = re.findall(r'"(/[a-zA-Z0-9\-_/]+)":\[(.*?)\]', content)

print(f"Found {len(mappings)} page mappings:")
for page, chunks in mappings:
    # Clean up chunk list
    chunk_list = [c.strip('"') for c in chunks.split(',')]
    print(f"Page: {page}")
    for c in chunk_list:
        if c.endswith('.js'):
            print(f"  - {c}")
