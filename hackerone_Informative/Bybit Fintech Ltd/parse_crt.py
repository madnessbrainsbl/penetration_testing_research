import json
import sys

def parse_crt(filename):
    domains = set()
    try:
        with open(filename, 'r') as f:
            # Handle potential JSON array errors (crt.sh sometimes returns malformed json)
            content = f.read()
            # Simple regex to extract common_name and name_value
            import re
            extracted = re.findall(r'"(common_name|name_value)":"([^"]+)"', content)
            for _, domain in extracted:
                # Split lines if multiple domains
                for d in domain.split('\\n'):
                    domains.add(d.lower().strip())
    except Exception as e:
        print(f"Error parsing {filename}: {e}")
    return domains

bybit_domains = parse_crt('/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data/crt_bycsi.json')
# weird_domains = parse_crt('/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data/crt_weird.json')

interesting_keywords = ['dev', 'test', 'uat', 'stg', 'stage', 'admin', 'int', 'corp', 'private', 'api', 's3', 'bucket', 'upload']

print("--- Interesting Bycsi Domains ---")
for d in sorted(bybit_domains):
     print(d)

