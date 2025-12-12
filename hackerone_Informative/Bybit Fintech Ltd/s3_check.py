#!/usr/bin/env python3
import requests
import xml.etree.ElementTree as ET

print("="*80)
print("S3 BUCKET INSPECTOR")
print("="*80)

BUCKET_URL = "https://s3.ap-southeast-1.amazonaws.com/app.bybit.com"

print(f"Checking {BUCKET_URL}...")

try:
    r = requests.get(BUCKET_URL, verify=False, timeout=5)
    print(f"Status: {r.status_code}")
    
    if r.status_code == 200:
        print("🚨 BUCKET LISTING ENABLED!")
        
        # Parse XML to find files
        try:
            root = ET.fromstring(r.content)
            ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}
            
            keys = []
            for contents in root.findall('s3:Contents', ns):
                key = contents.find('s3:Key', ns).text
                keys.append(key)
                
            print(f"\nFound {len(keys)} files:")
            for k in keys[:20]:
                print(f"  - {k}")
                
            # Check for interesting files
            interesting = [k for k in keys if "config" in k or "secret" in k or "env" in k or "dev" in k]
            if interesting:
                print(f"\n⚠️  INTERESTING FILES FOUND:")
                for k in interesting:
                    print(f"  - {BUCKET_URL}/{k}")
                    
        except Exception as e:
            print(f"Error parsing XML: {e}")
            print(f"Raw content start: {r.text[:200]}")
            
    elif "AccessDenied" in r.text:
        print("Access Denied (Secure)")
    else:
        print(f"Response: {r.text[:200]}")

except Exception as e:
    print(f"Error: {e}")
