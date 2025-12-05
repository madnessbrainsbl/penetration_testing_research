#!/usr/bin/env python3
"""
Test for GraphQL endpoints and introspection
"""
import requests
import json

requests.packages.urllib3.disable_warnings()

print("="*80)
print("SEARCHING FOR GRAPHQL ENDPOINTS")
print("="*80)

# Common GraphQL paths
graphql_paths = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/gql",
    "/api/gql",
]

domains = [
    "https://testnet.bybit.com",
    "https://api-testnet.bybit.com",
    "https://api2-testnet.bybit.com",
]

# Introspection query
introspection_query = {
    "query": """
    {
        __schema {
            types {
                name
                fields {
                    name
                }
            }
        }
    }
    """
}

print("\n[1] CHECKING FOR GRAPHQL ENDPOINTS")
print("-"*80)

found_graphql = []

for domain in domains:
    for path in graphql_paths:
        url = domain + path
        
        try:
            # Try POST with introspection
            r = requests.post(url, json=introspection_query, timeout=5, verify=False)
            
            if r.status_code == 200:
                print(f"\n✓ Found GraphQL at: {url}")
                print(f"  Response: {r.text[:200]}")
                found_graphql.append(url)
                
                # Check if introspection is enabled
                if '__schema' in r.text or 'types' in r.text:
                    print(f"  🚨 INTROSPECTION IS ENABLED!")
                    
            # Try GET
            r2 = requests.get(url, timeout=5, verify=False)
            if 'graphql' in r2.text.lower() or 'graphiql' in r2.text.lower():
                print(f"\n✓ GraphQL UI found at: {url}")
                print(f"  Response: {r2.text[:200]}")
                
        except:
            pass

if not found_graphql:
    print("\n✗ No GraphQL endpoints found")

print("\n" + "="*80)
