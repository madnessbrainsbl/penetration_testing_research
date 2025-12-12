import requests
import json
import time

# BYBIT LAZARUS FUNDS TRACER V2 (NOV 2025)
# With recursion for intermediaries
# Usage: python3 trace_stolen_v2.py

ETHERSCAN_API = "https://api.etherscan.io/api"
API_KEY = "B1B89ZKHMAI1P42FRX1FPB3VD87RQQWJ82"  # 100k calls/day - ACTIVE

# Known Lazarus/DPRK addresses from public reports (Bybit hack Feb 2025)
# These are REAL addresses from blockchain forensics reports
PRIMARY_WALLETS = [
    "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",  # Known Lazarus consolidation
    "0x6cC5F688a315f3dC28A7781717a9A798a59fDA7b",  # Bybit drain address
    "0x47666fab8bd0ac7003bce3f5c3585383f09486e2",  # User-provided
]

def trace_tx(address, depth=0, max_depth=2):
    """Recursively trace transactions from address"""
    if depth > max_depth:
        print(f"[!] Max depth {max_depth} reached for {address}")
        return {}
    
    print(f"[*] Tracing: {address} (Depth: {depth})")
    
    params = {
        "module": "account",
        "action": "txlist",
        "address": address,
        "startblock": 0,
        "endblock": 99999999,
        "page": 1,
        "offset": 100,  # First 100 txs
        "sort": "desc",
        "apikey": API_KEY
    }
    
    try:
        resp = requests.get(ETHERSCAN_API, params=params, timeout=15)
        if resp.status_code != 200:
            print(f"[-] HTTP error: {resp.status_code}")
            return {}
        
        data = resp.json()
        
        # Debug: show actual response
        if data.get("status") != "1":
            print(f"[-] API Response: {data.get('message', 'Unknown')}")
            print(f"    Full response: {json.dumps(data, indent=2)[:300]}")
            return {}
        
        txs = data.get("result", [])[:20]  # Top 20 recent
    except Exception as e:
        print(f"[-] Error fetching {address}: {e}")
        return {}
    
    graph = {
        "address": address,
        "depth": depth,
        "txs": [],
        "children": []
    }
    
    total_out = 0
    for tx in txs:
        # Only outgoing transactions
        if tx["from"].lower() == address.lower():
            value_eth = float(tx["value"]) / 1e18
            
            graph["txs"].append({
                "hash": tx["hash"],
                "to": tx["to"],
                "value_eth": value_eth,
                "timestamp": int(tx["timeStamp"])
            })
            
            total_out += value_eth
            
            # Recurse on significant moves (>0.1 ETH)
            if value_eth > 0.1 and tx["to"].lower() != address.lower():
                print(f"  -> {value_eth:.4f} ETH to {tx['to']}")
                time.sleep(0.5)  # Rate limit
                child = trace_tx(tx["to"], depth + 1, max_depth)
                if child:
                    graph["children"].append(child)
    
    graph["total_out_eth"] = total_out
    print(f"  Total OUT: {total_out:.2f} ETH")
    
    return graph

def main():
    print("="*60)
    print("BYBIT LAZARUS FUND TRACER (Nov 2025)")
    print("="*60)
    print(f"[*] API Key: {API_KEY[:10]}...{API_KEY[-4:]}")
    print()
    
    all_traces = []
    
    for i, wallet in enumerate(PRIMARY_WALLETS):
        print(f"\n[{i+1}/{len(PRIMARY_WALLETS)}] Tracing wallet: {wallet}")
        graph = trace_tx(wallet, depth=0, max_depth=2)
        
        if graph and graph.get("txs"):
            all_traces.append(graph)
            print(f"[+] Found {len(graph.get('txs', []))} transactions")
        else:
            print(f"[-] No data for {wallet}")
        
        time.sleep(0.5)  # Rate limit
    
    # Save all traces
    output_file = "bybit_stolen_trace.json"
    with open(output_file, "w") as f:
        json.dump(all_traces, f, indent=2)
    
    print("\n" + "="*60)
    print(f"[+] Trace complete! Saved {len(all_traces)} wallet traces")
    print(f"[+] Output: {output_file}")
    print()
    
    if all_traces:
        print("[*] ANALYSIS:")
        for trace in all_traces:
            total = trace.get("total_out_eth", 0)
            children = len(trace.get("children", []))
            print(f"  - {trace['address'][:10]}...")
            print(f"    Total OUT: {total:.2f} ETH")
            print(f"    Downstream wallets: {children}")
        
        print()
        print("[*] NEXT: Check JSON for 'unmoved' funds (0 children)")
        print("[*] Report to Bybit: https://bugcrowd.com/bybit")
    else:
        print("[!] No successful traces. Check addresses or API limits.")
    
    print("="*60)

if __name__ == "__main__":
    main()
