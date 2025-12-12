import requests
import json
import time

# LAZARUS FUNDS TRACER (PoC)
# Usage: python3 trace_stolen.py <START_ADDRESS>

ETHERSCAN_API_KEY = "" # Free tier works without key
BASE_URL = "https://api.etherscan.io/api"
STOLEN_WALLET = "0x47666fab8bd0ac7003bce3f5c3585383f09486e2"

def get_txs(address):
    url = f"{BASE_URL}?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&sort=desc&apikey={ETHERSCAN_API_KEY}"
    try:
        r = requests.get(url, timeout=15)
        data = r.json()
        if data.get('status') == "1":
            return data['result']
    except Exception as e:
        print(f"Error: {e}")
    return []

def trace(start_addr):
    print(f"[*] Tracing Lazarus Wallet: {start_addr}")
    print(f"[*] Fetching transactions...")
    
    txs = get_txs(start_addr)
    print(f"[*] Found {len(txs)} transactions.")
    
    if len(txs) == 0:
        print("[!] No transactions found (API limit or invalid address)")
        return
    
    outgoing = []
    total_out = 0
    
    for tx in txs[:50]:  # Top 50 recent
        if tx['from'].lower() == start_addr.lower():
            to_addr = tx['to']
            value = float(tx['value']) / 10**18
            
            if value > 0.1:  # Significant moves
                outgoing.append({
                    'to': to_addr,
                    'value': value,
                    'hash': tx['hash'],
                    'timestamp': tx['timeStamp']
                })
                total_out += value
    
    print(f"\n[+] OUTGOING TRANSACTIONS (>{0.1} ETH):")
    print(f"Total Moved: {total_out:.2f} ETH\n")
    
    for i, tx in enumerate(outgoing[:20]):
        print(f"{i+1}. To: {tx['to']}")
        print(f"   Value: {tx['value']:.4f} ETH")
        print(f"   Hash: {tx['hash']}")
        print(f"   Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(int(tx['timestamp'])))}")
        print()
    
    # Save to file
    with open("lazarus_trace.json", "w") as f:
        json.dump(outgoing, f, indent=2)
    print(f"[*] Full trace saved to: lazarus_trace.json")

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else STOLEN_WALLET
    trace(target)
