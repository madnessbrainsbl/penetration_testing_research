#!/bin/bash
# BYBIT LAZARUS RECOVERY TRACER (BASH)
# Fast tracing of stolen funds via Etherscan API

API_KEY="B1B89ZKHMAI1P42FRX1FPB3VD87RQQWJ82"
API_URL="https://api.etherscan.io/api"

# Known Lazarus addresses from public reports
WALLETS=(
    "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
    "0x6cC5F688a315f3dC28A7781717a9A798a59fDA7b"
    "0x47666fab8bd0ac7003bce3f5c3585383f09486e2"
)

OUTPUT="lazarus_trace_results.txt"
echo "========================================" > "$OUTPUT"
echo "BYBIT LAZARUS TRACER - $(date)" >> "$OUTPUT"
echo "========================================" >> "$OUTPUT"

echo ""
echo "============================================"
echo "BYBIT LAZARUS FUND TRACER (Nov 2025)"
echo "API Key: ${API_KEY:0:10}...${API_KEY: -4}"
echo "============================================"

for i in "${!WALLETS[@]}"; do
    addr="${WALLETS[$i]}"
    echo ""
    echo "[$((i+1))/${#WALLETS[@]}] Tracing: $addr"
    echo "-------------------------------------------" >> "$OUTPUT"
    echo "Wallet: $addr" >> "$OUTPUT"
    
    # Get balance
    balance_resp=$(curl -s "$API_URL?module=account&action=balance&address=$addr&tag=latest&apikey=$API_KEY")
    balance_wei=$(echo "$balance_resp" | grep -o '"result":"[^"]*"' | cut -d'"' -f4)
    
    if [ -n "$balance_wei" ] && [ "$balance_wei" != "0" ]; then
        balance_eth=$(echo "scale=4; $balance_wei / 1000000000000000000" | bc 2>/dev/null || echo "0")
        echo "[+] Balance: $balance_eth ETH"
        echo "Balance: $balance_eth ETH" >> "$OUTPUT"
    else
        echo "[-] Balance: 0 ETH (swept)"
        echo "Balance: 0 ETH" >> "$OUTPUT"
    fi
    
    # Get transactions
    tx_resp=$(curl -s "$API_URL?module=account&action=txlist&address=$addr&startblock=0&endblock=99999999&page=1&offset=50&sort=desc&apikey=$API_KEY")
    
    # Check status
    status=$(echo "$tx_resp" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
    message=$(echo "$tx_resp" | grep -o '"message":"[^"]*"' | head -1 | cut -d'"' -f4)
    
    if [ "$status" != "1" ]; then
        echo "[!] API Error: $message"
        echo "Error: $message" >> "$OUTPUT"
        continue
    fi
    
    # Parse transactions
    tx_count=$(echo "$tx_resp" | grep -o '"hash":"0x[^"]*"' | wc -l)
    echo "[*] Found $tx_count transactions"
    echo "Transaction count: $tx_count" >> "$OUTPUT"
    
    if [ "$tx_count" -gt 0 ]; then
        echo "" >> "$OUTPUT"
        echo "TOP OUTGOING TRANSFERS:" >> "$OUTPUT"
        
        # Extract outgoing transactions with value > 0.1 ETH
        echo "$tx_resp" | grep -o '"from":"[^"]*","to":"[^"]*","value":"[^"]*"' | while IFS= read -r line; do
            from=$(echo "$line" | grep -o '"from":"[^"]*"' | cut -d'"' -f4)
            to=$(echo "$line" | grep -o '"to":"[^"]*"' | cut -d'"' -f4)
            value=$(echo "$line" | grep -o '"value":"[^"]*"' | cut -d'"' -f4)
            
            # Check if FROM matches our wallet (outgoing)
            if [ "${from,,}" == "${addr,,}" ] && [ -n "$value" ] && [ "$value" != "0" ]; then
                value_eth=$(echo "scale=4; $value / 1000000000000000000" | bc 2>/dev/null || echo "0")
                
                # Only show significant transfers (>0.1 ETH)
                if (( $(echo "$value_eth > 0.1" | bc -l 2>/dev/null || echo 0) )); then
                    echo "  -> $value_eth ETH to $to" | tee -a "$OUTPUT"
                fi
            fi
        done | head -20
    fi
    
    echo "" >> "$OUTPUT"
    sleep 0.5  # Rate limit
done

echo ""
echo "============================================"
echo "[+] Trace complete!"
echo "[+] Results saved to: $OUTPUT"
echo ""
echo "[*] ANALYSIS:"
grep "Balance:" "$OUTPUT" | while read -r line; do
    echo "  $line"
done

echo ""
echo "[*] NEXT STEPS:"
echo "1. Check $OUTPUT for wallets with balance >0"
echo "2. Trace downstream addresses with significant transfers"
echo "3. Look for mixer patterns (Tornado, etc.)"
echo "4. Report unmoved funds to Bybit -> 10% bounty"
echo "============================================"
