#!/bin/bash
# BYBIT LAZARUS TRACER (ETHERSCAN API V2)
# Fast bash tracer for stolen funds recovery

API_KEY="B1B89ZKHMAI1P42FRX1FPB3VD87RQQWJ82"
API="https://api.etherscan.io/v2/api?chainid=1"

# Known addresses (from public blockchain forensics)
WALLETS=(
    "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
    "0x6cC5F688a315f3dC28A7781717a9A798a59fDA7b"
    "0x47666fab8bd0ac7003bce3f5c3585383f09486e2"
)

echo "========================================"
echo "BYBIT LAZARUS RECOVERY TRACER"
echo "API V2 | $(date '+%Y-%m-%d %H:%M')"
echo "========================================"
echo ""

for wallet in "${WALLETS[@]}"; do
    echo "[*] Checking: $wallet"
    
    # Get balance
    bal_resp=$(curl -s "$API&module=account&action=balance&address=$wallet&apikey=$API_KEY")
    bal_wei=$(echo "$bal_resp" | grep -o '"result":"[0-9]*"' | cut -d'"' -f4)
    
    if [ -n "$bal_wei" ] && [ "$bal_wei" != "0" ]; then
        bal_eth=$(echo "scale=6; $bal_wei / 1000000000000000000" | bc)
        echo "    Balance: $bal_eth ETH 💰"
        
        # Get transactions
        tx_resp=$(curl -s "$API&module=account&action=txlist&address=$wallet&startblock=0&endblock=99999999&page=1&offset=20&sort=desc&apikey=$API_KEY")
        
        tx_count=$(echo "$tx_resp" | grep -o '"hash":"0x[^"]*"' | wc -l)
        echo "    Transactions: $tx_count"
        
        if [ "$tx_count" -gt 0 ]; then
            echo "    Recent OUT:"
            
            # Parse top outgoing
            echo "$tx_resp" | grep -Po '"from":"[^"]*","to":"[^"]*","value":"[^"]*"' | head -10 | while read line; do
                from=$(echo "$line" | grep -o '"from":"[^"]*"' | cut -d'"' -f4)
                to=$(echo "$line" | grep -o '"to":"[^"]*"' | cut -d'"' -f4)
                val=$(echo "$line" | grep -o '"value":"[^"]*"' | cut -d'"' -f4)
                
                if [ "${from,,}" == "${wallet,,}" ] && [ "$val" != "0" ]; then
                    val_eth=$(echo "scale=4; $val / 1000000000000000000" | bc)
                    echo "      -> $val_eth ETH to ${to:0:20}..."
                fi
            done
        fi
        
        echo ""
    else
        echo "    Balance: 0 ETH (swept)"
    fi
    
    sleep 0.3
done

echo "========================================"
echo "[+] Scan complete!"
echo ""
echo "[*] FINDINGS:"
echo "- Any wallet with balance >0.1 ETH = UNMOVED FUNDS"
echo "- Report to Bybit with proof = 10% bounty"
echo "- Trace downstream wallets for laundering"
echo "========================================"
