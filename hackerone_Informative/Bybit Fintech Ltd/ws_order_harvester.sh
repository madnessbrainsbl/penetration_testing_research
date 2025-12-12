#!/bin/bash
# WEBSOCKET ORDER ID LEAK PROBE
# Connects to public WS and looks for orderID patterns

echo "=========================================="
echo "WEBSOCKET ORDER ID HARVESTER"
echo "=========================================="
echo ""
echo "Connecting to public orderbook stream..."
echo "Looking for leaked orderID patterns..."
echo ""

# Use websocat if available, otherwise explain
if command -v websocat &> /dev/null; then
    timeout 10 websocat "wss://stream.bybit.com/v5/public/linear" <<EOF | grep -o '"orderId":"[^"]*"' | head -20
{"op":"subscribe","args":["orderbook.50.BTCUSDT"]}
EOF
else
    echo "❌ websocat not installed"
    echo ""
    echo "To capture orderIDs from WebSocket:"
    echo "1. Install: pip install websocket-client"
    echo "2. Or use browser DevTools → Network → WS"
    echo "3. Subscribe to: wss://stream.bybit.com/v5/public/linear"
    echo "4. Look for any orderID leaks in messages"
    echo ""
    echo "Alternative: Use our Python ws_fuzz.py"
fi

echo ""
echo "=========================================="
