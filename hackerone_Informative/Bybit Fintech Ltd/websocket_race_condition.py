#!/usr/bin/env python3
"""
Test WebSocket for race conditions
Based on: https://github.com/redrays-io/WS_RaceCondition_PoC
"""
import asyncio
import websockets
import json
import time

async def test_ws_race_condition():
    """Test if WebSocket allows race conditions for duplicate orders"""
    uri = "wss://stream-testnet.bybit.com/v5/public/linear"
    
    print("="*80)
    print("TESTING WEBSOCKET RACE CONDITIONS")
    print("="*80)
    
    # Test 1: Multiple connections sending same subscription
    print("\n[1] Testing Multiple Simultaneous Subscriptions")
    print("-"*80)
    
    async def send_subscription(conn_id):
        try:
            async with websockets.connect(uri) as ws:
                # Subscribe to orderbook
                msg = {
                    "op": "subscribe",
                    "args": ["orderbook.50.BTCUSDT"]
                }
                
                start = time.time()
                await ws.send(json.dumps(msg))
                response = await ws.recv()
                elapsed = time.time() - start
                
                print(f"  Connection {conn_id}: {elapsed:.3f}s - {response[:100]}")
                return response
        except Exception as e:
            print(f"  Connection {conn_id} error: {e}")
            return None
    
    # Send 5 simultaneous subscriptions
    tasks = [send_subscription(i) for i in range(5)]
    results = await asyncio.gather(*tasks)
    
    # Check if all got different responses or errors
    unique_responses = set([r[:200] if r else None for r in results])
    print(f"\n  Unique responses: {len(unique_responses)}")
    if len(unique_responses) < len(results):
        print("  ⚠️  Some responses are identical - possible race condition")
    
    # Test 2: Check for rate limiting bypass via WS
    print("\n\n[2] Testing Rate Limiting via WebSocket")
    print("-"*80)
    
    try:
        async with websockets.connect(uri) as ws:
            # Send many requests rapidly
            for i in range(100):
                msg = {"op": "subscribe", "args": [f"orderbook.1.BTCUSDT"]}
                await ws.send(json.dumps(msg))
            
            # Check responses
            responses = []
            for _ in range(10):
                try:
                    resp = await asyncio.wait_for(ws.recv(), timeout=1)
                    responses.append(resp)
                except asyncio.TimeoutError:
                    break
            
            print(f"  Sent 100 requests, got {len(responses)} responses")
            
            # Check for rate limit errors
            rate_limited = any('rate' in r.lower() or 'limit' in r.lower() for r in responses)
            if not rate_limited:
                print("  ⚠️  No rate limiting detected on WebSocket!")
            
    except Exception as e:
        print(f"  Error: {e}")
    
    print("\n" + "="*80)

# Test 3: Check for authentication bypass via WS
async def test_ws_auth_bypass():
    """Test if private WS endpoints accept unauthenticated connections"""
    
    print("\n[3] TESTING WEBSOCKET AUTHENTICATION BYPASS")
    print("-"*80)
    
    # Private WebSocket endpoints
    private_uris = [
        "wss://stream-testnet.bybit.com/v5/private",
        "wss://stream-testnet.bybit.com/v5/trade",
        "wss://stream.bybit.com/realtime_private",
    ]
    
    for uri in private_uris:
        try:
            print(f"\n  Testing: {uri}")
            async with websockets.connect(uri, timeout=5) as ws:
                # Try to subscribe without auth
                msg = {"op": "subscribe", "args": ["position"]}
                await ws.send(json.dumps(msg))
                
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=3)
                    print(f"    Response: {response[:200]}")
                    
                    # Check if we got data instead of auth error
                    if 'success' in response.lower() and 'auth' not in response.lower():
                        print(f"    🚨 POSSIBLE AUTH BYPASS!")
                except asyncio.TimeoutError:
                    print(f"    Timeout - no response")
        except Exception as e:
            print(f"    Connection failed: {str(e)[:100]}")

if __name__ == "__main__":
    try:
        asyncio.run(test_ws_race_condition())
        asyncio.run(test_ws_auth_bypass())
    except Exception as e:
        print(f"Error: {e}")
        print("\nNote: Install websockets library: pip install websockets")
