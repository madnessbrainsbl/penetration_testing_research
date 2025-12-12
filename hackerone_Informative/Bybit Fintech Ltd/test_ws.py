import asyncio
import websockets
import json

async def test_ws():
    uri = "wss://stream-testnet.bybit.com/v5/public/linear"
    print(f"Connecting to {uri}...")
    try:
        async with websockets.connect(uri) as websocket:
            # Send a subscription request
            msg = {
                "op": "subscribe",
                "args": ["orderbook.1.BTCUSDT"]
            }
            await websocket.send(json.dumps(msg))
            print(f"Sent: {msg}")
            
            # Listen for response
            response = await websocket.recv()
            print(f"Received: {response}")
            
            # Listen for data
            data = await websocket.recv()
            print(f"Data: {str(data)[:100]}...")
            
    except Exception as e:
        print(f"WS Error: {e}")

# Check if library exists first
try:
    asyncio.get_event_loop().run_until_complete(test_ws())
except ImportError:
    print("websockets library not installed")
except Exception as e:
    print(f"Runtime error: {e}")
