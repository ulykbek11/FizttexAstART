import asyncio
import websockets
import json

async def test_scan():
    uri = "ws://localhost:8000/ws/scan/youtube.com"
    try:
        async with websockets.connect(uri) as websocket:
            print("Connected to WebSocket")
            while True:
                try:
                    message = await websocket.recv()
                    data = json.loads(message)
                    print(f"Received: {data.get('type')} - {data.get('message', '')[:50]}...")
                    if data.get('type') == 'complete' or data.get('type') == 'error':
                        break
                except websockets.exceptions.ConnectionClosed:
                    print("Connection closed by server")
                    break
    except Exception as e:
        print(f"Connection error: {e}")

if __name__ == "__main__":
    asyncio.run(test_scan())