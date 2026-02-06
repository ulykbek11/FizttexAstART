from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
import sys
import os
import uvicorn

# Add current directory to path to allow importing scanner_core
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from main import UltimateSecurityAnalyzer

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.websocket("/ws/scan/{domain}")
async def websocket_endpoint(websocket: WebSocket, domain: str):
    await websocket.accept()
    print(f"Accepted connection for {domain}")
    
    # Async callback for direct websocket communication
    async def log_callback(message, level):
        print(f"Sending log: {message[:50]}...")
        try:
            await websocket.send_json({
                "type": "log",
                "message": message,
                "level": level
            })
        except Exception as e:
            print(f"WebSocket send error: {e}")

    try:
        # Sanitize domain
        domain = domain.replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]
        print(f"Sanitized domain: {domain}")
        
        analyzer = UltimateSecurityAnalyzer(domain, log_callback=log_callback)
        
        # Run async scan directly
        print("Starting run_full_scan")
        await analyzer.run_full_scan()
        print("Finished run_full_scan")
        
        await websocket.send_json({
            "type": "complete", 
            "results": analyzer.results
        })
        print("Sent complete message")
        
    except WebSocketDisconnect:
        print(f"Client disconnected for {domain}")
    except Exception as e:
        import traceback
        traceback.print_exc()
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except:
            pass
        print(f"Error during scan: {e}")
    finally:
        print("Closing websocket")
        try:
            await websocket.close()
        except:
            pass

@app.get("/")
async def root():
    return {"message": "Ultimate Security Analyzer API is running"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
