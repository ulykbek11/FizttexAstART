from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
import sys
import os

# Add current directory to path to allow importing scanner_core
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scanner_core import UltimateSecurityAnalyzer

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
    
    async def log_callback(message, level):
        try:
            await websocket.send_json({
                "type": "log",
                "message": message,
                "level": level
            })
            # Add a small delay to prevent overwhelming the client
            await asyncio.sleep(0.01)
        except Exception as e:
            print(f"WebSocket send error: {e}")

    try:
        # Sanitize domain
        domain = domain.replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]
        
        analyzer = UltimateSecurityAnalyzer(domain, log_callback=log_callback)
        await analyzer.run_full_scan()
        
        await websocket.send_json({
            "type": "complete", 
            "results": analyzer.results
        })
        
    except WebSocketDisconnect:
        print(f"Client disconnected for {domain}")
    except Exception as e:
        await websocket.send_json({"type": "error", "message": str(e)})
        print(f"Error during scan: {e}")
    finally:
        try:
            await websocket.close()
        except:
            pass

@app.get("/")
async def root():
    return {"message": "Ultimate Security Analyzer API is running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
