"""
FastAPI Server for Project 2: Network Security Port Scanner
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
import os
from pydantic import BaseModel
from typing import Optional

from backend.scanner import NetworkPortScanner, TOP_20_PORTS, TOP_100_PORTS

app = FastAPI(
    title="Network Security Port Scanner API",
    description="Asynchronous multi-threaded port scanner with service identification and banner grabbing.",
    version="1.0.0"
)

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")

class ScanRequest(BaseModel):
    target: str
    preset: Optional[str] = "top20"
    custom_ports: Optional[str] = None
    timeout: Optional[float] = 1.0
    max_threads: Optional[int] = 50

@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Port Scanner Web Dashboard</h1>"

@app.post("/api/scan")
def run_port_scan(req: ScanRequest):
    if not req.target.strip():
        raise HTTPException(status_code=400, detail="Target IP or Hostname is required.")

    port_list = []
    if req.preset == "top20":
        port_list = TOP_20_PORTS
    elif req.preset == "top100":
        port_list = TOP_100_PORTS
    elif req.preset == "custom":
        if not req.custom_ports:
            raise HTTPException(status_code=400, detail="Custom port specification required.")
        try:
            port_list = NetworkPortScanner.parse_port_range(req.custom_ports)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid port range string: {e}")
    else:
        port_list = TOP_20_PORTS

    if len(port_list) > 1000:
        raise HTTPException(status_code=400, detail="Maximum 1000 ports permitted per web scan request.")

    scanner = NetworkPortScanner(req.target, timeout=req.timeout or 1.0, max_threads=req.max_threads or 50)
    data = scanner.scan_ports(port_list)

    if data.get("status") == "error":
        raise HTTPException(status_code=400, detail=data.get("message"))

    return data

@app.post("/api/export")
def export_scan_report(data: dict, format: str = "json"):
    if format == "csv":
        csv_content = NetworkPortScanner.export_csv(data)
        return Response(content=csv_content, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=port_scan_report.csv"})
    return Response(content=NetworkPortScanner.export_json(data), media_type="application/json", headers={"Content-Disposition": "attachment; filename=port_scan_report.json"})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
