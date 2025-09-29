import json
import logging
import os
import subprocess
import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
import yaml
import uvicorn
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from agent.exporter.state_exporter import StateExporter

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Security Monitoring API",
    description="API for accessing security monitoring data and history.",
    version="1.0.0",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Mount static files for the frontend
app.mount("/static", StaticFiles(directory="web"), name="static")

# Load config and initialize exporter
CONFIG_FILE = os.environ.get("SECURITY_MONITOR_CONFIG", "config/policies.yaml")
try:
    with open(CONFIG_FILE, 'r') as f:
        config = yaml.safe_load(f)
    export_config = config.get("export", {})
    state_exporter = StateExporter(export_config)
    logger.info("API module loaded successfully")
except Exception as e:
    logger.error(f"Failed to load configuration or initialize exporter: {e}")
    state_exporter = StateExporter({})  # Fallback to default

@app.get("/healthz", response_model=Dict[str, str])
async def health_check():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.get("/api/latest", response_model=Dict[str, Any])
async def get_latest_state(host: Optional[str] = Query(None, description="Hostname to retrieve latest state for")):
    if not host:
        raise HTTPException(status_code=400, detail="Host parameter is required")
    
    latest_data = state_exporter.get_latest_state(host)
    if not latest_data:
        raise HTTPException(status_code=404, detail=f"No latest state found for host {host}")
    return latest_data

@app.get("/api/history", response_model=List[Dict[str, Any]])
async def get_history(
    host: Optional[str] = Query(None, description="Hostname to retrieve history for"),
    from_ts: Optional[datetime] = Query(None, alias="from", description="Start timestamp (ISO 8601)"),
    to_ts: Optional[datetime] = Query(None, alias="to", description="End timestamp (ISO 8601)")
):
    if not host:
        raise HTTPException(status_code=400, detail="Host parameter is required")
    
    history_data = state_exporter.get_history(host, from_ts, to_ts)
    if not history_data:
        raise HTTPException(status_code=404, detail=f"No history found for host {host} in the specified range")
    return history_data

@app.get("/api/stats", response_model=Dict[str, Any])
async def get_stats():
    return state_exporter.get_export_stats()

async def run_scan_task():
    """Background task to run the monitoring scan"""
    try:
        # Change to project directory and run the scan
        project_root = Path(__file__).parent.parent
        cmd = ["python", "-m", "agent", "--collect", "--output", "./test-output"]
        
        logger.info(f"Starting scan: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=60  # 60 seconds timeout
        )
        
        if result.returncode == 0:
            logger.info("Scan completed successfully")
            return {"status": "success", "message": "Scan completed successfully"}
        else:
            logger.error(f"Scan failed: {result.stderr}")
            return {"status": "error", "message": f"Scan failed: {result.stderr}"}
            
    except subprocess.TimeoutExpired:
        logger.error("Scan timed out")
        return {"status": "error", "message": "Scan timed out"}
    except Exception as e:
        logger.error(f"Scan error: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/api/trigger-scan")
async def trigger_scan(background_tasks: BackgroundTasks):
    """Trigger a new security monitoring scan"""
    try:
        # Add the scan task to background tasks
        background_tasks.add_task(run_scan_task)
        
        return {
            "status": "started",
            "message": "Security scan started",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to trigger scan: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to trigger scan: {e}")

@app.get("/api/scan-status")
async def get_scan_status():
    """Get the status of the last scan"""
    # For now, we'll return a simple status
    # In a real implementation, you might want to track scan status in a database or file
    try:
        # Check if there are recent exports (within last 5 minutes)
        stats = state_exporter.get_export_stats()
        return {
            "status": "completed",
            "last_scan_time": datetime.now(timezone.utc).isoformat(),
            "total_exports": stats.get("total_exports", 0),
            "hosts": stats.get("hosts", [])
        }
    except Exception as e:
        logger.error(f"Failed to get scan status: {e}")
        return {
            "status": "error",
            "message": str(e)
        }

@app.get("/", response_class=HTMLResponse)
async def read_root():
    with open(Path("web/index.html"), "r") as f:
        return f.read()

@app.get("/app.js", response_class=HTMLResponse)
async def get_app_js():
    with open(Path("web/app.js"), "r") as f:
        return f.read()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8787)
