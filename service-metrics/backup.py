import json
import uuid
import time
import threading
import psutil
from datetime import datetime
from zoneinfo import ZoneInfo
from fastapi import FastAPI, Request

app = FastAPI(title="Metrics Service")

class JSONLogger:
    @staticmethod
    def log(service: str, event: str, data: dict):
        log_entry = {
            "timestamp": datetime.now(ZoneInfo("Africa/Tunis")).isoformat(),
            "service": service,
            "event": event,
            "data": data,
            "log_id": str(uuid.uuid4())
        }
        print(json.dumps(log_entry), flush=True)  # flush ajouté

def get_system_metrics():
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    return {
        "cpu_percent": cpu_percent,
        "memory_total_gb": round(memory.total / (1024**3), 2),
        "memory_used_gb": round(memory.used / (1024**3), 2),
        "memory_percent": memory.percent,
        "disk_total_gb": round(disk.total / (1024**3), 2),
        "disk_used_gb": round(disk.used / (1024**3), 2),
        "disk_percent": disk.percent
    }

def periodic_logger():
    while True:
        time.sleep(30)  # 30 secondes pour test
        metrics = get_system_metrics()
        JSONLogger.log("service-metrics", "periodic_metrics", metrics)

# Démarrer le thread du logger périodique
thread = threading.Thread(target=periodic_logger, daemon=True)
thread.start()

@app.get("/metrics")
async def get_metrics(request: Request):
    metrics = get_system_metrics()
    JSONLogger.log("service-metrics", "metrics_request", {
        "client_ip": request.client.host,
        "user_agent": request.headers.get("user-agent"),
        "metrics": metrics
    })
    return metrics

@app.get("/health")
async def health():
    JSONLogger.log("service-metrics", "health_check", {"status": "healthy"})
    return {"status": "healthy"}
