import json
import uuid
import random
import threading
import time
import psutil
from datetime import datetime
from zoneinfo import ZoneInfo
from fastapi import FastAPI, Request
from collections import deque

app = FastAPI(title="Metrics Service")

# -------------------- Logger --------------------
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
        print(json.dumps(log_entry))

# -------------------- Request counter --------------------
request_counter = 0
request_times = deque(maxlen=60)  # last 60 seconds

def record_request():
    global request_counter
    request_counter += 1
    request_times.append(time.time())

def get_requests_per_second():
    now = time.time()
    # Count requests in the last 1 second
    return sum(1 for t in request_times if now - t <= 1.0)

# -------------------- Network stats --------------------
def get_network_stats():
    net_io = psutil.net_io_counters()
    return {
        "bytes_sent": net_io.bytes_sent,
        "bytes_recv": net_io.bytes_recv,
        "packets_sent": net_io.packets_sent,
        "packets_recv": net_io.packets_recv,
        "errin": net_io.errin,
        "errout": net_io.errout,
        "dropin": net_io.dropin,
        "dropout": net_io.dropout,
    }

def get_active_connections():
    connections = psutil.net_connections(kind='inet')
    # Count TCP connections in established, listen, etc.
    total = len(connections)
    established = sum(1 for c in connections if c.status == 'ESTABLISHED')
    listening = sum(1 for c in connections if c.status == 'LISTEN')
    return {
        "total": total,
        "established": established,
        "listening": listening
    }

# -------------------- System metrics --------------------
def get_system_metrics():
    cpu_percent = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    return {
        "cpu_percent": cpu_percent,
        "memory_total_gb": round(mem.total / (1024**3), 2),
        "memory_used_gb": round(mem.used / (1024**3), 2),
        "memory_percent": mem.percent,
        "disk_total_gb": round(disk.total / (1024**3), 2),
        "disk_used_gb": round(disk.used / (1024**3), 2),
        "disk_percent": disk.percent
    }

# -------------------- Periodic logger (every 5 minutes) --------------------
def periodic_logger():
    while True:
        time.sleep(300)
        sys_metrics = get_system_metrics()
        net_stats = get_network_stats()
        active_conn = get_active_connections()
        metrics = {
            **sys_metrics,
            **net_stats,
            **active_conn,
            "requests_per_second": get_requests_per_second(),
            "timestamp": datetime.now(ZoneInfo("Africa/Tunis")).isoformat()
        }
        JSONLogger.log("service-metrics", "periodic_metrics", metrics)

threading.Thread(target=periodic_logger, daemon=True).start()

# -------------------- Endpoint /metrics --------------------
@app.get("/metrics")
async def metrics(request: Request):
    record_request()  # count this request for requests/sec
    sys_metrics = get_system_metrics()
    net_stats = get_network_stats()
    active_conn = get_active_connections()
    metrics_data = {
        **sys_metrics,
        **net_stats,
        **active_conn,
        "requests_per_second": get_requests_per_second(),
        "client_ip": request.client.host
    }
    JSONLogger.log("service-metrics", "metrics_request", metrics_data)
    return metrics_data

@app.get("/health")
async def health():
    JSONLogger.log("service-metrics", "health_check", {"status": "healthy"})
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
