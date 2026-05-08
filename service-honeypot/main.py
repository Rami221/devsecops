import json
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo
from fastapi import FastAPI, Request

app = FastAPI(title="Honeypot Service")

class JSONLogger:
    @staticmethod
    def log(event: str, data: dict):
        log_entry = {
            "timestamp": datetime.now(ZoneInfo("Africa/Tunis")).isoformat(),
            "service": "service-honeypot",
            "event": event,
            "data": data,
            "log_id": str(uuid.uuid4())
        }
        print(json.dumps(log_entry))

def log_attack(request: Request, endpoint: str, severity: str = "HIGH", details: dict = None):
    data = {
        "endpoint": endpoint,
        "method": request.method,
        "src_ip": request.client.host,
        "user_agent": request.headers.get("user-agent", "unknown"),
        "severity": severity,
    }
    if details:
        data.update(details)
    JSONLogger.log("attack_detected", data)

@app.get("/admin")
async def fake_admin(request: Request):
    log_attack(request, "/admin")
    return {"message": "Admin panel (fake)", "status": "success"}

@app.post("/admin/login")
async def fake_admin_login(request: Request):
    body = await request.form()
    credentials = dict(body)
    log_attack(request, "/admin/login", details={"credentials": credentials})
    return {"status": "success", "token": "fake_token"}

@app.get("/phpmyadmin/")
async def fake_phpmyadmin(request: Request):
    log_attack(request, "/phpmyadmin/")
    return "<html><body><h1>phpMyAdmin</h1><p>Fake panel</p></body></html>"

@app.get("/.git/config")
async def fake_git_config(request: Request):
    log_attack(request, "/.git/config", severity="CRITICAL")
    return "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false"

@app.post("/debug.php")
async def fake_debug(request: Request):
    try:
        body = await request.json()
    except:
        body = None
    log_attack(request, "/debug.php", details={"request_body": body})
    return {"output": "Command executed (simulated)", "status": "success"}

@app.get("/api/v1/users")
async def fake_users(request: Request):
    log_attack(request, "/api/v1/users", details={"query": dict(request.query_params)})
    return {"users": [{"id": 1, "name": "Fake User"}]}

@app.post("/login")
async def fake_login(request: Request):
    form = await request.form()
    log_attack(request, "/login", details={"credentials": dict(form)})
    return {"status": "success", "token": "fake_token"}

@app.get("/health")
async def health():
    JSONLogger.log("health_check", {"status": "healthy"})
    return {"status": "healthy"}
