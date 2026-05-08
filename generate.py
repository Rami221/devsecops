import random
import pandas as pd
from datetime import datetime, timedelta

random.seed(42)

# ---------------- Paramètres ----------------
normal_endpoints = [
    "/home", "/products", "/api/status", "/login",
    "/about", "/contact", "/dashboard", "/profile",
    "/search?q=item", "/cart", "/checkout"
]

attack_endpoints = [
    "/admin/login", "/wp-admin", "/.git/config", "/etc/passwd",
    "/debug.php", "/login", "/api/login", "/upload.php",
    "/shell.php", "/config.json"
]

attack_payloads = [
    "cmd=ls", "cmd=cat /etc/passwd", "' OR 1=1 --",
    "'; DROP TABLE users; --", "username=admin&password=123456",
    "password=admin", "token=../../../../etc/passwd",
    "file=../../../.git/config", "exec=whoami",
    "input=<script>alert(1)</script>"
]

methods = ["GET", "POST"]
user_agents = ["curl/8.0", "Mozilla/5.0", "python-requests/2.31", "PostmanRuntime/7.29"]
severities = ["HIGH", "MEDIUM", "LOW"]

# ---------------- Génération d'un log ----------------
def generate_log(is_attack: bool, base_time: datetime):
    if is_attack:
        endpoint = random.choice(attack_endpoints)
        payload = random.choice(attack_payloads)
        event = "attack_detected"
        severity = random.choice(severities)
    else:
        endpoint = random.choice(normal_endpoints)
        payload = ""
        event = "normal_request"
        severity = "LOW"

    method = random.choices(methods, weights=[0.6, 0.4])[0]
    user_agent = random.choice(user_agents)
    src_ip = f"10.244.{random.randint(1,255)}.{random.randint(1,255)}"
    timestamp = (base_time + timedelta(seconds=random.randint(0, 86400))).isoformat() + "+01:00"

    # Structure identique à vos logs honeypot
    log_entry = {
        "timestamp": timestamp,
        "service": "service-honeypot",
        "event": event,
        "data": {
            "endpoint": endpoint,
            "method": method,
            "src_ip": src_ip,
            "user_agent": user_agent,
            "severity": severity,
            "payload": payload if is_attack else None
        },
        "log_id": f"synth-{random.randint(10000,99999)}"
    }
    return log_entry

# ---------------- Générer le dataset ----------------
data = []
base_time = datetime(2026, 4, 21, 0, 0, 0)

for _ in range(500):
    data.append(generate_log(False, base_time))
for _ in range(500):
    data.append(generate_log(True, base_time))

random.shuffle(data)

# Convertir en DataFrame plat (pour correspondre à service_honeypot.csv)
rows = []
for log in data:
    row = {
        "timestamp": log["timestamp"],
        "event": log["event"],
        "endpoint": log["data"]["endpoint"],
        "method": log["data"]["method"],
        "src_ip": log["data"]["src_ip"],
        "user_agent": log["data"]["user_agent"],
        "severity": log["data"]["severity"],
        "attack_type": log["data"].get("payload", ""),  # on stocke le payload comme type d'attaque
        "credentials": None,
        "request_body": log["data"].get("payload"),
        "query_params": None
    }
    rows.append(row)

df = pd.DataFrame(rows)
df["label"] = [1 if e == "attack_detected" else 0 for e in df["event"]]

df.to_csv("synthetic_honeypot_logs.csv", index=False)
print(f"✅ Dataset synthétique généré : {len(df)} logs")
print(df["label"].value_counts())
