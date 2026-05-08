import os
import time
import json
import joblib
import pandas as pd
import requests
import shap
import threading
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import deque

# -------------------- Configuration --------------------
ES_HOST = os.environ.get('ES_HOST', 'https://elasticsearch-master:9200')
ES_USER = os.environ.get('ES_USER', 'elastic')
ES_PASS = os.environ.get('ES_PASS', '')
SLACK_WEBHOOK = os.environ.get('SLACK_WEBHOOK', '')

MODEL_PATH = '/app/attack_model_balanced.pkl'
CONFIDENCE_THRESHOLD = 0.7

# Metrics thresholds
CPU_THRESHOLD = 80
CONNECTION_THRESHOLD = 200
NETWORK_THRESHOLD = 5_000_000  # bytes/sec

METRICS_URL = "http://service-metrics/metrics"

# -------------------- Elasticsearch --------------------
if ES_USER and ES_PASS:
    es = Elasticsearch(
        ES_HOST,
        basic_auth=(ES_USER, ES_PASS),
        verify_certs=False,
        ssl_show_warn=False
    )
else:
    es = Elasticsearch(ES_HOST, verify_certs=False, ssl_show_warn=False)

# -------------------- Load Model --------------------
try:
    attack_model = joblib.load(MODEL_PATH)
    print("✅ Attack model loaded", flush=True)
except Exception as e:
    print(f"❌ Failed to load attack model: {e}", flush=True)
    attack_model = None

# -------------------- SHAP --------------------
explainer = None
if attack_model is not None:
    try:
        explainer = shap.TreeExplainer(attack_model)
        print("✅ SHAP explainer loaded", flush=True)
    except Exception as e:
        print(f"⚠️ SHAP explainer not loaded: {e}", flush=True)

# -------------------- Feature Extraction (attack logs) --------------------
def extract_attack_features(log_source):
    try:
        msg = log_source.get('message', '{}')
        parsed = json.loads(msg) if isinstance(msg, str) else {}
        data = parsed.get('data', {})
    except:
        data = {}

    try:
        dt = pd.to_datetime(log_source.get('@timestamp'))
    except:
        dt = datetime.utcnow()

    endpoint = data.get('endpoint', 'unknown')
    method = data.get('method', 'unknown')

    return {
        'hour': dt.hour,
        'day_of_week': dt.dayofweek,
        'is_weekend': 1 if dt.dayofweek >= 5 else 0,
        'user_agent_len': len(data.get('user_agent', '')),
        'is_admin_endpoint': 1 if 'admin' in endpoint else 0,
        'ep_/admin/login': 1 if endpoint == '/admin/login' else 0,
        'ep_unknown': 1 if endpoint == 'unknown' else 0,
        'meth_POST': 1 if method == 'POST' else 0,
        'meth_unknown': 1 if method == 'unknown' else 0,
    }

def prepare_features(features_dict):
    df = pd.DataFrame([features_dict])
    if attack_model and hasattr(attack_model, 'feature_names_in_'):
        df = df.reindex(columns=attack_model.feature_names_in_, fill_value=0)
    else:
        df = df.reindex(sorted(df.columns), axis=1)
    return df

def predict_attack(df):
    if attack_model is None:
        return 0, 0.0
    try:
        proba = attack_model.predict_proba(df)[0][1]
        pred = int(proba >= CONFIDENCE_THRESHOLD)
        return pred, proba
    except Exception as e:
        print(f"Prediction error: {e}", flush=True)
        return 0, 0.0

def get_shap_explanation(df):
    if explainer is None:
        return None
    try:
        shap_values = explainer.shap_values(df, check_additivity=False)
        if isinstance(shap_values, list):
            shap_vals = shap_values[1][0]
        else:
            shap_vals = shap_values[0]
        explanation = dict(zip(df.columns, shap_vals.tolist()))
        total = sum(abs(v) for v in explanation.values())
        if total > 0:
            explanation = {k: float(v / total) for k, v in explanation.items()}
        return explanation
    except Exception as e:
        print(f"SHAP error: {e}", flush=True)
        return None

# -------------------- Fetch attack logs --------------------
def fetch_recent_logs(minutes=1):
    now = datetime.utcnow()
    start = now - timedelta(minutes=minutes)
    query = {
        "query": {
            "bool": {
                "should": [
                    {"term": {"kubernetes.labels.app": "service-honeypot"}},
                    {"term": {"kubernetes.labels.app": "service-api"}}
                ],
                "minimum_should_match": 1,
                "must": [{"range": {"@timestamp": {"gte": start.isoformat() + "Z", "lte": now.isoformat() + "Z"}}}]
            }
        }
    }
    try:
        resp = es.search(index="filebeat-*", body=query, size=100)
        return resp['hits']['hits']
    except Exception as e:
        print(f"Elasticsearch error: {e}", flush=True)
        return []

# -------------------- SOAR actions (existing) --------------------
def send_slack_alert(alert):
    if not SLACK_WEBHOOK:
        return
    try:
        requests.post(SLACK_WEBHOOK, json={"text": json.dumps(alert, indent=2)}, timeout=2)
    except Exception as e:
        print(f"Slack error: {e}", flush=True)

def block_ip(ip):
    if ip == 'unknown' or ip.startswith('127.'):
        return
    print(f"[ACTION] Blocking IP {ip} with iptables", flush=True)
    result = os.system(f"iptables -A INPUT -s {ip} -j DROP")
    if result == 0:
        print(f"[SUCCESS] Rule added for {ip}", flush=True)
    else:
        print(f"[ERROR] Failed to block {ip}", flush=True)

# -------------------- Metrics analysis (NEW) --------------------
processed_metrics_logs = deque(maxlen=1000)  # optional, to avoid duplicates

def analyze_metrics():
    try:
        resp = requests.get(METRICS_URL, timeout=10)  # increased timeout
        metrics = resp.json()  # direct JSON, no 'data' wrapper
    except Exception as e:
        print(f"Metrics fetch error: {e}", flush=True)
        return

    score = 0
    alerts = []

    cpu = metrics.get('cpu_percent', 0)
    if cpu > CPU_THRESHOLD:
        alerts.append(f"High CPU usage: {cpu}%")
        score += 35

    # The metrics service returns 'total' for active connections
    total_conn = metrics.get('total', 0)
    if total_conn > CONNECTION_THRESHOLD:
        alerts.append(f"Too many active connections: {total_conn}")
        score += 35

    # Use absolute bytes (you can later compute per‑second rates if needed)
    bytes_recv = metrics.get('bytes_recv', 0)
    if bytes_recv > NETWORK_THRESHOLD:
        alerts.append(f"High incoming traffic: {bytes_recv} bytes")
        score += 30

    bytes_sent = metrics.get('bytes_sent', 0)
    if bytes_sent > NETWORK_THRESHOLD:
        alerts.append(f"High outgoing traffic: {bytes_sent} bytes")
        score = min(score + 20, 100)

    if alerts:
        probability = min(score, 100)
        alert_msg = {
            "type": "metrics_anomaly",
            "probability": probability,
            "alerts": alerts,
            "metrics": metrics,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        print(json.dumps(alert_msg), flush=True)
        if probability >= 50:
            send_slack_alert(alert_msg)
    else:
        print(f"Metrics normal: CPU={cpu}% | Conn={total_conn} | NetIn={bytes_recv} B", flush=True)
def metrics_loop():
    while True:
        analyze_metrics()
        time.sleep(5)   # check every 5 seconds

# -------------------- Attack detection loop (existing) --------------------
processed_logs = deque(maxlen=10000)

def detection_loop():
    while True:
        print("Detection loop running", flush=True)
        hits = fetch_recent_logs(minutes=1)
        for hit in hits:
            source = hit.get('_source', {})
            log_id = source.get('log_id') or source.get('@timestamp') or json.dumps(source)
            if log_id in processed_logs:
                continue
            processed_logs.append(log_id)

            features = extract_attack_features(source)
            df = prepare_features(features)
            pred, proba = predict_attack(df)

            if pred == 1 and proba >= CONFIDENCE_THRESHOLD:
                try:
                    parsed = json.loads(source.get('message', '{}'))
                    src_ip = parsed.get('data', {}).get('src_ip', 'unknown')
                except:
                    src_ip = 'unknown'

                alert = {
                    "type": "attack",
                    "ip": src_ip,
                    "confidence": float(proba),
                    "reason": f"ML prediction: attack ({proba:.2f})",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
                explanation = get_shap_explanation(df)
                if explanation:
                    alert["shap_explanation"] = explanation

                block_ip(src_ip)
                send_slack_alert(alert)
                print(json.dumps(alert), flush=True)

        time.sleep(15)

# -------------------- Health server --------------------
class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'OK')
        else:
            self.send_response(404)
            self.end_headers()

def start_http_server():
    server = HTTPServer(('0.0.0.0', 8080), HealthHandler)
    server.serve_forever()

# -------------------- Main --------------------
if __name__ == "__main__":
    threading.Thread(target=start_http_server, daemon=True).start()
    threading.Thread(target=detection_loop, daemon=True).start()
    threading.Thread(target=metrics_loop, daemon=True).start()
    # Keep main thread alive
    while True:
        time.sleep(1)
