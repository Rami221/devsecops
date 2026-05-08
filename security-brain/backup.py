cat brain.py
import os
import time
import json
import joblib
import pandas as pd
import requests
import shap
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# -------------------- Configuration --------------------
ES_HOST = os.environ.get('ES_HOST', 'https://elasticsearch-master:9200')
ES_USER = os.environ.get('ES_USER', 'elastic')
ES_PASS = os.environ.get('ES_PASS', '')
SLACK_WEBHOOK = os.environ.get('SLACK_WEBHOOK', '')
MODEL_PATH = '/app/attack_model_balanced.pkl'
CONFIDENCE_THRESHOLD = 0.7

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

# -------------------- SHAP Explainer --------------------
if attack_model is not None:
    try:
        explainer = shap.TreeExplainer(attack_model)
        print("✅ SHAP explainer loaded", flush=True)
    except Exception as e:
        print(f"⚠️ SHAP explainer not loaded: {e}", flush=True)
        explainer = None
else:
    explainer = None

# -------------------- Prevent duplicate alerts --------------------
processed_logs = set()

# -------------------- Feature Extraction --------------------
def extract_attack_features(log_source):
    try:
        msg = log_source.get('message', '{}')
        parsed = json.loads(msg)
        data = parsed.get('data', {})
    except:
        data = {}

    timestamp = log_source.get('@timestamp', datetime.utcnow().isoformat())
    try:
        dt = pd.to_datetime(timestamp)
    except:
        dt = datetime.utcnow()

    endpoint = data.get('endpoint', 'normal')
    method = data.get('method', 'normal')

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

# -------------------- Prepare Features --------------------
def prepare_features(features_dict):
    df = pd.DataFrame([features_dict])

    if hasattr(attack_model, 'feature_names_in_'):
        df = df.reindex(columns=attack_model.feature_names_in_, fill_value=0)
    else:
        df = df[sorted(df.columns)]

    return df

# -------------------- Prediction --------------------
def predict_attack(df):
    if attack_model is None:
        return 0, 0.0

    proba = attack_model.predict_proba(df)[0][1]
    pred = attack_model.predict(df)[0]
    return pred, proba

# -------------------- SHAP Explanation --------------------
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

        # Normalize for readability
        total = sum(abs(v) for v in explanation.values())
        if total > 0:
            explanation = {k: v / total for k, v in explanation.items()}

        return explanation

    except Exception as e:
        print(f"SHAP error: {e}", flush=True)
        return None

# -------------------- Elasticsearch Query --------------------
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
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start.isoformat() + "Z",
                                "lte": now.isoformat() + "Z"
                            }
                        }
                    }
                ]
            }
        }
    }

    try:
        resp = es.search(index="filebeat-*", body=query, size=100)
        return resp['hits']['hits']
    except Exception as e:
        print(f"Elasticsearch error: {e}", flush=True)
        return []

# -------------------- Actions --------------------
def send_slack_alert(alert):
    if not SLACK_WEBHOOK:
        return

    try:
        requests.post(
            SLACK_WEBHOOK,
            json={"text": json.dumps(alert, indent=2)},
            timeout=2
        )
    except Exception as e:
        print(f"Slack error: {e}", flush=True)

def block_ip(ip):
    if ip == 'unknown' or ip.startswith('127.'):
        return

    os.makedirs('/var/log/attacks', exist_ok=True)
    with open('/var/log/attacks/blocked_ips.txt', 'a') as f:
        f.write(f"{ip}\n")

    print(f"IP {ip} queued for blocking", flush=True)

# -------------------- Detection Loop --------------------
def detection_loop():
    while True:
        print("Detection loop running", flush=True)
        hits = fetch_recent_logs(minutes=1)

        for hit in hits:
            source = hit['_source']
            log_id = source.get('log_id')

            if log_id in processed_logs:
                continue
            processed_logs.add(log_id)

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

                # SHAP explanation
                explanation = get_shap_explanation(df)
                if explanation:
                    alert["shap_explanation"] = explanation

                block_ip(src_ip)
                send_slack_alert(alert)

                print(json.dumps(alert), flush=True)

        time.sleep(20)

# -------------------- Health Server --------------------
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
    detection_loop()
