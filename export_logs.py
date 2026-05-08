#!/usr/bin/env python3
import pandas as pd
import json
from elasticsearch import Elasticsearch
import warnings
warnings.filterwarnings("ignore")

# Connect to Elasticsearch (port-forward must be running)
es = Elasticsearch(
    "https://localhost:9200",
    http_auth=("elastic", "y0l8ji9hZbboTn2y"),
    verify_certs=False
)

def scroll_all(query, index="filebeat-*", size=1000):
    """Scroll through all logs matching the query."""
    resp = es.search(index=index, body=query, scroll='2m', size=size)
    scroll_id = resp['_scroll_id']
    hits = resp['hits']['hits']
    while hits:
        for hit in hits:
            yield hit['_source']
        resp = es.scroll(scroll_id=scroll_id, scroll='2m')
        scroll_id = resp['_scroll_id']
        hits = resp['hits']['hits']

# ---------- Service A (normal API logs) ----------
print("Fetching service-api logs...")
api_query = {
    "query": {
        "term": {"kubernetes.labels.app": "service-api"}
    }
}
api_records = []
for src in scroll_all(api_query):
    msg = src.get('message')
    if msg:
        try:
            parsed = json.loads(msg)
            data = parsed.get('data', {})
            api_records.append({
                "timestamp": parsed.get('timestamp'),
                "service": parsed.get('service'),
                "event": parsed.get('event'),
                "user_id": data.get('user_id'),
                "username": data.get('username'),
                "email": data.get('email'),
                "ip": data.get('ip'),
                "user_agent": data.get('user_agent'),
                "success": data.get('success'),
                "reason": data.get('reason')
            })
        except:
            pass
df_api = pd.DataFrame(api_records)
df_api.to_csv("service_api.csv", index=False)
print(f"Saved {len(df_api)} service-api logs to service_api.csv")

# ---------- Service B (metrics) ----------
print("Fetching service-metrics logs...")
metrics_query = {
    "query": {
        "term": {"kubernetes.labels.app": "service-metrics"}
    }
}
metrics_records = []
for src in scroll_all(metrics_query):
    msg = src.get('message')
    if msg:
        try:
            parsed = json.loads(msg)
            data = parsed.get('data', {})
            metrics_records.append({
                "timestamp": parsed.get('timestamp'),
                "event": parsed.get('event'),
                "cpu_percent": data.get('cpu_percent'),
                "memory_total_gb": data.get('memory_total_gb'),
                "memory_used_gb": data.get('memory_used_gb'),
                "memory_percent": data.get('memory_percent'),
                "disk_total_gb": data.get('disk_total_gb'),
                "disk_used_gb": data.get('disk_used_gb'),
                "disk_percent": data.get('disk_percent')
            })
        except:
            pass
df_metrics = pd.DataFrame(metrics_records)
df_metrics.to_csv("service_metrics.csv", index=False)
print(f"Saved {len(df_metrics)} service-metrics logs to service_metrics.csv")

# ---------- Service C (honeypot attacks) ----------
print("Fetching service-honeypot logs...")
honeypot_query = {
    "query": {
        "term": {"kubernetes.labels.app": "service-honeypot"}
    }
}
attack_records = []
for src in scroll_all(honeypot_query):
    msg = src.get('message')
    if msg:
        try:
            parsed = json.loads(msg)
            data = parsed.get('data', {})
            attack_records.append({
                "timestamp": parsed.get('timestamp'),
                "event": parsed.get('event'),
                "endpoint": data.get('endpoint'),
                "method": data.get('method'),
                "src_ip": data.get('src_ip'),
                "user_agent": data.get('user_agent'),
                "severity": data.get('severity'),
                "attack_type": data.get('attack_type'),
                "credentials": data.get('credentials'),
                "request_body": data.get('request_body'),
                "query_params": data.get('query_params')
            })
        except:
            pass
df_attacks = pd.DataFrame(attack_records)
df_attacks.to_csv("service_honeypot.csv", index=False)
print(f"Saved {len(df_attacks)} honeypot logs to service_honeypot.csv")
