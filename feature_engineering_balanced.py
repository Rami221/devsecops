import pandas as pd
import numpy as np
import random
from sklearn.utils import resample

# -------------------- Load real data --------------------
attacks = pd.read_csv('service_honeypot.csv')
normal = pd.read_csv('service_api.csv')

print(f"Attacks réelles: {len(attacks)}, Normal réel: {len(normal)}")

# -------------------- SYNTHETIC GENERATION (SAFE) --------------------
def generate_synthetic_logs(n=200, is_attack=True):
    rows = []

    attack_endpoints = [
        '/admin/login',
        '/debug.php',
        '/shell.php',
        '/upload.php',
        '/exec.php',
        '/api/run'
    ]

    normal_endpoints = [
        '/home',
        '/profile',
        '/products',
        '/search'
    ]

    methods = ['GET', 'POST']

    payloads = [
        "cmd=ls",
        "cmd=whoami",
        "' OR 1=1 --",
        "<script>alert(1)</script>",
        "test=data"
    ]

    for _ in range(n):
        if is_attack:
            endpoint = random.choice(attack_endpoints)
            payload = random.choice(payloads)
        else:
            endpoint = random.choice(normal_endpoints)
            payload = ""

        rows.append({
            "timestamp": pd.Timestamp.now() - pd.Timedelta(minutes=random.randint(1, 500)),
            "endpoint": endpoint,
            "method": random.choice(methods),
            "user_agent": "curl/8.0",
            "payload": payload
        })

    return pd.DataFrame(rows)

# -------------------- Create synthetic data --------------------
synth_attacks = generate_synthetic_logs(n=200, is_attack=True)
synth_normal = generate_synthetic_logs(n=200, is_attack=False)

# -------------------- KEEP REAL DATA UNTOUCHED --------------------
attacks['label'] = 1
normal['label'] = 0
synth_attacks['label'] = 1
synth_normal['label'] = 0

# -------------------- COMBINE --------------------
df = pd.concat([
    attacks,
    normal,
    synth_attacks,
    synth_normal
], ignore_index=True)

# -------------------- TIME FEATURES (CORRECTED) --------------------
# Convert timestamp to datetime, handling timezone offsets
df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True, errors='coerce')
# Fill any missing timestamps with current UTC time
df['timestamp'].fillna(pd.Timestamp.utcnow(), inplace=True)

df['hour'] = df['timestamp'].dt.hour.fillna(0).astype(int)
df['day_of_week'] = df['timestamp'].dt.dayofweek.fillna(0).astype(int)
df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)

df['user_agent_len'] = df['user_agent'].fillna('').apply(len)

# -------------------- FEATURES (MODEL COMPATIBLE) --------------------
df['endpoint'] = df['endpoint'].fillna('unknown')
df['method'] = df['method'].fillna('unknown')

df['is_admin_endpoint'] = df['endpoint'].str.contains('admin', na=False).astype(int)

df['ep_/admin/login'] = (df['endpoint'] == '/admin/login').astype(int)
df['ep_unknown'] = (df['endpoint'] == 'unknown').astype(int)

df['meth_POST'] = (df['method'] == 'POST').astype(int)
df['meth_unknown'] = (df['method'] == 'unknown').astype(int)

# -------------------- FINAL DATASET --------------------
feature_cols = [
    'hour', 'day_of_week', 'is_weekend', 'user_agent_len',
    'is_admin_endpoint',
    'ep_/admin/login',
    'ep_unknown',
    'meth_POST',
    'meth_unknown',
    'label'
]

df = df[feature_cols].fillna(0).astype(int)

# -------------------- BALANCING --------------------
df_attack = df[df.label == 1]
df_normal = df[df.label == 0]

min_len = min(len(df_attack), len(df_normal))

df_attack = resample(df_attack, n_samples=min_len, random_state=42)
df_normal = resample(df_normal, n_samples=min_len, random_state=42)

df_balanced = pd.concat([df_attack, df_normal])
df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)

print(df_balanced['label'].value_counts())

df_balanced.to_csv('dataset_balanced.csv', index=False)
print("✅ Dataset propre et équilibré sauvegardé")
