import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest

# Load metrics logs (already exported from Elasticsearch)
df = pd.read_csv('service_metrics.csv')

# Select numeric features
feature_cols = ['cpu_percent', 'memory_percent', 'disk_percent', 'memory_used_gb', 'disk_used_gb']
df = df[feature_cols].dropna()

# Train Isolation Forest (assume 95% of data is normal)
model = IsolationForest(contamination=0.05, random_state=42)
model.fit(df)

joblib.dump(model, 'metrics_anomaly_model.pkl')
print("✅ Metrics anomaly model saved.")
