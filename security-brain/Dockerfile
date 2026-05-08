FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y iptables
COPY brain.py .
COPY attack_model_balanced.pkl .
COPY metrics_anomaly_model.pkl .
CMD ["python", "brain.py"]
