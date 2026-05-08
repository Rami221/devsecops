#!/bin/bash
LOG_FILE="$HOME/devsecops-pfe/metrics-logs.txt"
while true; do
    POD=$(kubectl get pods -l app=service-metrics --field-selector status.phase=Running -o name | head -1)
    if [ -z "$POD" ]; then
        sleep 5
        continue
    fi
    kubectl logs -f "$POD" >> "$LOG_FILE" 2>&1
    sleep 2
done
