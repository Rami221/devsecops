#!/bin/bash
LOG_FILE="$HOME/devsecops-pfe/logs.txt"
while true; do
    # Wait for a running pod
    POD=$(kubectl get pods -l app=service-api --field-selector status.phase=Running -o name | head -1)
    if [ -z "$POD" ]; then
        sleep 5
        continue
    fi
    # Stream logs from that pod (without --since, just from the beginning of the pod)
    kubectl logs -f "$POD" >> "$LOG_FILE" 2>&1
    # When the pod restarts or the command exits, loop again
    sleep 2
done
