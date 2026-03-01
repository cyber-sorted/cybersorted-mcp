#!/bin/bash
# ZAP Worker Entrypoint
# Starts ZAP daemon, waits for readiness, runs the Python agent.

set -e

echo "[Entrypoint] Starting ZAP daemon..."

# Start ZAP in daemon mode with API key
/zap/zap.sh -daemon \
  -host 0.0.0.0 \
  -port 8080 \
  -config api.key="${ZAP_API_KEY:-cybersorted-scanner-key}" \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true \
  -config connection.timeoutInSecs=120 \
  -Xmx2g &

ZAP_PID=$!

echo "[Entrypoint] ZAP daemon started (PID: $ZAP_PID)"
echo "[Entrypoint] Waiting for ZAP to initialise..."

# Wait for ZAP to be ready (up to 60 seconds)
for i in $(seq 1 30); do
  if curl -sf "http://localhost:8080/JSON/core/view/version/?apikey=${ZAP_API_KEY:-cybersorted-scanner-key}" > /dev/null 2>&1; then
    echo "[Entrypoint] ZAP is ready!"
    break
  fi
  if [ $i -eq 30 ]; then
    echo "[Entrypoint] ERROR: ZAP failed to start within 60 seconds"
    kill $ZAP_PID 2>/dev/null || true
    exit 1
  fi
  echo "[Entrypoint] Waiting... ($i/30)"
  sleep 2
done

# Run the Python scan agent
echo "[Entrypoint] Starting scan agent..."
python /app/agent.py
AGENT_EXIT=$?

# Gracefully stop ZAP
echo "[Entrypoint] Stopping ZAP daemon..."
curl -sf "http://localhost:8080/JSON/core/action/shutdown/?apikey=${ZAP_API_KEY:-cybersorted-scanner-key}" > /dev/null 2>&1 || true
sleep 2
kill $ZAP_PID 2>/dev/null || true

echo "[Entrypoint] Done (exit code: $AGENT_EXIT)"
exit $AGENT_EXIT
