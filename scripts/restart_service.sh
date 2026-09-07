#!/usr/bin/env bash
# Restart the SOC-3s /triage FastAPI service (uvicorn main:app on :8000).
# Picks up .env changes, which are loaded at import time.
set -u
cd /home/ai-vm/stage/triage || exit 1

PORT=8000
PIDS=$(pgrep -f "uvicorn main:app --host 0.0.0.0 --port ${PORT}" || true)
if [ -n "${PIDS}" ]; then
  echo "stopping: ${PIDS}"
  kill ${PIDS}
  for _ in $(seq 1 10); do
    sleep 1
    pgrep -f "uvicorn main:app --host 0.0.0.0 --port ${PORT}" >/dev/null || break
  done
  pgrep -f "uvicorn main:app --host 0.0.0.0 --port ${PORT}" >/dev/null && kill -9 ${PIDS}
fi

nohup python3 -m uvicorn main:app --host 0.0.0.0 --port ${PORT} >> logs/uvicorn.out 2>&1 &
echo "started pid $!"
