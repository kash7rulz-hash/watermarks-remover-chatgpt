#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${WATERMARKS_SERVER_API_KEY:-}" ]]; then
  echo "Watermarks Remover is not started yet. Add the WATERMARKS_SERVER_API_KEY Codespaces secret, grant access to this repository, then restart the Codespace."
  exit 0
fi

LOG_FILE=/tmp/watermarks-remover.log
nohup python3 service/scripts/server.py --host 0.0.0.0 --port 10000 \
  >"$LOG_FILE" 2>&1 </dev/null &

service_pid=$!
for _ in $(seq 1 40); do
  if curl --fail --silent \
      -H "Authorization: Bearer ${WATERMARKS_SERVER_API_KEY}" \
      http://127.0.0.1:10000/health >/dev/null 2>&1; then
    echo "Watermarks Remover API is running on port 10000."
    exit 0
  fi
  if ! kill -0 "$service_pid" 2>/dev/null; then
    echo "Watermarks Remover failed to start. Recent log output:" >&2
    tail -n 80 "$LOG_FILE" >&2 || true
    exit 1
  fi
  sleep 1
done

echo "Watermarks Remover did not become healthy within 40 seconds. Recent log output:" >&2
tail -n 80 "$LOG_FILE" >&2 || true
exit 1
