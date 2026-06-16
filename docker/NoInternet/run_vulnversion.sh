#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="/root/VulnVersion"
OPENCODE_URL="${VV_OPENCODE_URL:-http://127.0.0.1:4096/global/health}"
DATASET_PATH="${VV_DATASET:-DataSet/BaseDataTest.json}"

log() {
  printf '[vv-run] %s\n' "$*" >&2
}

cd "$PROJECT_ROOT"

./start_opencode.sh >/tmp/opencode.log 2>&1 &
OPENCODE_PID=$!
trap 'kill ${OPENCODE_PID} >/dev/null 2>&1 || true' EXIT

for _ in $(seq 1 90); do
  if curl -fsS "$OPENCODE_URL" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! curl -fsS "$OPENCODE_URL" >/dev/null 2>&1; then
  log "OpenCode did not become healthy in time"
  log "---- /tmp/opencode.log ----"
  cat /tmp/opencode.log >&2 || true
  exit 1
fi

exec python main.py --dataset "$DATASET_PATH" --no-watch --no-allow-fetch-cve-desc "$@"
