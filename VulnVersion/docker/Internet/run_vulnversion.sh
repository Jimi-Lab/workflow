#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="/root/VulnVersion"
CONDA_ENV_NAME="${CONDA_ENV_NAME:-VulnVersion}"
OPENCODE_HOST="${OPENCODE_HOST:-127.0.0.1}"
OPENCODE_PORT="${OPENCODE_PORT:-4096}"
VV_DATASET="${VV_DATASET:-DataSet/BaseDataOrder.json}"

cd "${PROJECT_ROOT}"

./start_opencode.sh &
OPENCODE_PID=$!

cleanup() {
  if kill -0 "${OPENCODE_PID}" >/dev/null 2>&1; then
    kill "${OPENCODE_PID}" >/dev/null 2>&1 || true
    wait "${OPENCODE_PID}" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

echo "Waiting for OpenCode at http://${OPENCODE_HOST}:${OPENCODE_PORT} ..."
for _ in $(seq 1 90); do
  if curl -fsS "http://${OPENCODE_HOST}:${OPENCODE_PORT}/global/health" >/dev/null 2>&1; then
    echo "OpenCode is healthy."
    break
  fi
  sleep 2
done

if ! curl -fsS "http://${OPENCODE_HOST}:${OPENCODE_PORT}/global/health" >/dev/null 2>&1; then
  echo "ERROR: OpenCode did not become healthy in time." >&2
  exit 1
fi

if [[ "$#" -eq 0 ]]; then
  set -- --dataset "${VV_DATASET}" --no-watch
fi

exec conda run -n "${CONDA_ENV_NAME}" python main.py "$@"
