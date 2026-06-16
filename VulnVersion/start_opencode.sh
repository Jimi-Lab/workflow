#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
OPENCODE_HOST="${OPENCODE_HOST:-127.0.0.1}"
OPENCODE_PORT="${OPENCODE_PORT:-4096}"
CONDA_ENV_NAME="${CONDA_ENV_NAME:-VulnVersion}"

# Always launch OpenCode from the project root so project-local .opencode/skills
# are discovered regardless of the caller's current working directory.
cd "${SCRIPT_DIR}"

if [[ -f "${ENV_FILE}" ]]; then
  echo "Loading environment variables from \"${ENV_FILE}\""
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
else
  echo ".env file not found at \"${ENV_FILE}\". Starting OpenCode without loading .env."
fi

if [[ -n "${CONDA_EXE:-}" ]]; then
  CONDA_BIN="${CONDA_EXE}"
elif command -v conda >/dev/null 2>&1; then
  CONDA_BIN="$(command -v conda)"
else
  echo "ERROR: conda executable not found in PATH."
  echo "Install Conda/Miniforge first, then create the environment from environment.yml."
  echo "You can also set CONDA_EXE explicitly."
  exit 1
fi

if [[ -n "${OPENCODE_BIN:-}" ]]; then
  BIN="${OPENCODE_BIN}"
else
  BIN="opencode"
fi

echo "Starting OpenCode Server on http://${OPENCODE_HOST}:${OPENCODE_PORT} ..."
echo "Working directory: ${SCRIPT_DIR}"
echo "Conda environment: ${CONDA_ENV_NAME}"
exec "${CONDA_BIN}" run --no-capture-output -n "${CONDA_ENV_NAME}" "${BIN}" serve --hostname "${OPENCODE_HOST}" --port "${OPENCODE_PORT}" --print-logs
