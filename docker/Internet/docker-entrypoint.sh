#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="/root/VulnVersion"
CONDA_ENV_NAME="${CONDA_ENV_NAME:-VulnVersion}"

cd "${PROJECT_ROOT}"
mkdir -p repo Result

echo "VulnVersion Internet container ready."
echo "Working directory: ${PROJECT_ROOT}"
echo "Conda environment: ${CONDA_ENV_NAME}"

if [[ ! -f ".env" ]]; then
  echo "NOTICE: .env not found under ${PROJECT_ROOT}."
  echo "        You may provide runtime variables with --env-file or mount a project-root .env."
fi

if [[ -z "${VV_REPOS:-}" ]]; then
  echo "VV_REPOS is empty; no target repo will be downloaded."
elif [[ "${VV_REPOS}" == "none" ]]; then
  echo "VV_REPOS=none; skipping repo download."
else
  echo "Downloading target repos: ${VV_REPOS}"
  conda run -n "${CONDA_ENV_NAME}" python repo/clone_repos.py --repos "${VV_REPOS}"
fi

exec "$@"
