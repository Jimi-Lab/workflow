#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="/root/VulnVersion"
REPO_ROOT="${PROJECT_ROOT}/repo"
BUNDLE_ROOT="${VV_BUNDLE_DIR:-${PROJECT_ROOT}/repo-bundles}"

SUPPORTED_REPOS=(
  "FFmpeg"
  "ImageMagick"
  "curl"
  "httpd"
  "linux"
  "openjpeg"
  "openssl"
  "qemu"
  "wireshark"
)

log() {
  printf '[vv-entrypoint] %s\n' "$*" >&2
}

contains_repo() {
  local needle="$1"
  shift
  local item
  for item in "$@"; do
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

resolve_requested_repos() {
  local raw="${VV_REPOS:-all}"
  if [[ "$raw" == "all" ]]; then
    printf '%s\n' "${SUPPORTED_REPOS[@]}"
    return 0
  fi

  local normalized="${raw//;/,}"
  IFS=',' read -r -a parts <<< "$normalized"
  local out=()
  local repo
  for repo in "${parts[@]}"; do
    repo="$(echo "$repo" | xargs)"
    [[ -z "$repo" ]] && continue
    if ! contains_repo "$repo" "${SUPPORTED_REPOS[@]}"; then
      log "unsupported repo requested: $repo"
      exit 1
    fi
    out+=("$repo")
  done

  if [[ "${#out[@]}" -eq 0 ]]; then
    log "VV_REPOS resolved to empty set"
    exit 1
  fi

  printf '%s\n' "${out[@]}"
}

restore_repo_from_bundle() {
  local repo_name="$1"
  local target_dir="${REPO_ROOT}/${repo_name}"
  local bundle_path="${BUNDLE_ROOT}/${repo_name}.bundle"

  if [[ -d "${target_dir}/.git" ]]; then
    log "repo already present: ${repo_name}"
    return 0
  fi

  if [[ ! -f "$bundle_path" ]]; then
    log "missing bundle: ${bundle_path}"
    exit 1
  fi

  rm -rf "$target_dir"
  log "restoring ${repo_name} from ${bundle_path}"
  git clone "$bundle_path" "$target_dir" >/dev/null 2>&1

  if [[ ! -d "${target_dir}/.git" ]]; then
    log "bundle restore failed: ${repo_name} has no .git directory"
    exit 1
  fi

  git -C "$target_dir" rev-parse HEAD >/dev/null

  local tag_count
  tag_count="$(git -C "$target_dir" tag -l | wc -l | tr -d ' ')"
  if [[ "${tag_count}" == "0" ]]; then
    log "bundle restore failed: ${repo_name} has zero tags"
    exit 1
  fi

  # Sanity-check that remote-tracking branches are present when available.
  # VulnVersion only uses these as hints, but bundle clone should preserve them.
  git -C "$target_dir" branch -r >/dev/null || true
}

main() {
  mkdir -p "$REPO_ROOT"
  cd "$PROJECT_ROOT"

  local repos=()
  while IFS= read -r repo; do
    repos+=("$repo")
  done < <(resolve_requested_repos)

  local repo
  for repo in "${repos[@]}"; do
    restore_repo_from_bundle "$repo"
  done

  exec "$@"
}

main "$@"
