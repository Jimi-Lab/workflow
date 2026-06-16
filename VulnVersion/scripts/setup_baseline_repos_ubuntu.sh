#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

REPO_ROOT="${PROJECT_ROOT}/dataset/repo"
DATASET=""
REPORT=""
MANIFEST_DIR=""
SPEC_FILE=""
REPO_SELECTION="all"
VERIFY_ONLY=0

usage() {
  cat <<'EOF'
Clone and verify the nine repositories used by BaseDataOrder.json.

Usage:
  setup_baseline_repos_ubuntu.sh [options]

Options:
  --dataset PATH       BaseDataOrder.json path.
  --repo-root PATH     Repository root (default: <project>/dataset/repo).
  --repos LIST         Comma-separated names or "all" (default: all).
  --report PATH        JSON audit report path.
  --manifest-dir PATH  Per-repository manifest directory.
  --spec-file PATH     Override repository specification TSV (for testing).
  --verify-only        Do not clone or fetch; only verify existing repositories.
  --list               Print repository names and upstream URLs, then exit.
  -h, --help           Show this help.

Specification TSV columns:
  name<TAB>canonical_url<TAB>fallback_urls_separated_by_semicolon<TAB>required_paths_separated_by_comma
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 2
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

find_python() {
  local candidate
  for candidate in "${PYTHON:-}" python3 python; do
    [[ -n "${candidate}" ]] || continue
    if command -v "${candidate}" >/dev/null 2>&1 && "${candidate}" -c 'import sys' >/dev/null 2>&1; then
      PYTHON_BIN="${candidate}"
      return
    fi
  done
  die "required Python 3 interpreter not found (tried PYTHON, python3, python)"
}

resolve_path() {
  realpath -m -- "$1"
}

DEFAULT_SPEC_CONTENT=$(cat <<'EOF'
# name	canonical_url	fallback_urls	required_paths
curl	https://github.com/curl/curl.git		lib,src/tool_main.c
FFmpeg	https://git.ffmpeg.org/ffmpeg.git	https://github.com/FFmpeg/FFmpeg.git	libavcodec,configure
httpd	https://github.com/apache/httpd.git	https://gitbox.apache.org/repos/asf/httpd.git	server,modules,configure.in
ImageMagick	https://github.com/ImageMagick/ImageMagick.git		MagickCore,MagickWand,configure.ac
linux	https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git	https://github.com/torvalds/linux.git	kernel,init/main.c,drivers
openjpeg	https://github.com/uclouvain/openjpeg.git		src/lib/openjp2,CMakeLists.txt
openssl	https://github.com/openssl/openssl.git		crypto,ssl,Configure
qemu	https://gitlab.com/qemu-project/qemu.git	https://github.com/qemu/qemu.git	hw,meson.build
wireshark	https://gitlab.com/wireshark/wireshark.git	https://github.com/wireshark/wireshark.git	epan,wiretap,CMakeLists.txt
EOF
)

LIST_ONLY=0
while (($#)); do
  case "$1" in
    --dataset)
      (($# >= 2)) || die "--dataset requires a path"
      DATASET="$2"
      shift 2
      ;;
    --repo-root)
      (($# >= 2)) || die "--repo-root requires a path"
      REPO_ROOT="$2"
      shift 2
      ;;
    --repos)
      (($# >= 2)) || die "--repos requires a value"
      REPO_SELECTION="$2"
      shift 2
      ;;
    --report)
      (($# >= 2)) || die "--report requires a path"
      REPORT="$2"
      shift 2
      ;;
    --manifest-dir)
      (($# >= 2)) || die "--manifest-dir requires a path"
      MANIFEST_DIR="$2"
      shift 2
      ;;
    --spec-file)
      (($# >= 2)) || die "--spec-file requires a path"
      SPEC_FILE="$2"
      shift 2
      ;;
    --verify-only)
      VERIFY_ONLY=1
      shift
      ;;
    --list)
      LIST_ONLY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

require_command git
require_command realpath
find_python

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "${TEMP_DIR}"' EXIT

if [[ -z "${SPEC_FILE}" ]]; then
  SPEC_FILE="${TEMP_DIR}/repos.tsv"
  printf '%s\n' "${DEFAULT_SPEC_CONTENT}" >"${SPEC_FILE}"
fi

[[ -f "${SPEC_FILE}" ]] || die "specification file not found: ${SPEC_FILE}"
SPEC_FILE="$(resolve_path "${SPEC_FILE}")"

if ((LIST_ONLY)); then
  awk -F '\t' '!/^#/ && NF >= 2 { print $1 "\t" $2 }' "${SPEC_FILE}"
  exit 0
fi

if [[ -z "${DATASET}" ]]; then
  if [[ -f "${PROJECT_ROOT}/dataset/BaseDataOrder.json" ]]; then
    DATASET="${PROJECT_ROOT}/dataset/BaseDataOrder.json"
  elif [[ -f "${PROJECT_ROOT}/DataSet/BaseDataOrder.json" ]]; then
    DATASET="${PROJECT_ROOT}/DataSet/BaseDataOrder.json"
  else
    die "BaseDataOrder.json not found; pass --dataset PATH"
  fi
fi

DATASET="$(resolve_path "${DATASET}")"
REPO_ROOT="$(resolve_path "${REPO_ROOT}")"
REPORT="${REPORT:-${REPO_ROOT}/repo_audit.json}"
MANIFEST_DIR="${MANIFEST_DIR:-${REPO_ROOT}/manifests}"
REPORT="$(resolve_path "${REPORT}")"
MANIFEST_DIR="$(resolve_path "${MANIFEST_DIR}")"

[[ -f "${DATASET}" ]] || die "dataset not found: ${DATASET}"
mkdir -p -- "${REPO_ROOT}" "$(dirname -- "${REPORT}")" "${MANIFEST_DIR}"

declare -a SPEC_NAMES=()
declare -A CANONICAL=()
declare -A FALLBACKS=()
declare -A REQUIRED_PATHS=()

while IFS=$'\t' read -r name canonical fallbacks required_paths _; do
  [[ -n "${name}" && "${name}" != \#* ]] || continue
  [[ -n "${canonical}" ]] || die "missing canonical URL for ${name}"
  SPEC_NAMES+=("${name}")
  CANONICAL["${name}"]="${canonical}"
  FALLBACKS["${name}"]="${fallbacks:-}"
  REQUIRED_PATHS["${name}"]="${required_paths:-}"
done <"${SPEC_FILE}"

((${#SPEC_NAMES[@]} > 0)) || die "no repositories found in ${SPEC_FILE}"

declare -a SELECTED=()
if [[ "${REPO_SELECTION}" == "all" ]]; then
  SELECTED=("${SPEC_NAMES[@]}")
else
  IFS=',' read -r -a requested <<<"${REPO_SELECTION}"
  for raw in "${requested[@]}"; do
    name="${raw//[[:space:]]/}"
    [[ -n "${name}" ]] || continue
    if [[ -z "${CANONICAL[${name}]+x}" ]]; then
      die "unsupported repository: ${name}"
    fi
    SELECTED+=("${name}")
  done
fi

((${#SELECTED[@]} > 0)) || die "no repositories selected"

STATUS_FILE="${TEMP_DIR}/operations.tsv"
printf 'repo\toperation_ok\tmessage\n' >"${STATUS_FILE}"

remove_failed_clone() {
  local target="$1"
  case "${target}" in
    "${REPO_ROOT}"/*) rm -rf -- "${target}" ;;
    *) die "refusing to remove path outside repository root: ${target}" ;;
  esac
}

clone_one() {
  local name="$1"
  local target="${REPO_ROOT}/${name}"
  local canonical="${CANONICAL[${name}]}"
  local fallback_text="${FALLBACKS[${name}]}"
  local -a urls=("${canonical}")

  if [[ -n "${fallback_text}" ]]; then
    local -a fallback_array=()
    IFS=';' read -r -a fallback_array <<<"${fallback_text}"
    urls+=("${fallback_array[@]}")
  fi

  if ((VERIFY_ONLY)) && [[ ! -e "${target}" ]]; then
    printf '%s\t0\trepository is missing in verify-only mode\n' "${name}" >>"${STATUS_FILE}"
    printf '[FAIL] %s: repository is missing: %s\n' "${name}" "${target}" >&2
    return
  fi

  if [[ -e "${target}" ]]; then
    if [[ ! -d "${target}/.git" ]]; then
      printf '%s\t0\texisting target is not a Git working tree\n' "${name}" >>"${STATUS_FILE}"
      printf '[FAIL] %s: %s exists without .git\n' "${name}" "${target}" >&2
      return
    fi
    printf '[EXISTING] %s: %s\n' "${name}" "${target}"
  else
    local cloned=0
    local url
    for url in "${urls[@]}"; do
      [[ -n "${url}" ]] || continue
      printf '[CLONE] %s <- %s\n' "${name}" "${url}"
      if git clone --origin origin -- "${url}" "${target}"; then
        cloned=1
        break
      fi
      printf '[WARN] %s: clone failed from %s\n' "${name}" "${url}" >&2
      [[ ! -e "${target}" ]] || remove_failed_clone "${target}"
    done
    if ((cloned == 0)); then
      printf '%s\t0\tclone failed for canonical and fallback URLs\n' "${name}" >>"${STATUS_FILE}"
      return
    fi
  fi

  if ((VERIFY_ONLY)); then
    printf '%s\t1\tverify-only\n' "${name}" >>"${STATUS_FILE}"
    return
  fi

  if [[ "$(git -C "${target}" rev-parse --is-shallow-repository 2>/dev/null || true)" == "true" ]]; then
    printf '[FETCH] %s: converting shallow clone to complete history\n' "${name}"
    if ! git -C "${target}" fetch --unshallow origin; then
      printf '%s\t0\tfailed to unshallow repository\n' "${name}" >>"${STATUS_FILE}"
      return
    fi
  fi

  printf '[FETCH] %s: all branches and tags\n' "${name}"
  if ! git -C "${target}" fetch origin \
      '+refs/heads/*:refs/remotes/origin/*' \
      '+refs/tags/*:refs/tags/*' \
      --force --prune; then
    printf '%s\t0\tfailed to fetch branches and tags\n' "${name}" >>"${STATUS_FILE}"
    return
  fi

  printf '%s\t1\tclone/fetch completed\n' "${name}" >>"${STATUS_FILE}"
}

printf 'Dataset: %s\n' "${DATASET}"
printf 'Repository root: %s\n' "${REPO_ROOT}"
printf 'Selected repositories: %s\n' "${SELECTED[*]}"

for name in "${SELECTED[@]}"; do
  clone_one "${name}"
done

SELECTED_CSV="$(IFS=','; printf '%s' "${SELECTED[*]}")"

"${PYTHON_BIN}" - \
  "${DATASET}" \
  "${REPO_ROOT}" \
  "${SPEC_FILE}" \
  "${STATUS_FILE}" \
  "${SELECTED_CSV}" \
  "${REPORT}" \
  "${MANIFEST_DIR}" <<'PY'
import datetime as dt
import json
import shutil
import subprocess
import sys
from pathlib import Path


dataset_path = Path(sys.argv[1])
repo_root = Path(sys.argv[2])
spec_path = Path(sys.argv[3])
status_path = Path(sys.argv[4])
selected = [item for item in sys.argv[5].split(",") if item]
report_path = Path(sys.argv[6])
manifest_dir = Path(sys.argv[7])


def flatten_strings(value):
    if isinstance(value, str):
        value = value.strip()
        if value:
            yield value
    elif isinstance(value, list):
        for item in value:
            yield from flatten_strings(item)


def normalize_url(value):
    value = value.strip().rstrip("/")
    if "://" not in value and not value.startswith("git@"):
        cygpath = shutil.which("cygpath")
        if cygpath:
            converted = subprocess.run(
                [cygpath, "-am", value],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
            )
            if converted.returncode == 0:
                value = converted.stdout.strip()
        else:
            value = str(Path(value).expanduser().resolve())
        value = value.replace("\\", "/")
    if value.lower().endswith(".git"):
        value = value[:-4]
    return value.lower()


def run_git(repo, *args, input_text=None):
    return subprocess.run(
        ["git", "-c", f"safe.directory={repo.as_posix()}", "-C", str(repo), *args],
        input=input_text,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )


def git_output(repo, *args):
    result = run_git(repo, *args)
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


specs = {}
for raw in spec_path.read_text(encoding="utf-8").splitlines():
    if not raw or raw.startswith("#"):
        continue
    columns = raw.split("\t")
    columns += [""] * (4 - len(columns))
    name, canonical, fallbacks, required_paths = columns[:4]
    specs[name] = {
        "canonical": canonical,
        "fallbacks": [item for item in fallbacks.split(";") if item],
        "required_paths": [item for item in required_paths.split(",") if item],
    }

operation_status = {}
status_lines = status_path.read_text(encoding="utf-8").splitlines()[1:]
for raw in status_lines:
    name, ok, message = raw.split("\t", 2)
    operation_status[name] = {"ok": ok == "1", "message": message}

dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
if not isinstance(dataset, dict):
    raise SystemExit("BaseDataOrder.json must be a JSON object keyed by CVE")

repositories = []
manifest_dir.mkdir(parents=True, exist_ok=True)
generated_at = dt.datetime.now(dt.timezone.utc).isoformat()

for name in selected:
    repo = repo_root / name
    spec = specs[name]
    records = [(cve, value) for cve, value in dataset.items() if value.get("repo") == name]
    fics = sorted(
        {
            fic
            for _, value in records
            for fic in flatten_strings(value.get("fixing_commits", []))
        }
    )
    affected_versions = sorted(
        {
            version
            for _, value in records
            for version in flatten_strings(value.get("affected_version", []))
        }
    )

    item = {
        "repo": name,
        "path": str(repo),
        "operation": operation_status.get(name, {"ok": False, "message": "not processed"}),
        "cve_count": len(records),
        "unique_fic_count": len(fics),
        "dataset_unique_version_count": len(affected_versions),
        "errors": [],
        "warnings": [],
        "missing_fics": [],
        "missing_parents": [],
        "missing_dataset_tags": [],
    }

    if not item["operation"]["ok"]:
        item["errors"].append(item["operation"]["message"])

    inside = run_git(repo, "rev-parse", "--is-inside-work-tree")
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        item["errors"].append("not a valid Git working tree")
        repositories.append(item)
        continue

    origin = git_output(repo, "remote", "get-url", "origin")
    allowed_origins = {normalize_url(spec["canonical"])}
    allowed_origins.update(normalize_url(value) for value in spec["fallbacks"])
    item["origin"] = origin
    if normalize_url(origin) not in allowed_origins:
        item["errors"].append(f"unexpected origin URL: {origin}")

    item["head"] = git_output(repo, "rev-parse", "HEAD")
    item["branch"] = git_output(repo, "branch", "--show-current")
    item["shallow"] = git_output(repo, "rev-parse", "--is-shallow-repository") == "true"
    if item["shallow"]:
        item["errors"].append("repository is shallow")

    promisor = git_output(repo, "config", "--get", "remote.origin.promisor").lower()
    partial_extension = git_output(repo, "config", "--get", "extensions.partialClone")
    item["partial_clone"] = promisor == "true" or bool(partial_extension)
    if item["partial_clone"]:
        item["errors"].append("repository is a partial clone")

    status = run_git(repo, "status", "--porcelain")
    dirty_entries = status.stdout.splitlines()
    item["dirty_entry_count"] = len(dirty_entries)
    item["dirty_entry_examples"] = dirty_entries[:20]
    if dirty_entries:
        item["errors"].append(f"working tree is dirty ({len(dirty_entries)} entries)")

    fsck = run_git(repo, "fsck", "--connectivity-only", "--no-dangling")
    item["fsck_ok"] = fsck.returncode == 0
    if fsck.returncode != 0:
        detail = (fsck.stderr or fsck.stdout).strip()
        item["errors"].append(f"git fsck failed: {detail[:500]}")

    missing_paths = []
    for relative_path in spec["required_paths"]:
        if run_git(repo, "cat-file", "-e", f"HEAD:{relative_path}").returncode != 0:
            missing_paths.append(relative_path)
    item["missing_required_paths"] = missing_paths
    if missing_paths:
        item["errors"].append("missing expected HEAD paths: " + ", ".join(missing_paths))

    tags = set(run_git(repo, "tag", "-l").stdout.splitlines())
    item["tag_count"] = len(tags)
    missing_tags = [version for version in affected_versions if version not in tags]
    item["missing_dataset_tags"] = missing_tags
    if missing_tags:
        item["warnings"].append(
            f"{len(missing_tags)} dataset versions are not Git tags; keep the paper's cleaned "
            "historical release-version universe separate from raw Git tags"
        )

    if fics:
        fic_check = run_git(
            repo,
            "cat-file",
            "--batch-check=%(objectname) %(objecttype)",
            input_text="\n".join(fics) + "\n",
        )
        for fic, line in zip(fics, fic_check.stdout.splitlines()):
            if line.endswith(" missing") or not line.endswith(" commit"):
                item["missing_fics"].append(fic)

        parent_specs = [f"{fic}^1" for fic in fics]
        parent_check = run_git(
            repo,
            "cat-file",
            "--batch-check=%(objectname) %(objecttype)",
            input_text="\n".join(parent_specs) + "\n",
        )
        for fic, line in zip(fics, parent_check.stdout.splitlines()):
            if line.endswith(" missing") or not line.endswith(" commit"):
                item["missing_parents"].append(fic)

    if item["missing_fics"]:
        item["errors"].append(f"{len(item['missing_fics'])} dataset FICs are unavailable")
    if item["missing_parents"]:
        item["errors"].append(f"{len(item['missing_parents'])} FIC parents are unavailable")
    if not records:
        item["errors"].append("repository has no records in the dataset")

    item["ok"] = not item["errors"]
    manifest = manifest_dir / f"{name}.manifest.txt"
    manifest.write_text(
        "\n".join(
            [
                f"generated_at_utc={generated_at}",
                f"repo={name}",
                f"origin={item.get('origin', '')}",
                f"head={item.get('head', '')}",
                f"branch={item.get('branch', '')}",
                f"shallow={str(item.get('shallow', False)).lower()}",
                f"partial_clone={str(item.get('partial_clone', False)).lower()}",
                f"dirty_entry_count={item.get('dirty_entry_count', 0)}",
                f"tag_count={item.get('tag_count', 0)}",
                f"cve_count={item['cve_count']}",
                f"unique_fic_count={item['unique_fic_count']}",
                f"missing_fic_count={len(item['missing_fics'])}",
                f"missing_parent_count={len(item['missing_parents'])}",
                f"missing_dataset_tag_count={len(item['missing_dataset_tags'])}",
                f"status={'PASS' if item['ok'] else 'FAIL'}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    repositories.append(item)

for item in repositories:
    item.setdefault("ok", not item["errors"])

failed = [item for item in repositories if not item["ok"]]
report = {
    "schema_version": 1,
    "generated_at_utc": generated_at,
    "dataset": str(dataset_path),
    "repo_root": str(repo_root),
    "summary": {
        "selected_repos": len(selected),
        "passed_repos": len(repositories) - len(failed),
        "failed_repos": len(failed),
        "cve_count": sum(item["cve_count"] for item in repositories),
        "unique_fic_count_by_repo_sum": sum(item["unique_fic_count"] for item in repositories),
    },
    "repositories": repositories,
}
report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

print("\nVerification summary")
print(f"  report: {report_path}")
print(f"  manifests: {manifest_dir}")
print(f"  passed repositories: {report['summary']['passed_repos']}")
print(f"  failed repositories: {report['summary']['failed_repos']}")
for item in repositories:
    state = "PASS" if item["ok"] else "FAIL"
    print(
        f"  [{state}] {item['repo']}: CVEs={item['cve_count']}, "
        f"FICs={item['unique_fic_count']}, missing_FICs={len(item['missing_fics'])}, "
        f"missing_parents={len(item['missing_parents'])}, "
        f"missing_dataset_tags={len(item['missing_dataset_tags'])}"
    )
    for error in item["errors"]:
        print(f"         error: {error}")
    for warning in item["warnings"]:
        print(f"         warning: {warning}")

raise SystemExit(1 if failed else 0)
PY
