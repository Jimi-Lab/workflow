from __future__ import annotations

import hashlib
import json
import math
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

GENERATOR_VERSION = "rq2-validation-sampler-v1"
MULTI_BRANCH_REPOS = {"linux", "wireshark", "httpd", "curl", "openssl", "qemu", "FFmpeg"}
SINGLE_BRANCH_REPOS = {"ImageMagick", "openjpeg"}
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".inc", ".s"}
CONTROL_WORDS = {"if", "for", "while", "switch", "return", "sizeof"}


def build_validation_sample(
  *,
  dataset_path: str | Path,
  development_dataset_path: str | Path,
  repo_root: str | Path,
  sample_size: int = 100,
  seed: int = 20260619,
) -> tuple[dict[str, Any], dict[str, Any]]:
  dataset_path = Path(dataset_path)
  development_dataset_path = Path(development_dataset_path)
  repo_root = Path(repo_root)
  dataset_bytes = dataset_path.read_bytes()
  dataset = json.loads(dataset_bytes.decode("utf-8"))
  development = json.loads(development_dataset_path.read_text(encoding="utf-8"))
  excluded = set(development)
  pool = []
  for cve_id, record in dataset.items():
    if cve_id in excluded:
      continue
    pool.append(classify_case(cve_id, record, repo_root))
  if sample_size > len(pool):
    raise ValueError(f"sample_size {sample_size} exceeds pool size {len(pool)}")

  repo_counts = Counter(item["repo"] for item in pool)
  repo_quotas = allocate_repo_quotas(repo_counts, sample_size)
  selected = select_cases(pool, repo_quotas=repo_quotas, seed=seed)
  selected_ids = {item["cve_id"] for item in selected}
  derived_dataset = {cve_id: record for cve_id, record in dataset.items() if cve_id in selected_ids}
  derived_dataset_bytes = (json.dumps(derived_dataset, indent=2, ensure_ascii=True) + "\n").encode("utf-8")

  manifest = {
    "schema_version": "rq2-validation-sample-manifest-v1",
    "generator_version": GENERATOR_VERSION,
    "seed": seed,
    "sample_size": sample_size,
    "canonical_dataset": str(dataset_path.resolve()),
    "canonical_dataset_sha256": hashlib.sha256(dataset_bytes).hexdigest(),
    "selected_dataset_sha256": hashlib.sha256(derived_dataset_bytes).hexdigest(),
    "development_dataset": str(development_dataset_path.resolve()),
    "development_cve_count": len(excluded),
    "development_cve_ids": sorted(excluded),
    "candidate_pool_count": len(pool),
    "remaining_cves_frozen": False,
    "selection_features_exclude_affected_version": True,
    "repo_quotas": dict(sorted(repo_quotas.items())),
    "pool_distribution": summarize_distribution(pool),
    "selected_distribution": summarize_distribution(selected),
    "classification": {
      "patch_type": "aggregate source-line additions/deletions over the highest-signal parent diff for each fixing commit",
      "modification_scope": "changed source-file count plus distinct unified-diff function contexts; unresolved multi-hunk cases remain unknown",
      "branch_context": "p01 repository-level development model",
      "merge_fix": "any fixing commit has multiple parents",
      "multi_fix": "more than one unique fixing commit",
    },
    "selected_cases": selected,
  }
  return manifest, derived_dataset


def classify_case(cve_id: str, record: dict[str, Any], repo_root: Path) -> dict[str, Any]:
  repo = str(record.get("repo") or "")
  repo_path = repo_root / repo
  shas = flatten_fixing_commits(record.get("fixing_commits"))
  commit_results = [classify_fix_commit(repo_path, sha) for sha in shas]
  usable = [item for item in commit_results if item["status"] == "ok"]
  added = sum(item["added_lines"] for item in usable)
  deleted = sum(item["deleted_lines"] for item in usable)
  paths = sorted({path for item in usable for path in item["source_paths"]})
  functions = sorted({name for item in usable for name in item["function_contexts"]})
  unresolved_hunks = sum(item["unresolved_hunks"] for item in usable)
  hunk_count = sum(item["hunk_count"] for item in usable)

  if added and not deleted:
    patch_type = "add_only"
  elif deleted and not added:
    patch_type = "del_only"
  elif added and deleted:
    patch_type = "mixed"
  else:
    patch_type = "unknown"

  if len(paths) > 1:
    modification_scope = "multi_file"
    scope_confidence = "high"
  elif len(paths) == 1 and len(functions) > 1:
    modification_scope = "multi_function_single_file"
    scope_confidence = "medium" if unresolved_hunks else "high"
  elif len(paths) == 1 and len(functions) == 1:
    modification_scope = "single_function"
    scope_confidence = "medium" if unresolved_hunks else "high"
  elif len(paths) == 1 and hunk_count == 1:
    modification_scope = "single_function"
    scope_confidence = "low_proxy"
  else:
    modification_scope = "unknown"
    scope_confidence = "unresolved"

  if repo in MULTI_BRANCH_REPOS:
    branch_context = "multi_branch"
  elif repo in SINGLE_BRANCH_REPOS:
    branch_context = "single_branch"
  else:
    branch_context = "unknown"

  return {
    "cve_id": cve_id,
    "repo": repo,
    "cwe_ids": list(record.get("CWE") or []),
    "fixing_commits": shas,
    "patch_type": patch_type,
    "modification_scope": modification_scope,
    "scope_confidence": scope_confidence,
    "branch_context": branch_context,
    "merge_fix": any(item["parent_count"] > 1 for item in commit_results),
    "multi_fix": len(shas) > 1,
    "source_file_count": len(paths),
    "function_context_count": len(functions),
    "hunk_count": hunk_count,
    "added_lines": added,
    "deleted_lines": deleted,
    "classification_errors": [
      f"{item['commit_sha']}:{item['status']}" for item in commit_results if item["status"] != "ok"
    ],
  }


def classify_fix_commit(repo_path: Path, commit_sha: str) -> dict[str, Any]:
  base = {
    "commit_sha": commit_sha,
    "status": "ok",
    "parent_count": 0,
    "selected_parent": None,
    "added_lines": 0,
    "deleted_lines": 0,
    "source_paths": [],
    "function_contexts": [],
    "unresolved_hunks": 0,
    "hunk_count": 0,
  }
  parent_result = run_git(repo_path, ["rev-list", "--parents", "-n", "1", commit_sha])
  if parent_result.returncode != 0 or not parent_result.stdout.strip():
    return {**base, "status": "commit_missing"}
  tokens = parent_result.stdout.strip().split()
  parents = tokens[1:]
  base["parent_count"] = len(parents)
  if not parents:
    return {**base, "status": "root_commit"}

  parsed_parents = []
  for parent in parents:
    diff_result = run_git(
      repo_path,
      ["diff", "--no-color", "--unified=0", "--find-renames=40%", parent, commit_sha, "--"],
    )
    if diff_result.returncode != 0:
      continue
    parsed = parse_unified_diff(diff_result.stdout)
    parsed["selected_parent"] = parent
    parsed_parents.append(parsed)
  if not parsed_parents:
    return {**base, "status": "parent_diff_failed"}
  selected = max(
    parsed_parents,
    key=lambda item: (item["added_lines"] + item["deleted_lines"], item["hunk_count"], item["selected_parent"]),
  )
  return {**base, **selected}


def parse_unified_diff(diff_text: str) -> dict[str, Any]:
  added = 0
  deleted = 0
  paths: set[str] = set()
  functions: set[str] = set()
  unresolved_hunks = 0
  hunk_count = 0
  blocks = re.split(r"(?=^diff --git )", diff_text, flags=re.MULTILINE)
  for block in blocks:
    path = extract_diff_path(block)
    if not path or not is_source_path(path):
      continue
    paths.add(path)
    for raw_line in block.splitlines():
      if raw_line.startswith("@@ "):
        hunk_count += 1
        context = raw_line.split("@@", 2)[-1].strip()
        symbol = parse_function_context(context)
        if symbol:
          functions.add(f"{path}:{symbol}")
        else:
          unresolved_hunks += 1
      elif raw_line.startswith("+") and not raw_line.startswith("+++"):
        added += 1
      elif raw_line.startswith("-") and not raw_line.startswith("---"):
        deleted += 1
  return {
    "status": "ok" if paths and hunk_count else "no_source_hunks",
    "added_lines": added,
    "deleted_lines": deleted,
    "source_paths": sorted(paths),
    "function_contexts": sorted(functions),
    "unresolved_hunks": unresolved_hunks,
    "hunk_count": hunk_count,
  }


def extract_diff_path(block: str) -> str:
  match = re.search(r"^\+\+\+ b/(.+)$", block, flags=re.MULTILINE)
  if match and match.group(1).strip() != "/dev/null":
    return match.group(1).strip()
  match = re.search(r"^diff --git a/(.+?) b/(.+)$", block, flags=re.MULTILINE)
  return match.group(2).strip() if match else ""


def parse_function_context(context: str) -> str | None:
  if not context:
    return None
  names = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", context)
  for name in reversed(names):
    if name not in CONTROL_WORDS:
      return name
  return None


def is_source_path(path: str) -> bool:
  return Path(path).suffix.lower() in SOURCE_SUFFIXES


def flatten_fixing_commits(value: Any) -> list[str]:
  result: list[str] = []
  for item in value or []:
    if isinstance(item, str):
      result.append(item)
    elif isinstance(item, list):
      result.extend(str(entry) for entry in item if isinstance(entry, str))
  return list(dict.fromkeys(result))


def run_git(repo_path: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
  command = ["git", "-c", f"safe.directory={repo_path}", "-C", str(repo_path), *args]
  return subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="ignore", check=False)


def allocate_repo_quotas(repo_counts: Counter[str], sample_size: int, minimum: int = 5) -> dict[str, int]:
  if sample_size > sum(repo_counts.values()):
    raise ValueError("sample exceeds available cases")
  quotas = {repo: min(minimum, count) for repo, count in repo_counts.items()}
  remaining = sample_size - sum(quotas.values())
  while remaining > 0:
    eligible = [repo for repo, count in repo_counts.items() if quotas[repo] < count]
    if not eligible:
      raise ValueError("unable to allocate repository quotas")
    total_weight = sum(math.sqrt(repo_counts[repo]) for repo in eligible)
    ideals = {repo: remaining * math.sqrt(repo_counts[repo]) / total_weight for repo in eligible}
    progress = 0
    for repo in sorted(eligible, key=lambda name: (-(ideals[name] - math.floor(ideals[name])), name)):
      add = min(max(1, math.floor(ideals[repo])), repo_counts[repo] - quotas[repo], remaining)
      quotas[repo] += add
      remaining -= add
      progress += add
      if remaining == 0:
        break
    if progress == 0:
      raise ValueError("repository quota allocation stalled")
  return dict(sorted(quotas.items()))


def select_cases(pool: list[dict[str, Any]], *, repo_quotas: dict[str, int], seed: int) -> list[dict[str, Any]]:
  selected: list[dict[str, Any]] = []
  selected_ids: set[str] = set()
  repo_selected: Counter[str] = Counter()
  label_selected: Counter[str] = Counter()
  label_pool: Counter[str] = Counter(label for item in pool for label in case_labels(item))

  while len(selected) < sum(repo_quotas.values()):
    candidates = [
      item for item in pool
      if item["cve_id"] not in selected_ids and repo_selected[item["repo"]] < repo_quotas[item["repo"]]
    ]
    if not candidates:
      raise ValueError("selection exhausted before reaching target")
    best = max(candidates, key=lambda item: selection_score(item, label_pool, label_selected, seed))
    chosen = dict(best)
    chosen["selection_rank"] = len(selected) + 1
    selected.append(chosen)
    selected_ids.add(best["cve_id"])
    repo_selected[best["repo"]] += 1
    label_selected.update(case_labels(best))
  return selected


def case_labels(item: dict[str, Any]) -> list[str]:
  labels = [
    f"patch:{item['patch_type']}",
    f"scope:{item['modification_scope']}",
    f"branch:{item['branch_context']}",
  ]
  if item["merge_fix"]:
    labels.append("feature:merge_fix")
  if item["multi_fix"]:
    labels.append("feature:multi_fix")
  return labels


def selection_score(
  item: dict[str, Any],
  label_pool: Counter[str],
  label_selected: Counter[str],
  seed: int,
) -> tuple[float, float, str]:
  weights = {
    "patch:del_only": 4.0,
    "patch:add_only": 2.0,
    "patch:mixed": 1.0,
    "patch:unknown": 0.25,
    "scope:multi_file": 2.5,
    "scope:multi_function_single_file": 1.8,
    "scope:single_function": 1.0,
    "scope:unknown": 0.25,
    "feature:merge_fix": 3.0,
    "feature:multi_fix": 3.0,
  }
  score = 0.0
  for label in case_labels(item):
    rarity = 1.0 / math.sqrt(max(1, label_pool[label]))
    score += weights.get(label, 0.5) * rarity / (1 + label_selected[label])
  if item["patch_type"] == "unknown" or item["modification_scope"] == "unknown":
    score -= 5.0
  if item["classification_errors"]:
    score -= 5.0
  digest = hashlib.sha256(f"{seed}:{item['cve_id']}".encode()).hexdigest()
  tie_break = int(digest[:16], 16) / float(0xFFFFFFFFFFFFFFFF)
  return score, tie_break, item["cve_id"]


def summarize_distribution(cases: list[dict[str, Any]]) -> dict[str, Any]:
  return {
    "total": len(cases),
    "repo": dict(sorted(Counter(item["repo"] for item in cases).items())),
    "patch_type": dict(sorted(Counter(item["patch_type"] for item in cases).items())),
    "modification_scope": dict(sorted(Counter(item["modification_scope"] for item in cases).items())),
    "branch_context": dict(sorted(Counter(item["branch_context"] for item in cases).items())),
    "merge_fix": sum(bool(item["merge_fix"]) for item in cases),
    "multi_fix": sum(bool(item["multi_fix"]) for item in cases),
    "classification_error_cases": sum(bool(item["classification_errors"]) for item in cases),
  }
