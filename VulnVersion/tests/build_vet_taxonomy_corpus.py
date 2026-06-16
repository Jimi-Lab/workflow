from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnversion.stage1_semantic_aggregation.deterministic import run_step1_deterministic_extractor
from vulnversion.stage1_semantic_aggregation.schema import (
  ChunkSemantics,
  SemanticRegion,
  Step1QualityReport,
)


DEFAULT_DATASET = Path("DataSet/BaseDataOrder.json")
DEFAULT_NVD = Path("DataSet/BaseData_nvd.json")
DEFAULT_REPO_ROOT = Path("repo")
DEFAULT_OUT = Path("tests/vet_taxonomy_corpus")
DEFAULT_TARGET_SIZE = 81
LARGE_PATCH_THRESHOLD = 20
MIN_SELECTED_PER_REPO = 5

MEMORY_CWES = {
  "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787", "CWE-788", "CWE-190", "CWE-191"
}
NULL_CWES = {"CWE-476"}
VALIDATION_CWES = {"CWE-20", "CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-345"}
PERMISSION_CWES = {"CWE-200", "CWE-284", "CWE-287", "CWE-295", "CWE-306", "CWE-862", "CWE-863"}


def _load_json(path: Path) -> Any:
  return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, obj: Any) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  with path.open("w", encoding="utf-8") as f:
    for row in rows:
      f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def _flatten_commits(record: dict[str, Any]) -> list[str]:
  commits: list[str] = []
  for family in record.get("fixing_commits") or []:
    if isinstance(family, list):
      commits.extend(str(x) for x in family if x)
    elif family:
      commits.append(str(family))
  return commits


def _cvss_summary(nvd_record: dict[str, Any] | None) -> dict[str, Any]:
  if not nvd_record:
    return {"severity": None, "score": None, "vector": None, "source": None}
  for key in ("cvss4", "cvss3", "cvss2"):
    val = nvd_record.get(key)
    if isinstance(val, list) and val:
      item = val[0] if isinstance(val[0], dict) else {}
      score_text = str(item.get("score") or "")
      m = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*([A-Z]+)?", score_text)
      return {
        "severity": m.group(2) if m and m.group(2) else None,
        "score": float(m.group(1)) if m else None,
        "vector": item.get("vector"),
        "source": item.get("source"),
      }
  return {"severity": None, "score": None, "vector": None, "source": None}


def _read_jsonl_models(path: Path, model: Any) -> list[Any]:
  rows: list[Any] = []
  if not path.exists():
    return rows
  for line in path.read_text(encoding="utf-8").splitlines():
    if line.strip():
      rows.append(model.model_validate(json.loads(line)))
  return rows


def _step1_paths(out_dir: Path, repo: str, cve_id: str) -> dict[str, Path]:
  base = out_dir / "work" / repo / cve_id / "step1" / "output"
  return {
    "quality": base / "step1_quality_report.json",
    "chunks": base / "chunk_semantics.jsonl",
    "regions": base / "semantic_regions.jsonl",
  }


def _ensure_step1(
  *,
  out_dir: Path,
  repo_root: Path,
  repo: str,
  cve_id: str,
  record: dict[str, Any],
  nvd_record: dict[str, Any] | None,
  force: bool,
) -> tuple[Step1QualityReport, list[ChunkSemantics], list[SemanticRegion]]:
  paths = _step1_paths(out_dir, repo, cve_id)
  if force or not (paths["quality"].exists() and paths["chunks"].exists() and paths["regions"].exists()):
    commits = _flatten_commits(record)
    if not commits:
      raise ValueError("missing_fixing_commits")
    repo_path = repo_root / repo
    if not repo_path.exists():
      raise FileNotFoundError(f"repo_not_found:{repo_path}")
    run_step1_deterministic_extractor(
      result_root=out_dir / "work",
      repo_name=repo,
      cve_id=cve_id,
      repo_path=str(repo_path),
      fixing_commits=commits,
      cve_description=str((nvd_record or {}).get("description") or ""),
      cwe=list(record.get("CWE") or []),
      nvd_record=nvd_record,
      dataset_record=record,
      mode="deterministic_only",
    )
  quality = Step1QualityReport.model_validate(_load_json(paths["quality"]))
  chunks = _read_jsonl_models(paths["chunks"], ChunkSemantics)
  regions = _read_jsonl_models(paths["regions"], SemanticRegion)
  return quality, chunks, regions


def _case_patch_type(chunks: list[ChunkSemantics]) -> str:
  types = {ch.patch_type for ch in chunks}
  types.discard("empty_or_merge")
  if not types:
    return "empty_or_merge"
  if len(types) == 1:
    return next(iter(types))
  return "mixed"


def _file_extensions(chunks: list[ChunkSemantics]) -> list[str]:
  exts = sorted({Path(ch.file_path).suffix.lower() or "<none>" for ch in chunks})
  return exts


def _touched_file_roles(chunks: list[ChunkSemantics]) -> dict[str, int]:
  return dict(sorted(Counter(ch.file_role for ch in chunks).items()))


def _patch_size_bucket(chunk_count: int) -> str:
  if chunk_count <= 2:
    return "small"
  if chunk_count < LARGE_PATCH_THRESHOLD:
    return "medium"
  return "large"


def _family_kind(record: dict[str, Any]) -> str:
  commits = _flatten_commits(record)
  if len(commits) <= 1:
    return "single_commit"
  return "multi_commit"


def _contains_any(text: str, words: list[str]) -> bool:
  low = text.lower()
  return any(w in low for w in words)


def _infer_vet_archetype(
  *,
  cwe: list[str],
  desc: str,
  patch_type: str,
  regions: list[SemanticRegion],
) -> tuple[str, list[str]]:
  cwes = set(cwe)
  desc_low = desc.lower()
  has_guard = any(r.added_guard_sequence for r in regions)
  has_removed_critical = any(r.removed_critical_sequence for r in regions)
  file_text = " ".join(r.file_path.lower() for r in regions)
  reasons: list[str] = []

  if cwes & NULL_CWES or _contains_any(desc_low, ["null pointer", "null dereference", "null-pointer"]):
    reasons.append("cwe_or_description_null")
    return "null_lifetime_refcount", reasons
  if cwes & MEMORY_CWES or _contains_any(desc_low, ["out-of-bounds", "overflow", "underflow", "buffer", "heap", "memcpy"]):
    reasons.append("memory_safety_cwe_or_description")
    if has_guard:
      reasons.append("added_guard_sequence")
      return "bounds_length_check", reasons
    if has_removed_critical:
      reasons.append("removed_critical_sequence")
      return "unsafe_operation_replacement", reasons
    return "bounds_length_check", reasons
  if cwes & PERMISSION_CWES or _contains_any(desc_low, ["permission", "authentication", "authorization", "certificate", "trust", "privilege"]):
    reasons.append("permission_or_auth_cwe_description")
    return "permission_capability_check", reasons
  if cwes & VALIDATION_CWES or _contains_any(desc_low, ["validate", "validation", "sanitize", "injection", "path traversal", "traversal"]):
    reasons.append("validation_cwe_or_description")
    return "missing_guard_added_validation" if has_guard else "input_validation_invariant", reasons
  if _contains_any(file_text + " " + desc_low, ["parser", "parse", "decode", "decoder", "demux", "packet", "protocol", "state"]):
    reasons.append("parser_protocol_file_or_description")
    return "parser_state_or_protocol_invariant", reasons
  if patch_type == "del_only":
    reasons.append("del_only_patch")
    return "vulnerable_branch_removed", reasons
  if patch_type == "add_only" and has_guard:
    reasons.append("add_only_with_guard")
    return "missing_guard_added_validation", reasons
  if patch_type == "mixed" and has_guard and has_removed_critical:
    reasons.append("mixed_guard_and_removed_critical")
    return "status_error_handling_or_logic_correction", reasons
  return "unknown_requires_manual_review", ["heuristic_no_confident_match"]


def _vet_seed(
  *,
  cve_id: str,
  repo: str,
  record: dict[str, Any],
  nvd_record: dict[str, Any] | None,
  patch_type: str,
  chunks: list[ChunkSemantics],
  regions: list[SemanticRegion],
  archetype: str,
  archetype_reasons: list[str],
) -> dict[str, Any]:
  source_regions = [r for r in regions if r.file_role == "source"]
  top_regions = sorted(source_regions or regions, key=lambda r: (r.root_cause_score, len(r.source_refs)), reverse=True)[:5]
  scope = {
    "files": sorted({r.file_path for r in top_regions}),
    "functions": sorted({r.function_context for r in top_regions if r.function_context}),
    "commits": _flatten_commits(record),
  }
  vulnerable_condition = {
    "description": str((nvd_record or {}).get("description") or "")[:800],
    "cwe": list(record.get("CWE") or []),
    "removed_critical_sequence": [x for r in top_regions for x in r.removed_critical_sequence][:20],
    "nearby_dangerous_operation": [x for r in top_regions for x in r.nearby_dangerous_operation][:20],
  }
  fix_evidence = {
    "patch_type": patch_type,
    "added_guard_sequence": [x for r in top_regions for x in r.added_guard_sequence][:20],
    "changed_files": sorted({ch.file_path for ch in chunks}),
  }
  guards = {
    "candidate_regions": [
      {
        "region_id": r.region_id,
        "file_path": r.file_path,
        "function_context": r.function_context,
        "root_cause_score": r.root_cause_score,
        "score_reasons": r.score_reasons,
      }
      for r in top_regions
    ]
  }
  if archetype == "unknown_requires_manual_review":
    policy = "prompt_context_only"
  elif fix_evidence["added_guard_sequence"] or vulnerable_condition["removed_critical_sequence"]:
    policy = "vet_candidate_priority_signal"
  else:
    policy = "vet_candidate_needs_agent_refinement"
  return {
    "cve_id": cve_id,
    "repo": repo,
    "vet_archetype": archetype,
    "archetype_reasons": archetype_reasons,
    "theta": {
      "Scope": scope,
      "VulnerableCondition": vulnerable_condition,
      "FixEvidence": fix_evidence,
      "Guards": guards,
      "CertificatePolicy": policy,
    },
    "confidence": 0.35 if archetype == "unknown_requires_manual_review" else 0.6,
    "status": "heuristic_seed_requires_case_review",
  }


def _selection_score(row: dict[str, Any], current: list[dict[str, Any]]) -> tuple[int, str]:
  selected_repos = Counter(x["repo"] for x in current)
  selected_patch = Counter(x["patch_type"] for x in current)
  selected_size = Counter(x["patch_size_bucket"] for x in current)
  selected_family = Counter(x["fix_family_kind"] for x in current)
  selected_arch = Counter(x["vet_archetype_seed"] for x in current)
  score = 0
  if selected_repos[row["repo"]] < 4:
    score += 100
  if selected_patch[row["patch_type"]] < 8:
    score += 40
  if selected_size[row["patch_size_bucket"]] < 8:
    score += 25
  if row["fix_family_kind"] == "multi_commit" and selected_family["multi_commit"] < 16:
    score += 35
  if row["patch_chunk_count"] >= LARGE_PATCH_THRESHOLD:
    score += 20
  if selected_arch[row["vet_archetype_seed"]] < 5:
    score += 30
  score += min(10, len(row.get("cwe") or []))
  return score, row["cve_id"]


def _select_cases(rows: list[dict[str, Any]], target_size: int) -> list[dict[str, Any]]:
  selected: list[dict[str, Any]] = []
  seen: set[str] = set()

  def add(row: dict[str, Any]) -> None:
    if row["cve_id"] not in seen and len(selected) < target_size:
      selected.append(row)
      seen.add(row["cve_id"])

  # Hard coverage: every repo and every available repo-local patch type.
  for repo in sorted({r["repo"] for r in rows}):
    repo_rows = [r for r in rows if r["repo"] == repo]
    for patch_type in sorted({r["patch_type"] for r in repo_rows}):
      candidates = [r for r in repo_rows if r["patch_type"] == patch_type]
      for row in sorted(candidates, key=lambda x: (-x["patch_chunk_count"], x["cve_id"]))[:1]:
        add(row)
    while sum(1 for r in selected if r["repo"] == repo) < MIN_SELECTED_PER_REPO:
      candidates = [r for r in repo_rows if r["cve_id"] not in seen]
      if not candidates:
        break
      row = max(candidates, key=lambda x: _selection_score(x, selected))
      add(row)

  # Rare structural buckets.
  for patch_type in ("del_only", "add_only", "mixed", "empty_or_merge"):
    for row in sorted([r for r in rows if r["patch_type"] == patch_type], key=lambda x: (-x["patch_chunk_count"], x["repo"], x["cve_id"]))[:8]:
      add(row)

  # Multi-commit and large patches are important Step1/Step2 stress cases.
  for row in sorted([r for r in rows if r["fix_family_kind"] == "multi_commit"], key=lambda x: (-x["patch_chunk_count"], x["repo"], x["cve_id"]))[:18]:
    add(row)
  for row in sorted([r for r in rows if r["patch_chunk_count"] >= LARGE_PATCH_THRESHOLD], key=lambda x: (-x["patch_chunk_count"], x["repo"], x["cve_id"]))[:18]:
    add(row)

  # Heuristic VET archetype coverage.
  for archetype in sorted({r["vet_archetype_seed"] for r in rows}):
    for row in sorted([r for r in rows if r["vet_archetype_seed"] == archetype], key=lambda x: (-x["patch_chunk_count"], x["repo"], x["cve_id"]))[:4]:
      add(row)

  while len(selected) < target_size:
    remaining = [r for r in rows if r["cve_id"] not in seen]
    if not remaining:
      break
    best = max(remaining, key=lambda row: _selection_score(row, selected))
    add(best)
  return selected


def _case_row(
  *,
  cve_id: str,
  record: dict[str, Any],
  nvd_record: dict[str, Any] | None,
  quality: Step1QualityReport,
  chunks: list[ChunkSemantics],
  regions: list[SemanticRegion],
) -> dict[str, Any]:
  repo = str(record.get("repo") or "")
  patch_type = _case_patch_type(chunks)
  cwe = list(record.get("CWE") or [])
  desc = str((nvd_record or {}).get("description") or "")
  archetype, reasons = _infer_vet_archetype(cwe=cwe, desc=desc, patch_type=patch_type, regions=regions)
  return {
    "cve_id": cve_id,
    "repo": repo,
    "cwe": cwe,
    "cvss": _cvss_summary(nvd_record),
    "affected_version_count": len(record.get("affected_version") or []),
    "fix_commit_count": len(_flatten_commits(record)),
    "fix_family_kind": _family_kind(record),
    "patch_type": patch_type,
    "chunk_patch_type_counts": dict(sorted(Counter(ch.patch_type for ch in chunks).items())),
    "patch_chunk_count": quality.patch_chunk_count,
    "semantic_region_count": quality.semantic_region_count,
    "compression_ratio": quality.compression_ratio,
    "patch_size_bucket": _patch_size_bucket(quality.patch_chunk_count),
    "changed_files": sorted({ch.file_path for ch in chunks}),
    "file_extensions": _file_extensions(chunks),
    "file_role_counts": _touched_file_roles(chunks),
    "function_context_missing_chunks": sum(1 for ch in chunks if "function_context_missing" in ch.risk_flags),
    "root_cause_score_max": max([r.root_cause_score for r in regions], default=0.0),
    "has_added_guard_sequence": any(r.added_guard_sequence for r in regions),
    "has_removed_critical_sequence": any(r.removed_critical_sequence for r in regions),
    "vet_archetype_seed": archetype,
    "vet_archetype_reasons": reasons,
    "step1_quality_flags": quality.risk_flags,
  }


def _matrix(rows: list[dict[str, Any]]) -> dict[str, Any]:
  repo_patch: dict[str, Counter[str]] = defaultdict(Counter)
  repo_size: dict[str, Counter[str]] = defaultdict(Counter)
  repo_family: dict[str, Counter[str]] = defaultdict(Counter)
  archetypes: Counter[str] = Counter()
  cwes: Counter[str] = Counter()
  for row in rows:
    repo_patch[row["repo"]][row["patch_type"]] += 1
    repo_size[row["repo"]][row["patch_size_bucket"]] += 1
    repo_family[row["repo"]][row["fix_family_kind"]] += 1
    archetypes[row["vet_archetype_seed"]] += 1
    cwes.update(row["cwe"])
  return {
    "repo_patch_type": {repo: dict(sorted(counter.items())) for repo, counter in sorted(repo_patch.items())},
    "repo_patch_size": {repo: dict(sorted(counter.items())) for repo, counter in sorted(repo_size.items())},
    "repo_fix_family": {repo: dict(sorted(counter.items())) for repo, counter in sorted(repo_family.items())},
    "vet_archetype_seed_counts": dict(sorted(archetypes.items())),
    "top_cwe_counts": dict(cwes.most_common(30)),
  }


def _report(summary: dict[str, Any], selected: list[dict[str, Any]]) -> str:
  lines = [
    "# VET Taxonomy Corpus",
    "",
    "This corpus is a stratified case-study set for deriving VET archetypes from the VulnVersion dataset.",
    "All archetypes in this report are heuristic seeds and must be reviewed before becoming Step2 rules.",
    "",
    "## Summary",
    "",
    f"- total_cves: {summary['total_cves']}",
    f"- completed_cves: {summary['completed_cves']}",
    f"- failed_cves: {summary['failed_cves']}",
    f"- selected_cases: {summary['selected_cases']}",
    f"- target_size: {summary['target_size']}",
    "",
    "## Selected Cases",
    "",
    "| repo | CVE | patch_type | chunks | family | archetype_seed |",
    "| --- | --- | --- | ---: | --- | --- |",
  ]
  for row in selected:
    lines.append(
      f"| {row['repo']} | {row['cve_id']} | {row['patch_type']} | {row['patch_chunk_count']} | "
      f"{row['fix_family_kind']} | {row['vet_archetype_seed']} |"
    )
  lines.extend([
    "",
    "## Use",
    "",
    "- Use `selected_dataset.json` for compact multi-stage case studies.",
    "- Use `vet_archetype_seed.jsonl` as Step2 VET drafting input.",
    "- Do not treat `vet_archetype_seed` as ground truth; it is a deterministic seed for manual/agent review.",
  ])
  return "\n".join(lines)


def build_corpus(
  *,
  dataset_path: str | Path = DEFAULT_DATASET,
  nvd_path: str | Path = DEFAULT_NVD,
  repo_root: str | Path = DEFAULT_REPO_ROOT,
  out_dir: str | Path = DEFAULT_OUT,
  target_size: int = DEFAULT_TARGET_SIZE,
  force_step1: bool = False,
  sample_size: int | None = None,
) -> dict[str, Any]:
  dataset_path = Path(dataset_path)
  nvd_path = Path(nvd_path)
  repo_root = Path(repo_root)
  out_dir = Path(out_dir)
  dataset = _load_json(dataset_path)
  nvd = _load_json(nvd_path) if nvd_path.exists() else {}
  items = list(dataset.items())
  if sample_size is not None and sample_size > 0:
    items = items[:sample_size]

  rows: list[dict[str, Any]] = []
  failures: list[dict[str, Any]] = []
  vet_seeds_by_cve: dict[str, dict[str, Any]] = {}

  for cve_id, record in items:
    repo = str(record.get("repo") or "")
    nvd_record = nvd.get(cve_id) if isinstance(nvd, dict) else None
    try:
      quality, chunks, regions = _ensure_step1(
        out_dir=out_dir,
        repo_root=repo_root,
        repo=repo,
        cve_id=cve_id,
        record=record,
        nvd_record=nvd_record,
        force=force_step1,
      )
      row = _case_row(
        cve_id=cve_id,
        record=record,
        nvd_record=nvd_record,
        quality=quality,
        chunks=chunks,
        regions=regions,
      )
      rows.append(row)
      vet_seeds_by_cve[cve_id] = _vet_seed(
        cve_id=cve_id,
        repo=repo,
        record=record,
        nvd_record=nvd_record,
        patch_type=row["patch_type"],
        chunks=chunks,
        regions=regions,
        archetype=row["vet_archetype_seed"],
        archetype_reasons=row["vet_archetype_reasons"],
      )
    except Exception as exc:
      failures.append({
        "cve_id": cve_id,
        "repo": repo,
        "error": f"{type(exc).__name__}: {exc}",
      })

  selected = _select_cases(rows, target_size=target_size)
  selected_ids = {row["cve_id"] for row in selected}
  selected_dataset = {cve_id: dataset[cve_id] for cve_id in dataset if cve_id in selected_ids}
  selected_vet_seeds = [vet_seeds_by_cve[row["cve_id"]] for row in selected]
  matrix_all = _matrix(rows)
  matrix_selected = _matrix(selected)

  summary = {
    "dataset": str(dataset_path),
    "nvd": str(nvd_path),
    "repo_root": str(repo_root),
    "total_cves": len(items),
    "completed_cves": len(rows),
    "failed_cves": len(failures),
    "target_size": target_size,
    "selected_cases": len(selected),
    "large_patch_threshold": LARGE_PATCH_THRESHOLD,
    "all_matrix": matrix_all,
    "selected_matrix": matrix_selected,
  }

  _write_json(out_dir / "summary.json", summary)
  _write_json(out_dir / "repo_patch_type_matrix.json", {
    "all": matrix_all,
    "selected": matrix_selected,
  })
  _write_jsonl(out_dir / "case_index.jsonl", rows)
  _write_json(out_dir / "selected_cases.json", selected)
  _write_json(out_dir / "selected_dataset.json", selected_dataset)
  _write_json(out_dir / f"BaseDataOrder_vet_case_study_{len(selected)}.json", selected_dataset)
  _write_jsonl(out_dir / "vet_archetype_seed.jsonl", selected_vet_seeds)
  _write_json(out_dir / "manual_review_cases.json", {
    "unknown_or_low_confidence": [
      row for row in selected
      if row["vet_archetype_seed"] == "unknown_requires_manual_review"
      or row["root_cause_score_max"] <= 0
    ],
    "large_patch_cases": [row for row in selected if row["patch_chunk_count"] >= LARGE_PATCH_THRESHOLD],
    "multi_commit_cases": [row for row in selected if row["fix_family_kind"] == "multi_commit"],
    "del_only_cases": [row for row in selected if row["patch_type"] == "del_only"],
  })
  _write_json(out_dir / "failure_cases.json", failures)
  (out_dir / "report.md").write_text(_report(summary, selected), encoding="utf-8")
  return summary


def main() -> int:
  parser = argparse.ArgumentParser()
  parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
  parser.add_argument("--nvd", default=str(DEFAULT_NVD))
  parser.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT))
  parser.add_argument("--out", default=str(DEFAULT_OUT))
  parser.add_argument("--target-size", type=int, default=DEFAULT_TARGET_SIZE)
  parser.add_argument("--sample-size", type=int, default=None)
  parser.add_argument("--force-step1", action="store_true")
  args = parser.parse_args()
  summary = build_corpus(
    dataset_path=args.dataset,
    nvd_path=args.nvd,
    repo_root=args.repo_root,
    out_dir=args.out,
    target_size=args.target_size,
    force_step1=args.force_step1,
    sample_size=args.sample_size,
  )
  print(json.dumps(summary, ensure_ascii=False, indent=2))
  return 0 if summary["failed_cves"] == 0 else 1


if __name__ == "__main__":
  raise SystemExit(main())
