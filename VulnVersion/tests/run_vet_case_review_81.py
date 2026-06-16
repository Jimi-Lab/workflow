from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnversion.agent_harness.runtimes.opencode_runtime import OpenCodeRuntime
from vulnversion.config import Config
from vulnversion.opencode.agent import OpenCodeJSONParseError


DEFAULT_DATASET = Path("tests/vet_taxonomy_corpus/BaseDataOrder_vet_case_study_81.json")
DEFAULT_SELECTED_CASES = Path("tests/vet_taxonomy_corpus/selected_cases.json")
DEFAULT_VET_SEEDS = Path("tests/vet_taxonomy_corpus/vet_archetype_seed.jsonl")
DEFAULT_STEP1_WORK = Path("tests/vet_taxonomy_corpus/work")
DEFAULT_OUT = Path("tests/vet_taxonomy_case_review/pilot_9")
STEP2_VET_SCHEMA_VERSION = "step2_vet.v2"
LEGACY_REVIEW_SCHEMA_VERSION = "vet_case_review.v1"
STAGES = {"pilot_9", "expanded_27", "expanded_27_v2", "full_81"}
EXPANDED_PRIORITY_SEEDS = {
  "unknown_requires_manual_review",
  "status_error_handling_or_logic_correction",
  "unsafe_operation_replacement",
  "vulnerable_branch_removed",
  "input_validation_invariant",
  "parser_state_or_protocol_invariant",
}


def _load_json(path: Path) -> Any:
  return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
  if not path.exists():
    return []
  rows: list[dict[str, Any]] = []
  for line in path.read_text(encoding="utf-8").splitlines():
    if line.strip():
      rows.append(json.loads(line))
  return rows


def quality_failed_case_ids(out_dir: str | Path, *, severity: str = "error") -> set[str]:
  """Return CVEs that should be retried because prior quality audit failed.

  By default this only selects hard schema/structure failures. Warnings such as
  empty negative evidence are important, but rerunning every warning would
  collapse back into a full 27-case rerun and waste agent calls.
  """

  path = Path(out_dir) / "quality_findings.json"
  if not path.exists():
    return set()
  findings = _load_json(path)
  if not isinstance(findings, list):
    return set()
  return {
    str(item.get("cve_id") or "")
    for item in findings
    if isinstance(item, dict)
    and str(item.get("severity") or "") == severity
    and item.get("cve_id")
  }


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


def _seed_by_cve(path: Path) -> dict[str, dict[str, Any]]:
  return {row["cve_id"]: row for row in _read_jsonl(path) if row.get("cve_id")}


def _case_score(row: dict[str, Any]) -> tuple[int, str]:
  """Prefer medium/small source-like cases for pilot review."""

  chunks = int(row.get("patch_chunk_count") or 0)
  score = 0
  if row.get("vet_archetype_seed") == "unknown_requires_manual_review":
    score += 100
  if chunks == 0:
    score += 100
  if chunks > 20:
    score += 50 + chunks
  else:
    score += abs(chunks - 5)
  if row.get("patch_type") == "mixed":
    score += 2
  if row.get("fix_family_kind") == "multi_commit":
    score -= 3
  return score, str(row.get("cve_id") or "")


def _stage_limit(stage: str) -> int:
  if stage == "pilot_9":
    return 1
  if stage in {"expanded_27", "expanded_27_v2"}:
    return 3
  if stage == "full_81":
    return 10_000
  raise ValueError(f"unknown_stage:{stage}")


def _select_stage_rows(rows: list[dict[str, Any]], stage: str) -> list[dict[str, Any]]:
  if stage not in STAGES:
    raise ValueError(f"stage_must_be_one_of:{sorted(STAGES)}")
  if stage == "full_81":
    return list(rows)
  if stage in {"expanded_27", "expanded_27_v2"}:
    return _select_expanded_rows(rows)

  per_repo_limit = _stage_limit(stage)
  selected: list[dict[str, Any]] = []
  for repo in sorted({str(row.get("repo") or "") for row in rows}):
    repo_rows = [row for row in rows if row.get("repo") == repo]
    selected.extend(sorted(repo_rows, key=_case_score)[:per_repo_limit])
  return selected


def _ids(rows: Iterable[dict[str, Any]]) -> set[str]:
  return {str(row.get("cve_id") or "") for row in rows}


def _expanded_candidate_score(
  row: dict[str, Any],
  selected: list[dict[str, Any]],
  selected_for_repo: list[dict[str, Any]],
) -> tuple[float, str]:
  """Rank P1-B candidates by corpus diversity, not by easiest cases only."""

  global_patch = Counter(str(r.get("patch_type") or "") for r in selected)
  global_seed = Counter(str(r.get("vet_archetype_seed") or "") for r in selected)
  global_family = Counter(str(r.get("fix_family_kind") or "") for r in selected)
  repo_patch = Counter(str(r.get("patch_type") or "") for r in selected_for_repo)
  repo_seed = Counter(str(r.get("vet_archetype_seed") or "") for r in selected_for_repo)
  patch = str(row.get("patch_type") or "")
  seed = str(row.get("vet_archetype_seed") or "")
  family = str(row.get("fix_family_kind") or "")
  chunks = int(row.get("patch_chunk_count") or 0)
  score = 0.0

  if seed not in global_seed:
    score += 120
  if seed in EXPANDED_PRIORITY_SEEDS:
    score += 75
  if seed not in repo_seed:
    score += 25

  if patch not in global_patch:
    score += 80
  if patch == "del_only":
    score += 50 if global_patch[patch] < 3 else 15
  if patch not in repo_patch:
    score += 20

  if family not in global_family:
    score += 35
  if family == "multi_commit":
    score += 15

  # P1-B should include some large patches, but not over-select context bombs.
  if 8 <= chunks <= 40:
    score += 18
  elif chunks > 40:
    score += 8
  elif chunks <= 2:
    score += 5

  if row.get("step1_quality_flags"):
    score += 8
  if row.get("function_context_missing_chunks"):
    score += 6

  # Smaller final tie-breaker keeps runs deterministic and avoids needless
  # context blow-up when two rows add identical coverage.
  score -= min(chunks, 120) * 0.05
  return -score, str(row.get("cve_id") or "")


def _select_expanded_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
  """Select 3 cases per repo while maximizing P1-B taxonomy diversity."""

  per_repo_limit = _stage_limit("expanded_27")
  repos = sorted({str(row.get("repo") or "") for row in rows})
  selected: list[dict[str, Any]] = []
  selected_by_repo: dict[str, list[dict[str, Any]]] = {repo: [] for repo in repos}

  # Keep one stable pilot-like case per repo so P1-B remains comparable to P1-A.
  for repo in repos:
    repo_rows = [row for row in rows if row.get("repo") == repo]
    if not repo_rows:
      continue
    first = sorted(repo_rows, key=_case_score)[0]
    selected.append(first)
    selected_by_repo[repo].append(first)

  while any(len(selected_by_repo[repo]) < per_repo_limit for repo in repos):
    selected_ids = _ids(selected)
    candidates = [
      row
      for row in rows
      if str(row.get("cve_id") or "") not in selected_ids
      and len(selected_by_repo[str(row.get("repo") or "")]) < per_repo_limit
    ]
    if not candidates:
      break
    best = sorted(
      candidates,
      key=lambda row: _expanded_candidate_score(row, selected, selected_by_repo[str(row.get("repo") or "")]),
    )[0]
    selected.append(best)
    selected_by_repo[str(best.get("repo") or "")].append(best)

  ordered: list[dict[str, Any]] = []
  for repo in repos:
    ordered.extend(selected_by_repo[repo])
  return ordered


def build_case_plan(
  *,
  dataset_path: str | Path,
  selected_cases_path: str | Path,
  vet_seeds_path: str | Path,
  stage: str,
) -> list[dict[str, Any]]:
  dataset_path = Path(dataset_path)
  selected_cases_path = Path(selected_cases_path)
  vet_seeds_path = Path(vet_seeds_path)
  dataset = _load_json(dataset_path)
  selected_rows = _load_json(selected_cases_path)
  seeds = _seed_by_cve(vet_seeds_path)
  stage_rows = _select_stage_rows(selected_rows, stage)

  plan: list[dict[str, Any]] = []
  for row in stage_rows:
    cve_id = str(row.get("cve_id") or "")
    record = dataset.get(cve_id, {})
    seed = seeds.get(cve_id, {})
    theta = seed.get("theta") if isinstance(seed.get("theta"), dict) else {}
    plan.append({
      "cve_id": cve_id,
      "repo": str(row.get("repo") or record.get("repo") or ""),
      "fix_commits": _flatten_commits(record),
      "patch_type": str(row.get("patch_type") or ""),
      "patch_chunk_count": int(row.get("patch_chunk_count") or 0),
      "semantic_region_count": int(row.get("semantic_region_count") or 0),
      "fix_family_kind": str(row.get("fix_family_kind") or ""),
      "deterministic_seed": str(row.get("vet_archetype_seed") or seed.get("vet_archetype") or ""),
      "seed_confidence": seed.get("confidence"),
      "seed_theta_scope_files": ((theta.get("Scope") or {}).get("files") or []) if theta else [],
      "cwe": list(record.get("CWE") or row.get("cwe") or []),
      "selected_case": row,
      "vet_seed": seed,
    })
  return plan


def _report_md(*, title: str, summary: dict[str, Any], rows: list[dict[str, Any]]) -> str:
  lines = [
    f"# {title}",
    "",
    "## Summary",
    "",
  ]
  for key in ("stage", "dry_run", "planned_cases", "completed_cases", "agent_failed_cases", "needs_manual_review_cases"):
    if key in summary:
      lines.append(f"- {key}: {summary[key]}")
  quality = summary.get("quality") if isinstance(summary.get("quality"), dict) else None
  if quality:
    lines.extend([
      f"- quality.finding_count: {quality.get('finding_count')}",
      f"- quality.severity_counts: {quality.get('severity_counts')}",
      f"- quality.step2_admission_ready: {quality.get('step2_admission_ready')}",
    ])
  lines.extend([
    "",
    "## Cases",
    "",
    "| repo | CVE | patch_type | chunks | family | seed | status |",
    "| --- | --- | --- | ---: | --- | --- | --- |",
  ])
  for row in rows:
    lines.append(
      f"| {row.get('repo')} | {row.get('cve_id')} | {row.get('patch_type')} | "
      f"{row.get('patch_chunk_count')} | {row.get('fix_family_kind')} | "
      f"{row.get('deterministic_seed') or row.get('vet_archetype')} | {row.get('review_status', 'planned')} |"
    )
  lines.append("")
  return "\n".join(lines)


def _list_value(obj: Any) -> list[Any]:
  return obj if isinstance(obj, list) else []


def _dict_value(obj: Any) -> dict[str, Any]:
  return obj if isinstance(obj, dict) else {}


def _empty_reviewed_vet() -> dict[str, Any]:
  return {
    "root_cause_summary": "",
    "vulnerability_mechanism": "",
    "fix_mechanism": "",
    "scope": {"files": [], "functions": [], "components": [], "source_refs": []},
    "vulnerable_condition": {
      "necessary_conditions": [],
      "vulnerable_sequences": [],
      "missing_guards": [],
      "negative_evidence": [],
    },
    "fix_evidence": {"fix_guards": [], "changed_sequences": [], "semantic_change": ""},
    "guards": {"configuration_guards": [], "version_or_feature_guards": [], "preconditions": []},
    "uncertainty": [],
  }


def _empty_admission_evidence() -> dict[str, Any]:
  return {"evidence_items": []}


def _step2_v2_required_schema(case: dict[str, Any]) -> dict[str, Any]:
  return {
    "schema_version": STEP2_VET_SCHEMA_VERSION,
    "cve_id": case["cve_id"],
    "repo": case["repo"],
    "fix_commits": case["fix_commits"],
    "patch_type": case["patch_type"],
    "deterministic_seed": case["deterministic_seed"],
    "review_status": "reviewed|partial|agent_failed|needs_manual_review",
    "vet_archetype": "",
    "reviewed_vet": {
      "root_cause_summary": "",
      "vulnerability_mechanism": "",
      "fix_mechanism": "",
      "scope": {
        "files": [],
        "functions": [],
        "components": [],
        "source_refs": [
          {
            "source_ref": "",
            "kind": "git_diff|git_snapshot|commit_message|step1_region|agent_git_inspection",
            "commit": "",
            "file_path": "",
            "function_context": "",
            "line_start": None,
            "line_end": None,
            "snippet": "",
            "strength_hint": "priority|prompt_context|context_only|experimental_certificate_candidate",
          }
        ],
      },
      "vulnerable_condition": {
        "necessary_conditions": [],
        "vulnerable_sequences": [],
        "missing_guards": [],
        "negative_evidence": [],
      },
      "fix_evidence": {"fix_guards": [], "changed_sequences": [], "semantic_change": ""},
      "guards": {"configuration_guards": [], "version_or_feature_guards": [], "preconditions": []},
      "uncertainty": [],
    },
    "admission_evidence": {
      "evidence_items": [
        {
          "evidence_id": "",
          "kind": "root_cause_file|root_cause_function|vulnerable_sequence|fix_guard|semantic_invariant|grep_pattern|history_hint",
          "value": "",
          "scope": {},
          "source_refs": [],
          "local_validation": {},
          "confidence": "low|medium|high",
          "risk_flags": [],
          "agent_claimed_uses": [],
          "allowed_uses": [],
          "blocked_uses": [],
          "block_reasons": [],
        }
      ]
    },
    "uncertainty": [],
    "agent_trace_id": "",
    "evidence_paths": [],
  }


def audit_review_quality(reviews: list[dict[str, Any]]) -> dict[str, Any]:
  """Post-run quality audit for P1 case-review outputs.

  This is intentionally stricter than JSON parsing. A case can be valid JSON
  and still be unsafe for Step2/Step3 admission if evidence is unstructured or
  certificate claims are not backed by concrete refs.
  """

  legacy_required = [
    "schema_version",
    "cve_id",
    "repo",
    "fix_commits",
    "patch_type",
    "deterministic_seed",
    "review_status",
    "vet_archetype",
    "root_cause_summary",
    "fix_summary",
    "theta",
    "step3_usable_evidence",
    "uncertainty",
    "agent_trace_id",
    "evidence_paths",
  ]
  v2_required = [
    "schema_version",
    "cve_id",
    "repo",
    "fix_commits",
    "patch_type",
    "deterministic_seed",
    "review_status",
    "vet_archetype",
    "reviewed_vet",
    "admission_evidence",
    "uncertainty",
    "agent_trace_id",
    "evidence_paths",
  ]
  findings: list[dict[str, Any]] = []
  counters: Counter[str] = Counter()

  for review in reviews:
    cve_id = str(review.get("cve_id") or "")
    repo = str(review.get("repo") or "")
    prefix = {"repo": repo, "cve_id": cve_id}
    schema_version = str(review.get("schema_version") or "")
    is_v2 = schema_version == STEP2_VET_SCHEMA_VERSION

    for key in (v2_required if is_v2 else legacy_required):
      if key not in review:
        findings.append({**prefix, "severity": "error", "issue": "missing_required_field", "field": key})
        counters["missing_required_field"] += 1

    if is_v2:
      reviewed_vet = _dict_value(review.get("reviewed_vet"))
      scope = _dict_value(reviewed_vet.get("scope"))
      vuln = _dict_value(reviewed_vet.get("vulnerable_condition"))
      fix = _dict_value(reviewed_vet.get("fix_evidence"))
      admission = _dict_value(review.get("admission_evidence"))
      evidence_items = _list_value(admission.get("evidence_items"))

      source_refs = _list_value(scope.get("source_refs"))
      if not source_refs:
        findings.append({**prefix, "severity": "error", "issue": "empty_source_refs"})
        counters["empty_source_refs"] += 1
      elif any(not isinstance(ref, dict) for ref in source_refs):
        findings.append({**prefix, "severity": "warn", "issue": "non_object_source_refs", "count": sum(1 for ref in source_refs if not isinstance(ref, dict))})
        counters["non_object_source_refs"] += 1

      if not _list_value(vuln.get("necessary_conditions")):
        findings.append({**prefix, "severity": "error", "issue": "empty_necessary_conditions"})
        counters["empty_necessary_conditions"] += 1
      if not _list_value(vuln.get("vulnerable_sequences")) and not _list_value(vuln.get("missing_guards")):
        findings.append({**prefix, "severity": "error", "issue": "empty_vulnerable_condition_evidence"})
        counters["empty_vulnerable_condition_evidence"] += 1
      if not _list_value(fix.get("fix_guards")) and not _list_value(fix.get("changed_sequences")) and not str(fix.get("semantic_change") or ""):
        findings.append({**prefix, "severity": "error", "issue": "empty_fix_evidence"})
        counters["empty_fix_evidence"] += 1
      if not _list_value(vuln.get("negative_evidence")):
        findings.append({**prefix, "severity": "warn", "issue": "empty_negative_evidence"})
        counters["empty_negative_evidence"] += 1

      reviewed_uncertainty = _list_value(reviewed_vet.get("uncertainty"))
      top_uncertainty = _list_value(review.get("uncertainty"))
      if review.get("review_status") == "reviewed" and (reviewed_uncertainty or top_uncertainty):
        findings.append({**prefix, "severity": "warn", "issue": "reviewed_vet_with_uncertainty", "count": len(reviewed_uncertainty) + len(top_uncertainty)})
        counters["reviewed_vet_with_uncertainty"] += 1

      if not evidence_items:
        findings.append({**prefix, "severity": "error", "issue": "empty_admission_evidence_items"})
        counters["empty_admission_evidence_items"] += 1
      for idx, item in enumerate(evidence_items):
        if not isinstance(item, dict):
          findings.append({**prefix, "severity": "error", "issue": "non_object_evidence_item", "index": idx})
          counters["non_object_evidence_item"] += 1
          continue
        item_prefix = {**prefix, "evidence_id": item.get("evidence_id") or f"index:{idx}"}
        for key in ("evidence_id", "kind", "value", "scope", "source_refs", "local_validation", "confidence", "risk_flags", "agent_claimed_uses", "allowed_uses", "blocked_uses", "block_reasons"):
          if key not in item:
            findings.append({**item_prefix, "severity": "error", "issue": "missing_evidence_item_field", "field": key})
            counters["missing_evidence_item_field"] += 1
        if not _list_value(item.get("source_refs")):
          findings.append({**item_prefix, "severity": "warn", "issue": "empty_evidence_item_source_refs"})
          counters["empty_evidence_item_source_refs"] += 1
        if any(not isinstance(ref, dict) for ref in _list_value(item.get("source_refs"))):
          findings.append({**item_prefix, "severity": "warn", "issue": "non_object_evidence_item_source_refs"})
          counters["non_object_evidence_item_source_refs"] += 1
        allowed = set(str(x) for x in _list_value(item.get("allowed_uses")))
        claimed = set(str(x) for x in _list_value(item.get("agent_claimed_uses")))
        if "hard_certificate" in allowed:
          findings.append({**item_prefix, "severity": "warn", "issue": "evidence_item_allows_hard_certificate"})
          counters["evidence_item_allows_hard_certificate"] += 1
        if "hard_certificate" in claimed and "hard_certificate" not in set(str(x) for x in _list_value(item.get("blocked_uses"))):
          findings.append({**item_prefix, "severity": "warn", "issue": "evidence_item_claimed_hard_certificate_not_blocked"})
          counters["evidence_item_claimed_hard_certificate_not_blocked"] += 1
      continue

    theta = _dict_value(review.get("theta"))
    scope = _dict_value(theta.get("Scope"))
    vuln = _dict_value(theta.get("VulnerableCondition"))
    fix = _dict_value(theta.get("FixEvidence"))
    cert = _dict_value(theta.get("CertificatePolicy"))
    ev = _dict_value(review.get("step3_usable_evidence"))

    source_refs = _list_value(scope.get("source_refs"))
    if not source_refs:
      findings.append({**prefix, "severity": "error", "issue": "empty_source_refs"})
      counters["empty_source_refs"] += 1
    elif any(not isinstance(ref, dict) for ref in source_refs):
      findings.append({**prefix, "severity": "warn", "issue": "non_object_source_refs", "count": sum(1 for ref in source_refs if not isinstance(ref, dict))})
      counters["non_object_source_refs"] += 1

    line_risk = _list_value(ev.get("line_risk_signals"))
    if not line_risk:
      findings.append({**prefix, "severity": "warn", "issue": "empty_line_risk_signals"})
      counters["empty_line_risk_signals"] += 1
    elif any(not isinstance(item, dict) for item in line_risk):
      findings.append({**prefix, "severity": "warn", "issue": "non_object_line_risk_signals", "count": sum(1 for item in line_risk if not isinstance(item, dict))})
      counters["non_object_line_risk_signals"] += 1

    if not _list_value(vuln.get("necessary_conditions")):
      findings.append({**prefix, "severity": "error", "issue": "empty_necessary_conditions"})
      counters["empty_necessary_conditions"] += 1
    if not _list_value(vuln.get("vulnerable_code_patterns")):
      findings.append({**prefix, "severity": "error", "issue": "empty_vulnerable_code_patterns"})
      counters["empty_vulnerable_code_patterns"] += 1
    if not _list_value(fix.get("fix_code_patterns")) and not _list_value(fix.get("added_guards")) and not _list_value(fix.get("removed_vulnerable_logic")):
      findings.append({**prefix, "severity": "error", "issue": "empty_fix_evidence"})
      counters["empty_fix_evidence"] += 1

    if not _list_value(vuln.get("negative_evidence")):
      findings.append({**prefix, "severity": "warn", "issue": "empty_negative_evidence"})
      counters["empty_negative_evidence"] += 1

    uncertainties = _list_value(review.get("uncertainty"))
    if review.get("review_status") == "reviewed" and uncertainties:
      findings.append({**prefix, "severity": "warn", "issue": "reviewed_with_uncertainty", "count": len(uncertainties)})
      counters["reviewed_with_uncertainty"] += 1

    if cert.get("cert_fixed_allowed") is True:
      hard_candidates = _list_value(cert.get("hard_certificate_candidates"))
      admission = _list_value(cert.get("admission_requirements"))
      if not hard_candidates:
        findings.append({**prefix, "severity": "warn", "issue": "cert_fixed_without_hard_certificate_candidates"})
        counters["cert_fixed_without_hard_certificate_candidates"] += 1
      if not admission:
        findings.append({**prefix, "severity": "warn", "issue": "cert_fixed_without_admission_requirements"})
        counters["cert_fixed_without_admission_requirements"] += 1
      if uncertainties:
        findings.append({**prefix, "severity": "warn", "issue": "cert_fixed_with_uncertainty", "count": len(uncertainties)})
        counters["cert_fixed_with_uncertainty"] += 1

    if cert.get("cert_absent_allowed") is True:
      if not _list_value(cert.get("hard_certificate_candidates")):
        findings.append({**prefix, "severity": "warn", "issue": "cert_absent_without_hard_certificate_candidates"})
        counters["cert_absent_without_hard_certificate_candidates"] += 1

    if not _list_value(cert.get("forbidden_hard_certificates")):
      findings.append({**prefix, "severity": "warn", "issue": "empty_forbidden_hard_certificates"})
      counters["empty_forbidden_hard_certificates"] += 1

  severity_counts = Counter(str(f.get("severity")) for f in findings)
  return {
    "schema_version": "vet_case_review_quality.v1",
    "reviewed_cases": len(reviews),
    "finding_count": len(findings),
    "severity_counts": dict(sorted(severity_counts.items())),
    "issue_counts": dict(sorted(counters.items())),
    "findings": findings,
    "gate": {
      "json_schema_reload": not any(f.get("issue") == "missing_required_field" for f in findings),
      "step2_admission_ready": False,
      "reason": "P1-A is a pilot review. Warnings must be resolved or explicitly waived before Step2/Step3 hard-certificate admission.",
    },
  }


def write_dry_run_artifacts(*, out_dir: str | Path, stage: str, plan: list[dict[str, Any]]) -> dict[str, Any]:
  out = Path(out_dir)
  summary = {
    "schema_version": "vet_case_review_summary.v1",
    "stage": stage,
    "dry_run": True,
    "planned_cases": len(plan),
    "repos": sorted({case["repo"] for case in plan}),
    "patch_type_counts": dict(sorted(Counter(case["patch_type"] for case in plan).items())),
    "fix_family_counts": dict(sorted(Counter(case["fix_family_kind"] for case in plan).items())),
    "deterministic_seed_counts": dict(sorted(Counter(case["deterministic_seed"] for case in plan).items())),
  }
  _write_json(out / "case_plan.json", plan)
  _write_jsonl(out / "case_plan.jsonl", plan)
  _write_json(out / "summary.json", summary)
  (out / "review_report.md").write_text(
    _report_md(title="VET Case Review Dry Run", summary=summary, rows=plan),
    encoding="utf-8",
  )
  return summary


def _load_step1_artifacts(*, step1_work: Path, repo: str, cve_id: str) -> dict[str, Any]:
  base = step1_work / repo / cve_id / "step1"
  output = base / "output"
  fix_evidence = base / "fix_evidence"
  quality = _load_json(output / "step1_quality_report.json") if (output / "step1_quality_report.json").exists() else {}
  commits = _read_jsonl(output / "commit_semantics.jsonl")
  regions = _read_jsonl(output / "semantic_regions.jsonl")
  manifest = _load_json(fix_evidence / "manifest.json") if (fix_evidence / "manifest.json").exists() else {}
  top_regions = sorted(regions, key=lambda r: (float(r.get("root_cause_score") or 0), len(r.get("source_refs") or [])), reverse=True)[:8]
  return {
    "step1_base": str(base),
    "output_dir": str(output),
    "fix_evidence_dir": str(fix_evidence),
    "quality": quality,
    "commit_semantics": commits,
    "top_semantic_regions": top_regions,
    "fix_evidence_manifest": manifest,
  }


def _system_prompt() -> str:
  return "\n".join([
    "You are a VulnVersion P1 VET case-review agent.",
    "Your task is to construct a root-cause-level Vulnerability Existence Theorem for one CVE.",
    "Do not infer affected versions. Do not create a Step3 tag plan. Do not use ground-truth affected versions.",
    "Use only provided evidence and read-only git/bash inspection if needed.",
    "Output one strict JSON object only. No markdown. No code fences.",
  ])


def _prompt(case: dict[str, Any], step1: dict[str, Any]) -> str:
  required_schema = _step2_v2_required_schema(case)
  packet = {
    "task": "p1_vet_case_review",
    "case": case,
    "step1_artifacts": step1,
    "rules": [
      "Recover why the vulnerability exists, not just what the patch changes.",
      "Output reviewed_vet as the semantic layer: root cause, vulnerability mechanism, fix mechanism, scope, guards, and uncertainty.",
      "Output admission_evidence.evidence_items as the evidence layer for Step3 scoring and tag-judge prompt context.",
      "Do not leave reviewed_vet empty. If root cause is unclear, fill the best-supported hypothesis and put the unresolved part in reviewed_vet.uncertainty.",
      "Do not omit any evidence item field. Every evidence item must include evidence_id, kind, value, scope, source_refs, local_validation, confidence, risk_flags, agent_claimed_uses, allowed_uses, blocked_uses, and block_reasons.",
      "Every evidence item source_refs must be a list of structured objects, not plain strings.",
      "Every evidence item local_validation must describe how the evidence can be checked at a tag or why it is context-only.",
      "Do not decide final affected versions or final tag verdicts.",
      "Do not mark touched file, generic token, or commit message as a hard certificate.",
      "agent_claimed_uses may include priority or prompt_context; hard_certificate claims must be blocked unless fully justified.",
      "Leave allowed_uses empty if an Admission gate must decide later; use blocked_uses/block_reasons for unsafe uses.",
      "Every evidence item needs structured source_refs and local_validation.",
      "If review_status is reviewed, uncertainty must not contain unresolved root-cause questions.",
      "If evidence is insufficient, use needs_manual_review.",
      "If packet evidence is compressed or incomplete, inspect listed fix_evidence files or use read-only git commands.",
  ],
    "required_output_schema": required_schema,
  }
  return "\n".join([
    "Review this CVE and output strict JSON matching required_output_schema.",
    "The JSON must be directly parseable.",
    "",
    json.dumps(packet, ensure_ascii=False, indent=2),
  ])


def _fallback_json_prompt(case: dict[str, Any]) -> str:
  """Compact repair prompt used after a non-JSON model response."""

  minimal_schema = _step2_v2_required_schema(case)
  return "\n".join([
    "Your previous response was not parseable JSON.",
    "Do not continue analysis. Convert your prior analysis into exactly one valid JSON object.",
    "No markdown. No code fences. No comments. No trailing commas.",
    "If you are uncertain, set review_status to partial or needs_manual_review.",
    "Use this exact top-level schema and fill all fields:",
    json.dumps(minimal_schema, ensure_ascii=False, indent=2),
  ])


def _normalize_review(raw: dict[str, Any], case: dict[str, Any], *, status: str | None = None) -> dict[str, Any]:
  review = dict(raw) if isinstance(raw, dict) else {}
  review.setdefault("schema_version", STEP2_VET_SCHEMA_VERSION)
  # Case identity and deterministic metadata must never be rewritten by the
  # agent. The agent may refine vet_archetype, not the original seed/patch info.
  review["cve_id"] = str(case["cve_id"])
  review["repo"] = str(case["repo"])
  review["fix_commits"] = list(case["fix_commits"])
  review["patch_type"] = str(case["patch_type"])
  review["patch_chunk_count"] = int(case.get("patch_chunk_count") or 0)
  review["semantic_region_count"] = int(case.get("semantic_region_count") or 0)
  review["fix_family_kind"] = str(case.get("fix_family_kind") or "")
  review["deterministic_seed"] = str(case["deterministic_seed"])
  review["review_status"] = status or str(review.get("review_status") or "partial")
  review.setdefault("vet_archetype", review["deterministic_seed"])
  if review["schema_version"] == STEP2_VET_SCHEMA_VERSION:
    reviewed_vet = _dict_value(review.get("reviewed_vet"))
    if not reviewed_vet:
      reviewed_vet = _empty_reviewed_vet()
    else:
      base = _empty_reviewed_vet()
      base.update(reviewed_vet)
      for key in ("scope", "vulnerable_condition", "fix_evidence", "guards"):
        merged = _dict_value(_empty_reviewed_vet().get(key))
        merged.update(_dict_value(reviewed_vet.get(key)))
        base[key] = merged
      reviewed_vet = base
    review["reviewed_vet"] = reviewed_vet
    admission = _dict_value(review.get("admission_evidence"))
    evidence_items = _list_value(admission.get("evidence_items"))
    review["admission_evidence"] = {"evidence_items": evidence_items}
    review.pop("theta", None)
    review.pop("step3_usable_evidence", None)
  else:
    review.setdefault("root_cause_summary", "")
    review.setdefault("fix_summary", "")
    review.setdefault("theta", {})
    review.setdefault("step3_usable_evidence", {})
  review.setdefault("uncertainty", [])
  review.setdefault("agent_trace_id", "")
  review.setdefault("evidence_paths", [])
  return review


def should_resume_existing_review(
  review: dict[str, Any],
  *,
  retry_agent_failed: bool,
  retry_quality_failed: bool = False,
  quality_failed_case_ids: set[str] | None = None,
) -> bool:
  """Return whether an existing parsed review should be reused.

  Normal resume should reuse successful reviews. When a previous run was
  interrupted by network/provider failures, `--retry-agent-failed` lets us
  retry only failed cases without deleting artifacts manually. When quality
  retry is enabled, only CVEs listed by the prior quality audit are rerun.
  """

  if retry_quality_failed and str(review.get("cve_id") or "") in (quality_failed_case_ids or set()):
    return False
  if not retry_agent_failed:
    return True
  return str(review.get("review_status") or "") != "agent_failed"


def _summaries(reviews: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
  archetype = Counter(str(r.get("vet_archetype") or "unknown") for r in reviews)
  cert_absent = Counter(str(((r.get("theta") or {}).get("CertificatePolicy") or {}).get("cert_absent_allowed")) for r in reviews)
  cert_fixed = Counter(str(((r.get("theta") or {}).get("CertificatePolicy") or {}).get("cert_fixed_allowed")) for r in reviews)
  evidence_kind_counts: Counter[str] = Counter()
  allowed_use_counts: Counter[str] = Counter()
  blocked_use_counts: Counter[str] = Counter()
  evidence: dict[str, list[dict[str, Any]]] = defaultdict(list)
  for r in reviews:
    if r.get("schema_version") == STEP2_VET_SCHEMA_VERSION:
      ev = r.get("admission_evidence") if isinstance(r.get("admission_evidence"), dict) else {}
      for item in _list_value(ev.get("evidence_items")):
        if not isinstance(item, dict):
          continue
        evidence_kind_counts[str(item.get("kind") or "unknown")] += 1
        for use in _list_value(item.get("allowed_uses")):
          allowed_use_counts[str(use)] += 1
        for use in _list_value(item.get("blocked_uses")):
          blocked_use_counts[str(use)] += 1
    else:
      ev = r.get("step3_usable_evidence") if isinstance(r.get("step3_usable_evidence"), dict) else {}
    evidence[str(r.get("cve_id"))].append(ev)
  return (
    {"vet_archetype_counts": dict(sorted(archetype.items()))},
    {
      "schema_version": "admission_evidence_summary.v1",
      "deprecated_legacy_cert_absent_allowed": dict(sorted(cert_absent.items())),
      "deprecated_legacy_cert_fixed_allowed": dict(sorted(cert_fixed.items())),
      "evidence_kind_counts": dict(sorted(evidence_kind_counts.items())),
      "allowed_use_counts": dict(sorted(allowed_use_counts.items())),
      "blocked_use_counts": dict(sorted(blocked_use_counts.items())),
    },
    dict(evidence),
  )


def run_case_review(
  *,
  dataset_path: str | Path = DEFAULT_DATASET,
  selected_cases_path: str | Path = DEFAULT_SELECTED_CASES,
  vet_seeds_path: str | Path = DEFAULT_VET_SEEDS,
  step1_work: str | Path = DEFAULT_STEP1_WORK,
  stage: str,
  out_dir: str | Path,
  dry_run: bool,
  resume: bool,
  retry_agent_failed: bool,
  retry_quality_failed: bool,
  timeout_s: float,
  enable_readonly_git_tools: bool,
  agent_backend: str,
) -> dict[str, Any]:
  plan = build_case_plan(
    dataset_path=dataset_path,
    selected_cases_path=selected_cases_path,
    vet_seeds_path=vet_seeds_path,
    stage=stage,
  )
  out = Path(out_dir)
  if dry_run:
    return write_dry_run_artifacts(out_dir=out, stage=stage, plan=plan)

  if agent_backend != "opencode":
    raise ValueError("only_opencode_backend_is_currently_supported")

  cfg = Config()
  agent = OpenCodeRuntime.from_config(cfg, timeout_s=timeout_s, health_check=True, project_root=Path.cwd())
  diagnostics = agent.diagnostics()
  _write_json(out / "opencode_diagnostics.json", diagnostics)
  agent_calls = out / "agent_calls"
  agent_calls.mkdir(parents=True, exist_ok=True)

  reviews: list[dict[str, Any]] = []
  failures: list[dict[str, Any]] = []
  uncertain: list[dict[str, Any]] = []
  events: list[dict[str, Any]] = []
  tools = {"bash": bool(enable_readonly_git_tools), "git": bool(enable_readonly_git_tools)}
  quality_retry_ids = quality_failed_case_ids(out) if retry_quality_failed else set()

  for case in plan:
    cve_id = case["cve_id"]
    repo = case["repo"]
    parsed_path = agent_calls / f"{repo}__{cve_id}.parsed.json"
    if resume and parsed_path.exists():
      review = _normalize_review(_load_json(parsed_path), case)
      if should_resume_existing_review(
        review,
        retry_agent_failed=retry_agent_failed,
        retry_quality_failed=retry_quality_failed,
        quality_failed_case_ids=quality_retry_ids,
      ):
        reviews.append(review)
        events.append({"cve_id": cve_id, "repo": repo, "status": "resumed"})
        continue
      if cve_id in quality_retry_ids:
        events.append({"cve_id": cve_id, "repo": repo, "status": "retrying_quality_failed"})
      else:
        events.append({"cve_id": cve_id, "repo": repo, "status": "retrying_agent_failed"})

    start = time.monotonic()
    step1 = _load_step1_artifacts(step1_work=Path(step1_work), repo=repo, cve_id=cve_id)
    system = _system_prompt()
    prompt = _prompt(case, step1)
    trace_id = f"{repo}__{cve_id}"
    (agent_calls / f"{trace_id}.system.txt").write_text(system, encoding="utf-8")
    (agent_calls / f"{trace_id}.prompt.txt").write_text(prompt, encoding="utf-8")
    session_id = ""

    try:
      session_id = agent.create_readonly_session(title=f"P1 VET {repo} {cve_id}")
      try:
        raw = agent.run_json(
          session_id=session_id,
          prompt=prompt,
          system=system,
          tools=tools,
          timeout_s=timeout_s,
          metadata={"stage": stage, "repo": repo, "cve_id": cve_id},
        )
      except OpenCodeJSONParseError:
        fallback = _fallback_json_prompt(case)
        (agent_calls / f"{trace_id}.fallback_prompt.txt").write_text(fallback, encoding="utf-8")
        raw = agent.run_json(
          session_id=session_id,
          prompt=fallback,
          system=system,
          tools=tools,
          timeout_s=timeout_s,
          metadata={"stage": stage, "repo": repo, "cve_id": cve_id, "fallback": True},
        )
      (agent_calls / f"{trace_id}.response.json").write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
      review = _normalize_review(raw, case)
      review["agent_trace_id"] = session_id
      review["latency_s"] = round(time.monotonic() - start, 3)
      review["evidence_paths"] = sorted(set(list(review.get("evidence_paths") or []) + [
        step1.get("step1_base", ""),
        step1.get("fix_evidence_dir", ""),
      ]))
      _write_json(parsed_path, review)
      reviews.append(review)
      if review.get("review_status") in {"needs_manual_review", "partial"}:
        uncertain.append(review)
      events.append({"cve_id": cve_id, "repo": repo, "status": "completed", "latency_s": review["latency_s"]})
    except Exception as exc:
      failure = _normalize_review({}, case, status="agent_failed")
      failure["uncertainty"] = [f"{type(exc).__name__}: {exc}"]
      failure["agent_trace_id"] = session_id
      failure["latency_s"] = round(time.monotonic() - start, 3)
      failures.append(failure)
      reviews.append(failure)
      events.append({"cve_id": cve_id, "repo": repo, "status": "agent_failed", "error": failure["uncertainty"][0]})
      _write_json(parsed_path, failure)
      if session_id:
        try:
          _write_json(agent_calls / f"{trace_id}.messages.json", agent.export_session_messages(session_id=session_id))
        except Exception as export_exc:
          _write_json(agent_calls / f"{trace_id}.messages_export_error.json", {"error": f"{type(export_exc).__name__}: {export_exc}"})

  archetype_summary, certificate_policy_summary, step3_evidence = _summaries(reviews)
  quality_report = audit_review_quality(reviews)
  summary = {
    "schema_version": "vet_case_review_summary.v1",
    "stage": stage,
    "dry_run": False,
    "planned_cases": len(plan),
    "completed_cases": sum(1 for r in reviews if r.get("review_status") not in {"agent_failed"}),
    "agent_failed_cases": sum(1 for r in reviews if r.get("review_status") == "agent_failed"),
    "needs_manual_review_cases": sum(1 for r in reviews if r.get("review_status") == "needs_manual_review"),
    "quality_retry_requested": bool(retry_quality_failed),
    "quality_retry_case_count": len(quality_retry_ids),
    "quality_retry_case_ids": sorted(quality_retry_ids),
    "review_status_counts": dict(sorted(Counter(str(r.get("review_status") or "unknown") for r in reviews).items())),
    "quality": {
      "finding_count": quality_report["finding_count"],
      "severity_counts": quality_report["severity_counts"],
      "step2_admission_ready": quality_report["gate"]["step2_admission_ready"],
    },
    "opencode": {
      "health": diagnostics.get("health"),
      "provider_id": diagnostics.get("provider_id"),
      "model_id": diagnostics.get("model_id"),
      "agent_name": diagnostics.get("agent_name"),
    },
  }
  _write_json(out / "case_plan.json", plan)
  _write_jsonl(out / "case_plan.jsonl", plan)
  _write_jsonl(out / "per_case_vet.jsonl", reviews)
  _write_json(out / "archetype_summary.json", archetype_summary)
  _write_json(out / "certificate_policy_summary.json", certificate_policy_summary)
  _write_json(out / "admission_evidence_summary.json", certificate_policy_summary)
  _write_json(out / "step3_evidence_candidates.json", step3_evidence)
  _write_json(out / "review_quality_report.json", quality_report)
  _write_json(out / "quality_findings.json", quality_report["findings"])
  _write_json(out / "uncertain_cases.json", uncertain)
  _write_json(out / "agent_failure_cases.json", failures)
  _write_jsonl(out / "trace.jsonl", events)
  _write_json(out / "summary.json", summary)
  (out / "review_report.md").write_text(
    _report_md(title="VET Case Review", summary=summary, rows=reviews),
    encoding="utf-8",
  )
  return summary


def main(argv: list[str] | None = None) -> int:
  parser = argparse.ArgumentParser()
  parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
  parser.add_argument("--selected-cases", default=str(DEFAULT_SELECTED_CASES))
  parser.add_argument("--vet-seeds", default=str(DEFAULT_VET_SEEDS))
  parser.add_argument("--step1-work", default=str(DEFAULT_STEP1_WORK))
  parser.add_argument("--stage", choices=sorted(STAGES), default="pilot_9")
  parser.add_argument("--out", default=str(DEFAULT_OUT))
  parser.add_argument("--agent-backend", default="opencode")
  parser.add_argument("--enable-readonly-git-tools", action="store_true")
  parser.add_argument("--resume", action="store_true")
  parser.add_argument("--retry-agent-failed", action="store_true")
  parser.add_argument("--retry-quality-failed", action="store_true")
  parser.add_argument("--dry-run", action="store_true")
  parser.add_argument("--timeout-s", type=float, default=900.0)
  args = parser.parse_args(argv)
  summary = run_case_review(
    dataset_path=args.dataset,
    selected_cases_path=args.selected_cases,
    vet_seeds_path=args.vet_seeds,
    step1_work=args.step1_work,
    stage=args.stage,
    out_dir=args.out,
    dry_run=args.dry_run,
    resume=args.resume,
    retry_agent_failed=args.retry_agent_failed,
    retry_quality_failed=args.retry_quality_failed,
    timeout_s=args.timeout_s,
    enable_readonly_git_tools=args.enable_readonly_git_tools,
    agent_backend=args.agent_backend,
  )
  print(json.dumps(summary, ensure_ascii=False, indent=2))
  return 0 if int(summary.get("agent_failed_cases", 0)) == 0 else 1


if __name__ == "__main__":
  raise SystemExit(main())
