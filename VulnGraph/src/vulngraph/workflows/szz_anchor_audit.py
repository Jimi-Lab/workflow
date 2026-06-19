from __future__ import annotations

import csv
import json
import re
import statistics
import subprocess
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

from vulngraph.agent_backends.base import RootCauseBackend
from vulngraph.agent_io.model_view_contract import build_szz_anchor_model_view
from vulngraph.agent_io.szz_handoff_contract import validate_szz_handoff
from vulngraph.agent_io.szz_handoff_schema import (
  PreFixCandidateInventoryV1,
  RootCauseSzzHandoffV1,
  parse_szz_anchor_selection,
)
from vulngraph.services.blame_runner import CommandRunner, run_blame_for_anchors
from vulngraph.services.pre_fix_candidates import (
  GitPreFixSourceReader,
  PreFixSourceReader,
  build_pre_fix_candidate_inventory,
)


DEFAULT_SZZ_AUDIT_CVES = [
  "CVE-2020-14212",
  "CVE-2020-19667",
  "CVE-2020-8231",
  "CVE-2020-11984",
  "CVE-2022-0171",
  "CVE-2022-0286",
  "CVE-2020-15389",
  "CVE-2020-1967",
  "CVE-2020-11869",
  "CVE-2020-13164",
]

SEMANTIC_LABEL_FIELDS = (
  "mechanism_correct",
  "vulnerable_predicate_correct",
  "fix_predicate_correct",
  "anchor_file_correct",
  "anchor_hunk_correct",
  "evidence_link_precise",
  "unsupported_inference",
  "minimality_correct",
  "overall_root_cause_correct",
  "severity",
)


def verify_szz_audit_preconditions(
  cve_ids: list[str],
  *,
  root_cause_run: str | Path,
  dataset: str | Path,
  repo_root: str | Path,
  opencode_health: dict[str, Any] | None,
  provider_id: str,
  model_id: str,
  require_semantic_labels: bool = True,
  mode: str = "formal",
  allow_shallow_diagnostic: bool = False,
) -> dict[str, Any]:
  root = Path(root_cause_run)
  records = _read_json(Path(dataset))
  structural_cases: dict[str, bool] = {}
  for cve_id in cve_ids:
    case = root / cve_id
    structural_cases[cve_id] = (
      _read_optional_json(case / "contract_lint.json").get("ok") is True
      and _read_optional_json(case / "structural_validation.json").get("ok") is True
      and _read_optional_json(case / "ingestion_result.json").get("status") == "ingested_raw"
    )

  label_status = _semantic_label_status(root / "evaluation.csv", cve_ids)
  commit_checks: list[dict[str, Any]] = []
  shallow_cases: list[str] = []
  for cve_id in cve_ids:
    record = records.get(cve_id, {})
    repo_path = Path(repo_root) / str(record.get("repo") or "")
    shallow = _run_git(repo_path, ["rev-parse", "--is-shallow-repository"])
    if shallow["exit_code"] == 0 and shallow["stdout"].strip().lower() == "true":
      shallow_cases.append(cve_id)
    for fix_sha in _flatten_fix_commits(record.get("fixing_commits")):
      commit = _run_git(repo_path, ["cat-file", "-e", f"{fix_sha}^{{commit}}"])
      parent = _run_git(repo_path, ["rev-parse", f"{fix_sha}^"])
      commit_checks.append(
        {
          "cve_id": cve_id,
          "repo_path": str(repo_path),
          "fix_commit_sha": fix_sha,
          "commit_exists": commit["exit_code"] == 0,
          "parent_exists": parent["exit_code"] == 0 and bool(parent["stdout"].strip()),
          "parent_sha": parent["stdout"].strip() if parent["exit_code"] == 0 else "",
        }
      )

  blocking: list[str] = []
  if not all(structural_cases.values()) or len(structural_cases) != len(cve_ids):
    blocking.append("optimized_root_cause_not_structurally_accepted")
  if require_semantic_labels and not label_status["complete"]:
    blocking.append("optimized_semantic_labels_incomplete")
  if not commit_checks or not all(item["commit_exists"] and item["parent_exists"] for item in commit_checks):
    blocking.append("fix_commit_or_parent_missing")
  if not opencode_health or opencode_health.get("healthy") is False:
    blocking.append("opencode_unhealthy")
  if not provider_id or not model_id:
    blocking.append("provider_or_model_missing")
  if mode == "formal" and shallow_cases and not allow_shallow_diagnostic:
    blocking.append("shallow_history_in_formal_run")
  return {
    "ready": not blocking,
    "mode": mode,
    "require_semantic_labels": require_semantic_labels,
    "allow_shallow_diagnostic": allow_shallow_diagnostic,
    "requested_cves": cve_ids,
    "structurally_accepted": sum(1 for value in structural_cases.values() if value),
    "structural_cases": structural_cases,
    "semantic_labels_complete": label_status["complete"],
    "semantic_label_gaps": label_status["gaps"],
    "fix_commits_with_parents": sum(1 for item in commit_checks if item["commit_exists"] and item["parent_exists"]),
    "fix_commit_checks": commit_checks,
    "shallow_history_cases": shallow_cases,
    "opencode_health": opencode_health or {},
    "provider_id": provider_id,
    "model_id": model_id,
    "model_availability": "configured; first real invocation is the final availability check",
    "blocking_reasons": blocking,
  }


def run_szz_anchor_audit_case(
  *,
  cve_id: str,
  root_cause_case_dir: str | Path,
  repo_path: str | Path,
  out_dir: str | Path,
  backend: RootCauseBackend,
  source_reader: PreFixSourceReader | None = None,
  command_runner: CommandRunner | None = None,
  top_k_per_patch_family: int = 40,
) -> dict[str, Any]:
  started = time.monotonic()
  case_dir = Path(root_cause_case_dir)
  output_dir = Path(out_dir)
  output_dir.mkdir(parents=True, exist_ok=True)
  repo = Path(repo_path)
  required = {
    "packet": case_dir / "root_cause_packet.json",
    "root_cause": case_dir / "parsed_output.json",
    "trace": case_dir / "evidence_trace.json",
    "contract": case_dir / "contract_lint.json",
    "structural": case_dir / "structural_validation.json",
    "ingestion": case_dir / "ingestion_result.json",
  }
  missing = [str(path) for path in required.values() if not path.exists()]
  if missing:
    result = _failure_result(cve_id, "root_cause_artifact_missing", missing, started)
    _write_json(output_dir / "ingestion_result.json", result)
    return result

  packet = _read_json(required["packet"])
  root_cause = _read_json(required["root_cause"])
  root_trace = _read_json(required["trace"])
  contract = _read_json(required["contract"])
  structural = _read_json(required["structural"])
  ingestion = _read_json(required["ingestion"])
  if not contract.get("ok") or not structural.get("ok") or ingestion.get("status") != "ingested_raw":
    result = _failure_result(
      cve_id,
      "root_cause_not_structurally_accepted",
      [f"contract={contract.get('ok')}", f"structural={structural.get('ok')}", f"ingestion={ingestion.get('status')}"],
      started,
    )
    _write_json(output_dir / "ingestion_result.json", result)
    return result

  enriched_packet = _attach_wrapper_observation_refs(packet, root_trace)
  reader = source_reader or GitPreFixSourceReader(repo)
  try:
    inventory = build_pre_fix_candidate_inventory(packet=enriched_packet, repo_path=repo, source_reader=reader)
  except Exception as error:
    result = _failure_result(cve_id, "candidate_inventory_failed", [str(error)], started)
    _write_json(output_dir / "ingestion_result.json", result)
    return result
  inventory_data = inventory.model_dump(mode="json")
  _write_json(output_dir / "candidate_inventory.json", inventory_data)
  _write_json(output_dir / "pre_fix_candidate_inventory.json", inventory_data)
  compact_inventory = _selection_inventory(
    inventory_data,
    root_cause,
    top_k_per_patch_family=top_k_per_patch_family,
  )
  _write_json(output_dir / "compact_candidate_inventory.json", compact_inventory)

  prompt = _render_handoff_prompt(root_cause, inventory_data, top_k_per_patch_family=top_k_per_patch_family)
  compaction_metrics = {
    key: compact_inventory.get(key)
    for key in (
      "original_candidate_count",
      "compacted_candidate_count",
      "mandatory_candidate_count",
      "budget_overflow_count",
      "candidate_without_patch_family",
      "root_cause_hunks_total",
      "root_cause_hunks_requested_total",
      "root_cause_hunks_without_blameable_candidate",
      "root_cause_hunks_preserved",
      "root_cause_hunks_dropped",
      "root_cause_hunk_retention_rate",
      "fix_commits_total",
      "fix_commits_prompt_covered",
    )
  }
  compaction_metrics["candidate_count"] = len(inventory.candidates)
  compaction_metrics["prompt_bytes"] = len(prompt.encode("utf-8"))
  (output_dir / "szz_handoff_prompt.txt").write_text(prompt, encoding="utf-8")
  response = backend.generate(
    prompt,
    {
      "cve_id": cve_id,
      "root_cause": root_cause,
      "candidate_inventory": compact_inventory,
      "system_prompt": "Select only wrapper-owned candidate IDs. Return strict JSON only.",
    },
  )
  for name in ("raw_response.txt", "raw_szz_handoff_response.txt"):
    (output_dir / name).write_text(response.raw_text, encoding="utf-8")
  if response.status != "ok":
    result = _failure_result(cve_id, f"backend_{response.status}", [response.error or response.status], started)
    result.update({"backend_name": response.backend_name, "backend_type": response.backend_type, **compaction_metrics})
    _write_json(output_dir / "parse_error.json", result)
    _write_json(output_dir / "ingestion_result.json", result)
    return result

  parsed = parse_szz_anchor_selection(response.raw_text)
  if not parsed.ok or parsed.output is None or parsed.data is None:
    result = _failure_result(cve_id, "handoff_parse_error", [parsed.error or "parse failed"], started)
    result.update({"backend_name": response.backend_name, "backend_type": response.backend_type, **compaction_metrics})
    _write_json(output_dir / "parse_error.json", result)
    _write_json(output_dir / "ingestion_result.json", result)
    return result
  for name in ("parsed_selection.json", "parsed_szz_handoff.json"):
    _write_json(output_dir / name, parsed.data)

  validation = validate_szz_handoff(parsed.output, inventory, root_cause)
  lint_data = validation.to_dict()
  _write_json(output_dir / "contract_lint.json", lint_data)
  resolved_data = [item.model_dump(mode="json") for item in validation.resolved_anchors]
  for name in ("resolved_anchors.json", "resolved_pre_fix_anchors.json"):
    _write_json(output_dir / name, resolved_data)
  if not validation.ok:
    result = _failure_result(cve_id, "contract_rejected", validation.errors, started)
    result.update(
      {
        "backend_name": response.backend_name,
        "backend_type": response.backend_type,
        "invented_ids": validation.invented_ids,
        "taxonomy": validation.taxonomy,
        **compaction_metrics,
      }
    )
    _write_json(output_dir / "blame_trace.json", {"status": "not_run", "reason": "contract_rejected"})
    _write_json(output_dir / "candidate_commits.json", [])
    _write_json(output_dir / "ingestion_result.json", result)
    _write_manual_review(output_dir / "manual_anchor_review_template.csv", cve_id, resolved_data)
    return result

  blame = run_blame_for_anchors(repo, validation.resolved_anchors, command_runner=command_runner)
  blame_data = blame.to_dict()
  candidate_commits = _mark_fix_series_candidates(blame.candidate_commits, inventory, reader)
  blame_data["candidate_commits"] = candidate_commits
  _write_json(output_dir / "blame_trace.json", blame_data)
  _write_json(output_dir / "candidate_commits.json", candidate_commits)
  _write_manual_review(output_dir / "manual_anchor_review_template.csv", cve_id, resolved_data)

  status = "ingested_raw_candidate" if blame.status in {"success", "partial"} else "raw_candidate_censored"
  direct_old_side = sum(
    1 for item in validation.resolved_anchors
    if item.selection_mode in {"direct_deleted_line", "modified_old_side"}
  )
  add_only_semantic = sum(
    1 for item in validation.resolved_anchors if item.selection_mode == "add_only_semantic_target"
  )
  context_only = sum(1 for item in validation.resolved_anchors if item.selection_mode == "context_fallback")
  blamed_anchor_ids = {
    str(item.get("anchor_id")) for item in blame.line_records if item.get("status") == "success" and item.get("anchor_id")
  }
  result = {
    "cve_id": cve_id,
    "status": status,
    "lifecycle": "raw_candidate",
    "backend_name": response.backend_name,
    "backend_type": response.backend_type,
    "parse_status": parsed.format,
    "contract_ok": validation.ok,
    "resolved_anchor_count": len(validation.resolved_anchors),
    "direct_old_side_anchor_count": direct_old_side,
    "add_only_semantic_anchor_count": add_only_semantic,
    "context_only_anchor_count": context_only,
    "blame_worthy_anchor_count": len(validation.resolved_anchors) - context_only,
    "blame_success_anchor_count": len(blamed_anchor_ids),
    **compaction_metrics,
    "candidate_commit_count": len(candidate_commits),
    "blame_status": blame.status,
    "patch_family_coverage": validation.patch_family_coverage,
    "fix_commit_coverage": validation.fix_commit_coverage,
    "invented_ids": validation.invented_ids,
    "taxonomy": validation.taxonomy,
    "usage": response.usage,
    "raw_response_chars": len(response.raw_text),
    "git_query_count": len(inventory.git_trace) + len(blame.git_trace),
    "fix_series_candidates_excluded": sum(1 for item in candidate_commits if item.get("excluded")),
    "duration_s": round(time.monotonic() - started, 6),
    "errors": blame.errors,
  }
  _write_json(output_dir / "ingestion_result.json", result)
  (output_dir / "report.md").write_text(_render_case_report(result), encoding="utf-8")
  return result


def replay_szz_anchor_audit_case(
  *,
  cve_id: str,
  root_cause_case_dir: str | Path,
  previous_case_dir: str | Path,
  repo_path: str | Path,
  out_dir: str | Path,
  source_reader: PreFixSourceReader | None = None,
  command_runner: CommandRunner | None = None,
  top_k_per_patch_family: int = 40,
) -> dict[str, Any]:
  started = time.monotonic()
  case_dir = Path(root_cause_case_dir)
  previous_dir = Path(previous_case_dir)
  output_dir = Path(out_dir)
  output_dir.mkdir(parents=True, exist_ok=True)
  repo = Path(repo_path)

  required = {
    "root_cause": case_dir / "parsed_output.json",
    "contract": case_dir / "contract_lint.json",
    "structural": case_dir / "structural_validation.json",
    "ingestion": case_dir / "ingestion_result.json",
    "inventory": previous_dir / "candidate_inventory.json",
  }
  missing = [str(path) for path in required.values() if not path.exists()]
  if missing:
    result = _failure_result(cve_id, "replay_artifact_missing", missing, started)
    _write_json(output_dir / "ingestion_result.json", result)
    return result

  root_cause = _read_json(required["root_cause"])
  contract = _read_json(required["contract"])
  structural = _read_json(required["structural"])
  ingestion = _read_json(required["ingestion"])
  if not contract.get("ok") or not structural.get("ok") or ingestion.get("status") != "ingested_raw":
    result = _failure_result(
      cve_id,
      "root_cause_not_structurally_accepted",
      [f"contract={contract.get('ok')}", f"structural={structural.get('ok')}", f"ingestion={ingestion.get('status')}"],
      started,
    )
    _write_json(output_dir / "ingestion_result.json", result)
    return result

  inventory_data = _read_json(required["inventory"])
  inventory = PreFixCandidateInventoryV1.model_validate(inventory_data)
  _write_json(output_dir / "candidate_inventory.json", inventory_data)
  _write_json(output_dir / "pre_fix_candidate_inventory.json", inventory_data)

  compact_inventory = _read_optional_json(previous_dir / "compact_candidate_inventory.json")
  if not compact_inventory:
    compact_inventory = _selection_inventory(
      inventory_data,
      root_cause,
      top_k_per_patch_family=top_k_per_patch_family,
    )
  _write_json(output_dir / "compact_candidate_inventory.json", compact_inventory)
  compaction_metrics = _compaction_metrics_from_inventory(
    inventory,
    compact_inventory,
    previous_dir=previous_dir,
  )

  raw_response_path = previous_dir / "raw_szz_handoff_response.txt"
  if not raw_response_path.exists():
    raw_response_path = previous_dir / "raw_response.txt"
  if raw_response_path.exists():
    raw_text = raw_response_path.read_text(encoding="utf-8")
    parsed = parse_szz_anchor_selection(raw_text)
    for name in ("raw_response.txt", "raw_szz_handoff_response.txt"):
      (output_dir / name).write_text(raw_text, encoding="utf-8")
    if not parsed.ok or parsed.output is None or parsed.data is None:
      result = _failure_result(cve_id, "handoff_parse_error", [parsed.error or "parse failed"], started)
      result.update({"backend_name": "replay_existing_handoff", "backend_type": "replay_existing_handoff", **compaction_metrics})
      _write_json(output_dir / "parse_error.json", result)
      _write_json(output_dir / "ingestion_result.json", result)
      return result
    handoff = parsed.output
    parsed_data = parsed.data
    parse_status = parsed.format
  else:
    parsed_path = previous_dir / "parsed_szz_handoff.json"
    if not parsed_path.exists():
      parsed_path = previous_dir / "parsed_selection.json"
    if not parsed_path.exists():
      result = _failure_result(cve_id, "replay_handoff_missing", [str(previous_dir)], started)
      result.update({"backend_name": "replay_existing_handoff", "backend_type": "replay_existing_handoff", **compaction_metrics})
      _write_json(output_dir / "ingestion_result.json", result)
      return result
    parsed_data = _read_json(parsed_path)
    handoff = RootCauseSzzHandoffV1.model_validate(parsed_data)
    parse_status = "parsed_json_artifact"
    raw_text = json.dumps(parsed_data, ensure_ascii=False)

  for name in ("parsed_selection.json", "parsed_szz_handoff.json"):
    _write_json(output_dir / name, parsed_data)

  validation = validate_szz_handoff(handoff, inventory, root_cause)
  lint_data = validation.to_dict()
  _write_json(output_dir / "contract_lint.json", lint_data)
  resolved_data = [item.model_dump(mode="json") for item in validation.resolved_anchors]
  for name in ("resolved_anchors.json", "resolved_pre_fix_anchors.json"):
    _write_json(output_dir / name, resolved_data)
  _write_manual_review(output_dir / "manual_anchor_review_template.csv", cve_id, resolved_data)
  if not validation.ok:
    result = _failure_result(cve_id, "contract_rejected", validation.errors, started)
    result.update(
      {
        "backend_name": "replay_existing_handoff",
        "backend_type": "replay_existing_handoff",
        "parse_status": parse_status,
        "contract_ok": False,
        "invented_ids": validation.invented_ids,
        "taxonomy": validation.taxonomy,
        **compaction_metrics,
      }
    )
    _write_json(output_dir / "blame_trace.json", {"status": "not_run", "reason": "contract_rejected"})
    _write_json(output_dir / "candidate_commits.json", [])
    _write_json(output_dir / "ingestion_result.json", result)
    (output_dir / "report.md").write_text(_render_case_report(result), encoding="utf-8")
    return result

  blame = run_blame_for_anchors(repo, validation.resolved_anchors, command_runner=command_runner)
  reader = source_reader or GitPreFixSourceReader(repo)
  blame_data = blame.to_dict()
  candidate_commits = _mark_fix_series_candidates(blame.candidate_commits, inventory, reader)
  blame_data["candidate_commits"] = candidate_commits
  _write_json(output_dir / "blame_trace.json", blame_data)
  _write_json(output_dir / "candidate_commits.json", candidate_commits)

  direct_old_side = sum(
    1 for item in validation.resolved_anchors
    if item.selection_mode in {"direct_deleted_line", "modified_old_side"}
  )
  add_only_semantic = sum(
    1 for item in validation.resolved_anchors if item.selection_mode == "add_only_semantic_target"
  )
  context_only = sum(1 for item in validation.resolved_anchors if item.selection_mode == "context_fallback")
  blamed_anchor_ids = {
    str(item.get("anchor_id")) for item in blame.line_records if item.get("status") == "success" and item.get("anchor_id")
  }
  status = "ingested_raw_candidate" if blame.status in {"success", "partial"} else "raw_candidate_censored"
  result = {
    "cve_id": cve_id,
    "status": status,
    "lifecycle": "raw_candidate",
    "backend_name": "replay_existing_handoff",
    "backend_type": "replay_existing_handoff",
    "parse_status": parse_status,
    "contract_ok": validation.ok,
    "resolved_anchor_count": len(validation.resolved_anchors),
    "direct_old_side_anchor_count": direct_old_side,
    "add_only_semantic_anchor_count": add_only_semantic,
    "context_only_anchor_count": context_only,
    "blame_worthy_anchor_count": len(validation.resolved_anchors) - context_only,
    "blame_success_anchor_count": len(blamed_anchor_ids),
    **compaction_metrics,
    "candidate_commit_count": len(candidate_commits),
    "blame_status": blame.status,
    "patch_family_coverage": validation.patch_family_coverage,
    "fix_commit_coverage": validation.fix_commit_coverage,
    "invented_ids": validation.invented_ids,
    "taxonomy": validation.taxonomy,
    "usage": {},
    "raw_response_chars": len(raw_text),
    "git_query_count": len(blame.git_trace),
    "fix_series_candidates_excluded": sum(1 for item in candidate_commits if item.get("excluded")),
    "duration_s": round(time.monotonic() - started, 6),
    "errors": blame.errors,
  }
  _write_json(output_dir / "ingestion_result.json", result)
  (output_dir / "report.md").write_text(_render_case_report(result), encoding="utf-8")
  return result


def replay_szz_anchor_audit(
  cve_ids: list[str],
  *,
  root_cause_run: str | Path,
  previous_run: str | Path,
  dataset: str | Path,
  repo_root: str | Path,
  out_dir: str | Path,
  top_k_per_patch_family: int = 40,
) -> dict[str, Any]:
  root_cause_root = Path(root_cause_run)
  previous_root = Path(previous_run)
  output_root = Path(out_dir)
  output_root.mkdir(parents=True, exist_ok=True)
  dataset_records = _read_json(Path(dataset))
  results: list[dict[str, Any]] = []
  for cve_id in cve_ids:
    record = dataset_records.get(cve_id, {})
    repo_name = str(record.get("repo") or "")
    repo_path = Path(repo_root) / repo_name
    if not repo_name or not repo_path.exists():
      result = _failure_result(cve_id, "repo_missing", [str(repo_path)], time.monotonic())
      (output_root / cve_id).mkdir(parents=True, exist_ok=True)
      _write_json(output_root / cve_id / "ingestion_result.json", result)
    else:
      result = replay_szz_anchor_audit_case(
        cve_id=cve_id,
        root_cause_case_dir=root_cause_root / cve_id,
        previous_case_dir=previous_root / cve_id,
        repo_path=repo_path,
        out_dir=output_root / cve_id,
        top_k_per_patch_family=top_k_per_patch_family,
      )
    results.append(result)
  summary = _aggregate_summary(results, output_root)
  summary.update(
    {
      "execution_mode": "replay_existing_handoff",
      "previous_run": str(previous_root),
      "model_invocation_count": 0,
      "fixture_invocation_count": 0,
    }
  )
  _write_json(output_root / "summary.json", summary)
  _write_json(output_root / "failure_taxonomy.json", _failure_taxonomy(results))
  _write_batch_csv(output_root / "szz_anchor_audit.csv", results)
  _write_batch_review(output_root / "manual_anchor_review_template.csv", output_root, cve_ids)
  (output_root / "report.md").write_text(_render_batch_report(summary, results), encoding="utf-8")
  return summary


def run_szz_anchor_audit(
  cve_ids: list[str],
  *,
  root_cause_run: str | Path,
  dataset: str | Path,
  repo_root: str | Path,
  out_dir: str | Path,
  backend: RootCauseBackend,
  top_k_per_patch_family: int = 40,
) -> dict[str, Any]:
  root_cause_root = Path(root_cause_run)
  output_root = Path(out_dir)
  output_root.mkdir(parents=True, exist_ok=True)
  dataset_records = _read_json(Path(dataset))
  results: list[dict[str, Any]] = []
  for cve_id in cve_ids:
    record = dataset_records.get(cve_id, {})
    repo_name = str(record.get("repo") or "")
    repo_path = Path(repo_root) / repo_name
    if not repo_name or not repo_path.exists():
      result = _failure_result(cve_id, "repo_missing", [str(repo_path)], time.monotonic())
      (output_root / cve_id).mkdir(parents=True, exist_ok=True)
      _write_json(output_root / cve_id / "ingestion_result.json", result)
    else:
      result = run_szz_anchor_audit_case(
        cve_id=cve_id,
        root_cause_case_dir=root_cause_root / cve_id,
        repo_path=repo_path,
        out_dir=output_root / cve_id,
        backend=backend,
        top_k_per_patch_family=top_k_per_patch_family,
      )
    results.append(result)
  summary = _aggregate_summary(results, output_root)
  _write_json(output_root / "summary.json", summary)
  _write_json(output_root / "failure_taxonomy.json", _failure_taxonomy(results))
  _write_batch_csv(output_root / "szz_anchor_audit.csv", results)
  _write_batch_review(output_root / "manual_anchor_review_template.csv", output_root, cve_ids)
  (output_root / "report.md").write_text(_render_batch_report(summary, results), encoding="utf-8")
  return summary


def _attach_wrapper_observation_refs(packet: dict[str, Any], trace: dict[str, Any]) -> dict[str, Any]:
  enriched = deepcopy(packet)
  observations = [
    item for item in trace.get("git_observations", []) or []
    if item.get("source") == "wrapper_git_trace"
    and item.get("valid_evidence") is True
    and item.get("observation_kind") == "patch_diff"
  ]
  by_hunk: dict[str, list[str]] = {}
  for observation in observations:
    for hunk_id in observation.get("patch_hunk_ids", []) or []:
      by_hunk.setdefault(str(hunk_id), []).append(str(observation.get("id")))
  for item in enriched.get("patch_evidence", []) or []:
    if item.get("type") == "PatchHunk":
      item.setdefault("content", {})["git_observation_refs"] = sorted(set(by_hunk.get(str(item.get("id")), [])))
  return enriched


def _render_handoff_prompt(
  root_cause: dict[str, Any],
  inventory: dict[str, Any],
  *,
  top_k_per_patch_family: int = 40,
) -> str:
  template_path = Path(__file__).resolve().parents[1] / "prompts" / "szz_anchor_v1.md"
  template = template_path.read_text(encoding="utf-8")
  compact_inventory = _selection_inventory(
    inventory,
    root_cause,
    top_k_per_patch_family=top_k_per_patch_family,
  )
  model_view = build_szz_anchor_model_view(
    root_cause,
    compact_inventory,
    top_k_per_patch_family=top_k_per_patch_family,
  )
  return (
    template.replace("{{SZZ_ANCHOR_MODEL_VIEW}}", json.dumps(model_view, ensure_ascii=False, separators=(",", ":")))
    .replace("{{OUTPUT_SCHEMA}}", json.dumps(RootCauseSzzHandoffV1.model_json_schema(), ensure_ascii=False, indent=2))
  )


def _selection_inventory(
  inventory: dict[str, Any],
  root_cause: dict[str, Any] | None = None,
  *,
  top_k_per_patch_family: int = 40,
  line_text_limit: int = 180,
) -> dict[str, Any]:
  candidate_fields = (
    "candidate_id",
    "fix_set_id",
    "patch_family_id",
    "fix_commit_id",
    "patch_hunk_id",
    "path_before",
    "path_after",
    "old_line_start",
    "old_line_end",
    "line_text",
    "function_id",
    "function_name",
    "candidate_source",
    "change_type",
    "selection_mode_eligibility",
    "git_observation_refs",
    "generated_file",
    "test_file",
    "documentation_file",
    "changelog_file",
    "comment_only",
    "blank_line",
    "source_file",
    "exclusion_reasons",
  )
  candidates = list(inventory.get("candidates", []) or [])
  family_ids = list((inventory.get("fix_families") or {}).keys())
  family_id_set = set(family_ids)
  family_candidates = {
    family_id: [item for item in candidates if item.get("patch_family_id") == family_id]
    for family_id in family_ids
  }
  isolated_candidates = [item for item in candidates if item.get("patch_family_id") not in family_id_set]
  root_cause_hunks = {
    str(item.get("patch_hunk_id"))
    for item in (root_cause or {}).get("code_anchors", []) or []
    if item.get("patch_hunk_id")
  }
  mandatory_by_id: dict[str, dict[str, Any]] = {}
  blameable_root_cause_hunks: set[str] = set()

  for patch_hunk_id in sorted(root_cause_hunks):
    eligible = [
      item for item in candidates
      if item.get("patch_hunk_id") == patch_hunk_id
      and item.get("patch_family_id") in family_id_set
      and _is_blameable_prompt_candidate(item)
    ]
    if eligible:
      blameable_root_cause_hunks.add(patch_hunk_id)
      chosen = min(eligible, key=lambda item: _candidate_compaction_key(item, root_cause or {}))
      mandatory_by_id[str(chosen.get("candidate_id"))] = chosen

  fix_commit_ids: set[str] = set()
  for family_id in family_ids:
    by_commit: dict[str, list[dict[str, Any]]] = {}
    for candidate in family_candidates[family_id]:
      fix_commit_id = str(candidate.get("fix_commit_id") or "")
      if fix_commit_id:
        fix_commit_ids.add(fix_commit_id)
        by_commit.setdefault(fix_commit_id, []).append(candidate)
    for commit_candidates in by_commit.values():
      eligible = [item for item in commit_candidates if _is_blameable_prompt_candidate(item)]
      if eligible:
        chosen = min(eligible, key=lambda item: _candidate_compaction_key(item, root_cause or {}))
        mandatory_by_id[str(chosen.get("candidate_id"))] = chosen

  selected: list[dict[str, Any]] = []
  selected_ids: set[str] = set()
  budget_overflow_count = 0
  for family_id in family_ids:
    ranked = sorted(family_candidates[family_id], key=lambda item: _candidate_compaction_key(item, root_cause or {}))
    family_selected = list(ranked[:max(1, top_k_per_patch_family)])
    family_selected_ids = {str(item.get("candidate_id")) for item in family_selected}
    for mandatory in mandatory_by_id.values():
      if mandatory.get("patch_family_id") == family_id and str(mandatory.get("candidate_id")) not in family_selected_ids:
        family_selected.append(mandatory)
        family_selected_ids.add(str(mandatory.get("candidate_id")))
    budget_overflow_count += max(0, len(family_selected) - max(1, top_k_per_patch_family))
    for candidate in family_selected:
      candidate_id = str(candidate.get("candidate_id"))
      if candidate_id not in selected_ids:
        selected.append(candidate)
        selected_ids.add(candidate_id)

  preserved_hunks = {
    str(item.get("patch_hunk_id"))
    for item in selected
    if item.get("patch_hunk_id") in blameable_root_cause_hunks
  }
  prompt_fix_commits = {str(item.get("fix_commit_id")) for item in selected if item.get("fix_commit_id")}
  root_cause_hunks_total = len(blameable_root_cause_hunks)
  root_cause_hunks_preserved = len(preserved_hunks)

  return {
    "cve_id": inventory.get("cve_id"),
    "repo_id": inventory.get("repo_id"),
    "fix_families": inventory.get("fix_families", {}),
    "issues": inventory.get("issues", []),
    "original_candidate_count": len(candidates),
    "compacted_candidate_count": len(selected),
    "mandatory_candidate_count": len(mandatory_by_id),
    "budget_overflow_count": budget_overflow_count,
    "candidate_without_patch_family": len(isolated_candidates),
    "isolated_candidate_ids": sorted(str(item.get("candidate_id") or "") for item in isolated_candidates),
    "root_cause_hunks_total": root_cause_hunks_total,
    "root_cause_hunks_requested_total": len(root_cause_hunks),
    "root_cause_hunks_without_blameable_candidate": len(root_cause_hunks - blameable_root_cause_hunks),
    "root_cause_hunks_preserved": root_cause_hunks_preserved,
    "root_cause_hunks_dropped": root_cause_hunks_total - root_cause_hunks_preserved,
    "root_cause_hunk_retention_rate": (
      root_cause_hunks_preserved / root_cause_hunks_total if root_cause_hunks_total else None
    ),
    "fix_commits_total": len(fix_commit_ids),
    "fix_commits_prompt_covered": len(prompt_fix_commits & fix_commit_ids),
    "top_k_per_patch_family": top_k_per_patch_family,
    "line_text_limit": line_text_limit,
    "candidates": [
      _compact_candidate_fields(candidate, candidate_fields, line_text_limit)
      for candidate in selected
    ],
  }


def _is_blameable_prompt_candidate(candidate: dict[str, Any]) -> bool:
  return (
    candidate.get("source_file") is True
    and candidate.get("comment_only") is not True
    and candidate.get("blank_line") is not True
    and candidate.get("test_file") is not True
    and candidate.get("documentation_file") is not True
    and candidate.get("generated_file") is not True
    and candidate.get("changelog_file") is not True
  )


def _compact_candidate_fields(
  candidate: dict[str, Any],
  candidate_fields: tuple[str, ...],
  line_text_limit: int,
) -> dict[str, Any]:
  item = {field: candidate.get(field) for field in candidate_fields}
  text = str(item.get("line_text") or "")
  if len(text) > line_text_limit:
    item["line_text"] = text[:line_text_limit] + "...[truncated]"
    item["line_text_truncated"] = True
  else:
    item["line_text_truncated"] = False
  return item


def _candidate_compaction_key(candidate: dict[str, Any], root_cause: dict[str, Any]) -> tuple[Any, ...]:
  source_rank = {"deleted_line": 0, "pre_fix_function_body": 1, "hunk_context": 2}
  if candidate.get("candidate_source") == "deleted_line" and candidate.get("change_type") == "modify":
    source_score = 0
  else:
    source_score = source_rank.get(str(candidate.get("candidate_source") or ""), 9)
  source_file_score = 0 if candidate.get("source_file") is True else 1
  noise_score = 0 if not any(
    candidate.get(key) is True
    for key in ("comment_only", "blank_line", "test_file", "documentation_file", "generated_file", "changelog_file")
  ) else 1
  shared_evidence_score = 0 if _candidate_shares_root_cause_evidence(candidate, root_cause) else 1
  add_only_relevance = 0 if _add_only_candidate_is_semantically_relevant(candidate, root_cause) else 1
  return (
    source_score,
    source_file_score,
    noise_score,
    shared_evidence_score,
    add_only_relevance,
    int(candidate.get("old_line_start") or 0),
    str(candidate.get("candidate_id") or ""),
  )


def _candidate_shares_root_cause_evidence(candidate: dict[str, Any], root_cause: dict[str, Any]) -> bool:
  refs = set(candidate.get("git_observation_refs") or [])
  if not refs:
    return False
  for key in ("root_cause_hypotheses", "vulnerable_predicates", "fix_predicates", "guard_conditions", "negative_conditions"):
    for item in root_cause.get(key, []) or []:
      if refs & set(item.get("git_observation_refs") or []):
        return True
  return False


def _add_only_candidate_is_semantically_relevant(candidate: dict[str, Any], root_cause: dict[str, Any]) -> bool:
  if candidate.get("change_type") != "add_only" or candidate.get("candidate_source") != "pre_fix_function_body":
    return True
  haystack = " ".join(
    str(value or "")
    for value in (
      candidate.get("line_text"),
      candidate.get("function_name"),
      candidate.get("path_before"),
      candidate.get("patch_hunk_id"),
    )
  ).lower()
  root_text = json.dumps(root_cause, ensure_ascii=False).lower()
  tokens = {token for token in re.findall(r"[a-zA-Z_][a-zA-Z0-9_]{2,}", haystack) if len(token) >= 4}
  return bool(tokens and any(token in root_text for token in tokens))


def _mark_fix_series_candidates(
  commits: list[dict[str, Any]],
  inventory: PreFixCandidateInventoryV1,
  reader: PreFixSourceReader,
) -> list[dict[str, Any]]:
  fix_shas = {item.fix_commit_sha for item in inventory.candidates}
  fix_families = set(inventory.fix_families)
  output: list[dict[str, Any]] = []
  for commit in commits:
    item = deepcopy(commit)
    reasons: list[str] = []
    sha = str(item.get("commit_sha") or "")
    if sha in fix_shas:
      reasons.append("is_fix_commit")
    try:
      if sha and reader.patch_family_id(sha) in fix_families:
        reasons.append("patch_family_matches_fix")
    except Exception:
      item.setdefault("uncertainty", []).append("candidate_patch_family_unavailable")
    item["excluded"] = bool(reasons)
    item["exclusion_reasons"] = reasons
    item["lifecycle"] = "raw_candidate"
    output.append(item)
  return output


def _compaction_metrics_from_inventory(
  inventory: PreFixCandidateInventoryV1,
  compact_inventory: dict[str, Any],
  *,
  previous_dir: Path,
) -> dict[str, Any]:
  prompt_path = previous_dir / "szz_handoff_prompt.txt"
  return {
    "original_candidate_count": int(compact_inventory.get("original_candidate_count") or len(inventory.candidates)),
    "compacted_candidate_count": int(compact_inventory.get("compacted_candidate_count") or 0),
    "mandatory_candidate_count": int(compact_inventory.get("mandatory_candidate_count") or 0),
    "budget_overflow_count": int(compact_inventory.get("budget_overflow_count") or 0),
    "candidate_without_patch_family": int(compact_inventory.get("candidate_without_patch_family") or 0),
    "root_cause_hunks_total": int(compact_inventory.get("root_cause_hunks_total") or 0),
    "root_cause_hunks_requested_total": int(compact_inventory.get("root_cause_hunks_requested_total") or 0),
    "root_cause_hunks_without_blameable_candidate": int(
      compact_inventory.get("root_cause_hunks_without_blameable_candidate") or 0
    ),
    "root_cause_hunks_preserved": int(compact_inventory.get("root_cause_hunks_preserved") or 0),
    "root_cause_hunks_dropped": int(compact_inventory.get("root_cause_hunks_dropped") or 0),
    "root_cause_hunk_retention_rate": compact_inventory.get("root_cause_hunk_retention_rate"),
    "fix_commits_total": int(compact_inventory.get("fix_commits_total") or 0),
    "fix_commits_prompt_covered": int(compact_inventory.get("fix_commits_prompt_covered") or 0),
    "candidate_count": len(inventory.candidates),
    "prompt_bytes": prompt_path.stat().st_size if prompt_path.exists() else 0,
  }


def _aggregate_summary(results: list[dict[str, Any]], out_root: Path) -> dict[str, Any]:
  inventory_built = [item for item in results if "original_candidate_count" in item]
  agent_accepted = [item for item in results if item.get("contract_ok") is True]
  censored = [
    item for item in agent_accepted
    if item.get("status") == "raw_candidate_censored" or item.get("blame_status") == "shallow_history"
  ]
  blame_evaluable = [item for item in agent_accepted if item.get("blame_status") and item not in censored]
  resolved_counts = [int(item.get("resolved_anchor_count") or 0) for item in agent_accepted]
  evaluable_resolved_counts = [int(item.get("resolved_anchor_count") or 0) for item in blame_evaluable]
  candidate_counts = [int(item.get("candidate_count") or 0) for item in inventory_built]
  total_resolved = sum(resolved_counts)
  total_candidates = sum(candidate_counts)
  family_statuses = [
    status
    for item in agent_accepted
    for status in (item.get("patch_family_coverage") or {}).values()
    if isinstance(status, dict)
  ]
  commit_statuses = [
    status
    for item in agent_accepted
    for status in (item.get("fix_commit_coverage") or {}).values()
    if isinstance(status, dict)
  ]
  total_fix_families = len(family_statuses)
  anchored_fix_families = sum(1 for status in family_statuses if status.get("anchored"))
  accounted_fix_families = sum(1 for status in family_statuses if status.get("accounted"))
  uncertain_fix_families = sum(1 for status in family_statuses if status.get("uncertain"))
  prompt_bytes = [int(item.get("prompt_bytes") or 0) for item in inventory_built]
  original_counts = [int(item.get("original_candidate_count") or item.get("candidate_count") or 0) for item in inventory_built]
  compacted_counts = [int(item.get("compacted_candidate_count") or 0) for item in inventory_built]
  evaluable_anchor_total = sum(evaluable_resolved_counts)
  root_cause_hunks_total = sum(int(item.get("root_cause_hunks_total") or 0) for item in inventory_built)
  root_cause_hunks_requested_total = sum(int(item.get("root_cause_hunks_requested_total") or 0) for item in inventory_built)
  root_cause_hunks_without_blameable_candidate = sum(
    int(item.get("root_cause_hunks_without_blameable_candidate") or 0) for item in inventory_built
  )
  root_cause_hunks_preserved = sum(int(item.get("root_cause_hunks_preserved") or 0) for item in inventory_built)
  fix_commits_total = sum(int(item.get("fix_commits_total") or 0) for item in inventory_built)
  fix_commits_prompt_covered = sum(int(item.get("fix_commits_prompt_covered") or 0) for item in inventory_built)
  return {
    "cases_total": len(results),
    "requested_count": len(results),
    "inventory_built_count": len(inventory_built),
    "agent_accepted_count": len(agent_accepted),
    "blame_evaluable_count": len(blame_evaluable),
    "censored_count": len(censored),
    "candidate_inventory_coverage": sum(1 for count in candidate_counts if count > 0) / len(results) if results else 0.0,
    "statement_localization_precision": None,
    "statement_localization_precision_status": "requires_manual_anchor_review",
    "handoff_parse_success": sum(1 for item in results if item.get("parse_status") in {"json", "fenced_json"}),
    "handoff_contract_acceptance": sum(1 for item in results if item.get("contract_ok") is True),
    "resolved_anchor_count": sum(resolved_counts),
    "direct_old_side_anchor_count": sum(int(item.get("direct_old_side_anchor_count") or 0) for item in agent_accepted),
    "add_only_semantic_anchor_count": sum(int(item.get("add_only_semantic_anchor_count") or 0) for item in agent_accepted),
    "context_only_anchor_count": sum(int(item.get("context_only_anchor_count") or 0) for item in agent_accepted),
    "context_only_noise_rate": (
      sum(int(item.get("context_only_anchor_count") or 0) for item in agent_accepted) / total_resolved if total_resolved else None
    ),
    "blame_worthy_anchor_rate": (
      sum(int(item.get("blame_worthy_anchor_count") or 0) for item in agent_accepted) / total_resolved if total_resolved else None
    ),
    "blame_success_rate": (
      sum(int(item.get("blame_success_anchor_count") or 0) for item in blame_evaluable) / evaluable_anchor_total
      if evaluable_anchor_total else None
    ),
    "candidate_recall_diagnostic": sum(1 for count in candidate_counts if count > 0) / len(results) if results else 0.0,
    "candidates_per_anchor": total_candidates / total_resolved if total_resolved else None,
    "blame_success_cases": sum(1 for item in results if item.get("blame_status") in {"success", "partial"}),
    "shallow_history_cases": [item.get("cve_id") for item in results if item.get("blame_status") == "shallow_history"],
    "unique_candidate_commits": sum(int(item.get("candidate_commit_count") or 0) for item in blame_evaluable),
    "candidate_commit_ready_cases": sum(1 for item in blame_evaluable if int(item.get("candidate_commit_count") or 0) > 0),
    "median_candidates_per_case": statistics.median(candidate_counts) if candidate_counts else 0,
    "multi_anchor_coverage": sum(1 for count in resolved_counts if count > 1),
    "fix_family_anchor_coverage": {
      "anchored": anchored_fix_families,
      "total": total_fix_families,
      "rate": anchored_fix_families / total_fix_families if total_fix_families else None,
    },
    "fix_family_accounted_coverage": {
      "accounted": accounted_fix_families,
      "total": total_fix_families,
      "rate": accounted_fix_families / total_fix_families if total_fix_families else None,
    },
    "fix_family_uncertain_coverage": {
      "uncertain": uncertain_fix_families,
      "total": total_fix_families,
      "rate": uncertain_fix_families / total_fix_families if total_fix_families else None,
    },
    "fix_commit_anchor_coverage": {
      "anchored": sum(1 for status in commit_statuses if status.get("anchored")),
      "total": len(commit_statuses),
      "rate": (
        sum(1 for status in commit_statuses if status.get("anchored")) / len(commit_statuses)
        if commit_statuses else None
      ),
    },
    "fix_commit_accounted_coverage": {
      "accounted": sum(1 for status in commit_statuses if status.get("accounted")),
      "total": len(commit_statuses),
      "rate": (
        sum(1 for status in commit_statuses if status.get("accounted")) / len(commit_statuses)
        if commit_statuses else None
      ),
    },
    "original_candidate_count": sum(original_counts),
    "compacted_candidate_count": sum(compacted_counts),
    "mandatory_candidate_count": sum(int(item.get("mandatory_candidate_count") or 0) for item in inventory_built),
    "budget_overflow_count": sum(int(item.get("budget_overflow_count") or 0) for item in inventory_built),
    "candidate_without_patch_family": sum(int(item.get("candidate_without_patch_family") or 0) for item in inventory_built),
    "root_cause_hunks_total": root_cause_hunks_total,
    "root_cause_hunks_requested_total": root_cause_hunks_requested_total,
    "root_cause_hunks_without_blameable_candidate": root_cause_hunks_without_blameable_candidate,
    "root_cause_hunks_preserved": root_cause_hunks_preserved,
    "root_cause_hunks_dropped": root_cause_hunks_total - root_cause_hunks_preserved,
    "root_cause_hunk_retention_rate": (
      root_cause_hunks_preserved / root_cause_hunks_total if root_cause_hunks_total else None
    ),
    "fix_commits_total": fix_commits_total,
    "fix_commits_prompt_covered": fix_commits_prompt_covered,
    "fix_commit_prompt_coverage_rate": (
      fix_commits_prompt_covered / fix_commits_total if fix_commits_total else None
    ),
    "average_prompt_bytes": statistics.mean(prompt_bytes) if prompt_bytes else 0,
    "fix_series_candidates_excluded": sum(int(item.get("fix_series_candidates_excluded") or 0) for item in blame_evaluable),
    "git_query_count": sum(int(item.get("git_query_count") or 0) for item in inventory_built),
    "total_duration_s": sum(float(item.get("duration_s") or 0.0) for item in results),
    "total_raw_response_chars": sum(int(item.get("raw_response_chars") or 0) for item in inventory_built),
    "invented_ids": sorted({invented for item in results for invented in item.get("invented_ids", []) or []}),
    "output_dir": str(out_root),
    "results": results,
  }


def _failure_taxonomy(results: list[dict[str, Any]]) -> dict[str, Any]:
  categories: dict[str, list[str]] = {}
  for item in results:
    status = str(item.get("status") or "unknown")
    if status not in {"ingested_raw_candidate", "raw_candidate_censored"}:
      categories.setdefault(status, []).append(str(item.get("cve_id") or ""))
    if item.get("blame_status") == "shallow_history":
      categories.setdefault("shallow_history", []).append(str(item.get("cve_id") or ""))
    if int(item.get("candidate_count") or 0) > 1000:
      categories.setdefault("candidate_inventory_large", []).append(str(item.get("cve_id") or ""))
    for key, count in (item.get("taxonomy") or {}).items():
      if count:
        categories.setdefault(key, []).append(str(item.get("cve_id") or ""))
  return {key: {"count": len(values), "cases": values} for key, values in sorted(categories.items())}


def _write_manual_review(path: Path, cve_id: str, anchors: list[dict[str, Any]]) -> None:
  columns = [
    "cve_id", "anchor_id", "candidate_id", "root_cause_binding_correct", "parent_line_exists",
    "line_role_correct", "minimal_anchor", "blame_worthy", "context_only_noise", "fix_family_covered", "notes",
  ]
  with path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=columns)
    writer.writeheader()
    for anchor in anchors:
      writer.writerow({"cve_id": cve_id, "anchor_id": anchor.get("anchor_id"), "candidate_id": anchor.get("candidate_id")})


def _write_batch_review(path: Path, out_root: Path, cve_ids: list[str]) -> None:
  rows: list[dict[str, str]] = []
  columns: list[str] = []
  for cve_id in cve_ids:
    case_path = out_root / cve_id / "manual_anchor_review_template.csv"
    if not case_path.exists():
      continue
    with case_path.open(newline="", encoding="utf-8") as handle:
      reader = csv.DictReader(handle)
      columns = reader.fieldnames or columns
      rows.extend(dict(row) for row in reader)
  if not columns:
    columns = ["cve_id", "anchor_id", "candidate_id", "notes"]
  with path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=columns)
    writer.writeheader()
    writer.writerows(rows)


def _write_batch_csv(path: Path, results: list[dict[str, Any]]) -> None:
  columns = [
    "cve_id", "status", "backend_type", "parse_status", "contract_ok", "candidate_count",
    "original_candidate_count", "compacted_candidate_count", "prompt_bytes",
    "root_cause_hunks_total", "root_cause_hunks_preserved",
    "fix_commits_total", "fix_commits_prompt_covered",
    "resolved_anchor_count", "blame_status", "candidate_commit_count", "duration_s",
  ]
  with path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=columns)
    writer.writeheader()
    for item in results:
      writer.writerow({key: item.get(key, "") for key in columns})


def _render_case_report(result: dict[str, Any]) -> str:
  return "\n".join(
    [
      f"# {result.get('cve_id')} SZZ Anchor Audit",
      "",
      f"- Status: `{result.get('status')}`",
      f"- Lifecycle: `{result.get('lifecycle')}`",
      f"- Backend: `{result.get('backend_type')}/{result.get('backend_name')}`",
      f"- Resolved anchors: {result.get('resolved_anchor_count', 0)}",
      f"- Candidates: {result.get('original_candidate_count', 0)} -> {result.get('compacted_candidate_count', 0)}",
      f"- Prompt bytes: {result.get('prompt_bytes', 0)}",
      f"- Root Cause hunks preserved: {result.get('root_cause_hunks_preserved', 0)}/{result.get('root_cause_hunks_total', 0)}",
      f"- Root Cause hunks without blameable candidate: {result.get('root_cause_hunks_without_blameable_candidate', 0)}",
      f"- Fix commits prompt-covered: {result.get('fix_commits_prompt_covered', 0)}/{result.get('fix_commits_total', 0)}",
      f"- Blame status: `{result.get('blame_status')}`",
      "- Boundary: candidate commits are audit-only raw candidates, not validated BICs.",
    ]
  ) + "\n"


def _render_batch_report(summary: dict[str, Any], results: list[dict[str, Any]]) -> str:
  family = summary.get("fix_family_anchor_coverage") or {}
  accounted = summary.get("fix_family_accounted_coverage") or {}
  uncertain = summary.get("fix_family_uncertain_coverage") or {}
  commit_anchored = summary.get("fix_commit_anchor_coverage") or {}
  commit_accounted = summary.get("fix_commit_accounted_coverage") or {}
  fixture_mode = results and all(item.get("backend_type") == "fixture" for item in results)
  lines = [
    "# Root Cause to SZZ Anchor Audit",
    "",
    "This run measures parent-side statement localization and blame candidate retrieval. It does not measure BIC correctness or infer affected versions.",
    "Fixture mode only proves pipeline integrity; it does not prove semantic anchor quality." if fixture_mode or not results else "",
    "",
    "## Metrics",
    "",
    f"- Cases: {summary.get('cases_total', 0)}",
    f"- Requested / inventory built / agent accepted / blame evaluable / censored: "
    f"{summary.get('requested_count', 0)} / {summary.get('inventory_built_count', 0)} / "
    f"{summary.get('agent_accepted_count', 0)} / {summary.get('blame_evaluable_count', 0)} / {summary.get('censored_count', 0)}",
    f"- Candidate inventory coverage: {summary.get('candidate_inventory_coverage', 0):.3f}",
    f"- Statement localization precision: not computed ({summary.get('statement_localization_precision_status', 'requires_manual_anchor_review')})",
    f"- Handoff parse success: {summary.get('handoff_parse_success', 0)}",
    f"- Contract acceptance: {summary.get('handoff_contract_acceptance', 0)}",
    f"- Resolved anchors: {summary.get('resolved_anchor_count', 0)}",
    f"- Direct old-side anchors: {summary.get('direct_old_side_anchor_count', 0)}",
    f"- Add-only semantic anchors: {summary.get('add_only_semantic_anchor_count', 0)}",
    f"- Context-only noise rate: {summary.get('context_only_noise_rate')}",
    f"- Blame-worthy anchor rate: {summary.get('blame_worthy_anchor_rate')}",
    f"- Blame success rate: {summary.get('blame_success_rate')}",
    f"- Candidate recall diagnostic: {summary.get('candidate_recall_diagnostic')}",
    f"- Candidates per anchor: {summary.get('candidates_per_anchor')}",
    f"- Fix-family coverage anchored: {family.get('anchored', 0)}/{family.get('total', 0)} ({family.get('rate')})",
    f"- Fix-family accounted coverage: {accounted.get('accounted', 0)}/{accounted.get('total', 0)} ({accounted.get('rate')})",
    f"- Fix-family uncertain coverage: {uncertain.get('uncertain', 0)}/{uncertain.get('total', 0)} ({uncertain.get('rate')})",
    f"- Fix-commit anchored coverage: {commit_anchored.get('anchored', 0)}/{commit_anchored.get('total', 0)} ({commit_anchored.get('rate')})",
    f"- Fix-commit accounted coverage: {commit_accounted.get('accounted', 0)}/{commit_accounted.get('total', 0)} ({commit_accounted.get('rate')})",
    f"- Original candidate count: {summary.get('original_candidate_count', 0)}",
    f"- Compacted candidate count: {summary.get('compacted_candidate_count', 0)}",
    f"- Mandatory candidates / budget overflow: {summary.get('mandatory_candidate_count', 0)} / {summary.get('budget_overflow_count', 0)}",
    f"- Candidates without patch family: {summary.get('candidate_without_patch_family', 0)}",
    f"- Root Cause hunk retention: {summary.get('root_cause_hunks_preserved', 0)}/{summary.get('root_cause_hunks_total', 0)} ({summary.get('root_cause_hunk_retention_rate')})",
    f"- Root Cause hunks requested / without blameable candidate: {summary.get('root_cause_hunks_requested_total', 0)} / {summary.get('root_cause_hunks_without_blameable_candidate', 0)}",
    f"- Fix commits prompt-covered: {summary.get('fix_commits_prompt_covered', 0)}/{summary.get('fix_commits_total', 0)} ({summary.get('fix_commit_prompt_coverage_rate')})",
    f"- Average prompt bytes: {summary.get('average_prompt_bytes', 0)}",
    f"- Multi-anchor coverage: {summary.get('multi_anchor_coverage', 0)} cases",
    f"- Blame success cases: {summary.get('blame_success_cases', 0)}",
    f"- Shallow history cases: `{summary.get('shallow_history_cases', [])}`",
    f"- Fix-series candidates excluded: {summary.get('fix_series_candidates_excluded', 0)}",
    f"- Invented IDs: `{summary.get('invented_ids', [])}`",
    f"- Git query count: {summary.get('git_query_count', 0)}",
    f"- Total duration: {summary.get('total_duration_s', 0)} seconds",
    f"- Total raw response size: {summary.get('total_raw_response_chars', 0)} characters",
    "- Token usage: unavailable unless the OpenCode backend returns usage metadata.",
    "",
    "## Per-CVE",
    "",
    "| CVE | Status | Parse | Contract | Anchors | Blame | Candidate commits |",
    "| --- | --- | --- | --- | ---: | --- | ---: |",
  ]
  for item in results:
    lines.append(
      f"| {item.get('cve_id')} | {item.get('status')} | {item.get('parse_status', '')} | "
      f"{item.get('contract_ok', '')} | {item.get('resolved_anchor_count', 0)} | "
      f"{item.get('blame_status', '')} | {item.get('candidate_commit_count', 0)} |"
    )
  return "\n".join(lines) + "\n"


def _failure_result(cve_id: str, status: str, errors: list[str], started: float) -> dict[str, Any]:
  return {
    "cve_id": cve_id,
    "status": status,
    "lifecycle": "raw_candidate",
    "errors": errors,
    "duration_s": round(time.monotonic() - started, 6),
  }


def _read_json(path: Path) -> dict[str, Any]:
  data = json.loads(path.read_text(encoding="utf-8"))
  if not isinstance(data, dict):
    raise ValueError(f"expected JSON object: {path}")
  return data


def _read_optional_json(path: Path) -> dict[str, Any]:
  if not path.exists():
    return {}
  try:
    return _read_json(path)
  except Exception:
    return {}


def _semantic_label_status(path: Path, cve_ids: list[str]) -> dict[str, Any]:
  if not path.exists():
    return {"complete": False, "gaps": {cve_id: ["evaluation.csv missing"] for cve_id in cve_ids}}
  with path.open(newline="", encoding="utf-8") as handle:
    rows = {str(row.get("cve_id") or ""): row for row in csv.DictReader(handle)}
  gaps: dict[str, list[str]] = {}
  for cve_id in cve_ids:
    row = rows.get(cve_id)
    if row is None:
      gaps[cve_id] = ["row missing"]
      continue
    missing = [field for field in SEMANTIC_LABEL_FIELDS if not str(row.get(field) or "").strip()]
    if missing:
      gaps[cve_id] = missing
  return {"complete": not gaps, "gaps": gaps}


def _flatten_fix_commits(value: Any) -> list[str]:
  output: list[str] = []
  for group in value or []:
    if isinstance(group, list):
      output.extend(str(item) for item in group if str(item).strip())
    elif str(group).strip():
      output.append(str(group))
  return output


def _run_git(repo_path: Path, args: list[str]) -> dict[str, Any]:
  if not repo_path.exists():
    return {"exit_code": 1, "stdout": "", "stderr": f"repo missing: {repo_path}"}
  command = ["git", "-c", f"safe.directory={repo_path}", "-C", str(repo_path), *args]
  result = subprocess.run(
    command,
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="ignore",
    check=False,
  )
  return {"exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr, "command": command}


def _write_json(path: Path, data: Any) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
