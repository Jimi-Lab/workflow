from __future__ import annotations

import json
import shutil
import time
from collections import Counter
from pathlib import Path
from typing import Any

from vulngraph.agent_io.judge_boundary_v1_2_contract import lint_judge_boundary_output_v1_2
from vulngraph.workflows.affected_version_converter_v1 import p01_metrics
from vulngraph.workflows.branch_context_v1_2 import SubprocessGitGraph
from vulngraph.workflows.branch_context_v1_2_1 import build_complete_branch_scoped_groups
from vulngraph.workflows.semantic_state_batch_v1_2_1 import precompute_git_semantic_states
from vulngraph.workflows.semantic_state_v1_2_1 import (
  GitSemanticStateRunner,
  SemanticStateVerifier,
  cluster_history_events,
)
from vulngraph.workflows.szz_anchor_version_probe import DirectReachabilityRunner, build_tag_universe


_PRESENT_STATES = {"present_exact", "present_normalized", "present_predicate_equivalent"}
_ACTIVATION_ROLES = {"primary_boundary", "branch_equivalent_boundary"}
_GROUP_CACHE: dict[tuple[str, str, str], dict[str, Any]] = {}


def convert_affected_versions_for_cve_v1_2_1(
  *, cve_id: str, boundary_run: str | Path, dataset: str | Path,
  repo_root: str | Path, git_runner: Any | None = None, graph: Any | None = None,
) -> dict[str, Any]:
  records = _read(Path(dataset))
  record = records.get(cve_id, {})
  repo = str(record.get("repo") or "")
  repo_path = Path(repo_root) / repo
  reachability = git_runner or DirectReachabilityRunner()
  if hasattr(reachability, "set_repo"):
    reachability.set_repo(repo_path)
  graph_api = graph or (reachability if _is_graph(reachability) else SubprocessGitGraph(repo_path))
  release_tags = build_tag_universe(repo, reachability.list_tags(repo_path))["release_tag_universe"]
  case = Path(boundary_run) / cve_id
  boundary_input = _read(case / "judge_boundary_input_v1_2.json")
  parsed = _read(case / "parsed_boundary_output_v1_2.json")
  result = _read(case / "judge_boundary_result_v1_2.json")
  if not result.get("contract_ok"):
    return _blocked(cve_id, repo, release_tags, "judge_boundary_contract_not_accepted")
  contract = lint_judge_boundary_output_v1_2(parsed, boundary_input)
  if not contract.ok:
    return _blocked(cve_id, repo, release_tags, "converter_boundary_contract_revalidation_failed")

  declared = _flatten_fix_shas(record.get("fixing_commits"))
  cache_key = (cve_id, str(Path(boundary_run).resolve()), str(Path(repo_root).resolve()))
  rebuilt = _GROUP_CACHE.get(cache_key)
  if rebuilt is None:
    rebuilt = build_complete_branch_scoped_groups(
      cve_id, repo, list(boundary_input.get("history_event_candidates") or []), declared, graph_api,
    )
    _GROUP_CACHE[cache_key] = rebuilt
  audit = _resolved_fix_audit(rebuilt)
  if audit["coverage"] < 1.0 or audit["unresolved_declared_fix_count"]:
    return {
      **_blocked(cve_id, repo, release_tags, "incomplete_declared_fix_universe"),
      "fix_universe_audit": audit,
    }

  judgments = list(parsed.get("candidate_judgments") or [])
  clusters = cluster_history_events(rebuilt["history_event_candidates"], judgments)
  selected_ids = {
    str(item.get("event_candidate_id") or "")
    for item in judgments
    if item.get("decision") == "selected" and item.get("boundary_role") in _ACTIVATION_ROLES
  }
  prerequisite_ids = {
    str(item.get("event_candidate_id") or "")
    for item in judgments
    if item.get("decision") == "selected" and item.get("boundary_role") == "conjunctive_prerequisite"
  }
  unresolved_clusters = [item for item in clusters if item["resolution"] == "unresolved_primary"]
  if not selected_ids:
    status = "unresolved_boundary" if unresolved_clusters else "unknown_state"
    return {
      "cve_id": cve_id, "repo": repo, "affected_versions": [], "evidence": [],
      "uncertainty": [{"reason": "no_selected_primary_history_event_cluster"}],
      "prediction_status": status, "unknown_version_count": len(release_tags),
      "release_tag_universe_size": len(release_tags), "fix_universe_audit": audit,
      "history_event_clusters": clusters, "semantic_state_counts": {},
      "lifecycle": "deterministic_semantic_state_reconstruction_v1_2_1_unresolved",
    }

  semantic_runner = reachability if hasattr(reachability, "read_file") else GitSemanticStateRunner(repo_path)
  semantic = SemanticStateVerifier(semantic_runner)
  events = {str(item.get("event_candidate_id") or ""): item for item in rebuilt["history_event_candidates"]}
  contexts = {item["branch_context_id"]: item for item in rebuilt["branch_contexts"]}
  groups = {item["branch_context_id"]: item for item in rebuilt["fix_groups"]}
  selected_events = [events[event_id] for event_id in selected_ids if event_id in events]
  prerequisite_events = [events[event_id] for event_id in prerequisite_ids if event_id in events]
  all_semantic_events = [*selected_events, *prerequisite_events]
  semantic_cache = (
    precompute_git_semantic_states(repo_path, all_semantic_events, release_tags)
    if isinstance(semantic_runner, GitSemanticStateRunner) else {}
  )
  affected: set[str] = set()
  unknown: set[str] = set()
  evidence: list[dict[str, Any]] = []
  state_counts: Counter[str] = Counter()
  reachability_cache: dict[tuple[str, str], str] = {}
  for context_id in contexts:
    activators = [item for item in selected_events if context_id in item.get("branch_context_ids", [])]
    prerequisites = [item for item in prerequisite_events if context_id in item.get("branch_context_ids", [])]
    if not activators:
      continue
    fix_group = groups.get(context_id)
    for tag in release_tags:
      activation, activation_evidence = _semantic_event_group_state(semantic, activators, tag, semantic_cache)
      prerequisite, prerequisite_evidence = _semantic_prerequisite_state(semantic, prerequisites, tag, semantic_cache)
      state_counts.update(item["state"] for item in [*activation_evidence, *prerequisite_evidence])
      fix_state, fix_evidence = _fix_state(
        reachability, fix_group, rebuilt.get("fix_equivalence_groups", []), tag,
        reachability_cache,
      ) if fix_group else ("unknown", {"reason": "missing_fix_group"})
      if "unknown" in {activation, prerequisite, fix_state}:
        vulnerability_state = "unknown"
        unknown.add(tag)
      elif activation == "active" and prerequisite == "complete" and fix_state == "incomplete":
        vulnerability_state = "affected"
        affected.add(tag)
      else:
        vulnerability_state = "not_affected"
      evidence.append({
        "branch_context_id": context_id, "tag": tag,
        "activation_state": activation, "activation_evidence": activation_evidence,
        "prerequisite_state": prerequisite, "prerequisite_evidence": prerequisite_evidence,
        "fix_state": fix_state, "fix_evidence": fix_evidence,
        "vulnerability_state": vulnerability_state,
      })
  status = "unknown_state" if unknown else "converted"
  return {
    "cve_id": cve_id, "repo": repo, "affected_versions": sorted(affected),
    "evidence": evidence,
    "uncertainty": ([{"reason": "predicate_state_unknown", "unknown_version_count": len(unknown)}] if unknown else []),
    "prediction_status": status, "unknown_version_count": len(unknown),
    "release_tag_universe_size": len(release_tags), "fix_universe_audit": audit,
    "history_event_clusters": clusters, "semantic_state_counts": dict(sorted(state_counts.items())),
    "lifecycle": "deterministic_semantic_state_reconstruction_v1_2_1",
  }


def run_affected_version_converter_v1_2_1(
  *, cve_ids: list[str], boundary_run: str | Path, dataset: str | Path,
  repo_root: str | Path, out_dir: str | Path, reset: bool = False,
) -> dict[str, Any]:
  root = Path(out_dir)
  if reset and root.exists():
    shutil.rmtree(root)
  root.mkdir(parents=True, exist_ok=True)
  records = _read(Path(dataset))
  started = time.monotonic()

  fix_audit = audit_fix_universe_v1_2_1(cve_ids, boundary_run, records, repo_root)
  _write(root / "fix_universe_audit.json", fix_audit)
  if fix_audit["coverage"] < 1.0 or fix_audit["unresolved_declared_fix_count"]:
    summary = {
      "cases_total": len(cve_ids), "replay_started": False,
      "blocked_reason": "fix_universe_coverage_gate_failed",
      "fix_universe_audit": fix_audit, "model_invocation_count": 0,
      "duration_s": round(time.monotonic() - started, 6),
    }
    _write(root / "summary.json", summary)
    return summary

  predictions = []
  metric_rows = []
  for cve_id in cve_ids:
    prediction = convert_affected_versions_for_cve_v1_2_1(
      cve_id=cve_id, boundary_run=boundary_run, dataset=dataset, repo_root=repo_root,
    )
    predictions.append(prediction)
    truth = set(records.get(cve_id, {}).get("affected_version", []) or [])
    metric_rows.append({"cve_id": cve_id, "predicted": set(prediction["affected_versions"]), "ground_truth": truth})
    case = root / cve_id
    case.mkdir(parents=True, exist_ok=True)
    _write(case / "semantic_state_reconstruction.json", prediction)
    _write(case / "public_prediction.json", {
      "cve_id": cve_id, "affected_versions": prediction["affected_versions"],
      "evidence": prediction["evidence"], "uncertainty": prediction["uncertainty"],
      "prediction_status": prediction["prediction_status"], "lifecycle": prediction["lifecycle"],
    })
    print(json.dumps({"progress_cve": cve_id, "prediction_status": prediction["prediction_status"], "affected_count": len(prediction["affected_versions"])}, ensure_ascii=False), flush=True)
  metrics = p01_metrics(metric_rows)
  statuses = Counter(item["prediction_status"] for item in predictions)
  stage_errors = _stage_error_attribution(predictions)
  summary = {
    "cases_total": len(predictions), "replay_started": True,
    "prediction_status_counts": dict(sorted(statuses.items())),
    "converted_count": statuses.get("converted", 0),
    "unresolved_count": statuses.get("unresolved_boundary", 0),
    "unknown_state_count": statuses.get("unknown_state", 0),
    "blocked_count": statuses.get("blocked", 0),
    "fix_universe_audit": fix_audit, "model_invocation_count": 0,
    "duration_s": round(time.monotonic() - started, 6),
    "lifecycle": "deterministic_semantic_state_reconstruction_v1_2_1_evaluation",
  }
  _write(root / "summary.json", summary)
  _write(root / "paper_metrics.json", metrics)
  _write(root / "stage_error_attribution.json", stage_errors)
  with (root / "per_cve_predictions.jsonl").open("w", encoding="utf-8") as handle:
    for item in predictions:
      handle.write(json.dumps({
        "cve_id": item["cve_id"], "repo": item["repo"],
        "affected_versions": item["affected_versions"],
        "uncertainty": item["uncertainty"], "prediction_status": item["prediction_status"],
        "unknown_version_count": item["unknown_version_count"], "lifecycle": item["lifecycle"],
      }, ensure_ascii=False) + "\n")
  return {**summary, "paper_metrics": metrics, "stage_error_attribution": stage_errors}


def audit_fix_universe_v1_2_1(cve_ids: list[str], boundary_run: str | Path, records: dict[str, Any], repo_root: str | Path) -> dict[str, Any]:
  rows = []
  for cve_id in cve_ids:
    record = records.get(cve_id, {})
    repo = str(record.get("repo") or "")
    boundary_input = _read(Path(boundary_run) / cve_id / "judge_boundary_input_v1_2.json")
    grouped = build_complete_branch_scoped_groups(
      cve_id, repo, list(boundary_input.get("history_event_candidates") or []),
      _flatten_fix_shas(record.get("fixing_commits")), SubprocessGitGraph(Path(repo_root) / repo),
    )
    _GROUP_CACHE[(cve_id, str(Path(boundary_run).resolve()), str(Path(repo_root).resolve()))] = grouped
    rows.append({"cve_id": cve_id, **_resolved_fix_audit(grouped)})
  declared = sum(item["declared_fix_count"] for item in rows)
  represented = sum(item["represented_declared_fix_count"] for item in rows)
  unresolved = sum(item["unresolved_declared_fix_count"] for item in rows)
  return {
    "cases_total": len(rows), "declared_fix_count": declared,
    "represented_declared_fix_count": represented,
    "unresolved_declared_fix_count": unresolved,
    "missing_declared_fix_count": sum(item["missing_declared_fix_count"] for item in rows),
    "alias_fix_count": sum(item["alias_fix_count"] for item in rows),
    "coverage": represented / declared if declared else 1.0,
    "cases": rows,
  }


def ranked_raw_top1_metrics(dataset: dict[str, Any], diagnostics: dict[str, Any], per_candidate: dict[str, Any]) -> dict[str, Any]:
  tp = fp = fn = exact = mismatches = 0
  mismatch_rows = []
  for cve_id, record in dataset.items():
    diagnostic = diagnostics.get(cve_id, {})
    top1 = diagnostic.get("release_tag_universe", {}).get("top1", {})
    predicted = set(top1.get("predicted_tags") or [])
    truth = set(record.get("affected_version") or [])
    local_tp = len(predicted & truth)
    tp += local_tp
    fp += len(predicted - truth)
    fn += len(truth - predicted)
    exact += int(predicted == truth)
    entries = per_candidate.get(cve_id, {}).get("release_tag_universe", []) or []
    first = entries[0] if entries else {}
    first_sha = str(first.get("commit_sha") or first.get("candidate_commit_sha") or "")
    ranked_sha = str(diagnostic.get("top1_candidate_commit") or diagnostic.get("release_tag_universe", {}).get("top1_candidate_commit") or "")
    first_predicted = set(first.get("predicted_tags") or [])
    sha_mismatch = bool(first_sha and ranked_sha and first_sha != ranked_sha)
    order_mismatch = sha_mismatch or bool(first_predicted and first_predicted != predicted)
    if order_mismatch:
      mismatches += 1
      mismatch_rows.append({"cve_id": cve_id, "array_first": first_sha, "ranked_top1": ranked_sha})
  precision = tp / (tp + fp) if tp + fp else 0.0
  recall = tp / (tp + fn) if tp + fn else 0.0
  return {
    "case_count": len(dataset), "exact_match_count": exact,
    "true_positive_count": tp, "false_positive_count": fp, "false_negative_count": fn,
    "micro_precision": precision, "micro_recall": recall,
    "micro_f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
    "ordering_mismatch_count": mismatches, "ordering_mismatches": mismatch_rows,
    "source": "ranking_diagnostics.release_tag_universe.top1",
  }


def _semantic_event_group_state(verifier: SemanticStateVerifier, events: list[dict[str, Any]], tag: str, cache: dict[tuple[str, str], dict[str, Any]] | None = None) -> tuple[str, list[dict[str, Any]]]:
  cache = cache or {}
  evidence = [cache.get((str(event.get("event_candidate_id") or ""), tag)) or verifier.verify(event, tag) for event in events]
  if any(item["state"] in _PRESENT_STATES for item in evidence):
    return "active", evidence
  if any(item["state"] == "unknown" for item in evidence):
    return "unknown", evidence
  return "inactive", evidence


def _semantic_prerequisite_state(verifier: SemanticStateVerifier, events: list[dict[str, Any]], tag: str, cache: dict[tuple[str, str], dict[str, Any]] | None = None) -> tuple[str, list[dict[str, Any]]]:
  if not events:
    return "complete", []
  cache = cache or {}
  evidence = [cache.get((str(event.get("event_candidate_id") or ""), tag)) or verifier.verify(event, tag) for event in events]
  if any(item["state"] == "unknown" for item in evidence):
    return "unknown", evidence
  return ("complete" if all(item["state"] in _PRESENT_STATES for item in evidence) else "incomplete"), evidence


def _fix_state(runner: Any, group: dict[str, Any], equivalence_groups: list[dict[str, Any]], tag: str, cache: dict[tuple[str, str], str]) -> tuple[str, dict[str, Any]]:
  semantics = str(group.get("completion_semantics") or "unknown")
  members = set(group.get("fix_commit_shas") or [])
  evidence_groups = []
  for equivalence in equivalence_groups:
    equivalent_members = set(equivalence.get("fix_commit_shas") or [])
    if members & equivalent_members:
      members.update(equivalent_members)
      evidence_groups.append(str(equivalence.get("fix_equivalence_group_id") or ""))
  values = {sha: _reachability(runner, sha, tag, cache) for sha in sorted(members)}
  if semantics == "unknown" or not members:
    return "unknown", {"reason": "fix_equivalence_unknown", "reachability": values}
  if semantics in {"any_equivalent_fix", "branch_local_single"}:
    if any(value == "yes" for value in values.values()):
      return "complete", {"reason": "reachable_fix_or_equivalent", "reachability": values, "equivalence_groups": evidence_groups}
    if any(value == "unknown" for value in values.values()):
      return "unknown", {"reason": "fix_reachability_unknown", "reachability": values}
    semantic_fn = getattr(runner, "fix_predicate_state", None)
    semantic = semantic_fn(group, tag) if callable(semantic_fn) else "absent"
    if semantic in _PRESENT_STATES or semantic == "present":
      return "complete", {"reason": "branch_local_fix_predicate_present", "semantic_state": semantic, "reachability": values}
    if semantic == "unknown":
      return "unknown", {"reason": "fix_predicate_state_unknown", "reachability": values}
    return "incomplete", {"reason": "no_fix_or_equivalent_reachable", "reachability": values}
  if semantics == "all_conjunctive_fixes":
    if all(value == "yes" for value in values.values()):
      return "complete", {"reason": "all_explicit_conjunctive_fixes_reachable", "reachability": values}
    if any(value == "unknown" for value in values.values()):
      return "unknown", {"reason": "conjunctive_fix_reachability_unknown", "reachability": values}
    return "incomplete", {"reason": "conjunctive_fix_group_incomplete", "reachability": values}
  return "unknown", {"reason": "fix_equivalence_unknown", "reachability": values}


def _reachability(runner: Any, sha: str, tag: str, cache: dict[tuple[str, str], str]) -> str:
  key = (sha, tag)
  if key not in cache:
    contains_fn = getattr(runner, "tags_containing", None)
    if callable(contains_fn):
      containing = contains_fn(sha)
      if containing is not None:
        cache[key] = "yes" if tag in set(containing) else "no"
        return cache[key]
    value = runner.is_ancestor(sha, tag)
    cache[key] = "yes" if value is True or value == "yes" else "no" if value is False or value == "no" else "unknown"
  return cache[key]


def _resolved_fix_audit(grouped: dict[str, Any]) -> dict[str, Any]:
  audit = dict(grouped.get("fix_universe_audit") or {})
  facts = [fact for group in grouped.get("fix_groups", []) for fact in group.get("fix_commit_facts", [])]
  unresolved = sorted({fact["fix_commit_sha"] for fact in facts if fact.get("declared_in_dataset") and fact.get("resolution_status") != "resolved"})
  audit["unresolved_declared_fix_count"] = len(unresolved)
  audit["unresolved_declared_fix_shas"] = unresolved
  return audit


def _stage_error_attribution(predictions: list[dict[str, Any]]) -> dict[str, Any]:
  taxonomy = Counter()
  cases = []
  for item in predictions:
    reasons = {str(value.get("reason") or "") for value in item.get("uncertainty", [])}
    if item.get("prediction_status") == "blocked":
      taxonomy["missing_fix_context"] += 1
    if item.get("prediction_status") == "unresolved_boundary":
      taxonomy["unresolved_judge"] += 1
    if "predicate_state_unknown" in reasons:
      taxonomy["predicate_state_unknown"] += 1
    if item.get("prediction_status") != "converted":
      cases.append({"cve_id": item["cve_id"], "prediction_status": item["prediction_status"], "reasons": sorted(reasons)})
  return {"taxonomy": dict(sorted(taxonomy.items())), "cases": cases, "derivation": "converter_invariants_only"}


def _flatten_fix_shas(value: Any) -> list[str]:
  if isinstance(value, str):
    return [value]
  if isinstance(value, list):
    return sorted({item for child in value for item in _flatten_fix_shas(child)})
  if isinstance(value, dict):
    return sorted({item for child in value.values() for item in _flatten_fix_shas(child)})
  return []


def _is_graph(value: Any) -> bool:
  return all(hasattr(value, name) for name in ("containing_branch_refs", "merge_base", "patch_id", "commit_metadata"))


def _blocked(cve_id: str, repo: str, tags: list[str], reason: str) -> dict[str, Any]:
  return {
    "cve_id": cve_id, "repo": repo, "affected_versions": [], "evidence": [],
    "uncertainty": [{"reason": reason}], "prediction_status": "blocked",
    "blocked_reason": reason, "unknown_version_count": len(tags),
    "release_tag_universe_size": len(tags), "semantic_state_counts": {},
    "history_event_clusters": [], "lifecycle": "deterministic_semantic_state_reconstruction_v1_2_1_blocked",
  }


def _read(path: Path) -> dict[str, Any]:
  return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, value: Any) -> None:
  path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
