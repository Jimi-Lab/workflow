from __future__ import annotations

import json
import shutil
import time
from collections import Counter
from pathlib import Path
from typing import Any

from vulngraph.agent_io.judge_boundary_v1_2_contract import lint_judge_boundary_output_v1_2
from vulngraph.workflows.affected_version_converter_v1 import p01_metrics
from vulngraph.workflows.affected_version_converter_v1_2_1 import (
  audit_fix_universe_v1_2_1,
  ranked_raw_top1_metrics,
)
from vulngraph.workflows.branch_context_v1_2 import SubprocessGitGraph
from vulngraph.workflows.branch_context_v1_2_1 import build_complete_branch_scoped_groups
from vulngraph.workflows.semantic_state_batch_v1_2_2 import precompute_function_scope_semantic_states
from vulngraph.workflows.semantic_state_v1_2_2 import FunctionScopeSemanticVerifier
from vulngraph.workflows.semantic_state_v1_2_1 import GitSemanticStateRunner, cluster_history_events
from vulngraph.workflows.szz_anchor_version_probe import DirectReachabilityRunner, build_tag_universe


_PRESENT_PREDICATE_STATES = {"present_exact", "present_normalized", "present_predicate_equivalent"}
_FIX_PRESENT_STATES = {"fix_reachable", "patch_id_equivalent", "alias_equivalent", "fix_predicate_present"}
_ACTIVATION_ROLES = {"primary_boundary", "branch_equivalent_boundary"}
_GROUP_CACHE: dict[tuple[str, str, str], dict[str, Any]] = {}


def convert_affected_versions_for_cve_v1_2_2(
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
    return {**_blocked(cve_id, repo, release_tags, "incomplete_declared_fix_universe"), "fix_universe_audit": audit}

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
      "cve_id": cve_id, "repo": repo,
      "affected_versions": [], "predicted_affected_versions_for_metric": [],
      "confirmed_affected_versions": [], "confirmed_unaffected_versions": [],
      "unknown_versions": release_tags, "evidence": [],
      "uncertainty": [{"reason": "no_selected_primary_history_event_cluster"}],
      "prediction_status": status, "unknown_version_count": len(release_tags),
      "release_tag_universe_size": len(release_tags), "fix_universe_audit": audit,
      "history_event_clusters": clusters, "semantic_state_counts": {},
      "metric_policy": "blocked_no_selected_primary_history_event_cluster",
      "lifecycle": "deterministic_function_scope_state_reconstruction_v1_2_2_unresolved",
    }

  semantic_runner = reachability if hasattr(reachability, "read_file") else GitSemanticStateRunner(repo_path)
  semantic = FunctionScopeSemanticVerifier(semantic_runner)
  events = {str(item.get("event_candidate_id") or ""): item for item in rebuilt["history_event_candidates"]}
  contexts = {item["branch_context_id"]: item for item in rebuilt["branch_contexts"]}
  groups = {item["branch_context_id"]: item for item in rebuilt["fix_groups"]}
  selected_events = [events[event_id] for event_id in selected_ids if event_id in events]
  prerequisite_events = [events[event_id] for event_id in prerequisite_ids if event_id in events]
  all_semantic_events = [*selected_events, *prerequisite_events]
  semantic_cache = (
    precompute_function_scope_semantic_states(repo_path, all_semantic_events, release_tags)
    if isinstance(semantic_runner, GitSemanticStateRunner) else {}
  )

  confirmed_affected: set[str] = set()
  confirmed_unaffected: set[str] = set()
  unknown: set[str] = set()
  predicted_for_metric: set[str] = set()
  evidence: list[dict[str, Any]] = []
  state_counts: Counter[str] = Counter()
  fp_taxonomy: Counter[str] = Counter()
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
      fix_evidence = evaluate_fix_state_v1_2_2(
        reachability, fix_group or {}, rebuilt.get("fix_equivalence_groups", []), tag, reachability_cache,
      ) if fix_group else _fix_unknown("missing_fix_group")
      outcome = classify_version_state_v1_2_2(activation, prerequisite, fix_evidence)
      if outcome["confirmed_affected"]:
        confirmed_affected.add(tag)
      if outcome["confirmed_unaffected"]:
        confirmed_unaffected.add(tag)
      if outcome["bucket"] == "unknown":
        unknown.add(tag)
      if outcome["metric_predicted_affected"]:
        predicted_for_metric.add(tag)
      for reason in outcome.get("fp_taxonomy_hints", []):
        fp_taxonomy[reason] += 1
      evidence.append({
        "branch_context_id": context_id, "tag": tag,
        "activation_state": activation, "activation_evidence": activation_evidence,
        "prerequisite_state": prerequisite, "prerequisite_evidence": prerequisite_evidence,
        "fix_state": fix_evidence.get("fix_presence"), "fix_evidence": fix_evidence,
        "vulnerability_state": outcome["bucket"],
        "metric_predicted_affected": outcome["metric_predicted_affected"],
        "metric_policy": outcome["metric_policy"],
      })
  if unknown and (confirmed_affected or predicted_for_metric):
    status = "converted_with_unknowns"
  elif unknown:
    status = "unknown_state"
  else:
    status = "converted"
  return {
    "cve_id": cve_id, "repo": repo,
    "affected_versions": sorted(predicted_for_metric),
    "predicted_affected_versions_for_metric": sorted(predicted_for_metric),
    "confirmed_affected_versions": sorted(confirmed_affected),
    "confirmed_unaffected_versions": sorted(confirmed_unaffected),
    "unknown_versions": sorted(unknown),
    "evidence": evidence,
    "uncertainty": ([{"reason": "predicate_or_fix_state_unknown", "unknown_version_count": len(unknown)}] if unknown else []),
    "prediction_status": status, "unknown_version_count": len(unknown),
    "release_tag_universe_size": len(release_tags), "fix_universe_audit": audit,
    "history_event_clusters": clusters, "semantic_state_counts": dict(sorted(state_counts.items())),
    "fp_taxonomy": dict(sorted(fp_taxonomy.items())),
    "metric_policy": "confirmed_affected_plus_optimistic_unknown_activation_fix_absent",
    "lifecycle": "deterministic_function_scope_state_reconstruction_v1_2_2",
  }


def run_affected_version_converter_v1_2_2(
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
    summary = {"cases_total": len(cve_ids), "replay_started": False, "blocked_reason": "fix_universe_coverage_gate_failed", "fix_universe_audit": fix_audit, "model_invocation_count": 0}
    _write(root / "summary.json", summary)
    return summary
  predictions = []
  metric_rows = []
  for cve_id in cve_ids:
    prediction = convert_affected_versions_for_cve_v1_2_2(cve_id=cve_id, boundary_run=boundary_run, dataset=dataset, repo_root=repo_root)
    predictions.append(prediction)
    truth = set(records.get(cve_id, {}).get("affected_version", []) or [])
    metric_rows.append({"cve_id": cve_id, "predicted": set(prediction["predicted_affected_versions_for_metric"]), "ground_truth": truth})
    case = root / cve_id
    case.mkdir(parents=True, exist_ok=True)
    _write(case / "semantic_state_reconstruction.json", prediction)
    _write(case / "public_prediction.json", {
      "cve_id": cve_id,
      "affected_versions": prediction["predicted_affected_versions_for_metric"],
      "confirmed_affected_versions": prediction["confirmed_affected_versions"],
      "confirmed_unaffected_versions": prediction["confirmed_unaffected_versions"],
      "unknown_versions": prediction["unknown_versions"],
      "evidence": prediction["evidence"],
      "uncertainty": prediction["uncertainty"],
      "prediction_status": prediction["prediction_status"],
      "metric_policy": prediction["metric_policy"],
      "lifecycle": prediction["lifecycle"],
    })
    print(json.dumps({"progress_cve": cve_id, "prediction_status": prediction["prediction_status"], "affected_count": len(prediction["predicted_affected_versions_for_metric"])}, ensure_ascii=False), flush=True)
  metrics = p01_metrics(metric_rows)
  statuses = Counter(item["prediction_status"] for item in predictions)
  stage_errors = _stage_error_attribution(predictions)
  summary = {
    "cases_total": len(predictions), "replay_started": True,
    "prediction_status_counts": dict(sorted(statuses.items())),
    "confirmed_affected_version_count": sum(len(item["confirmed_affected_versions"]) for item in predictions),
    "confirmed_unaffected_version_count": sum(len(item["confirmed_unaffected_versions"]) for item in predictions),
    "unknown_version_count": sum(len(item["unknown_versions"]) for item in predictions),
    "unknown_state_count": statuses.get("unknown_state", 0),
    "converted_with_unknowns_count": statuses.get("converted_with_unknowns", 0),
    "fix_universe_audit": fix_audit, "model_invocation_count": 0,
    "duration_s": round(time.monotonic() - started, 6),
    "lifecycle": "deterministic_function_scope_state_reconstruction_v1_2_2_evaluation",
  }
  _write(root / "summary.json", summary)
  _write(root / "paper_metrics.json", metrics)
  _write(root / "stage_error_attribution.json", stage_errors)
  with (root / "per_cve_predictions.jsonl").open("w", encoding="utf-8") as handle:
    for item in predictions:
      handle.write(json.dumps({
        "cve_id": item["cve_id"], "repo": item["repo"],
        "affected_versions": item["predicted_affected_versions_for_metric"],
        "confirmed_affected_versions": item["confirmed_affected_versions"],
        "confirmed_unaffected_versions": item["confirmed_unaffected_versions"],
        "unknown_versions": item["unknown_versions"],
        "prediction_status": item["prediction_status"],
        "unknown_version_count": item["unknown_version_count"], "lifecycle": item["lifecycle"],
      }, ensure_ascii=False) + "\n")
  return {**summary, "paper_metrics": metrics, "stage_error_attribution": stage_errors}


def classify_version_state_v1_2_2(activation: str, prerequisite: str, fix_evidence: dict[str, Any]) -> dict[str, Any]:
  fix_presence = str(fix_evidence.get("fix_presence") or "unknown")
  if fix_presence == "present":
    return {"bucket": "confirmed_unaffected", "confirmed_affected": False, "confirmed_unaffected": True, "metric_predicted_affected": False, "metric_policy": "fix_present_confirms_unaffected", "fp_taxonomy_hints": []}
  if activation == "inactive" or prerequisite == "incomplete":
    return {"bucket": "confirmed_unaffected", "confirmed_affected": False, "confirmed_unaffected": True, "metric_predicted_affected": False, "metric_policy": "predicate_absent_confirms_unaffected", "fp_taxonomy_hints": []}
  if activation == "active" and prerequisite == "complete" and fix_presence == "absent":
    return {"bucket": "confirmed_affected", "confirmed_affected": True, "confirmed_unaffected": False, "metric_predicted_affected": True, "metric_policy": "confirmed_affected", "fp_taxonomy_hints": []}
  hints = []
  if fix_presence == "absent" and activation == "unknown":
    hints.append("unknown_included_by_policy")
  return {
    "bucket": "unknown",
    "confirmed_affected": False,
    "confirmed_unaffected": False,
    "metric_predicted_affected": fix_presence == "absent" and activation in {"unknown", "active"},
    "metric_policy": "optimistic_unknown_activation_fix_absent" if fix_presence == "absent" else "unknown_not_predicted",
    "fp_taxonomy_hints": hints,
  }


def evaluate_fix_state_v1_2_2(runner: Any, group: dict[str, Any], equivalence_groups: list[dict[str, Any]], tag: str, cache: dict[tuple[str, str], str]) -> dict[str, Any]:
  semantics = str(group.get("completion_semantics") or "unknown")
  direct_members = set(group.get("fix_commit_shas") or [])
  if semantics == "unknown" or not direct_members:
    return _fix_unknown("fix_equivalence_unknown", group=group)
  equivalent: dict[str, str] = {}
  for equivalence in equivalence_groups:
    members = set(equivalence.get("fix_commit_shas") or [])
    if direct_members & members:
      evidence = str(equivalence.get("equivalence_evidence") or "")
      for sha in members - direct_members:
        equivalent[sha] = evidence
  direct_values = {sha: _reachability(runner, sha, tag, cache) for sha in sorted(direct_members)}
  equivalent_values = {sha: _reachability(runner, sha, tag, cache) for sha in sorted(equivalent)}
  if semantics in {"any_equivalent_fix", "branch_local_single"}:
    for sha, value in direct_values.items():
      if value == "yes":
        return _fix_present("fix_reachable", sha, tag, group, direct_values, equivalent_values)
    for sha, value in equivalent_values.items():
      if value == "yes":
        state = "alias_equivalent" if "alias" in equivalent.get(sha, "") or "cherry" in equivalent.get(sha, "") else "patch_id_equivalent"
        return _fix_present(state, sha, tag, group, direct_values, equivalent_values)
    if "unknown" in set(direct_values.values()) | set(equivalent_values.values()):
      return _fix_unknown("fix_reachability_unknown", group=group, reachability={**direct_values, **equivalent_values})
    semantic_fn = getattr(runner, "fix_predicate_state", None)
    semantic = semantic_fn(group, tag) if callable(semantic_fn) else "absent"
    if semantic in {"present", "present_exact", "present_normalized", "present_predicate_equivalent"}:
      return _fix_present("fix_predicate_present", "", tag, group, direct_values, equivalent_values, semantic_state=semantic)
    if semantic == "unknown":
      return _fix_unknown("fix_predicate_state_unknown", group=group, reachability={**direct_values, **equivalent_values})
    return _fix_absent("no_fix_or_equivalent_reachable", group, {**direct_values, **equivalent_values})
  if semantics == "all_conjunctive_fixes":
    if all(value == "yes" for value in direct_values.values()):
      return _fix_present("fix_reachable", ",".join(sorted(direct_members)), tag, group, direct_values, equivalent_values, reason="all_explicit_conjunctive_fixes_reachable")
    if any(value == "unknown" for value in direct_values.values()):
      return _fix_unknown("conjunctive_fix_reachability_unknown", group=group, reachability=direct_values)
    return _fix_absent("conjunctive_fix_group_incomplete", group, direct_values)
  return _fix_unknown("fix_equivalence_unknown", group=group)


def _semantic_event_group_state(verifier: FunctionScopeSemanticVerifier, events: list[dict[str, Any]], tag: str, cache: dict[tuple[str, str], dict[str, Any]] | None = None) -> tuple[str, list[dict[str, Any]]]:
  cache = cache or {}
  evidence = [cache.get((str(event.get("event_candidate_id") or ""), tag)) or verifier.verify(event, tag) for event in events]
  if any(item["state"] in _PRESENT_PREDICATE_STATES for item in evidence):
    return "active", evidence
  if any(item["state"] == "unknown" for item in evidence):
    return "unknown", evidence
  return "inactive", evidence


def _semantic_prerequisite_state(verifier: FunctionScopeSemanticVerifier, events: list[dict[str, Any]], tag: str, cache: dict[tuple[str, str], dict[str, Any]] | None = None) -> tuple[str, list[dict[str, Any]]]:
  if not events:
    return "complete", []
  cache = cache or {}
  evidence = [cache.get((str(event.get("event_candidate_id") or ""), tag)) or verifier.verify(event, tag) for event in events]
  if any(item["state"] == "unknown" for item in evidence):
    return "unknown", evidence
  return ("complete" if all(item["state"] in _PRESENT_PREDICATE_STATES for item in evidence) else "incomplete"), evidence


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


def _fix_present(state: str, sha: str, tag: str, group: dict[str, Any], direct: dict[str, str], equivalent: dict[str, str], *, semantic_state: str = "", reason: str = "") -> dict[str, Any]:
  return {
    "state": state, "fix_presence": "present", "fix_commit_sha": sha,
    "branch_context": group.get("branch_context_id", ""), "matched_fix_statement": "",
    "fix_fingerprint": {}, "evidence_reason": reason or state,
    "reachability": {**direct, **equivalent}, "semantic_state": semantic_state,
  }


def _fix_absent(reason: str, group: dict[str, Any], reachability: dict[str, str]) -> dict[str, Any]:
  return {
    "state": "absent", "fix_presence": "absent", "fix_commit_sha": "",
    "branch_context": group.get("branch_context_id", ""), "matched_fix_statement": "",
    "fix_fingerprint": {}, "evidence_reason": reason, "reachability": reachability,
  }


def _fix_unknown(reason: str, *, group: dict[str, Any] | None = None, reachability: dict[str, str] | None = None) -> dict[str, Any]:
  group = group or {}
  return {
    "state": "unknown", "fix_presence": "unknown", "fix_commit_sha": "",
    "branch_context": group.get("branch_context_id", ""), "matched_fix_statement": "",
    "fix_fingerprint": {}, "evidence_reason": reason, "reachability": reachability or {},
  }


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
    if item.get("prediction_status") == "unknown_state":
      taxonomy["predicate_or_fix_state_unknown"] += 1
    if item.get("prediction_status") == "unresolved_boundary":
      taxonomy["unresolved_judge"] += 1
    if item.get("unknown_versions"):
      taxonomy["unknown_versions_present"] += 1
    if item.get("fp_taxonomy", {}).get("unknown_included_by_policy"):
      taxonomy["unknown_included_by_policy"] += 1
    if item.get("prediction_status") != "converted":
      cases.append({"cve_id": item["cve_id"], "prediction_status": item["prediction_status"], "unknown_version_count": len(item.get("unknown_versions", [])), "fp_taxonomy": item.get("fp_taxonomy", {})})
  return {"taxonomy": dict(sorted(taxonomy.items())), "cases": cases, "derivation": "function_scope_converter_invariants_only"}


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
    "cve_id": cve_id, "repo": repo, "affected_versions": [],
    "predicted_affected_versions_for_metric": [], "confirmed_affected_versions": [],
    "confirmed_unaffected_versions": [], "unknown_versions": tags,
    "evidence": [], "uncertainty": [{"reason": reason}], "prediction_status": "blocked",
    "blocked_reason": reason, "unknown_version_count": len(tags),
    "release_tag_universe_size": len(tags), "semantic_state_counts": {},
    "history_event_clusters": [], "lifecycle": "deterministic_function_scope_state_reconstruction_v1_2_2_blocked",
    "metric_policy": "blocked_empty_prediction",
  }


def _read(path: Path) -> dict[str, Any]:
  return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, value: Any) -> None:
  path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
