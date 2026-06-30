from __future__ import annotations

import json
import shutil
import time
from collections import Counter
from pathlib import Path
from typing import Any

from vulngraph.agent_io.judge_boundary_contract import (
  derive_boundary_views,
  lint_judge_boundary_output_v1,
)
from vulngraph.workflows.szz_anchor_version_probe import DirectReachabilityRunner, build_tag_universe


def discover_boundary_cves(boundary_run: str | Path) -> list[str]:
  root = Path(boundary_run)
  if not root.exists():
    return []
  flat = sorted(
    child.name
    for child in root.iterdir()
    if child.is_dir() and (child / "judge_boundary_result.json").exists()
  )
  if flat:
    return flat
  nested = []
  for group in ("30", "10"):
    group_root = root / "cases" / group
    if group_root.exists():
      nested.extend(
        child.name
        for child in group_root.iterdir()
        if child.is_dir() and (child / "judge_boundary_result.json").exists()
      )
  return sorted(set(nested))


def convert_affected_versions_for_cve(
  *,
  cve_id: str,
  boundary_run: str | Path,
  dataset: str | Path,
  repo_root: str | Path,
  git_runner: Any | None = None,
) -> dict[str, Any]:
  runner = git_runner or DirectReachabilityRunner()
  boundary_root = Path(boundary_run)
  record = _dataset_record(Path(dataset), cve_id)
  repo_name = str(record.get("repo") or "")
  repo_path = Path(repo_root) / repo_name
  case_root = boundary_root / cve_id
  parsed = _read_json_default(case_root / "parsed_boundary_output.json", {})
  result = _read_json_default(case_root / "judge_boundary_result.json", {})
  boundary_input = _read_json_default(case_root / "judge_boundary_input_v1.json", {})
  candidates = {
    str(item.get("candidate_id") or ""): item
    for item in boundary_input.get("candidate_set", []) or []
  }
  release_tags = build_tag_universe(repo_name, runner.list_tags(repo_path))[
    "release_tag_universe"
  ]

  if not result.get("contract_ok"):
    return _blocked_prediction(
      cve_id=cve_id,
      repo=repo_name,
      release_tags=release_tags,
      reason="judge_boundary_contract_not_accepted",
    )

  contract = lint_judge_boundary_output_v1(parsed, boundary_input)
  if not contract.ok:
    return _blocked_prediction(
      cve_id=cve_id,
      repo=repo_name,
      release_tags=release_tags,
      reason="converter_boundary_contract_revalidation_failed",
      details=contract.errors,
    )

  views = derive_boundary_views(parsed, boundary_input)
  selected_events = views["selected_boundary_events"]
  uncertain_judgments = views["uncertain_candidates"]
  boundary_groups = {
    str(item.get("boundary_group_id") or ""): item
    for item in boundary_input.get("boundary_groups", []) or []
    if item.get("boundary_group_id")
  }
  fix_groups = {
    str(item.get("fix_group_id") or ""): item
    for item in boundary_input.get("fix_groups", []) or []
    if item.get("fix_group_id")
  }
  if selected_events and (not boundary_groups or not fix_groups):
    return _blocked_prediction(
      cve_id=cve_id,
      repo=repo_name,
      release_tags=release_tags,
      reason="missing_wrapper_owned_boundary_or_fix_groups",
    )

  selected_by_group: dict[str, list[dict[str, Any]]] = {
    group_id: [] for group_id in boundary_groups
  }
  for event in selected_events:
    for group_id in event.get("boundary_group_ids", []) or []:
      if group_id in selected_by_group:
        selected_by_group[group_id].append(event)

  uncertainty: list[dict[str, Any]] = []
  evidence: list[dict[str, Any]] = []
  affected: set[str] = set()
  reachability_cache: dict[str, dict[str, str]] = {}

  for group_id, group in boundary_groups.items():
    events = selected_by_group.get(group_id, [])
    activators = [
      item for item in events if item.get("boundary_role") in {"introduction", "activation"}
    ]
    prerequisites = [
      item for item in events if item.get("boundary_role") == "prerequisite"
    ]
    if prerequisites and not activators:
      uncertainty.append(
        {
          "boundary_group_id": group_id,
          "reason": "prerequisite_without_activation",
        }
      )
    if not activators:
      continue

    fix_group_id = str(group.get("fix_group_id") or "")
    fix_group = fix_groups.get(fix_group_id)
    if not fix_group:
      uncertainty.append(
        {
          "boundary_group_id": group_id,
          "reason": "missing_related_fix_group",
          "fix_group_id": fix_group_id,
        }
      )
      continue

    event_states = {
      item["candidate_id"]: _reachable_tags(
        runner,
        str(item.get("candidate_commit_sha") or ""),
        release_tags,
        reachability_cache,
      )
      for item in events
    }
    fix_state = _fix_group_states(
      runner,
      fix_group,
      release_tags,
      reachability_cache,
    )

    for tag in release_tags:
      activator_values = [
        event_states[item["candidate_id"]].get(tag, "unknown") for item in activators
      ]
      prerequisite_values = [
        event_states[item["candidate_id"]].get(tag, "unknown") for item in prerequisites
      ]
      activation_state = _activation_state(activator_values, prerequisite_values)
      completion_state = fix_state["tags"].get(tag, "unknown")
      is_affected = activation_state == "active" and completion_state == "incomplete"
      if is_affected:
        affected.add(tag)
      if activation_state == "unknown" or completion_state == "unknown":
        uncertainty.append(
          {
            "boundary_group_id": group_id,
            "fix_group_id": fix_group_id,
            "tag": tag,
            "reason": "unknown_boundary_or_fix_reachability",
            "activation_state": activation_state,
            "fix_completion_state": completion_state,
          }
        )
      evidence.append(
        {
          "boundary_group_id": group_id,
          "fix_group_id": fix_group_id,
          "tag": tag,
          "activation_state": activation_state,
          "fix_completion_state": completion_state,
          "affected": is_affected,
          "activator_candidate_ids": [item["candidate_id"] for item in activators],
          "prerequisite_candidate_ids": [item["candidate_id"] for item in prerequisites],
          "patch_family_states": fix_state["patch_family_states"].get(tag, {}),
          "lifecycle": "deterministic_vulnerability_state_evidence",
        }
      )

  if not selected_events:
    uncertainty.append({"reason": "no_selected_boundary_events"})

  selected_sources = sorted({
    str(item.get("candidate_source") or "unknown") for item in selected_events
  })
  patch_types = sorted({
    _patch_type(item, candidates.get(str(item.get("candidate_id") or ""), {}))
    for item in selected_events
  })
  return {
    "cve_id": cve_id,
    "repo": repo_name,
    "affected_versions": sorted(affected),
    "evidence": evidence,
    "uncertainty": uncertainty,
    "release_tag_universe_size": len(release_tags),
    "selected_boundary_event_count": len(selected_events),
    "uncertain_judgment_count": len(uncertain_judgments),
    "selected_candidate_sources": selected_sources,
    "selected_patch_types": patch_types,
    "prediction_status": "converted_with_uncertainty" if uncertainty else "converted",
    "blocked_reason": "",
    "lifecycle": "deterministic_converter_v1_1_prediction",
  }


def _activation_state(
  activator_values: list[str],
  prerequisite_values: list[str],
) -> str:
  if not activator_values:
    return "inactive"
  if any(value == "unknown" for value in prerequisite_values):
    return "unknown"
  if any(value != "yes" for value in prerequisite_values):
    return "inactive"
  if any(value == "yes" for value in activator_values):
    return "active"
  if any(value == "unknown" for value in activator_values):
    return "unknown"
  return "inactive"


def _fix_group_states(
  runner: Any,
  fix_group: dict[str, Any],
  release_tags: list[str],
  cache: dict[str, dict[str, str]],
) -> dict[str, Any]:
  family_states_by_tag: dict[str, dict[str, str]] = {tag: {} for tag in release_tags}
  for family in fix_group.get("patch_families", []) or []:
    family_id = str(family.get("patch_family_id") or "")
    members = [str(item) for item in family.get("fix_commit_shas", []) or [] if str(item)]
    member_states = {
      sha: _reachable_tags(runner, sha, release_tags, cache) for sha in members
    }
    for tag in release_tags:
      values = [states.get(tag, "unknown") for states in member_states.values()]
      if any(value == "yes" for value in values):
        state = "complete"
      elif any(value == "unknown" for value in values):
        state = "unknown"
      else:
        state = "incomplete"
      family_states_by_tag[tag][family_id] = state

  tag_states = {}
  for tag, family_states in family_states_by_tag.items():
    values = list(family_states.values())
    if values and all(value == "complete" for value in values):
      tag_states[tag] = "complete"
    elif any(value == "unknown" for value in values):
      tag_states[tag] = "unknown"
    else:
      tag_states[tag] = "incomplete"
  return {"tags": tag_states, "patch_family_states": family_states_by_tag}


def _reachable_tags(
  runner: Any,
  commit_sha: str,
  release_tags: list[str],
  cache: dict[str, dict[str, str]],
) -> dict[str, str]:
  if commit_sha in cache:
    return cache[commit_sha]
  tags_containing = getattr(runner, "tags_containing", None)
  if callable(tags_containing):
    contained = tags_containing(commit_sha)
    if contained is not None:
      contained_set = set(contained)
      cache[commit_sha] = {
        tag: ("yes" if tag in contained_set else "no") for tag in release_tags
      }
      return cache[commit_sha]
  cache[commit_sha] = {
    tag: runner.is_ancestor(commit_sha, tag) for tag in release_tags
  }
  return cache[commit_sha]


def _blocked_prediction(
  *,
  cve_id: str,
  repo: str,
  release_tags: list[str],
  reason: str,
  details: list[str] | None = None,
) -> dict[str, Any]:
  return {
    "cve_id": cve_id,
    "repo": repo,
    "affected_versions": [],
    "evidence": [],
    "uncertainty": [{"reason": reason, "details": details or []}],
    "release_tag_universe_size": len(release_tags),
    "selected_boundary_event_count": 0,
    "uncertain_judgment_count": 0,
    "selected_candidate_sources": [],
    "selected_patch_types": [],
    "prediction_status": "blocked",
    "blocked_reason": reason,
    "lifecycle": "deterministic_converter_v1_1_blocked",
  }


def _patch_type(event: dict[str, Any], candidate: dict[str, Any]) -> str:
  mode = str(event.get("candidate_selection_mode") or candidate.get("candidate_selection_mode") or "")
  flags = set(candidate.get("risk_flags", []) or [])
  if "add_only_semantic_anchor" in flags or mode == "add_only_semantic_target":
    return "add_only"
  if mode in {"modified_old_side", "direct_deleted_line"}:
    return "modify_delete"
  if "fallback" in mode or "context" in mode:
    return "context_fallback"
  return "other"


def run_affected_version_converter_v1(
  *,
  cve_ids: list[str],
  boundary_run: str | Path,
  dataset: str | Path,
  repo_root: str | Path,
  out_dir: str | Path,
  git_runner: Any | None = None,
  reset: bool = False,
) -> dict[str, Any]:
  output_root = Path(out_dir)
  if reset and output_root.exists():
    shutil.rmtree(output_root)
  output_root.mkdir(parents=True, exist_ok=True)
  started = time.monotonic()
  runner = git_runner or DirectReachabilityRunner()
  records = _read_json(Path(dataset))
  predictions = [
    convert_affected_versions_for_cve(
      cve_id=cve_id,
      boundary_run=boundary_run,
      dataset=dataset,
      repo_root=repo_root,
      git_runner=runner,
    )
    for cve_id in cve_ids
  ]
  prediction_rows = []
  for prediction in predictions:
    cve_id = prediction["cve_id"]
    gt = set(_affected_versions(records.get(cve_id, {})))
    prediction_rows.append(
      {
        "cve_id": cve_id,
        "predicted": set(prediction["affected_versions"]),
        "ground_truth": gt,
      }
    )
  metrics = p01_metrics(prediction_rows)
  diagnostics = _diagnostics(prediction_rows, predictions)
  grouped_metrics = _grouped_metrics(prediction_rows, predictions)
  stage_errors = _stage_error_attribution(predictions)
  summary = {
    "cases_total": len(predictions),
    "prediction_count": len(predictions),
    "blocked_count": sum(1 for item in predictions if item["prediction_status"] == "blocked"),
    "converted_count": sum(1 for item in predictions if item["prediction_status"] != "blocked"),
    "paper_metrics": metrics,
    "diagnostics": diagnostics,
    "grouped_metrics": grouped_metrics,
    "stage_error_attribution": stage_errors,
    "lifecycle": "deterministic_converter_v1_1_prediction",
    "duration_s": round(time.monotonic() - started, 6),
  }
  _write_json(output_root / "summary.json", summary)
  _write_json(output_root / "paper_metrics.json", metrics)
  _write_json(output_root / "stage_error_attribution.json", stage_errors)
  _write_json(output_root / "grouped_metrics.json", grouped_metrics)
  with (output_root / "per_cve_predictions.jsonl").open("w", encoding="utf-8") as handle:
    for prediction in predictions:
      handle.write(json.dumps(prediction, ensure_ascii=False) + "\n")
  (output_root / "error_attribution.md").write_text(
    _render_error_attribution(diagnostics, stage_errors),
    encoding="utf-8",
  )
  (output_root / "next_step_recommendations.md").write_text(
    _render_next_steps(diagnostics, stage_errors),
    encoding="utf-8",
  )
  return summary


def p01_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
  if not rows:
    return {
      "exact_accuracy": 0.0,
      "nmr": 0.0,
      "version_micro_precision": 0.0,
      "version_micro_recall": 0.0,
      "version_micro_f1": 0.0,
    }
  exact = sum(
    1 for row in rows if set(row["predicted"]) == set(row["ground_truth"])
  )
  nmr = sum(
    1
    for row in rows
    if set(row["ground_truth"]).issubset(set(row["predicted"]))
  )
  tp = sum(
    len(set(row["predicted"]) & set(row["ground_truth"])) for row in rows
  )
  fp = sum(
    len(set(row["predicted"]) - set(row["ground_truth"])) for row in rows
  )
  fn = sum(
    len(set(row["ground_truth"]) - set(row["predicted"])) for row in rows
  )
  precision = tp / (tp + fp) if tp + fp else 0.0
  recall = tp / (tp + fn) if tp + fn else 0.0
  f1 = (
    2 * precision * recall / (precision + recall)
    if precision + recall
    else 0.0
  )
  return {
    "exact_accuracy": exact / len(rows),
    "nmr": nmr / len(rows),
    "version_micro_precision": precision,
    "version_micro_recall": recall,
    "version_micro_f1": f1,
    "true_positive_versions": tp,
    "false_positive_versions": fp,
    "false_negative_versions": fn,
  }


def _diagnostics(
  rows: list[dict[str, Any]],
  predictions: list[dict[str, Any]],
) -> dict[str, Any]:
  by_cve = {item["cve_id"]: item for item in predictions}
  exact_cases = []
  miss_cases = []
  fp_heavy_cases = []
  uncertainty_cases = []
  blocked_cases = []
  source_cases: dict[str, list[str]] = {}
  for row in rows:
    cve_id = row["cve_id"]
    predicted = set(row["predicted"])
    gt = set(row["ground_truth"])
    if predicted == gt:
      exact_cases.append(cve_id)
    if gt - predicted:
      miss_cases.append(cve_id)
    if len(predicted - gt) >= 3:
      fp_heavy_cases.append(cve_id)
    prediction = by_cve.get(cve_id, {})
    if prediction.get("uncertainty"):
      uncertainty_cases.append(cve_id)
    if prediction.get("prediction_status") == "blocked":
      blocked_cases.append(cve_id)
    for source in prediction.get("selected_candidate_sources", []) or ["none"]:
      source_cases.setdefault(source, []).append(cve_id)
  return {
    "exact_match_cases": exact_cases,
    "miss_cases": miss_cases,
    "false_positive_heavy_cases": fp_heavy_cases,
    "branch_backport_uncertainty_cases": uncertainty_cases,
    "blocked_cases": blocked_cases,
    "judge_selected_boundary_vs_candidate_type": source_cases,
  }


def _grouped_metrics(
  rows: list[dict[str, Any]],
  predictions: list[dict[str, Any]],
) -> dict[str, Any]:
  row_by_cve = {item["cve_id"]: item for item in rows}
  groups: dict[str, list[str]] = {}
  for prediction in predictions:
    cve_id = prediction["cve_id"]
    status = str(prediction.get("prediction_status") or "unknown")
    groups.setdefault(f"status:{status}", []).append(cve_id)
    for source in prediction.get("selected_candidate_sources", []) or ["none"]:
      groups.setdefault(f"candidate_source:{source}", []).append(cve_id)
    for patch_type in prediction.get("selected_patch_types", []) or ["none"]:
      groups.setdefault(f"patch_type:{patch_type}", []).append(cve_id)
    if status == "blocked":
      groups.setdefault("boundary_decision:blocked", []).append(cve_id)
    elif prediction.get("selected_boundary_event_count"):
      groups.setdefault("boundary_decision:selected", []).append(cve_id)
    elif prediction.get("uncertain_judgment_count"):
      groups.setdefault("boundary_decision:uncertain", []).append(cve_id)
    else:
      groups.setdefault("boundary_decision:none", []).append(cve_id)
  for required_group in (
    "status:blocked",
    "boundary_decision:selected",
    "boundary_decision:uncertain",
    "boundary_decision:blocked",
    "candidate_source:strong",
    "candidate_source:fallback",
    "patch_type:add_only",
    "patch_type:modify_delete",
    "patch_type:context_fallback",
  ):
    groups.setdefault(required_group, [])
  output = {}
  for name, cve_ids in sorted(groups.items()):
    unique = sorted(set(cve_ids))
    output[name] = {
      "case_count": len(unique),
      "cve_ids": unique,
      "metrics": p01_metrics([row_by_cve[cve_id] for cve_id in unique]),
    }
  return output


def _stage_error_attribution(predictions: list[dict[str, Any]]) -> dict[str, Any]:
  counter: Counter[str] = Counter()
  cases: dict[str, list[str]] = {}
  for prediction in predictions:
    cve_id = prediction["cve_id"]
    if prediction.get("prediction_status") == "blocked":
      key = f"blocked:{prediction.get('blocked_reason') or 'unknown'}"
      counter[key] += 1
      cases.setdefault(key, []).append(cve_id)
    for item in prediction.get("uncertainty", []) or []:
      reason = str(item.get("reason") or "unknown")
      counter[reason] += 1
      cases.setdefault(reason, []).append(cve_id)
  return {
    "counts": dict(sorted(counter.items())),
    "cases": {key: sorted(set(value)) for key, value in sorted(cases.items())},
  }


def _render_error_attribution(
  diagnostics: dict[str, Any],
  stage_errors: dict[str, Any],
) -> str:
  lines = ["# Converter v1.1 Error Attribution", ""]
  for key, values in diagnostics.items():
    lines.extend([f"## {key}", "", f"- {values}", ""])
  lines.extend(["## stage_errors", ""])
  for key, value in stage_errors.get("counts", {}).items():
    lines.append(f"- {key}: {value}")
  return "\n".join(lines) + "\n"


def _render_next_steps(
  diagnostics: dict[str, Any],
  stage_errors: dict[str, Any],
) -> str:
  return "\n".join(
    [
      "# Next Step Recommendations",
      "",
      "- Inspect v1.1 blocked and miss cases before any 100-CVE validation.",
      "- Validate fix-group semantics independently from ground-truth labels.",
      "- Keep boundary selection and version conversion error attribution separate.",
      f"- Current blocked cases: {diagnostics.get('blocked_cases', [])}",
      f"- Current miss cases: {diagnostics.get('miss_cases', [])}",
      f"- Stage errors: {stage_errors.get('counts', {})}",
      "",
    ]
  )


def _dataset_record(dataset: Path, cve_id: str) -> dict[str, Any]:
  records = _read_json(dataset)
  record = records.get(cve_id, {})
  return record if isinstance(record, dict) else {}


def _affected_versions(record: dict[str, Any]) -> list[str]:
  for key in (
    "affected_version",
    "affected_versions",
    "ground_truth_affected_versions",
  ):
    value = record.get(key)
    if isinstance(value, list):
      return [str(item) for item in value]
  return []


def _read_json(path: Path) -> dict[str, Any]:
  data = json.loads(path.read_text(encoding="utf-8"))
  if not isinstance(data, dict):
    raise ValueError(f"expected JSON object: {path}")
  return data


def _read_json_default(path: Path, default: dict[str, Any]) -> dict[str, Any]:
  if not path.exists():
    return default
  return _read_json(path)


def _write_json(path: Path, data: Any) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(
    json.dumps(data, ensure_ascii=False, indent=2),
    encoding="utf-8",
  )
