from __future__ import annotations

import hashlib
import json
import shutil
import time
import subprocess
from pathlib import Path
from typing import Any

from vulngraph.agent_io.judge_boundary_v1_2_contract import (
  derive_boundary_views_v1_2,
  lint_judge_boundary_output_v1_2,
)
from vulngraph.workflows.szz_anchor_version_probe import DirectReachabilityRunner, build_tag_universe
from vulngraph.workflows.affected_version_converter_v1 import p01_metrics


def convert_affected_versions_for_cve_v1_2(
  *, cve_id: str, boundary_run: str | Path, dataset: str | Path,
  repo_root: str | Path, git_runner: Any | None = None,
) -> dict[str, Any]:
  runner = git_runner or DirectReachabilityRunner()
  records = json.loads(Path(dataset).read_text(encoding="utf-8"))
  record = records.get(cve_id, {})
  repo = str(record.get("repo") or "")
  repo_path = Path(repo_root) / repo
  if hasattr(runner, "set_repo"):
    runner.set_repo(repo_path)
  release_tags = build_tag_universe(repo, runner.list_tags(repo_path))["release_tag_universe"]
  case = Path(boundary_run) / cve_id
  boundary_input = _read(case / "judge_boundary_input_v1_2.json")
  parsed = _read(case / "parsed_boundary_output_v1_2.json")
  result = _read(case / "judge_boundary_result_v1_2.json")
  if not result.get("contract_ok"):
    return _blocked(cve_id, repo, release_tags, "judge_boundary_contract_not_accepted")
  contract = lint_judge_boundary_output_v1_2(parsed, boundary_input)
  if not contract.ok:
    return _blocked(cve_id, repo, release_tags, "converter_boundary_contract_revalidation_failed")
  views = derive_boundary_views_v1_2(parsed, boundary_input)
  if not views["activation_events"]:
    status = "unresolved_boundary" if views["uncertain_candidates"] else "unknown_state"
    return {
      "cve_id": cve_id, "repo": repo, "affected_versions": [],
      "evidence": [], "uncertainty": [{"reason": "no_selected_primary_boundary"}],
      "prediction_status": status, "unknown_version_count": len(release_tags),
      "release_tag_universe_size": len(release_tags), "lifecycle": "deterministic_converter_v1_2_unresolved",
    }
  contexts = {item["branch_context_id"]: item for item in boundary_input.get("branch_contexts", [])}
  fix_groups = {item["branch_context_id"]: item for item in boundary_input.get("fix_groups", [])}
  affected: set[str] = set()
  unknown: set[str] = set()
  evidence: list[dict[str, Any]] = []
  reachability_cache: dict[str, dict[str, str]] = {}
  all_selected_events = [*views["activation_events"], *views["conjunctive_prerequisites"]]
  line_state_cache = _precompute_line_states(runner, all_selected_events, release_tags, reachability_cache)
  for context_id in contexts:
    activators = [item for item in views["activation_events"] if context_id in item.get("branch_context_ids", [])]
    prerequisites = [item for item in views["conjunctive_prerequisites"] if context_id in item.get("branch_context_ids", [])]
    if not activators:
      continue
    fix_group = fix_groups.get(context_id)
    for tag in release_tags:
      activation = _event_group_state(runner, activators, tag, reachability_cache, line_state_cache)
      prerequisite = _prerequisite_state(runner, prerequisites, tag, reachability_cache, line_state_cache)
      fix_state = _fix_state(runner, fix_group, tag, reachability_cache) if fix_group else "unknown"
      state = "affected" if activation == "active" and prerequisite == "complete" and fix_state == "incomplete" else "not_affected"
      if "unknown" in {activation, prerequisite, fix_state}:
        state = "unknown"
        unknown.add(tag)
      elif state == "affected":
        affected.add(tag)
      evidence.append({"branch_context_id": context_id, "tag": tag, "activation_state": activation, "prerequisite_state": prerequisite, "fix_state": fix_state, "vulnerability_state": state})
  status = "unknown_state" if unknown else "converted"
  return {
    "cve_id": cve_id, "repo": repo, "affected_versions": sorted(affected),
    "evidence": evidence, "uncertainty": ([{"reason": "predicate_or_line_state_unknown", "unknown_version_count": len(unknown)}] if unknown else []),
    "prediction_status": status, "unknown_version_count": len(unknown),
    "release_tag_universe_size": len(release_tags), "lifecycle": "deterministic_converter_v1_2_prediction",
  }


def run_affected_version_converter_v1_2(
  *, cve_ids: list[str], boundary_run: str | Path, dataset: str | Path,
  repo_root: str | Path, out_dir: str | Path, git_runner: Any | None = None,
  reset: bool = False,
) -> dict[str, Any]:
  root = Path(out_dir)
  if reset and root.exists():
    shutil.rmtree(root)
  root.mkdir(parents=True, exist_ok=True)
  records = json.loads(Path(dataset).read_text(encoding="utf-8"))
  runner = git_runner or DirectReachabilityRunner()
  started = time.monotonic()
  predictions = []
  metric_rows = []
  for cve_id in cve_ids:
    prediction = convert_affected_versions_for_cve_v1_2(
      cve_id=cve_id, boundary_run=boundary_run, dataset=dataset,
      repo_root=repo_root, git_runner=runner,
    )
    predictions.append(prediction)
    truth = set(records.get(cve_id, {}).get("affected_version", []) or [])
    metric_rows.append({"cve_id": cve_id, "predicted": set(prediction["affected_versions"]), "ground_truth": truth})
    case = root / cve_id
    case.mkdir(parents=True, exist_ok=True)
    _write(case / "converter_internal_state_v1_2.json", prediction)
    _write(case / "public_prediction.json", {
      "cve_id": cve_id, "affected_versions": prediction["affected_versions"],
      "evidence": prediction["evidence"], "uncertainty": prediction["uncertainty"],
      "prediction_status": prediction["prediction_status"], "lifecycle": prediction["lifecycle"],
    })
  metrics = p01_metrics(metric_rows)
  statuses: dict[str, int] = {}
  for item in predictions:
    statuses[item["prediction_status"]] = statuses.get(item["prediction_status"], 0) + 1
  summary = {
    "cases_total": len(predictions), "prediction_status_counts": statuses,
    "converted_count": statuses.get("converted", 0),
    "unresolved_count": statuses.get("unresolved_boundary", 0),
    "unknown_state_count": statuses.get("unknown_state", 0),
    "blocked_count": statuses.get("blocked", 0),
    "duration_s": round(time.monotonic() - started, 6),
    "lifecycle": "deterministic_converter_v1_2_evaluation",
  }
  _write(root / "summary.json", summary)
  _write(root / "paper_metrics.json", metrics)
  with (root / "per_cve_predictions.jsonl").open("w", encoding="utf-8") as handle:
    for item in predictions:
      handle.write(json.dumps({
        "cve_id": item["cve_id"], "repo": item["repo"],
        "affected_versions": item["affected_versions"],
        "uncertainty": item["uncertainty"], "prediction_status": item["prediction_status"],
        "unknown_version_count": item["unknown_version_count"], "lifecycle": item["lifecycle"],
      }, ensure_ascii=False) + "\n")
  _write(root / "stage_error_attribution.json", {
    "prediction_status_counts": statuses,
    "cases": [{"cve_id": item["cve_id"], "prediction_status": item["prediction_status"], "uncertainty": item["uncertainty"]} for item in predictions if item["prediction_status"] != "converted"],
  })
  return {**summary, "paper_metrics": metrics}


def _event_group_state(runner: Any, events: list[dict[str, Any]], tag: str, reachability_cache: dict[str, dict[str, str]], line_state_cache: dict[tuple[str, str], str]) -> str:
  values = [_event_state(runner, event, tag, reachability_cache, line_state_cache) for event in events]
  if "active" in values:
    return "active"
  if "unknown" in values:
    return "unknown"
  return "inactive"


def _prerequisite_state(runner: Any, events: list[dict[str, Any]], tag: str, reachability_cache: dict[str, dict[str, str]], line_state_cache: dict[tuple[str, str], str]) -> str:
  if not events:
    return "complete"
  values = [_event_state(runner, event, tag, reachability_cache, line_state_cache) for event in events]
  if "unknown" in values:
    return "unknown"
  return "complete" if all(value == "active" for value in values) else "incomplete"


def _event_state(runner: Any, event: dict[str, Any], tag: str, reachability_cache: dict[str, dict[str, str]], line_state_cache: dict[tuple[str, str], str]) -> str:
  reachable = _reachability_state(runner, str(event.get("event_commit_sha") or ""), tag, reachability_cache)
  if reachable == "unknown":
    return "unknown"
  if reachable != "yes" and reachable is not True:
    return "inactive"
  key = (str(event.get("event_candidate_id") or ""), tag)
  line_state_fn = getattr(runner, "line_state", None)
  state = line_state_cache.get(key)
  if state is None and callable(line_state_fn):
    state = line_state_fn(tag, str(event.get("path_before") or ""), str(event.get("old_line_text") or ""), str(event.get("old_line_text_hash") or ""))
  if state is None:
    state = "unknown"
  if state == "present":
    return "active"
  if state == "absent":
    return "inactive"
  return "unknown"


def _fix_state(runner: Any, fix_group: dict[str, Any], tag: str, reachability_cache: dict[str, dict[str, str]]) -> str:
  semantics = str(fix_group.get("completion_semantics") or "unknown")
  values = [_reachability_state(runner, str(sha), tag, reachability_cache) for sha in fix_group.get("fix_commit_shas", []) or []]
  if not values or semantics == "unknown":
    return "unknown"
  if semantics in {"any_equivalent_fix", "branch_local_single"}:
    if any(value == "yes" or value is True for value in values):
      return "complete"
    if any(value == "unknown" for value in values):
      return "unknown"
    return "incomplete"
  if semantics == "all_conjunctive_fixes":
    if all(value == "yes" or value is True for value in values):
      return "complete"
    if any(value == "unknown" for value in values):
      return "unknown"
    return "incomplete"
  return "unknown"


def _reachability_state(runner: Any, sha: str, tag: str, cache: dict[str, dict[str, str]]) -> str:
  if sha not in cache:
    containing = getattr(runner, "tags_containing", None)
    values = containing(sha) if callable(containing) else None
    if values is not None:
      cache[sha] = {name: "yes" if name in values else "no" for name in getattr(runner, "_v1_2_release_tags", [])}
    else:
      cache[sha] = {}
  if tag not in cache[sha]:
    cache[sha][tag] = runner.is_ancestor(sha, tag)
  return cache[sha][tag]


def _precompute_line_states(runner: Any, events: list[dict[str, Any]], release_tags: list[str], reachability_cache: dict[str, dict[str, str]]) -> dict[tuple[str, str], str]:
  setattr(runner, "_v1_2_release_tags", release_tags)
  if callable(getattr(runner, "line_state", None)):
    return {}
  repo = getattr(runner, "current_repo", None)
  if not repo:
    return {}
  output: dict[tuple[str, str], str] = {}
  for event in events:
    event_id = str(event.get("event_candidate_id") or "")
    sha = str(event.get("event_commit_sha") or "")
    path = str(event.get("path_before") or "")
    line = str(event.get("old_line_text") or "")
    if not event_id or not sha or not path or not line:
      continue
    reachable = [tag for tag in release_tags if _reachability_state(runner, sha, tag, reachability_cache) == "yes"]
    for tag in release_tags:
      if tag not in reachable:
        output[(event_id, tag)] = "absent"
    for index in range(0, len(reachable), 50):
      chunk = reachable[index:index + 50]
      command = ["git", "-C", str(repo), "grep", "-F", "-n", "-e", line.strip(), *chunk, "--", path]
      result = subprocess.run(command, text=True, encoding="utf-8", errors="replace", capture_output=True, check=False)
      if result.returncode not in {0, 1}:
        for tag in chunk:
          output[(event_id, tag)] = "unknown"
        continue
      matched = set()
      for row in result.stdout.splitlines():
        parts = row.split(":", 3)
        if len(parts) == 4 and parts[3].strip() == line.strip():
          matched.add(parts[0])
      for tag in chunk:
        output[(event_id, tag)] = "present" if tag in matched else "absent"
  return output


def _blocked(cve_id: str, repo: str, tags: list[str], reason: str) -> dict[str, Any]:
  return {"cve_id": cve_id, "repo": repo, "affected_versions": [], "evidence": [], "uncertainty": [{"reason": reason}], "prediction_status": "blocked", "blocked_reason": reason, "unknown_version_count": len(tags), "release_tag_universe_size": len(tags), "lifecycle": "deterministic_converter_v1_2_blocked"}


def _read(path: Path) -> dict[str, Any]:
  return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, value: Any) -> None:
  path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
