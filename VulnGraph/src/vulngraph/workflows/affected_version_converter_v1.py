from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any

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
      nested.extend(child.name for child in group_root.iterdir() if child.is_dir() and (child / "judge_boundary_result.json").exists())
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
  fixing_commits = _flatten_fix_commits(record.get("fixing_commits"))
  parsed = _read_json_default(boundary_root / cve_id / "parsed_boundary_output.json", {})
  result = _read_json_default(boundary_root / cve_id / "judge_boundary_result.json", {})
  boundary_input = _read_json_default(boundary_root / cve_id / "judge_boundary_input_v1.json", {})
  candidates = {str(item.get("candidate_id") or ""): item for item in boundary_input.get("candidate_set", []) or []}
  tags = runner.list_tags(repo_path)
  release_tags = build_tag_universe(repo_name, tags)["release_tag_universe"]
  uncertainty: list[dict[str, Any]] = []
  evidence: list[dict[str, Any]] = []
  affected: set[str] = set()

  if not result.get("contract_ok"):
    uncertainty.append({"reason": "judge_boundary_contract_not_accepted"})
  selected_events = [item for item in parsed.get("selected_boundary_events", []) or [] if isinstance(item, dict)]
  if not selected_events:
    uncertainty.append({"reason": "no_selected_boundary_events"})

  for event in selected_events:
    role = str(event.get("boundary_role") or "")
    candidate_id = str(event.get("candidate_id") or "")
    candidate_sha = str(event.get("candidate_commit_sha") or "")
    candidate = candidates.get(candidate_id, {})
    if role in {"fix_series_noise", "refactor_noise", "equivalent_fix_noise", "uncertain_boundary"}:
      uncertainty.append({"candidate_id": candidate_id, "reason": f"selected_event_role_not_direct_introduction:{role}"})
      continue
    if not candidate_sha:
      uncertainty.append({"candidate_id": candidate_id, "reason": "missing_candidate_sha"})
      continue
    if _convert_with_tags_containing(
      runner=runner,
      candidate_id=candidate_id,
      candidate_sha=candidate_sha,
      candidate=candidate,
      role=role,
      fixing_commits=fixing_commits,
      release_tags=release_tags,
      affected=affected,
      evidence=evidence,
      uncertainty=uncertainty,
    ):
      continue
    _convert_with_merge_base(
      runner=runner,
      candidate_id=candidate_id,
      candidate_sha=candidate_sha,
      candidate=candidate,
      role=role,
      fixing_commits=fixing_commits,
      release_tags=release_tags,
      affected=affected,
      evidence=evidence,
      uncertainty=uncertainty,
    )

  return {
    "cve_id": cve_id,
    "repo": repo_name,
    "affected_versions": sorted(affected),
    "evidence": evidence,
    "uncertainty": uncertainty,
    "release_tag_universe_size": len(release_tags),
    "selected_boundary_event_count": len(selected_events),
    "lifecycle": "deterministic_converter_v1_prediction",
  }


def _convert_with_tags_containing(
  *,
  runner: Any,
  candidate_id: str,
  candidate_sha: str,
  candidate: dict[str, Any],
  role: str,
  fixing_commits: list[str],
  release_tags: list[str],
  affected: set[str],
  evidence: list[dict[str, Any]],
  uncertainty: list[dict[str, Any]],
) -> bool:
  tags_containing = getattr(runner, "tags_containing", None)
  if not callable(tags_containing):
    return False
  release_set = set(release_tags)
  candidate_tags = tags_containing(candidate_sha)
  if candidate_tags is None:
    return False
  fix_tag_sets: dict[str, set[str]] = {}
  for fix in fixing_commits:
    fix_tags = tags_containing(fix)
    if fix_tags is None:
      uncertainty.append({"candidate_id": candidate_id, "reason": "unknown_git_tag_contains", "commit_sha": fix})
      return False
    fix_tag_sets[fix] = set(fix_tags) & release_set
  candidate_release_tags = set(candidate_tags) & release_set
  fixed_release_tags = set().union(*fix_tag_sets.values()) if fix_tag_sets else set()
  affected.update(candidate_release_tags - fixed_release_tags)
  for tag in sorted(candidate_release_tags | fixed_release_tags):
    fix_states = {fix: ("yes" if tag in fix_tags else "no") for fix, fix_tags in fix_tag_sets.items()}
    evidence.append(
      {
        "candidate_id": candidate_id,
        "candidate_commit_sha": candidate_sha,
        "tag": tag,
        "boundary_role": role,
        "candidate_source": candidate.get("candidate_source", ""),
        "candidate_reachable_to_tag": "yes" if tag in candidate_release_tags else "no",
        "fix_reachable_to_tag": "yes" if tag in fixed_release_tags else "no",
        "fix_commit_states": fix_states,
        "reachability_method": "git_tag_contains",
        "lifecycle": "deterministic_reachability_evidence",
      }
    )
  return True


def _convert_with_merge_base(
  *,
  runner: Any,
  candidate_id: str,
  candidate_sha: str,
  candidate: dict[str, Any],
  role: str,
  fixing_commits: list[str],
  release_tags: list[str],
  affected: set[str],
  evidence: list[dict[str, Any]],
  uncertainty: list[dict[str, Any]],
) -> None:
  for tag in release_tags:
    candidate_reachable = runner.is_ancestor(candidate_sha, tag)
    fix_states = {fix: runner.is_ancestor(fix, tag) for fix in fixing_commits}
    fix_reachable = any(state == "yes" for state in fix_states.values())
    if candidate_reachable == "unknown" or any(state == "unknown" for state in fix_states.values()):
      uncertainty.append({"candidate_id": candidate_id, "tag": tag, "reason": "unknown_git_reachability"})
    if candidate_reachable == "yes" and not fix_reachable:
      affected.add(tag)
    evidence.append(
      {
        "candidate_id": candidate_id,
        "candidate_commit_sha": candidate_sha,
        "tag": tag,
        "boundary_role": role,
        "candidate_source": candidate.get("candidate_source", ""),
        "candidate_reachable_to_tag": candidate_reachable,
        "fix_reachable_to_tag": "yes" if fix_reachable else "no",
        "fix_commit_states": fix_states,
        "reachability_method": "git_merge_base_is_ancestor",
        "lifecycle": "deterministic_reachability_evidence",
      }
    )


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
    prediction_rows.append({"cve_id": cve_id, "predicted": set(prediction["affected_versions"]), "ground_truth": gt})
  metrics = p01_metrics(prediction_rows)
  diagnostics = _diagnostics(prediction_rows, predictions)
  summary = {
    "cases_total": len(predictions),
    "prediction_count": len(predictions),
    "paper_metrics": metrics,
    "diagnostics": diagnostics,
    "lifecycle": "deterministic_converter_v1_prediction",
    "duration_s": round(time.monotonic() - started, 6),
  }
  _write_json(output_root / "summary.json", summary)
  _write_json(output_root / "paper_metrics.json", metrics)
  with (output_root / "per_cve_predictions.jsonl").open("w", encoding="utf-8") as handle:
    for prediction in predictions:
      handle.write(json.dumps(prediction, ensure_ascii=False) + "\n")
  (output_root / "error_attribution.md").write_text(_render_error_attribution(diagnostics), encoding="utf-8")
  (output_root / "next_step_recommendations.md").write_text(_render_next_steps(diagnostics), encoding="utf-8")
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
  exact = sum(1 for row in rows if set(row["predicted"]) == set(row["ground_truth"]))
  nmr = sum(1 for row in rows if set(row["ground_truth"]).issubset(set(row["predicted"])))
  tp = sum(len(set(row["predicted"]) & set(row["ground_truth"])) for row in rows)
  fp = sum(len(set(row["predicted"]) - set(row["ground_truth"])) for row in rows)
  fn = sum(len(set(row["ground_truth"]) - set(row["predicted"])) for row in rows)
  precision = tp / (tp + fp) if tp + fp else 0.0
  recall = tp / (tp + fn) if tp + fn else 0.0
  f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
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


def _diagnostics(rows: list[dict[str, Any]], predictions: list[dict[str, Any]]) -> dict[str, Any]:
  by_cve = {item["cve_id"]: item for item in predictions}
  exact_cases = []
  miss_cases = []
  fp_heavy_cases = []
  uncertainty_cases = []
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
    sources = sorted({str(item.get("candidate_source") or "unknown") for item in prediction.get("evidence", []) if item.get("candidate_id")})
    for source in sources or ["none"]:
      source_cases.setdefault(source, []).append(cve_id)
  return {
    "exact_match_cases": exact_cases,
    "miss_cases": miss_cases,
    "false_positive_heavy_cases": fp_heavy_cases,
    "branch_backport_uncertainty_cases": uncertainty_cases,
    "judge_selected_boundary_vs_candidate_type": source_cases,
  }


def _render_error_attribution(diagnostics: dict[str, Any]) -> str:
  lines = ["# Converter v1 Error Attribution", ""]
  for key, values in diagnostics.items():
    lines.append(f"## {key}")
    lines.append("")
    if isinstance(values, dict):
      for subkey, subvalues in values.items():
        lines.append(f"- {subkey}: {subvalues}")
    else:
      for value in values:
        lines.append(f"- {value}")
    lines.append("")
  return "\n".join(lines)


def _render_next_steps(diagnostics: dict[str, Any]) -> str:
  return "\n".join(
    [
      "# Next Step Recommendations",
      "",
      "- Inspect miss cases before running any 100-CVE validation.",
      "- Separate fallback-only cases from strong-boundary cases in diagnostics.",
      "- Add branch-local/backport reasoning only after deterministic reachability errors are understood.",
      f"- Current miss cases: {diagnostics.get('miss_cases', [])}",
      f"- Current branch/backport uncertainty cases: {diagnostics.get('branch_backport_uncertainty_cases', [])}",
      "",
    ]
  )


def _dataset_record(dataset: Path, cve_id: str) -> dict[str, Any]:
  records = _read_json(dataset)
  record = records.get(cve_id, {})
  return record if isinstance(record, dict) else {}


def _affected_versions(record: dict[str, Any]) -> list[str]:
  for key in ("affected_version", "affected_versions", "ground_truth_affected_versions"):
    value = record.get(key)
    if isinstance(value, list):
      return [str(item) for item in value]
  return []


def _flatten_fix_commits(value: Any) -> list[str]:
  output: list[str] = []
  for item in value or []:
    if isinstance(item, list):
      output.extend(str(inner) for inner in item if str(inner).strip())
    elif str(item).strip():
      output.append(str(item))
  return output


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
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
