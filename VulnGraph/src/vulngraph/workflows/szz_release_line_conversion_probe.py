from __future__ import annotations

import csv
import json
import re
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vulngraph.workflows.szz_anchor_version_probe import DirectReachabilityRunner, set_metrics


VERSION_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])(?:v|n)?(\d+(?:[._-]\d+){1,5}[a-z]?)(?![A-Za-z0-9])", re.IGNORECASE)
FORBIDDEN_EXACT_KEYS = {"validated_bic", "correct_bic", "affected_versions"}


@dataclass(frozen=True)
class ReleaseVersion:
  major: int
  minor: int | None
  patch: str | None

  @property
  def major_line(self) -> str:
    return f"{self.major}.x"

  @property
  def major_minor(self) -> str:
    if self.minor is None:
      return self.major_line
    return f"{self.major}.{self.minor}"


def parse_release_version(tag: str) -> ReleaseVersion | None:
  matches = VERSION_TOKEN_RE.findall(tag)
  if not matches:
    return None
  token = matches[-1].replace("_", ".").replace("-", ".")
  parts = token.split(".")
  if len(parts) < 2:
    return None
  if not parts[0].isdigit() or not parts[1].isdigit():
    return None
  patch = parts[2] if len(parts) > 2 else None
  return ReleaseVersion(major=int(parts[0]), minor=int(parts[1]), patch=patch)


def build_release_line_groups(*, ground_truth_tags: set[str], predicted_tags: set[str]) -> list[dict[str, Any]]:
  by_line: dict[str, dict[str, set[str]]] = {}
  for tag in ground_truth_tags | predicted_tags:
    version = parse_release_version(tag)
    line_id = version.major_minor if version else "unparsed"
    by_line.setdefault(line_id, {"tags": set(), "ground_truth_tags": set(), "predicted_tags": set()})
    by_line[line_id]["tags"].add(tag)
    if tag in ground_truth_tags:
      by_line[line_id]["ground_truth_tags"].add(tag)
    if tag in predicted_tags:
      by_line[line_id]["predicted_tags"].add(tag)
  groups: list[dict[str, Any]] = []
  for line_id, values in sorted(by_line.items()):
    gt = values["ground_truth_tags"]
    pred = values["predicted_tags"]
    metrics = set_metrics(pred, gt)
    groups.append(
      {
        "line_id": line_id,
        "tags": sorted(values["tags"]),
        "ground_truth_tags": sorted(gt),
        "predicted_tags": sorted(pred),
        "false_positive_tags": sorted(pred - gt),
        "false_negative_tags": sorted(gt - pred),
        "line_precision": metrics["precision"],
        "line_recall": metrics["recall"],
        "line_f1": metrics["f1"],
      }
    )
  return groups


def apply_conversion_strategies(
  *,
  predicted_tags: set[str],
  ground_truth_tags: set[str],
  tag_diagnostics: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
  gt_lines = {_line_id(tag) for tag in ground_truth_tags if _line_id(tag)}
  diag_by_tag = {str(item.get("tag") or ""): item for item in tag_diagnostics}
  direct = set(predicted_tags)
  same_line = {tag for tag in predicted_tags if _line_id(tag) in gt_lines}
  fix_excluded = {
    tag for tag in predicted_tags if str(diag_by_tag.get(tag, {}).get("known_fix_reachable")) != "yes"
  }
  time_uncertainty: list[str] = []
  time_excluded: set[str] = set()
  for tag in predicted_tags:
    diag = diag_by_tag.get(tag, {})
    known_fix = str(diag.get("known_fix_reachable"))
    tag_after_fix = diag.get("tag_after_fix")
    if tag_after_fix == "unknown":
      time_uncertainty.append(f"{tag}:missing_time_or_fix_reachability")
    if known_fix == "yes" and tag_after_fix is True:
      time_uncertainty.append(f"{tag}:removed_by_known_fix_reachable_after_fix_time")
      continue
    time_excluded.add(tag)
  return {
    "direct_release_reachability": _strategy_payload(direct, ground_truth_tags),
    "same_line_trim": {
      **_strategy_payload(same_line, ground_truth_tags),
      "diagnostic_uses_ground_truth_line": True,
    },
    "fix_reachable_exclusion": _strategy_payload(fix_excluded, ground_truth_tags),
    "time_after_fix_exclusion": {
      **_strategy_payload(time_excluded, ground_truth_tags),
      "uncertainty": time_uncertainty,
    },
  }


def run_release_line_conversion_probe(
  *,
  anchor_audit_run: str | Path,
  version_probe_run: str | Path,
  dataset: str | Path,
  repo_root: str | Path,
  out_dir: str | Path,
  cve_ids: list[str],
  git_runner: Any | None = None,
) -> dict[str, Any]:
  started = time.monotonic()
  anchor_root = Path(anchor_audit_run)
  version_root = Path(version_probe_run)
  output_root = Path(out_dir)
  output_root.mkdir(parents=True, exist_ok=True)
  records = _read_json(Path(dataset))
  ranking = _read_json(version_root / "ranking_diagnostics.json")
  runner = git_runner or DirectReachabilityRunner()

  per_cve: dict[str, Any] = {}
  fp_rows: list[dict[str, Any]] = []
  strategy_rows: list[dict[str, Any]] = []
  manual_rows: list[dict[str, Any]] = []
  removed_by_fix: dict[str, list[str]] = {}
  unexplained_fp: dict[str, list[str]] = {}

  for cve_id in cve_ids:
    record = records.get(cve_id, {})
    repo = str(record.get("repo") or "")
    repo_path = Path(repo_root) / repo
    if hasattr(runner, "set_repo"):
      runner.set_repo(repo_path)
    gt = set(_ground_truth(record))
    fix_commits = _flatten_fix_commits(record.get("fixing_commits"))
    case_rank = ranking.get(cve_id, {})
    release_rank = case_rank.get("release_tag_universe", {})
    top1 = release_rank.get("top1", {})
    oracle = release_rank.get("oracle", {})
    top1_predicted = set(top1.get("predicted_tags") or [])
    oracle_predicted = set(oracle.get("predicted_tags") or [])
    top1_commit = str(case_rank.get("top1_candidate_commit") or top1.get("commit_sha") or "")
    oracle_commit = str(oracle.get("oracle_best_candidate_commit") or "")
    fp = top1_predicted - gt
    fn = gt - top1_predicted
    tag_diags = [
      _false_positive_tag_diagnostic(
        repo_path=repo_path,
        tag=tag,
        candidate_commit=top1_commit,
        fix_commits=fix_commits,
        ground_truth_tags=gt,
        runner=runner,
      )
      for tag in sorted(fp)
    ]
    strategies = apply_conversion_strategies(
      predicted_tags=top1_predicted,
      ground_truth_tags=gt,
      tag_diagnostics=tag_diags,
    )
    for tag_diag in tag_diags:
      fp_rows.append({"cve_id": cve_id, "repo": repo, **tag_diag})
    for strategy_name, payload in strategies.items():
      strategy_rows.append(
        {
          "cve_id": cve_id,
          "repo": repo,
          "strategy": strategy_name,
          "predicted_tags": ";".join(payload["predicted_tags"]),
          "precision": payload["precision"],
          "recall": payload["recall"],
          "f1": payload["f1"],
          "exact_match": payload["exact_match"],
          "false_positive_count": payload["false_positive_count"],
          "false_negative_count": payload["false_negative_count"],
          "diagnostic_uses_ground_truth_line": payload.get("diagnostic_uses_ground_truth_line", False),
        }
      )
    fix_removed = sorted(tag for tag in fp if tag not in set(strategies["fix_reachable_exclusion"]["predicted_tags"]))
    removed_by_fix[cve_id] = fix_removed
    remaining = set(strategies["fix_reachable_exclusion"]["predicted_tags"]) - gt
    unexplained_fp[cve_id] = sorted(remaining)
    candidate_commits = _read_list(anchor_root / cve_id / "candidate_commits.json")
    resolved_anchors = _read_list(anchor_root / cve_id / "resolved_pre_fix_anchors.json")
    manual_rows.extend(
      _manual_review_rows(
        cve_id=cve_id,
        repo=repo,
        selected_candidate_commit=top1_commit,
        current_predicted_tags=top1_predicted,
        ground_truth_tags=gt,
        candidate_commits=candidate_commits,
        resolved_anchors=resolved_anchors,
      )
    )
    per_cve[cve_id] = {
      "cve_id": cve_id,
      "repo": repo,
      "candidate_lifecycle": "raw_candidate",
      "ground_truth_affected_versions": sorted(gt),
      "current_top1_candidate_commit": top1_commit,
      "current_oracle_candidate_commit": oracle_commit,
      "current_top1_predicted_tags": sorted(top1_predicted),
      "current_oracle_predicted_tags": sorted(oracle_predicted),
      "false_positive_release_tags": sorted(fp),
      "false_negative_release_tags": sorted(fn),
      "release_line_groups": build_release_line_groups(ground_truth_tags=gt, predicted_tags=top1_predicted),
      "false_positive_tag_diagnostics": tag_diags,
      "prototype_strategies": strategies,
    }

  summary = _summary(
    per_cve=per_cve,
    strategy_rows=strategy_rows,
    removed_by_fix=removed_by_fix,
    unexplained_fp=unexplained_fp,
    anchor_audit_run=anchor_root,
    version_probe_run=version_root,
    dataset=dataset,
    repo_root=repo_root,
    duration_s=time.monotonic() - started,
  )
  _write_json(output_root / "per_cve_release_line_diagnostic.json", per_cve)
  _write_csv(output_root / "per_tag_false_positive_diagnostic.csv", fp_rows)
  _write_csv(output_root / "per_strategy_metrics.csv", strategy_rows)
  _write_csv(output_root / "manual_anchor_review_residual_3.csv", manual_rows)
  _write_json(output_root / "summary.json", summary)
  _write_json(output_root / "provenance_manifest.json", _provenance(anchor_root, version_root, dataset, repo_root))
  (output_root / "report.md").write_text(_render_report(summary), encoding="utf-8")
  _assert_no_forbidden_exact_keys(output_root)
  return summary


def _false_positive_tag_diagnostic(
  *,
  repo_path: Path,
  tag: str,
  candidate_commit: str,
  fix_commits: list[str],
  ground_truth_tags: set[str],
  runner: Any,
) -> dict[str, Any]:
  candidate_reachable = _safe_is_ancestor(runner, candidate_commit, tag)
  fix_states = [_safe_is_ancestor(runner, fix, tag) for fix in fix_commits]
  known_fix_reachable = "yes" if "yes" in fix_states else ("unknown" if "unknown" in fix_states else "no")
  tag_time = _safe_commit_time(runner, repo_path, tag)
  fix_times = [_safe_commit_time(runner, repo_path, fix) for fix in fix_commits]
  known_fix_times = [item for item in fix_times if item is not None]
  nearest_fix_time = _nearest_time(tag_time, known_fix_times)
  tag_after_fix: bool | str
  if tag_time is None or nearest_fix_time is None:
    tag_after_fix = "unknown"
  else:
    tag_after_fix = tag_time > nearest_fix_time
  line_id = _line_id(tag) or "unparsed"
  gt_lines = {_line_id(gt) for gt in ground_truth_tags if _line_id(gt)}
  same_gt_line = line_id in gt_lines
  neighbor_gt_line = _same_major_line(line_id, gt_lines) and not same_gt_line
  if known_fix_reachable == "yes":
    source = "fix_line_exclusion_missing"
  elif same_gt_line:
    source = "release_line_overreach"
  elif candidate_reachable == "yes" and known_fix_reachable == "no":
    source = "raw_candidate_too_early"
  elif tag_time is None:
    source = "tag_mapping_issue"
  else:
    source = "branch_backport_unknown"
  return {
    "tag": tag,
    "line_id": line_id,
    "candidate_reachable": candidate_reachable,
    "known_fix_reachable": known_fix_reachable,
    "tag_time": tag_time,
    "nearest_fix_time": nearest_fix_time,
    "tag_after_fix": tag_after_fix,
    "same_gt_line": same_gt_line,
    "neighbor_gt_line": neighbor_gt_line,
    "likely_error_source": source,
  }


def _strategy_payload(predicted: set[str], gt: set[str]) -> dict[str, Any]:
  metrics = set_metrics(predicted, gt)
  return {
    "predicted_tags": sorted(predicted),
    "precision": metrics["precision"],
    "recall": metrics["recall"],
    "f1": metrics["f1"],
    "exact_match": metrics["exact_match"],
    "false_positive_count": metrics["false_positive_count"],
    "false_negative_count": metrics["false_negative_count"],
  }


def _summary(
  *,
  per_cve: dict[str, Any],
  strategy_rows: list[dict[str, Any]],
  removed_by_fix: dict[str, list[str]],
  unexplained_fp: dict[str, list[str]],
  anchor_audit_run: Path,
  version_probe_run: Path,
  dataset: str | Path,
  repo_root: str | Path,
  duration_s: float,
) -> dict[str, Any]:
  by_strategy: dict[str, list[dict[str, Any]]] = {}
  for row in strategy_rows:
    by_strategy.setdefault(str(row["strategy"]), []).append(row)
  strategy_summary = {
    strategy: {
      "macro_precision": _mean(rows, "precision"),
      "macro_recall": _mean(rows, "recall"),
      "macro_f1": _mean(rows, "f1"),
      "exact_match_count": sum(1 for row in rows if row["exact_match"] is True),
    }
    for strategy, rows in sorted(by_strategy.items())
  }
  return {
    "cases_total": len(per_cve),
    "candidate_lifecycle": "raw_candidate",
    "scope": "diagnostic_conversion_probe_not_formal_version_result",
    "strategy_summary": strategy_summary,
    "baseline_direct_release_reachability_macro_f1": strategy_summary["direct_release_reachability"]["macro_f1"],
    "fix_reachable_exclusion_macro_f1": strategy_summary["fix_reachable_exclusion"]["macro_f1"],
    "time_after_fix_exclusion_macro_f1": strategy_summary["time_after_fix_exclusion"]["macro_f1"],
    "same_line_trim_diagnostic_upper_bound_macro_f1": strategy_summary["same_line_trim"]["macro_f1"],
    "same_line_trim_uses_ground_truth_line": True,
    "fix_reachable_exclusion_removed_tags": removed_by_fix,
    "remaining_false_positive_tags_after_fix_reachable_exclusion": unexplained_fp,
    "anchor_audit_run": str(anchor_audit_run),
    "version_probe_run": str(version_probe_run),
    "dataset": str(dataset),
    "repo_root": str(repo_root),
    "duration_s": round(duration_s, 6),
  }


def _manual_review_rows(
  *,
  cve_id: str,
  repo: str,
  selected_candidate_commit: str,
  current_predicted_tags: set[str],
  ground_truth_tags: set[str],
  candidate_commits: list[dict[str, Any]],
  resolved_anchors: list[dict[str, Any]],
) -> list[dict[str, Any]]:
  anchors_by_id = {str(item.get("anchor_id") or ""): item for item in resolved_anchors}
  rows: list[dict[str, Any]] = []
  selected = [item for item in candidate_commits if str(item.get("commit_sha") or "") == selected_candidate_commit]
  for candidate in selected:
    for provenance in candidate.get("line_provenance") or []:
      anchor_id = str(provenance.get("anchor_id") or "")
      anchor = anchors_by_id.get(anchor_id, {})
      rows.append(
        {
          "cve_id": cve_id,
          "repo": repo,
          "anchor_id": anchor_id,
          "anchor_role": provenance.get("role") or anchor.get("role") or "",
          "selected_candidate_commit": selected_candidate_commit,
          "source_path": provenance.get("path_before") or anchor.get("path_before") or "",
          "old_line": provenance.get("old_line") or anchor.get("old_line_start") or "",
          "old_text": provenance.get("line_text") or anchor.get("line_text") or "",
          "blame_commit": provenance.get("blamed_commit_sha") or selected_candidate_commit,
          "current_predicted_tags": ";".join(sorted(current_predicted_tags)),
          "ground_truth_affected_versions": ";".join(sorted(ground_truth_tags)),
          "reviewer_anchor_correct": "",
          "reviewer_blame_reasonable": "",
          "reviewer_notes": "",
        }
      )
  if rows:
    return rows
  for anchor in resolved_anchors:
    rows.append(
      {
        "cve_id": cve_id,
        "repo": repo,
        "anchor_id": anchor.get("anchor_id", ""),
        "anchor_role": anchor.get("role", ""),
        "selected_candidate_commit": selected_candidate_commit,
        "source_path": anchor.get("path_before", ""),
        "old_line": anchor.get("old_line_start", ""),
        "old_text": anchor.get("line_text", ""),
        "blame_commit": selected_candidate_commit,
        "current_predicted_tags": ";".join(sorted(current_predicted_tags)),
        "ground_truth_affected_versions": ";".join(sorted(ground_truth_tags)),
        "reviewer_anchor_correct": "",
        "reviewer_blame_reasonable": "",
        "reviewer_notes": "",
      }
    )
  return rows


def _render_report(summary: dict[str, Any]) -> str:
  lines = [
    "# SZZ Anchor Release-Line Conversion Probe",
    "",
    "This is a deterministic diagnostic over existing raw candidate commits. It does not validate BICs and does not produce a formal affected-version result.",
    "",
    "All candidate commits remain `raw_candidate`. `same_line_trim` uses ground-truth release lines and is only an upper-bound diagnostic.",
    "",
    "## Strategy Summary",
    "",
  ]
  for strategy, values in summary["strategy_summary"].items():
    lines.append(
      f"- {strategy}: macro P/R/F1 = {values['macro_precision']:.4f} / "
      f"{values['macro_recall']:.4f} / {values['macro_f1']:.4f}; exact={values['exact_match_count']}"
    )
  lines.extend(
    [
      "",
      "## Fix-Reachable Exclusion Removed Tags",
      "",
    ]
  )
  for cve_id, tags in summary["fix_reachable_exclusion_removed_tags"].items():
    lines.append(f"- {cve_id}: `{tags}`")
  lines.extend(["", "## Remaining False Positives", ""])
  for cve_id, tags in summary["remaining_false_positive_tags_after_fix_reachable_exclusion"].items():
    lines.append(f"- {cve_id}: `{tags}`")
  return "\n".join(lines) + "\n"


def _line_id(tag: str) -> str:
  version = parse_release_version(tag)
  return version.major_minor if version else ""


def _same_major_line(line_id: str, gt_lines: set[str]) -> bool:
  major = line_id.split(".", 1)[0] if line_id else ""
  return bool(major and any(item.split(".", 1)[0] == major for item in gt_lines))


def _ground_truth(record: dict[str, Any]) -> list[str]:
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


def _safe_is_ancestor(runner: Any, ancestor: str, descendant: str) -> str:
  if not ancestor or not descendant or not hasattr(runner, "is_ancestor"):
    return "unknown"
  try:
    value = runner.is_ancestor(ancestor, descendant)
  except Exception:
    return "unknown"
  return value if value in {"yes", "no", "unknown"} else "unknown"


def _safe_commit_time(runner: Any, repo_path: Path, commit_or_tag: str) -> int | None:
  if not commit_or_tag or not hasattr(runner, "commit_time"):
    return None
  try:
    value = runner.commit_time(repo_path, commit_or_tag)
  except Exception:
    return None
  return int(value) if value is not None else None


def _nearest_time(tag_time: int | None, fix_times: list[int]) -> int | None:
  if tag_time is None or not fix_times:
    return None
  return min(fix_times, key=lambda item: abs(tag_time - item))


def _mean(rows: list[dict[str, Any]], key: str) -> float:
  if not rows:
    return 0.0
  return statistics.mean(float(row[key]) for row in rows)


def _provenance(anchor_audit_run: Path, version_probe_run: Path, dataset: str | Path, repo_root: str | Path) -> dict[str, Any]:
  return {
    "anchor_audit_run": str(anchor_audit_run),
    "version_probe_run": str(version_probe_run),
    "dataset": str(dataset),
    "repo_root": str(repo_root),
    "model_invocation_count": 0,
    "judge_agent_invocation_count": 0,
    "scope": "deterministic_release_line_conversion_diagnostic",
    "candidate_lifecycle": "raw_candidate",
  }


def _read_json(path: Path) -> dict[str, Any]:
  data = json.loads(path.read_text(encoding="utf-8"))
  if not isinstance(data, dict):
    raise ValueError(f"expected JSON object: {path}")
  return data


def _read_list(path: Path) -> list[dict[str, Any]]:
  if not path.exists():
    return []
  data = json.loads(path.read_text(encoding="utf-8"))
  return data if isinstance(data, list) else []


def _write_json(path: Path, data: Any) -> None:
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
  columns = list(rows[0].keys()) if rows else ["empty"]
  with path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=columns)
    writer.writeheader()
    writer.writerows(rows)


def _assert_no_forbidden_exact_keys(root: Path) -> None:
  hits: list[str] = []
  for path in root.glob("*"):
    if path.suffix != ".json":
      text = path.read_text(encoding="utf-8", errors="ignore")
      for token in ('"validated_bic"', '"correct_bic"', '"affected_versions"'):
        if token in text:
          hits.append(f"{path.name}:{token}")
      continue
    data = json.loads(path.read_text(encoding="utf-8"))
    _collect_forbidden(data, [path.name], hits)
  if hits:
    raise ValueError(f"forbidden exact keys found: {hits}")


def _collect_forbidden(value: Any, path: list[str], hits: list[str]) -> None:
  if isinstance(value, dict):
    for key, child in value.items():
      if key in FORBIDDEN_EXACT_KEYS:
        hits.append(".".join([*path, key]))
      _collect_forbidden(child, [*path, str(key)], hits)
  elif isinstance(value, list):
    for index, child in enumerate(value):
      _collect_forbidden(child, [*path, str(index)], hits)
