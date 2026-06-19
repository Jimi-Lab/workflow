from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any


def main() -> None:
  parser = argparse.ArgumentParser(description="Write the 30-CVE fallback hardening review report.")
  parser.add_argument("--old-probe", required=True)
  parser.add_argument("--metric-fix-probe", required=True)
  parser.add_argument("--fallback-artifact", required=True)
  parser.add_argument("--fallback-probe", required=True)
  parser.add_argument("--out-dir", required=True)
  parser.add_argument("--reset", action="store_true")
  args = parser.parse_args()

  out_dir = Path(args.out_dir)
  if args.reset and out_dir.exists():
    shutil.rmtree(out_dir)
  out_dir.mkdir(parents=True, exist_ok=True)

  old_summary = _read_json(Path(args.old_probe) / "summary.json")
  metric_summary = _read_json(Path(args.metric_fix_probe) / "summary.json")
  fallback_artifact = _read_json(Path(args.fallback_artifact) / "summary.json")
  fallback_probe = _read_json(Path(args.fallback_probe) / "summary.json")
  comparison = _comparison(old_summary, metric_summary, fallback_artifact, fallback_probe)
  _write_json(out_dir / "summary.json", comparison)
  (out_dir / "report.md").write_text(_render_report(comparison), encoding="utf-8")
  print(f"wrote {out_dir}")


def _comparison(
  old_summary: dict[str, Any],
  metric_summary: dict[str, Any],
  fallback_artifact: dict[str, Any],
  fallback_probe: dict[str, Any],
) -> dict[str, Any]:
  old_release = old_summary.get("release_evaluation_universe_metrics", {})
  metric_release = metric_summary.get("release_evaluation_universe_metrics", {})
  fallback_release = fallback_probe.get("release_evaluation_universe_metrics", {})
  metric_groups = metric_summary.get("release_metric_groups", {})
  fallback_groups = fallback_probe.get("release_metric_groups", {})
  return {
    "model_invocation_count": 0,
    "lifecycle": "raw_candidate",
    "cases_total": fallback_artifact.get("cases_total", 0),
    "old_reported_all_case_top1_f1": _metric(old_release, "top1", "f1"),
    "corrected_all_case_top1_f1": _metric(metric_release, "top1", "f1"),
    "accepted_only_top1_f1": _metric(metric_groups.get("strong_only", {}), "top1", "f1"),
    "fallback_all_case_top1_f1": _metric(fallback_release, "top1", "f1"),
    "fallback_strong_only_top1_f1": _metric(fallback_groups.get("strong_only", {}), "top1", "f1"),
    "fallback_only_top1_f1": _metric(fallback_groups.get("fallback_only", {}), "top1", "f1"),
    "fallback_combined_candidate_ready_top1_f1": _metric(fallback_groups.get("strong_plus_fallback", {}), "top1", "f1"),
    "old_cases_with_candidate_commits": metric_summary.get("cases_with_candidate_commits", 0),
    "fallback_cases_with_candidate_commits": fallback_probe.get("cases_with_candidate_commits", 0),
    "strong_candidate_ready_count": fallback_artifact.get("strong_candidate_ready_count", 0),
    "fallback_candidate_ready_count": fallback_artifact.get("fallback_candidate_ready_count", 0),
    "judge_input_ready_count": fallback_artifact.get("judge_input_ready_count", 0),
    "no_candidate_count": fallback_artifact.get("no_candidate_count", 0),
    "no_candidate_cases": fallback_artifact.get("no_candidate_cases", []),
    "strong_raw_candidate_commit_count": fallback_artifact.get("strong_raw_candidate_commit_count", 0),
    "fallback_raw_candidate_commit_count": fallback_artifact.get("fallback_raw_candidate_commit_count", 0),
    "candidate_generation_mode_distribution": fallback_probe.get("candidate_generation_mode_distribution", {}),
    "evidence_level_distribution": fallback_probe.get("evidence_level_distribution", {}),
    "per_blocked_case_fallback_results": fallback_artifact.get("per_blocked_case_fallback_results", []),
    "fallback_error_buckets": fallback_probe.get("per_error_bucket_counts", {}),
  }


def _metric(section: dict[str, Any], metric_name: str, value_name: str) -> float:
  metric = section.get(metric_name, {}) if isinstance(section, dict) else {}
  return float(metric.get(value_name) or 0.0)


def _render_report(data: dict[str, Any]) -> str:
  lines = [
    "# VulnGraph 30-CVE Fallback Hardening Review",
    "",
    "This review is an engineering diagnostic. It did not call OpenCode/DeepSeek, did not regenerate root causes or model-selected SZZ anchors, and did not implement Judge/BIC/affected-version inference.",
    "",
    "All commit outputs remain `raw_candidate`. The oracle score is only a raw candidate-pool upper bound.",
    "",
    "## Metric Delta",
    "",
    f"- old reported all-case release top1 F1: {data['old_reported_all_case_top1_f1']:.4f}",
    f"- corrected all-case release top1 F1: {data['corrected_all_case_top1_f1']:.4f}",
    f"- accepted-only release top1 F1: {data['accepted_only_top1_f1']:.4f}",
    f"- fallback-enhanced all-case release top1 F1: {data['fallback_all_case_top1_f1']:.4f}",
    f"- fallback-only release top1 F1: {data['fallback_only_top1_f1']:.4f}",
    f"- strong+fallback candidate-ready release top1 F1: {data['fallback_combined_candidate_ready_top1_f1']:.4f}",
    "",
    "## Coverage",
    "",
    f"- cases_total: {data['cases_total']}",
    f"- candidate-ready before fallback: {data['old_cases_with_candidate_commits']}/{data['cases_total']}",
    f"- candidate-ready after fallback: {data['fallback_cases_with_candidate_commits']}/{data['cases_total']}",
    f"- strong_candidate_ready_count: {data['strong_candidate_ready_count']}",
    f"- fallback_candidate_ready_count: {data['fallback_candidate_ready_count']}",
    f"- judge_input_ready_count: {data['judge_input_ready_count']}",
    f"- no_candidate_count: {data['no_candidate_count']}",
    f"- strong_raw_candidate_commit_count: {data['strong_raw_candidate_commit_count']}",
    f"- fallback_raw_candidate_commit_count: {data['fallback_raw_candidate_commit_count']}",
    f"- candidate_generation_mode_distribution: `{data['candidate_generation_mode_distribution']}`",
    f"- evidence_level_distribution: `{data['evidence_level_distribution']}`",
    "",
    "## Blocked Case Fallback Results",
    "",
    "| CVE | status | candidate_count | mode | evidence | no_candidate_reason | blame_status |",
    "|---|---|---:|---|---|---|---|",
  ]
  for item in data["per_blocked_case_fallback_results"]:
    lines.append(
      f"| {item.get('cve_id')} | {item.get('status')} | {int(item.get('candidate_commit_count') or 0)} | "
      f"{item.get('candidate_generation_mode')} | {item.get('evidence_level')} | "
      f"{item.get('no_fallback_candidate_reason', '')} | {item.get('blame_status', '')} |"
    )
  lines.extend(
    [
      "",
      "## Risk Notes",
      "",
      "- `strong_model_anchor` candidates preserve the accepted DeepSeek SZZ handoff path and are higher-quality inputs for the next Judge.",
      "- `fallback_inventory_anchor` candidates are deterministic wrapper-owned recovery candidates for blocked cases. They improve candidate coverage but carry weaker semantic precision risk.",
      "- The fallback lane is closer to a MAS-SZZ-style line-candidate generator than a complete BIC method: it supplies auditable parent-side lines and blame commits, but does not decide canonical BIC or affected versions.",
      "- The remaining no-candidate case should enter Judge as censored/unknown unless a later root-cause or inventory fix supplies a blameable parent-side line.",
      "",
      "## Next Judge Input Recommendation",
      "",
      "- Pass `candidate_generation_mode`, `evidence_level`, `anchor_source`, line provenance, exclusion reasons, and raw candidate commits to Judge.",
      "- Judge should prioritize strong candidates, use fallback candidates as recall-oriented alternatives, and keep branch-local/equivalent-introduction reasoning separate from version conversion.",
      "- Do not treat oracle, fallback, or raw candidate commits as final BICs.",
      "",
      "## No-Candidate Cases",
      "",
    ]
  )
  for item in data["no_candidate_cases"]:
    lines.append(f"- {item.get('cve_id')}: {item.get('no_fallback_candidate_reason')}")
  return "\n".join(lines) + "\n"


def _read_json(path: Path) -> dict[str, Any]:
  data = json.loads(path.read_text(encoding="utf-8"))
  if not isinstance(data, dict):
    raise ValueError(f"expected JSON object: {path}")
  return data


def _write_json(path: Path, data: Any) -> None:
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
  main()
