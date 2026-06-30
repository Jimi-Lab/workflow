from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulngraph.workflows.tri_state_audit_v1_2_2_1 import run_tri_state_policy_audit


def main() -> None:
  parser = argparse.ArgumentParser(
    description="Replay frozen v1.2.2 tag evidence with fail-closed tri-state policy"
  )
  parser.add_argument("--source-run", required=True)
  parser.add_argument("--dataset", required=True)
  parser.add_argument("--out-dir", required=True)
  parser.add_argument("--v1-2-1-run")
  parser.add_argument("--raw-top1-run")
  parser.add_argument("--cves", nargs="*")
  parser.add_argument("--reset", action="store_true")
  args = parser.parse_args()
  records = _read(Path(args.dataset))
  cve_ids = args.cves or list(records)
  result = run_tri_state_policy_audit(
    source_run=args.source_run,
    dataset=args.dataset,
    out_dir=args.out_dir,
    cve_ids=cve_ids,
    reset=args.reset,
  )
  out = Path(args.out_dir)
  comparisons = {
    "v1.2.1": _read_optional(
      Path(args.v1_2_1_run) / "paper_metrics.json" if args.v1_2_1_run else None
    ),
    "v1.2.2_optimistic_unknown_included": _read_optional(
      Path(args.source_run) / "paper_metrics.json"
    ),
    "v1.2.2.1_confirmed_only_primary": result["paper_metrics"],
    "raw_top1_diagnostic": _read_optional(
      Path(args.raw_top1_run) / "raw_top1_reproduction.json"
      if args.raw_top1_run else Path(args.source_run) / "raw_top1_reproduction.json"
    ),
  }
  _write(out / "metrics_comparison.json", comparisons)
  (out / "tri_state_policy_spec.md").write_text(
    _policy_spec(result["state_transition_audit"]), encoding="utf-8"
  )
  (out / "v1_2_1_vs_v1_2_2_vs_v1_2_2_1_vs_raw_top1.md").write_text(
    _comparison_report(comparisons), encoding="utf-8"
  )
  (out / "handoff_report.md").write_text(
    _handoff(result), encoding="utf-8"
  )
  print(json.dumps({**result, "comparisons": comparisons}, indent=2))


def _policy_spec(audit: dict) -> str:
  independence = audit["predicate_fix_independence"]
  return "\n".join([
    "# VulnGraph v1.2.2.1 Tri-State Decision Policy",
    "",
    "## Evidence Boundary",
    "",
    "- Input is frozen v1.2.2 tag-local state evidence. No Git or model evidence is recomputed.",
    "- present_exact and present_normalized are strong vulnerability-predicate presence.",
    "- present_predicate_equivalent is a function-structural token fingerprint, not semantic equivalence, and cannot confirm affected.",
    "- weak fingerprints, reordered tokens, unavailable paths/functions, and missing evidence remain unknown.",
    "",
    "## State Transitions",
    "",
    "- confirmed_affected: strong predicate presence, complete prerequisite state, confirmed branch context, absent branch-local fix completion, and no conflicting fix evidence.",
    "- confirmed_unaffected: branch-local fix completion is present, or the vulnerability predicate is strongly absent in readable scope.",
    "- all remaining combinations are unknown.",
    "- the public affected_versions field contains only confirmed_affected tags.",
    "",
    "## Known Evidence Limitation",
    "",
    f"- Independent fix-predicate evidence rows: {independence['independent_fix_predicate_evidence_count']}.",
    f"- Fix-absence reachability proxies: {independence['fix_absence_reachability_proxy_count']}.",
    "- Frozen v1.2.2 does not independently prove code-level fix-predicate absence; it records fix completion through branch-local commit/equivalence reachability.",
    "",
  ]) + "\n"


def _comparison_report(comparisons: dict) -> str:
  rows = [
    "# v1.2.1 vs v1.2.2 vs v1.2.2.1 vs Raw Top-1",
    "",
    "| Version | Exact | NMR | Precision | Recall | F1 | TP | FP | FN |",
    "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
  ]
  for name, metrics in comparisons.items():
    if not metrics:
      rows.append(
        f"| {name} | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable |"
      )
      continue
    exact = _metric(
      metrics, "exact_accuracy", "exact_match_count",
      denominator=int(metrics.get("case_count") or 30),
    )
    nmr = f"{float(metrics['nmr']):.6f}" if "nmr" in metrics else "n/a"
    rows.append(
      "| {name} | {exact:.6f} | {nmr} | {p:.6f} | {r:.6f} | {f1:.6f} | {tp} | {fp} | {fn} |".format(
        name=name,
        exact=exact,
        nmr=nmr,
        p=_metric(metrics, "version_micro_precision", "micro_precision"),
        r=_metric(metrics, "version_micro_recall", "micro_recall"),
        f1=_metric(metrics, "version_micro_f1", "micro_f1"),
        tp=int(metrics.get("true_positive_versions", metrics.get("true_positive_count", 0))),
        fp=int(metrics.get("false_positive_versions", metrics.get("false_positive_count", 0))),
        fn=int(metrics.get("false_negative_versions", metrics.get("false_negative_count", 0))),
      )
    )
  rows.extend([
    "",
    "v1.2.2 is an optimistic diagnostic because it includes unknown tags. v1.2.2.1 is the fail-closed primary prediction.",
    "",
  ])
  return "\n".join(rows)


def _handoff(result: dict) -> str:
  audit = result["state_transition_audit"]
  metrics = result["paper_metrics"]
  passed = (
    audit["fix_universe_coverage"] == 1.0
    and audit["unknown_in_primary_prediction_count"] == 0
    and audit["per_tag_accounting_rate"] == 1.0
  )
  f1_gate = metrics["version_micro_f1"] > 0.641491
  return "\n".join([
    "# VulnGraph v1.2.2.1 Handoff",
    "",
    f"- Cases: {result['cases_total']}",
    "- Model invocations: 0",
    f"- Tags total: {audit['tags_total']}",
    f"- Confirmed affected: {audit['confirmed_affected_tag_count']}",
    f"- Confirmed unaffected: {audit['confirmed_unaffected_tag_count']}",
    f"- Unknown: {audit['unknown_tag_count']} ({audit['unknown_tag_rate']:.6f})",
    f"- Unknown in primary prediction: {audit['unknown_in_primary_prediction_count']}",
    f"- Weak fingerprint confirmed: {audit['weak_fingerprint_confirmed_count']}",
    f"- Per-tag accounting: {audit['per_tag_accounting_rate']:.6f}",
    f"- Fix universe: {audit['fix_universe_represented']}/{audit['fix_universe_declared']}",
    f"- Policy gates: {'passed' if passed else 'failed'}",
    f"- Primary micro F1: {metrics['version_micro_f1']:.10f}",
    f"- Exceeds v1.2.1 F1 gate: {f1_gate}",
    f"- 100-CVE decision: {'blocked' if not f1_gate else 'eligible but not executed'}",
    "",
    "Function-structural matching remains ordered token-subsequence/fingerprint matching. It is not AST, CFG, data-flow, or semantic equivalence.",
    "",
  ]) + "\n"


def _metric(
  metrics: dict,
  primary: str,
  fallback: str = "",
  *,
  denominator: int | None = None,
) -> float:
  if primary in metrics:
    return float(metrics[primary])
  value = float(metrics.get(fallback, 0.0)) if fallback else 0.0
  return value / denominator if denominator and value > 1 else value


def _read(path: Path) -> dict:
  value = json.loads(path.read_text(encoding="utf-8"))
  if not isinstance(value, dict):
    raise ValueError(f"expected JSON object: {path}")
  return value


def _read_optional(path: Path | None) -> dict:
  if path is None or not path.exists():
    return {}
  return _read(path)


def _write(path: Path, value: object) -> None:
  path.write_text(
    json.dumps(value, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
  )


if __name__ == "__main__":
  main()
