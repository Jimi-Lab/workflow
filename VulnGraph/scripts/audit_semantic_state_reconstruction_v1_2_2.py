from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


FOCUS_CVES = {"CVE-2020-11647", "CVE-2020-11993", "CVE-2020-13904", "CVE-2020-27814"}


def main() -> None:
  parser = argparse.ArgumentParser(description="Audit v1.2.1 unknown_state cases before v1.2.2 replay")
  parser.add_argument("--converter-run", required=True)
  parser.add_argument("--boundary-run", required=True)
  parser.add_argument("--dataset", required=True)
  parser.add_argument("--out-dir", required=True)
  parser.add_argument("--cves", nargs="*")
  args = parser.parse_args()

  dataset = _read(Path(args.dataset))
  cve_ids = args.cves or list(dataset)
  root = Path(args.out_dir)
  root.mkdir(parents=True, exist_ok=True)

  rows = []
  for cve_id in cve_ids:
    case_path = Path(args.converter_run) / cve_id / "semantic_state_reconstruction.json"
    if not case_path.exists():
      continue
    prediction = _read(case_path)
    include = prediction.get("prediction_status") == "unknown_state" or cve_id in FOCUS_CVES
    if not include:
      continue
    boundary_input = _read(Path(args.boundary_run) / cve_id / "judge_boundary_input_v1_2.json")
    event_by_id = {
      str(item.get("event_candidate_id") or ""): item
      for item in boundary_input.get("history_event_candidates", []) or []
    }
    selected_ids = _selected_event_ids(prediction)
    selected_events = [event_by_id[event_id] for event_id in selected_ids if event_id in event_by_id]
    predicate_reasons = Counter()
    fix_reasons = Counter()
    flags = Counter()
    for entry in prediction.get("evidence", []) or []:
      for evidence in entry.get("activation_evidence", []) or []:
        if evidence.get("state") == "unknown":
          reason = str(evidence.get("reason") or evidence.get("failure_reason") or "unknown")
          predicate_reasons[reason] += 1
          _reason_flags(reason, flags)
      if entry.get("fix_state") == "unknown":
        reason = str((entry.get("fix_evidence") or {}).get("reason") or "unknown")
        fix_reasons[reason] += 1
        _reason_flags(reason, flags)
    predicted = set(prediction.get("affected_versions") or prediction.get("predicted_affected_versions_for_metric") or [])
    truth = set((dataset.get(cve_id) or {}).get("affected_version") or [])
    row = {
      "cve_id": cve_id,
      "repo": str((dataset.get(cve_id) or {}).get("repo") or prediction.get("repo") or ""),
      "status": str(prediction.get("prediction_status") or ""),
      "selected_event_count": len(selected_events),
      "selected_event_ids": sorted(selected_ids),
      "selected_cluster_count": len([c for c in prediction.get("history_event_clusters", []) or [] if c.get("resolution") == "selected_primary"]),
      "candidate_sources": sorted({str(item.get("candidate_source") or "") for item in selected_events if item.get("candidate_source")}),
      "candidate_selection_modes": sorted({str(item.get("candidate_selection_mode") or "") for item in selected_events if item.get("candidate_selection_mode")}),
      "risk_flags": sorted({str(flag) for item in selected_events for flag in item.get("risk_flags", []) or []}),
      "paths": sorted({str(item.get("path_before") or "") for item in selected_events if item.get("path_before")}),
      "function_ids": sorted({str(item.get("function_id") or "") for item in selected_events if item.get("function_id")}),
      "function_names": sorted({str(item.get("function_name") or "") for item in selected_events if item.get("function_name")}),
      "predicate_state_unknown_reasons": dict(sorted(predicate_reasons.items())),
      "fix_state_unknown_reasons": dict(sorted(fix_reasons.items())),
      "path_missing": bool(flags["path_missing"]),
      "function_missing": not any(item.get("function_id") or item.get("function_name") for item in selected_events),
      "line_hash_mismatch": bool(flags["line_hash_mismatch"]),
      "blob_too_large": bool(flags["blob_too_large"]),
      "predicate_fingerprint_missing": bool(flags["predicate_fingerprint_missing"]),
      "fix_predicate_missing": bool(flags["fix_predicate_missing"]),
      "branch_alias_unknown": bool(flags["branch_alias_unknown"]),
      "false_positive_count": len(predicted - truth),
      "false_negative_count": len(truth - predicted),
      "true_positive_count": len(predicted & truth),
      "focus_case": cve_id in FOCUS_CVES,
    }
    rows.append(row)

  summary = {
    "case_count": len(rows),
    "unknown_state_case_count": sum(1 for row in rows if row["status"] == "unknown_state"),
    "focus_cves": sorted(FOCUS_CVES),
    "predicate_unknown_reason_counts": _sum_counter(rows, "predicate_state_unknown_reasons"),
    "fix_unknown_reason_counts": _sum_counter(rows, "fix_state_unknown_reasons"),
    "flag_counts": {
      key: sum(1 for row in rows if row[key])
      for key in [
        "path_missing", "function_missing", "line_hash_mismatch", "blob_too_large",
        "predicate_fingerprint_missing", "fix_predicate_missing", "branch_alias_unknown",
      ]
    },
    "fp_contribution": sum(int(row["false_positive_count"]) for row in rows),
    "fn_contribution": sum(int(row["false_negative_count"]) for row in rows),
    "model_invocation_count": 0,
  }
  _write(root / "summary.json", summary)
  _write(root / "unknown_state_audit.json", {"summary": summary, "cases": rows})
  _write_csv(root / "unknown_state_audit.csv", rows)
  _write_report(root / "state_audit_report.md", summary, rows)
  print(json.dumps(summary, ensure_ascii=False, indent=2))


def _selected_event_ids(prediction: dict[str, Any]) -> set[str]:
  selected: set[str] = set()
  for cluster in prediction.get("history_event_clusters", []) or []:
    if cluster.get("resolution") == "selected_primary":
      selected.update(str(value) for value in cluster.get("selected_event_candidate_ids", []) or [] if value)
  return selected


def _reason_flags(reason: str, flags: Counter) -> None:
  if "path_unavailable" in reason:
    flags["path_missing"] += 1
  if "line_text_hash_mismatch" in reason or "old_line_text_hash_mismatch" in reason:
    flags["line_hash_mismatch"] += 1
  if "blob_too_large" in reason:
    flags["blob_too_large"] += 1
  if "fingerprint" in reason and "missing" in reason:
    flags["predicate_fingerprint_missing"] += 1
  if "fix_predicate" in reason:
    flags["fix_predicate_missing"] += 1
  if "alias" in reason or "equivalence_unknown" in reason:
    flags["branch_alias_unknown"] += 1


def _sum_counter(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
  counter: Counter[str] = Counter()
  for row in rows:
    counter.update(row.get(key, {}) or {})
  return dict(sorted(counter.items()))


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
  fieldnames = [
    "cve_id", "repo", "status", "selected_event_count", "selected_cluster_count",
    "candidate_sources", "candidate_selection_modes", "risk_flags", "paths",
    "function_ids", "function_names", "predicate_state_unknown_reasons",
    "fix_state_unknown_reasons", "path_missing", "function_missing",
    "line_hash_mismatch", "blob_too_large", "predicate_fingerprint_missing",
    "fix_predicate_missing", "branch_alias_unknown", "false_positive_count",
    "false_negative_count", "true_positive_count", "focus_case",
  ]
  with path.open("w", encoding="utf-8", newline="") as handle:
    writer = csv.DictWriter(handle, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
      writer.writerow({key: _csv_value(row.get(key)) for key in fieldnames})


def _write_report(path: Path, summary: dict[str, Any], rows: list[dict[str, Any]]) -> None:
  lines = [
    "# VulnGraph v1.2.2 State Audit",
    "",
    "This is a deterministic no-model audit of v1.2.1 unknown-state cases before v1.2.2 replay.",
    "",
    f"- cases audited: {summary['case_count']}",
    f"- unknown_state cases: {summary['unknown_state_case_count']}",
    f"- model_invocation_count: {summary['model_invocation_count']}",
    f"- FP contribution: {summary['fp_contribution']}",
    f"- FN contribution: {summary['fn_contribution']}",
    "",
    "## Focus Cases",
    "",
  ]
  for cve_id in sorted(FOCUS_CVES):
    row = next((item for item in rows if item["cve_id"] == cve_id), None)
    if not row:
      lines.append(f"- {cve_id}: not present in audited rows")
      continue
    lines.append(
      f"- {cve_id}: status={row['status']}, selected_events={row['selected_event_count']}, "
      f"predicate_unknown={row['predicate_state_unknown_reasons']}, "
      f"fix_unknown={row['fix_state_unknown_reasons']}, FP={row['false_positive_count']}, FN={row['false_negative_count']}"
    )
  path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _csv_value(value: Any) -> str:
  if isinstance(value, (list, dict, bool)):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
  return "" if value is None else str(value)


def _read(path: Path) -> dict[str, Any]:
  return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, value: object) -> None:
  path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
  main()
