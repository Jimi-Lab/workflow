from __future__ import annotations

import json
import runpy
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "runs" / "batches" / "vulngraph-affected-version-converter-v1-2-2-dev30"
DATASET = ROOT.parent / "VulnVersion" / "DataSet" / "BaseDataSet_30.json"
V121 = ROOT / "runs" / "batches" / "vulngraph-affected-version-converter-v1-2-1-dev30"
SCRIPT = ROOT / "scripts" / "run_tri_state_policy_audit_v1_2_2_1.py"
TARGETED = ROOT / "runs" / "batches" / "vulngraph-tri-state-policy-v1-2-2-1-targeted"
DEV30 = ROOT / "runs" / "batches" / "vulngraph-tri-state-policy-v1-2-2-1-dev30"


def test_generate_targeted_then_dev30_artifacts() -> None:
  top3 = _top_unknown_included_fp_cves()
  requested = ["CVE-2020-11647", "CVE-2020-11993", "CVE-2020-27814", *top3]
  targeted_cves = list(dict.fromkeys(requested))
  _run(TARGETED, targeted_cves)
  targeted = _read(TARGETED / "state_transition_audit.json")
  assert targeted["gate_ok"] is True
  assert targeted["unknown_in_primary_prediction_count"] == 0
  assert targeted["weak_fingerprint_confirmed_count"] == 0
  assert targeted["per_tag_accounting_rate"] == 1.0
  _write_targeted_report(targeted_cves, top3)

  _run(DEV30, [])
  dev30 = _read(DEV30 / "state_transition_audit.json")
  raw = _read(DEV30 / "metrics_comparison.json")["raw_top1_diagnostic"]
  assert dev30["fix_universe_declared"] == 49
  assert dev30["fix_universe_represented"] == 49
  assert dev30["fix_universe_coverage"] == 1.0
  assert dev30["unknown_in_primary_prediction_count"] == 0
  assert dev30["per_tag_accounting_rate"] == 1.0
  assert raw["exact_match_count"] == 15
  assert abs(raw["micro_f1"] - 0.7048723897911834) < 1e-12


def _top_unknown_included_fp_cves() -> list[str]:
  records = _read(DATASET)
  rows = []
  for cve_id, record in records.items():
    frozen = _read(SOURCE / cve_id / "semantic_state_reconstruction.json")
    predicted = set(frozen.get("predicted_affected_versions_for_metric", []))
    unknown = set(frozen.get("unknown_versions", []))
    truth = set(record.get("affected_version", []))
    rows.append({
      "cve_id": cve_id,
      "unknown_included_fp_count": len((predicted & unknown) - truth),
    })
  rows.sort(key=lambda item: (-item["unknown_included_fp_count"], item["cve_id"]))
  (TARGETED.parent / "vulngraph-tri-state-policy-v1-2-2-1-target-selection.json").write_text(
    json.dumps({"ranking": rows, "top3": rows[:3]}, indent=2) + "\n",
    encoding="utf-8",
  )
  return [item["cve_id"] for item in rows[:3]]


def _write_targeted_report(cves: list[str], top3: list[str]) -> None:
  cases = []
  for cve_id in cves:
    ledger = _read(TARGETED / cve_id / "per_tag_state_ledger.json")
    state_counts = Counter(row["final_tri_state"] for row in ledger)
    reason_counts = Counter(row["final_reason"] for row in ledger)
    match_counts = Counter(row["function_scope_match_kind"] for row in ledger)
    cases.append({
      "cve_id": cve_id,
      "tags_total": len(ledger),
      "confirmed_affected": state_counts["confirmed_affected"],
      "confirmed_unaffected": state_counts["confirmed_unaffected"],
      "unknown": state_counts["unknown"],
      "state_sources": dict(sorted(reason_counts.items())),
      "match_kinds": dict(sorted(match_counts.items())),
    })
  payload = {
    "targeted_cves": cves,
    "unknown_included_fp_top3": top3,
    "top3_overlap_note": "CVE-2020-11993 is both a required case and a top-3 FP case; five unique CVEs are replayed.",
    "cases": cases,
  }
  (TARGETED / "targeted_case_state_sources.json").write_text(
    json.dumps(payload, indent=2) + "\n", encoding="utf-8"
  )
  lines = [
    "# v1.2.2.1 Targeted Tri-State Replay",
    "",
    f"- Unique cases: {len(cves)}",
    f"- Unknown-included FP top-3: {', '.join(top3)}",
    "- CVE-2020-11993 overlaps the required list and top-3 list.",
    "",
    "| CVE | Tags | Confirmed affected | Confirmed unaffected | Unknown |",
    "|---|---:|---:|---:|---:|",
  ]
  for item in cases:
    lines.append(
      f"| {item['cve_id']} | {item['tags_total']} | {item['confirmed_affected']} | "
      f"{item['confirmed_unaffected']} | {item['unknown']} |"
    )
  lines.extend(["", "## State Sources", ""])
  for item in cases:
    lines.append(f"### {item['cve_id']}")
    lines.append("")
    for reason, count in item["state_sources"].items():
      lines.append(f"- {reason}: {count}")
    lines.append("")
  (TARGETED / "targeted_case_report.md").write_text(
    "\n".join(lines), encoding="utf-8"
  )


def _run(out: Path, cves: list[str]) -> None:
  argv = [
    str(SCRIPT),
    "--source-run", str(SOURCE),
    "--dataset", str(DATASET),
    "--out-dir", str(out),
    "--v1-2-1-run", str(V121),
    "--raw-top1-run", str(SOURCE),
    "--reset",
  ]
  if cves:
    argv.extend(["--cves", *cves])
  previous = sys.argv
  try:
    sys.argv = argv
    runpy.run_path(str(SCRIPT), run_name="__main__")
  finally:
    sys.argv = previous


def _read(path: Path):
  return json.loads(path.read_text(encoding="utf-8"))
