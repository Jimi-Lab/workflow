from __future__ import annotations

import csv
import json
import shutil
import time
from collections import Counter
from pathlib import Path
from typing import Any

from vulngraph.workflows.affected_version_converter_v1 import p01_metrics
from vulngraph.workflows.tri_state_policy_v1_2_2_1 import (
  audit_ledger_gates,
  build_tag_state_ledger,
)


LEDGER_FIELDS = [
  "cve_id",
  "repo",
  "tag",
  "release_line",
  "branch_context_id",
  "vulnerability_predicate_state",
  "fix_predicate_state",
  "fix_reachability_state",
  "boundary_state",
  "function_scope_match_kind",
  "evidence_refs",
  "final_tri_state",
  "final_reason",
  "included_in_primary_prediction",
]


def compute_match_kind_metrics(
  ledger: list[dict[str, Any]],
  truths: dict[str, set[str]],
) -> list[dict[str, Any]]:
  groups: dict[str, list[dict[str, Any]]] = {}
  for row in ledger:
    groups.setdefault(
      str(row.get("function_scope_match_kind") or "unavailable"), []
    ).append(row)
  output = []
  for kind, rows in sorted(groups.items()):
    tp = fp = fn = tn = 0
    for row in rows:
      truth = str(row.get("tag") or "") in truths.get(
        str(row.get("cve_id") or ""), set()
      )
      predicted = bool(row.get("included_in_primary_prediction"))
      if predicted and truth:
        tp += 1
      elif predicted:
        fp += 1
      elif truth:
        fn += 1
      else:
        tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    output.append({
      "match_kind": kind,
      "tag_count": len(rows),
      "predicted_positive_count": tp + fp,
      "tp": tp,
      "fp": fp,
      "fn": fn,
      "tn": tn,
      "precision": precision,
      "recall": recall,
      "f1": (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
      ),
    })
  return output


def run_tri_state_policy_audit(
  *,
  source_run: str | Path,
  dataset: str | Path,
  out_dir: str | Path,
  cve_ids: list[str],
  reset: bool = False,
) -> dict[str, Any]:
  started = time.monotonic()
  source_root = Path(source_run)
  output_root = Path(out_dir)
  if reset and output_root.exists():
    shutil.rmtree(output_root)
  output_root.mkdir(parents=True, exist_ok=True)
  records = _read(Path(dataset))
  truths = {
    cve_id: set(records.get(cve_id, {}).get("affected_version", []) or [])
    for cve_id in cve_ids
  }
  all_ledger: list[dict[str, Any]] = []
  predictions: list[dict[str, Any]] = []
  case_audits: list[dict[str, Any]] = []
  taxonomy: Counter[str] = Counter()
  match_counts: Counter[str] = Counter()
  predicate_present_assessments = 0
  fix_present_assessments = 0
  independent_fix_predicate_evidence = 0
  fix_reachability_proxy = 0
  declared_fixes = 0
  represented_fixes = 0
  unresolved_fixes = 0

  for cve_id in cve_ids:
    frozen_path = source_root / cve_id / "semantic_state_reconstruction.json"
    if not frozen_path.exists():
      raise FileNotFoundError(f"missing frozen v1.2.2 evidence: {frozen_path}")
    frozen = _read(frozen_path)
    ledger = build_tag_state_ledger(frozen)
    expected = int(frozen.get("release_tag_universe_size") or len(ledger))
    gate = audit_ledger_gates(ledger, expected_tag_count=expected)
    gate["cve_id"] = cve_id
    case_audits.append(gate)
    all_ledger.extend(ledger)
    for row in ledger:
      taxonomy[str(row.get("final_reason") or "unknown")] += 1
      for context in row.get("context_states", []) or []:
        kind = str(context.get("function_scope_match_kind") or "unavailable")
        match_counts[kind] += 1
        if context.get("vulnerability_predicate_state") in {
          "present_exact", "present_normalized", "present_predicate_equivalent"
        }:
          predicate_present_assessments += 1
        raw_fix = (context.get("context_evidence") or {}).get("fix_evidence", {})
        if raw_fix.get("fix_presence") == "present":
          fix_present_assessments += 1
        if raw_fix.get("semantic_state"):
          independent_fix_predicate_evidence += 1
        elif raw_fix.get("state") == "absent":
          fix_reachability_proxy += 1

    affected = sorted(
      row["tag"] for row in ledger
      if row["final_tri_state"] == "confirmed_affected"
    )
    unaffected = sorted(
      row["tag"] for row in ledger
      if row["final_tri_state"] == "confirmed_unaffected"
    )
    unknown = sorted(
      row["tag"] for row in ledger if row["final_tri_state"] == "unknown"
    )
    status = (
      "confirmed_only_with_unknowns" if unknown
      else "confirmed_only_complete"
    )
    prediction = {
      "cve_id": cve_id,
      "repo": str(frozen.get("repo") or records.get(cve_id, {}).get("repo") or ""),
      "affected_versions": affected,
      "confirmed_affected_versions": affected,
      "confirmed_unaffected_versions": unaffected,
      "unknown_versions": unknown,
      "uncertainty": [
        {
          "reason": "tri_state_unknown_tags",
          "unknown_tag_count": len(unknown),
          "state_ledger_ref": "per_tag_state_ledger.json",
        }
      ] if unknown else [],
      "prediction_status": status,
      "metric_policy": "confirmed_affected_only",
      "lifecycle": "deterministic_tri_state_policy_v1_2_2_1",
    }
    predictions.append(prediction)
    case_root = output_root / cve_id
    case_root.mkdir(parents=True, exist_ok=True)
    _write(case_root / "per_tag_state_ledger.json", ledger)
    _write(case_root / "state_transition_audit.json", gate)
    _write(case_root / "public_prediction.json", prediction)

    fix = dict(frozen.get("fix_universe_audit") or {})
    declared_fixes += int(fix.get("declared_fix_count") or 0)
    represented_fixes += int(fix.get("represented_declared_fix_count") or 0)
    unresolved_fixes += int(fix.get("unresolved_declared_fix_count") or 0)

  global_gate = _aggregate_gate(case_audits)
  metrics = p01_metrics([
    {
      "cve_id": item["cve_id"],
      "predicted": set(item["affected_versions"]),
      "ground_truth": truths[item["cve_id"]],
    }
    for item in predictions
  ])
  match_metrics = compute_match_kind_metrics(all_ledger, truths)
  fix_coverage = represented_fixes / declared_fixes if declared_fixes else 1.0
  state_audit = {
    **global_gate,
    "cases_total": len(cve_ids),
    "fix_universe_declared": declared_fixes,
    "fix_universe_represented": represented_fixes,
    "fix_universe_unresolved": unresolved_fixes,
    "fix_universe_coverage": fix_coverage,
    "model_invocation_count": 0,
    "frozen_evidence_source": str(source_root),
    "frozen_evidence_recomputed": False,
    "predicate_fix_independence": {
      "predicate_present_assessment_count": predicate_present_assessments,
      "fix_present_assessment_count": fix_present_assessments,
      "independent_fix_predicate_evidence_count": independent_fix_predicate_evidence,
      "fix_absence_reachability_proxy_count": fix_reachability_proxy,
      "independent_judgment_confirmed": independent_fix_predicate_evidence > 0,
    },
    "verifier_parity": {
      "single_and_batch_shared_core": "evaluate_predicate_in_content",
      "frozen_run_reexecution_count": 0,
      "status": "shared_core_verified_by_unit_tests_not_reexecuted",
    },
    "function_structural_semantics": {
      "implementation": "ordered_token_subsequence_plus_fingerprint_overlap",
      "is_ast_cfg_dataflow_equivalence": False,
      "allowed_as_strong_confirmation": False,
      "required_name": "function_structural_token_fingerprint",
    },
    "match_kind_context_evidence_counts": dict(sorted(match_counts.items())),
    "duration_s": round(time.monotonic() - started, 6),
  }
  summary = {
    "cases_total": len(cve_ids),
    "state_transition_audit": state_audit,
    "paper_metrics": metrics,
    "model_invocation_count": 0,
  }

  _write_csv(output_root / "per_tag_state_ledger.csv", all_ledger, LEDGER_FIELDS)
  _write_csv(
    output_root / "match_kind_metrics.csv",
    match_metrics,
    [
      "match_kind", "tag_count", "predicted_positive_count",
      "tp", "fp", "fn", "tn", "precision", "recall", "f1",
    ],
  )
  _write(output_root / "state_transition_audit.json", state_audit)
  _write(output_root / "unknown_root_cause_taxonomy.json", {
    "counts": dict(sorted(taxonomy.items())),
    "note": "Taxonomy is derived from frozen evidence and tri-state transitions.",
  })
  _write(output_root / "paper_metrics.json", metrics)
  _write(output_root / "summary.json", summary)
  with (output_root / "per_cve_predictions.jsonl").open("w", encoding="utf-8") as handle:
    for item in predictions:
      handle.write(json.dumps(item, ensure_ascii=False) + "\n")
  return summary


def _aggregate_gate(case_audits: list[dict[str, Any]]) -> dict[str, Any]:
  tags_total = sum(int(item["tags_total"]) for item in case_audits)
  affected = sum(int(item["confirmed_affected_tag_count"]) for item in case_audits)
  unaffected = sum(int(item["confirmed_unaffected_tag_count"]) for item in case_audits)
  unknown = sum(int(item["unknown_tag_count"]) for item in case_audits)
  unknown_primary = sum(
    int(item["unknown_in_primary_prediction_count"]) for item in case_audits
  )
  weak_confirmed = sum(
    int(item["weak_fingerprint_confirmed_count"]) for item in case_audits
  )
  accounting = (
    sum(int(item["tags_total"]) for item in case_audits)
    / sum(
      int(item["tags_total"]) / float(item["per_tag_accounting_rate"])
      if item["per_tag_accounting_rate"] else int(item["tags_total"])
      for item in case_audits
    )
    if case_audits else 1.0
  )
  return {
    "tags_total": tags_total,
    "confirmed_affected_tag_count": affected,
    "confirmed_unaffected_tag_count": unaffected,
    "unknown_tag_count": unknown,
    "unknown_tag_rate": unknown / tags_total if tags_total else 0.0,
    "unknown_in_primary_prediction_count": unknown_primary,
    "weak_fingerprint_confirmed_count": weak_confirmed,
    "per_tag_accounting_rate": accounting,
    "gate_ok": (
      all(item["gate_ok"] for item in case_audits)
      and unknown_primary == 0
      and weak_confirmed == 0
      and accounting == 1.0
    ),
    "case_audits": case_audits,
  }


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
  with path.open("w", newline="", encoding="utf-8-sig") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
      serialized = dict(row)
      for field in fields:
        if isinstance(serialized.get(field), (list, dict)):
          serialized[field] = json.dumps(serialized[field], ensure_ascii=False)
      writer.writerow(serialized)


def _read(path: Path) -> dict[str, Any]:
  value = json.loads(path.read_text(encoding="utf-8"))
  if not isinstance(value, dict):
    raise ValueError(f"expected JSON object: {path}")
  return value


def _write(path: Path, value: Any) -> None:
  path.write_text(
    json.dumps(value, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
  )
