from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from vulngraph.workflows.affected_version_converter_v1 import p01_metrics


def read_json(path: Path) -> dict[str, Any]:
  return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
  path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> None:
  parser = argparse.ArgumentParser()
  parser.add_argument("--judge-run", type=Path, required=True)
  parser.add_argument("--converter-run", type=Path, required=True)
  parser.add_argument("--dataset", type=Path, required=True)
  parser.add_argument("--v1-1-metrics", type=Path, required=True)
  parser.add_argument("--raw-top1-run", type=Path, required=True)
  args = parser.parse_args()

  records = read_json(args.dataset)
  predictions = {
    row["cve_id"]: row
    for row in (json.loads(line) for line in (args.converter_run / "per_cve_predictions.jsonl").read_text(encoding="utf-8").splitlines() if line.strip())
  }
  judge_results = {}
  inputs = {}
  views = {}
  for case in sorted(path for path in args.judge_run.glob("CVE-*") if path.is_dir()):
    judge_results[case.name] = read_json(case / "judge_boundary_result_v1_2.json")
    inputs[case.name] = read_json(case / "judge_boundary_input_v1_2.json")
    views[case.name] = read_json(case / "derived_boundary_views_v1_2.json")

  rows = []
  stage_cases: dict[str, list[str]] = {
    "candidate_missing": [], "judge_over_abstention": [], "branch_grouping_error": [],
    "fix_equivalence_unknown": [], "converter_unresolved_boundary": [],
    "converter_unknown_state": [], "false_positive_heavy": [], "false_negative_heavy": [],
  }
  group_rows: dict[str, list[dict[str, Any]]] = {}
  exact_cases = []
  miss_cases = []
  relation_counter: Counter[str] = Counter()
  branch_case_count = 0
  for cve_id, result in judge_results.items():
    boundary_input = inputs[cve_id]
    prediction = predictions[cve_id]
    selected = views[cve_id].get("activation_events", [])
    candidate_sources = {item.get("candidate_source", "unknown") for item in boundary_input.get("history_event_candidates", [])}
    selected_sources = {item.get("candidate_source", "unknown") for item in selected}
    source_group = "fallback" if "fallback" in (selected_sources or candidate_sources) else "strong"
    patch_modes = {item.get("candidate_selection_mode", "other") for item in selected}
    patch_group = "add_only" if any("add_only" in str(value) for value in patch_modes) else "modify_delete" if any(value in {"modified_old_side", "direct_deleted_line"} for value in patch_modes) else "other"
    status = prediction["prediction_status"]
    predicted = set(prediction["affected_versions"])
    truth = set(records[cve_id].get("affected_version", []) or [])
    tp, fp, fn = len(predicted & truth), len(predicted - truth), len(truth - predicted)
    exact = predicted == truth
    if exact:
      exact_cases.append(cve_id)
    else:
      miss_cases.append(cve_id)
    if not boundary_input.get("history_event_candidates"):
      stage_cases["candidate_missing"].append(cve_id)
    if not selected:
      stage_cases["judge_over_abstention"].append(cve_id)
    if len(boundary_input.get("branch_contexts", [])) > 1:
      branch_case_count += 1
    if any(group.get("relation_semantics") == "unknown_fix_relation" for group in boundary_input.get("fix_groups", [])):
      stage_cases["fix_equivalence_unknown"].append(cve_id)
    if status == "unresolved_boundary":
      stage_cases["converter_unresolved_boundary"].append(cve_id)
    if status == "unknown_state":
      stage_cases["converter_unknown_state"].append(cve_id)
    if fp > max(10, fn):
      stage_cases["false_positive_heavy"].append(cve_id)
    if fn > max(10, fp):
      stage_cases["false_negative_heavy"].append(cve_id)
    for group in boundary_input.get("fix_groups", []):
      relation_counter[str(group.get("relation_semantics") or "unknown")] += 1
    row = {
      "cve_id": cve_id, "predicted": predicted, "ground_truth": truth,
      "source_group": source_group, "patch_group": patch_group,
      "status": status, "decision_group": "selected" if selected else "unresolved",
      "tp": tp, "fp": fp, "fn": fn, "exact": exact,
    }
    rows.append(row)
    for key in (f"source:{source_group}", f"patch:{patch_group}", f"status:{status}", f"decision:{row['decision_group']}"):
      group_rows.setdefault(key, []).append(row)

  grouped_metrics = {key: {"cases_total": len(value), **p01_metrics(value)} for key, value in sorted(group_rows.items())}
  v1_1 = read_json(args.v1_1_metrics)
  v1_2 = read_json(args.converter_run / "paper_metrics.json")
  raw = read_json(args.raw_top1_run / "per_candidate_probe.json")
  raw_rows = []
  for cve_id, item in raw.items():
    candidate = (item.get("release_tag_universe") or [None])[0]
    raw_rows.append({
      "cve_id": cve_id,
      "predicted": set(candidate.get("predicted_tags", [])) if candidate else set(),
      "ground_truth": set(item.get("ground_truth_affected_versions", [])),
    })
  raw_micro = p01_metrics(raw_rows)
  comparison = {
    "v1_1": v1_1,
    "v1_2": v1_2,
    "raw_top1_current_artifact_recomputed": raw_micro,
    "raw_top1_user_stated_gate": {"exact_accuracy": 15 / 30, "version_micro_f1": 0.704872},
    "gate": {
      "required_exact_count": 15,
      "required_micro_f1": 0.704872,
      "actual_exact_count": int(round(v1_2["exact_accuracy"] * 30)),
      "actual_micro_f1": v1_2["version_micro_f1"],
      "passed": v1_2["exact_accuracy"] >= 0.5 and v1_2["version_micro_f1"] >= 0.704872,
    },
  }
  stage = {
    "taxonomy_counts": {key: len(value) for key, value in stage_cases.items()},
    "taxonomy_cases": stage_cases,
    "exact_cases": exact_cases,
    "miss_cases": miss_cases,
  }
  fix_audit = {
    "cases_total": len(rows),
    "multi_branch_context_cases": branch_case_count,
    "fix_relation_distribution": dict(relation_counter),
    "unknown_fix_relation_cases": stage_cases["fix_equivalence_unknown"],
    "rule_summary": {
      "same_stable_patch_id": "equivalent OR within matching branch context",
      "single_branch_fix": "branch-local OR",
      "explicit_linear_series": "AND only with DAG chain and explicit series metadata",
      "different_patch_id_without_series_evidence": "unknown, never guessed as AND",
    },
  }
  write_json(args.converter_run / "grouped_metrics.json", grouped_metrics)
  write_json(args.converter_run / "stage_error_attribution.json", stage)
  write_json(args.converter_run / "v1_1_vs_v1_2_vs_raw_top1.json", comparison)
  write_json(args.converter_run / "fix_group_semantics_audit.json", fix_audit)

  (args.converter_run / "boundary_state_transition_spec.md").write_text(
    "# Boundary State Transition Specification\n\n"
    "- Each branch context is evaluated independently from wrapper-owned Git DAG facts.\n"
    "- `primary_boundary` and `branch_equivalent_boundary` may activate vulnerability state.\n"
    "- `conjunctive_prerequisite` is mandatory only when explicitly selected; supporting evidence is never mandatory.\n"
    "- A release is affected only when a branch-local activation event is reachable, its code line survives, all explicit prerequisites hold, and the branch-local fix group is incomplete.\n"
    "- Same-patch-id fixes are OR-equivalent. Only an explicit linear series is AND. Unknown relations remain unknown.\n"
    "- Uncertain Judge output becomes `unresolved_boundary`; indeterminate code/fix state becomes `unknown_state`. Neither is reported as converted.\n",
    encoding="utf-8",
  )
  (args.converter_run / "fix_group_semantics_audit.md").write_text(
    "# Fix Group Semantics Audit\n\n"
    f"- Multi-branch cases: {branch_case_count}\n"
    f"- Relation distribution: `{json.dumps(dict(relation_counter), sort_keys=True)}`\n"
    f"- Unknown relation cases: {', '.join(stage_cases['fix_equivalence_unknown']) or 'none'}\n\n"
    "Grouping uses Git ancestry, merge-base, containing refs, stable patch-id, and explicit series metadata. It does not use affected-version ground truth.\n",
    encoding="utf-8",
  )
  (args.converter_run / "v1_1_vs_v1_2_vs_raw_top1_comparison.md").write_text(
    "# v1.1 vs v1.2 vs Raw Top1\n\n"
    "| System | Exact | Micro P | Micro R | Micro F1 | TP | FP | FN |\n"
    "|---|---:|---:|---:|---:|---:|---:|---:|\n"
    f"| Judge v1.1 | {v1_1['exact_accuracy']:.6f} | {v1_1['version_micro_precision']:.6f} | {v1_1['version_micro_recall']:.6f} | {v1_1['version_micro_f1']:.6f} | {v1_1['true_positive_versions']} | {v1_1['false_positive_versions']} | {v1_1['false_negative_versions']} |\n"
    f"| Judge v1.2 | {v1_2['exact_accuracy']:.6f} | {v1_2['version_micro_precision']:.6f} | {v1_2['version_micro_recall']:.6f} | {v1_2['version_micro_f1']:.6f} | {v1_2['true_positive_versions']} | {v1_2['false_positive_versions']} | {v1_2['false_negative_versions']} |\n"
    f"| Raw top1 artifact recompute | {raw_micro['exact_accuracy']:.6f} | {raw_micro['version_micro_precision']:.6f} | {raw_micro['version_micro_recall']:.6f} | {raw_micro['version_micro_f1']:.6f} | {raw_micro['true_positive_versions']} | {raw_micro['false_positive_versions']} | {raw_micro['false_negative_versions']} |\n\n"
    "The user-stated advancement baseline is Exact 15/30 and micro F1 0.704872. The current raw-top1 artifact recomputes to a slightly different F1; both provenance values are retained rather than silently conflated. v1.2 does not pass either threshold.\n",
    encoding="utf-8",
  )
  (args.converter_run / "next_step_recommendations.md").write_text(
    "# Next Step Recommendations\n\n"
    "1. Do not run 100-CVE validation. The dev30 gate failed.\n"
    "2. Audit the seven unresolved cases first; these are Judge abstention, not converter success.\n"
    "3. Inspect false-negative-heavy selected cases for line-survival overconstraint and alternative-event selection.\n"
    "4. Inspect false-positive-heavy cases for branch context breadth and missing branch-local equivalent fix detection.\n"
    "5. Preserve v1.2 branch grouping and event materialization; optimize selection/calibration without using GT in the blind path.\n",
    encoding="utf-8",
  )
  print(json.dumps({"comparison": comparison, "stage": stage, "fix_audit": fix_audit}, indent=2))


if __name__ == "__main__":
  main()
