from __future__ import annotations

import csv
import json
import statistics
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any


def build_judge_input_readiness(
  *,
  anchor_artifact: str | Path,
  version_probe: str | Path,
  ten_artifact: str | Path | None,
  out_dir: str | Path,
) -> dict[str, Any]:
  started = time.monotonic()
  anchor_root = Path(anchor_artifact)
  probe_root = Path(version_probe)
  output_root = Path(out_dir)
  output_root.mkdir(parents=True, exist_ok=True)

  anchor_summary = _read_json(anchor_root / "summary.json")
  probe_summary = _read_json_default(probe_root / "summary.json", {})
  per_candidate_probe = _read_json_default(probe_root / "per_candidate_probe.json", {})
  ten_summary = _read_json_default(Path(ten_artifact) / "summary.json", {}) if ten_artifact else {}

  summary_rows: list[dict[str, Any]] = []
  quality_rows: list[dict[str, Any]] = []
  packets: dict[str, dict[str, Any]] = {}
  results = [item for item in anchor_summary.get("results", []) if item.get("cve_id")]
  for result in results:
    cve_id = str(result["cve_id"])
    case_dir = anchor_root / cve_id
    output_case_dir = output_root / cve_id
    output_case_dir.mkdir(parents=True, exist_ok=True)
    candidates = _read_list(case_dir / "candidate_commits.json")
    anchors = _read_list(case_dir / "resolved_pre_fix_anchors.json")
    blame_trace = _read_json_default(case_dir / "blame_trace.json", {})
    ingestion = _read_json_default(case_dir / "ingestion_result.json", {})
    probe_case = per_candidate_probe.get(cve_id, {}) if isinstance(per_candidate_probe, dict) else {}
    candidate_packets = [
      _candidate_packet(
        candidate,
        anchors=anchors,
        blame_trace=blame_trace,
        ingestion=ingestion,
        probe_case=probe_case,
        probe_summary=probe_summary,
      )
      for candidate in candidates
      if candidate.get("lifecycle") == "raw_candidate"
    ]
    case_status = "judge_ready" if candidate_packets else "not_judge_ready"
    if candidate_packets and all("fallback_candidate" in item["risk_flags"] for item in candidate_packets):
      case_status = "judge_ready_fallback_only"
    packet = {
      "schema_version": "judge_input_packet_v0",
      "cve_id": cve_id,
      "case_status": case_status,
      "lifecycle": "raw_candidate",
      "candidate_count": len(candidate_packets),
      "candidates": candidate_packets,
      "diagnostic": {
        "source_anchor_artifact": str(anchor_root),
        "source_version_probe": str(probe_root),
        "release_probe_present": bool(probe_case),
        "manual_anchor_review_required": cve_id in set(probe_summary.get("manual_anchor_review_required_cases") or []),
        "not_formal_result": True,
      },
    }
    _write_json(output_case_dir / "judge_input_packet.json", packet)
    _write_csv(output_case_dir / "judge_input_summary.csv", [_case_summary_row(cve_id, packet, ingestion)])
    packets[cve_id] = packet
    summary_rows.append(_case_summary_row(cve_id, packet, ingestion))
    quality_rows.append(_fallback_quality_row(cve_id, packet, ingestion, probe_case))

  _write_csv(output_root / "judge_input_summary.csv", summary_rows)
  _write_csv(output_root / "fallback_quality_audit.csv", quality_rows)
  no_candidate_analysis = _analyze_no_candidate_cases(anchor_root, packets)
  (output_root / "cve_missing_or_weak_candidates.md").write_text(
    _render_missing_or_weak(summary_rows, quality_rows, no_candidate_analysis),
    encoding="utf-8",
  )
  fallback_report = _render_fallback_quality_report(quality_rows)
  (output_root / "fallback_quality_report.md").write_text(fallback_report, encoding="utf-8")
  summary = _summary(
    anchor_summary=anchor_summary,
    probe_summary=probe_summary,
    ten_summary=ten_summary,
    rows=summary_rows,
    quality_rows=quality_rows,
    no_candidate_analysis=no_candidate_analysis,
    duration_s=time.monotonic() - started,
  )
  _write_json(output_root / "summary.json", summary)
  _write_json(output_root / "provenance_manifest.json", _provenance(anchor_root, probe_root, ten_artifact))
  (output_root / "judge_input_readiness_report.md").write_text(_render_report(summary), encoding="utf-8")
  return summary


def _candidate_packet(
  candidate: dict[str, Any],
  *,
  anchors: list[dict[str, Any]],
  blame_trace: dict[str, Any],
  ingestion: dict[str, Any],
  probe_case: dict[str, Any],
  probe_summary: dict[str, Any],
) -> dict[str, Any]:
  commit_sha = str(candidate.get("commit_sha") or "")
  mode = str(candidate.get("candidate_generation_mode") or "legacy_raw_candidate")
  source = "fallback" if mode.startswith("fallback_") else "strong"
  anchor_lookup = {str(anchor.get("anchor_id") or ""): anchor for anchor in anchors}
  candidate_id_lookup = {str(anchor.get("candidate_id") or ""): anchor for anchor in anchors}
  anchor = _best_anchor(candidate, anchor_lookup, candidate_id_lookup)
  provenance = [dict(item) for item in candidate.get("line_provenance") or []]
  first_line = provenance[0] if provenance else {}
  probe_result = _probe_result_for_commit(probe_case, commit_sha)
  risk_flags = _risk_flags(
    source=source,
    mode=mode,
    candidate=candidate,
    anchor=anchor,
    ingestion=ingestion,
    probe_result=probe_result,
    probe_summary=probe_summary,
    provenance=provenance,
  )
  predicate_ids = list(anchor.get("predicate_ids") or [])
  return {
    "candidate_commit_sha": commit_sha,
    "candidate_source": source,
    "candidate_generation_mode": mode,
    "evidence_level": str(candidate.get("evidence_level") or "unknown"),
    "lifecycle": "raw_candidate",
    "selected_anchor_id": str(anchor.get("anchor_id") or "") if source == "strong" else "",
    "fallback_anchor_id": str(anchor.get("anchor_id") or "") if source == "fallback" else "",
    "all_anchor_ids": list(candidate.get("anchor_ids") or []),
    "candidate_ids": list(candidate.get("candidate_ids") or []),
    "path_before": str(anchor.get("path_before") or first_line.get("path_before") or candidate.get("old_path") or ""),
    "old_line_start": int(anchor.get("old_line_start") or first_line.get("old_line") or candidate.get("old_line") or 0),
    "old_line_end": int(anchor.get("old_line_end") or first_line.get("old_line") or candidate.get("old_line") or 0),
    "old_line_text_hash": str(anchor.get("line_text_sha256") or first_line.get("line_text_sha256") or ""),
    "blame_trace": {
      "status": blame_trace.get("status", ""),
      "errors": blame_trace.get("errors", []),
      "line_provenance": provenance,
    },
    "fix_commit_id": str(anchor.get("fix_commit_id") or candidate.get("fix_commit_id") or first_line.get("fix_commit_id") or ""),
    "patch_family_id": str(anchor.get("patch_family_id") or candidate.get("patch_family_id") or first_line.get("patch_family_id") or ""),
    "root_cause_hypothesis_bindings": list(anchor.get("root_cause_hypothesis_ids") or []),
    "vulnerable_predicate_bindings": _split_predicate_ids(predicate_ids)[0],
    "fix_predicate_bindings": _split_predicate_ids(predicate_ids)[1],
    "predicate_bindings": predicate_ids,
    "predicted_release_tags_from_version_probe": list(probe_result.get("predicted_tags") or []),
    "diagnostic": {
      "gt_release_tags": list(probe_case.get("ground_truth_affected_versions") or []),
      "overlap_release_tags": sorted(
        set(probe_result.get("predicted_tags") or []) & set(probe_case.get("ground_truth_affected_versions") or [])
      ),
      "release_metrics": probe_result.get("metrics", {}),
      "false_positive_taxonomy": probe_result.get("false_positive_taxonomy", {}),
      "not_formal_result": True,
    },
    "risk_flags": risk_flags,
    "suitable_for_judge": "empty_or_missing_trace" not in risk_flags,
  }


def _best_anchor(
  candidate: dict[str, Any],
  anchor_lookup: dict[str, dict[str, Any]],
  candidate_id_lookup: dict[str, dict[str, Any]],
) -> dict[str, Any]:
  for anchor_id in candidate.get("anchor_ids") or []:
    if str(anchor_id) in anchor_lookup:
      return anchor_lookup[str(anchor_id)]
  for candidate_id in candidate.get("candidate_ids") or []:
    if str(candidate_id) in candidate_id_lookup:
      return candidate_id_lookup[str(candidate_id)]
  return {}


def _probe_result_for_commit(probe_case: dict[str, Any], commit_sha: str) -> dict[str, Any]:
  for item in probe_case.get("release_tag_universe") or []:
    if str(item.get("commit_sha") or "") == commit_sha:
      return item
  return {}


def _split_predicate_ids(predicate_ids: list[str]) -> tuple[list[str], list[str]]:
  vulnerable: list[str] = []
  fix: list[str] = []
  for predicate_id in predicate_ids:
    lower = predicate_id.lower()
    if "fix" in lower or lower.startswith("fp") or "fix-pred" in lower:
      fix.append(predicate_id)
    elif "vul" in lower or lower.startswith("vp") or "predicate" in lower:
      vulnerable.append(predicate_id)
  return vulnerable, fix


def _risk_flags(
  *,
  source: str,
  mode: str,
  candidate: dict[str, Any],
  anchor: dict[str, Any],
  ingestion: dict[str, Any],
  probe_result: dict[str, Any],
  probe_summary: dict[str, Any],
  provenance: list[dict[str, Any]],
) -> list[str]:
  flags: set[str] = set()
  cve_id = str(anchor.get("cve_id") or ingestion.get("cve_id") or "")
  if source == "fallback":
    flags.add("fallback_candidate")
  if mode.startswith("fallback_"):
    flags.add("no_model_anchor")
  if (ingestion.get("taxonomy") or {}).get("weak_root_cause_binding") or not anchor.get("root_cause_hypothesis_ids"):
    flags.add("weak_root_cause_binding")
  modes = set(candidate.get("selection_modes") or [])
  if anchor.get("selection_mode") == "add_only_semantic_target" or "add_only_semantic_target" in modes:
    flags.add("add_only_semantic_anchor")
  if anchor.get("selection_mode") == "context_fallback" or anchor.get("candidate_source") == "hunk_context":
    flags.add("broad_candidate_range")
  if int(candidate.get("vote_count") or 0) >= 10:
    flags.add("broad_candidate_range")
  taxonomy = probe_result.get("false_positive_taxonomy") or {}
  if taxonomy.get("release_line_overreach") or cve_id in set(probe_summary.get("release_line_overreach_cases") or []):
    flags.add("release_line_overreach")
  if taxonomy.get("non_release_tag_noise") or cve_id in set(probe_summary.get("any_candidate_non_release_tag_noise_cases") or []):
    flags.add("non_release_tag_noise")
  if not provenance:
    flags.add("empty_or_missing_trace")
  return sorted(flags)


def _case_summary_row(cve_id: str, packet: dict[str, Any], ingestion: dict[str, Any]) -> dict[str, Any]:
  candidates = packet["candidates"]
  fallback_count = sum(1 for item in candidates if item["candidate_source"] == "fallback")
  strong_count = sum(1 for item in candidates if item["candidate_source"] == "strong")
  risk_flags = sorted({flag for item in candidates for flag in item.get("risk_flags", [])})
  return {
    "cve_id": cve_id,
    "case_status": packet["case_status"],
    "candidate_count": len(candidates),
    "strong_candidate_count": strong_count,
    "fallback_candidate_count": fallback_count,
    "candidate_generation_modes": ";".join(sorted({item["candidate_generation_mode"] for item in candidates})),
    "evidence_levels": ";".join(sorted({item["evidence_level"] for item in candidates})),
    "risk_flags": ";".join(risk_flags),
    "suitable_for_judge": bool(candidates) and all(item.get("suitable_for_judge") for item in candidates),
    "manual_anchor_review_recommended": bool(fallback_count) or "weak_root_cause_binding" in risk_flags,
    "no_candidate_reason": str(ingestion.get("no_fallback_candidate_reason") or ""),
  }


def _fallback_quality_row(
  cve_id: str,
  packet: dict[str, Any],
  ingestion: dict[str, Any],
  probe_case: dict[str, Any],
) -> dict[str, Any]:
  fallback_candidates = [item for item in packet["candidates"] if item["candidate_source"] == "fallback"]
  top1_f1 = 0.0
  if fallback_candidates:
    top1_f1 = float(fallback_candidates[0].get("diagnostic", {}).get("release_metrics", {}).get("f1") or 0.0)
  has_binding = any(
    item.get("root_cause_hypothesis_bindings") and item.get("predicate_bindings")
    for item in fallback_candidates
  )
  parent_side = any(item.get("path_before") and item.get("old_line_start") for item in fallback_candidates)
  broad = any("broad_candidate_range" in item.get("risk_flags", []) for item in fallback_candidates)
  return {
    "cve_id": cve_id,
    "fallback_candidate_count": len(fallback_candidates),
    "fallback_top1_release_f1": top1_f1,
    "fallback_candidate_reason": str(ingestion.get("fallback_reason") or ""),
    "has_root_cause_predicate_binding": has_binding,
    "from_parent_side_blameable_line": parent_side,
    "broad_hunk_or_context_only": broad,
    "suitable_for_judge": bool(fallback_candidates) and parent_side and "empty_or_missing_trace" not in {
      flag for item in fallback_candidates for flag in item.get("risk_flags", [])
    },
    "candidate_probe_count": len(probe_case.get("release_tag_universe") or []),
    "no_candidate_reason": str(ingestion.get("no_fallback_candidate_reason") or ""),
  }


def _summary(
  *,
  anchor_summary: dict[str, Any],
  probe_summary: dict[str, Any],
  ten_summary: dict[str, Any],
  rows: list[dict[str, Any]],
  quality_rows: list[dict[str, Any]],
  no_candidate_analysis: dict[str, Any],
  duration_s: float,
) -> dict[str, Any]:
  strong_cases = [row for row in rows if int(row["strong_candidate_count"]) > 0]
  fallback_cases = [row for row in rows if int(row["fallback_candidate_count"]) > 0]
  candidate_counts = [int(row["candidate_count"]) for row in rows]
  fallback_noise = [
    row["cve_id"]
    for row in rows
    if int(row["fallback_candidate_count"]) > 0
    and ("weak_root_cause_binding" in row["risk_flags"] or "broad_candidate_range" in row["risk_flags"])
  ]
  no_candidate_cases = anchor_summary.get("no_candidate_cases") or [
    {"cve_id": row["cve_id"], "no_fallback_candidate_reason": row["no_candidate_reason"]}
    for row in rows
    if int(row["candidate_count"]) == 0
  ]
  return {
    "cases_total": len(rows),
    "candidate_ready_before_fallback": int(anchor_summary.get("strong_candidate_ready_count") or 0),
    "candidate_ready_after_fallback": sum(1 for row in rows if int(row["candidate_count"]) > 0),
    "strong_candidate_ready": len(strong_cases),
    "fallback_candidate_ready": len(fallback_cases),
    "no_candidate_cases": no_candidate_cases,
    "strong_raw_candidate_count": int(anchor_summary.get("strong_raw_candidate_commit_count") or 0),
    "fallback_raw_candidate_count": int(anchor_summary.get("fallback_raw_candidate_commit_count") or 0),
    "avg_candidates_per_strong_case": statistics.mean(int(row["candidate_count"]) for row in strong_cases) if strong_cases else 0.0,
    "avg_candidates_per_fallback_case": statistics.mean(int(row["candidate_count"]) for row in fallback_cases) if fallback_cases else 0.0,
    "max_candidates_per_case": max(candidate_counts) if candidate_counts else 0,
    "fallback_candidate_noise_warning_cases": fallback_noise,
    "judge_ready_cases": [row["cve_id"] for row in rows if row["case_status"] != "not_judge_ready"],
    "fallback_or_weak_evidence_cases": sorted(set(fallback_noise + [row["cve_id"] for row in fallback_cases])),
    "manual_anchor_review_cases": sorted(
      set(probe_summary.get("manual_anchor_review_required_cases") or [])
      | {row["cve_id"] for row in rows if row["manual_anchor_review_recommended"]}
    ),
    "failure_analysis_only_cases": [item["cve_id"] for item in no_candidate_cases],
    "candidate_generation_mode_distribution": _semicolon_distribution(rows, "candidate_generation_modes"),
    "case_status_distribution": dict(Counter(row["case_status"] for row in rows)),
    "ten_cve_reference": _ten_reference(ten_summary),
    "no_candidate_deterministic_analysis": no_candidate_analysis,
    "duration_s": round(duration_s, 6),
    "model_invocation_count": 0,
    "lifecycle": "raw_candidate",
  }


def _ten_reference(ten_summary: dict[str, Any]) -> dict[str, Any]:
  if not ten_summary:
    return {"available": False}
  return {
    "available": True,
    "cases_total": ten_summary.get("cases_total"),
    "candidate_ready_count": ten_summary.get("candidate_commit_ready_cases") or ten_summary.get("judge_input_ready_count"),
    "candidate_commit_count": ten_summary.get("unique_candidate_commits") or ten_summary.get("candidates_total"),
  }


def _semicolon_distribution(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
  counter: Counter[str] = Counter()
  for row in rows:
    raw = str(row.get(key) or "")
    for item in [part for part in raw.split(";") if part]:
      counter[item] += 1
  return dict(sorted(counter.items()))


def _analyze_no_candidate_cases(anchor_root: Path, packets: dict[str, dict[str, Any]]) -> dict[str, Any]:
  analyses: dict[str, Any] = {}
  for cve_id, packet in packets.items():
    if packet["candidates"]:
      continue
    case_dir = anchor_root / cve_id
    inventory = _read_json_default(case_dir / "candidate_inventory.json", {})
    ingestion = _read_json_default(case_dir / "ingestion_result.json", {})
    analysis = {
      "cve_id": cve_id,
      "no_candidate_reason": ingestion.get("no_fallback_candidate_reason") or "candidate_missing",
      "inventory_candidate_count": len(inventory.get("candidates") or []),
      "fix_patch_classification": "unknown",
      "parent_commit_exists": None,
      "old_side_blameable_statement_available": False,
      "semantic_fallback_possible": False,
      "impossible_reason": "",
    }
    if cve_id == "CVE-2020-27814":
      analysis.update(_analyze_cve_2020_27814(anchor_root))
    analyses[cve_id] = analysis
  return analyses


def _analyze_cve_2020_27814(anchor_root: Path) -> dict[str, Any]:
  root_cause_run = _read_json_default(anchor_root / "summary.json", {}).get("root_cause_run")
  packet_path = Path(root_cause_run or "") / "CVE-2020-27814" / "root_cause_packet.json"
  if not packet_path.exists():
    return {
      "fix_patch_classification": "missing_root_cause_packet",
      "parent_commit_exists": None,
      "old_side_blameable_statement_available": False,
      "semantic_fallback_possible": False,
      "impossible_reason": "root cause packet unavailable",
    }
  packet = _read_json(packet_path)
  fix_commits = [
    item.get("content", {})
    for item in packet.get("patch_evidence", [])
    if item.get("type") == "FixCommit"
  ]
  patch_hunks = [item for item in packet.get("patch_evidence", []) if item.get("type") == "PatchHunk"]
  if not fix_commits:
    return {
      "fix_patch_classification": "missing_fix_commit",
      "parent_commit_exists": None,
      "old_side_blameable_statement_available": False,
      "semantic_fallback_possible": False,
      "impossible_reason": "no fix commit in packet",
    }
  content = fix_commits[0]
  repo = content.get("repo") or ""
  sha = content.get("commit_sha") or ""
  repo_path = Path("E:/AI/Agent/workflow/VulnVersion/repo") / str(repo)
  parent_exists = _git_ok(repo_path, ["cat-file", "-e", f"{sha}^{{commit}}"])
  parents = _git_stdout(repo_path, ["rev-list", "--parents", "-n", "1", sha]).strip().split()
  classification = "merge_commit_without_materialized_patch_hunks" if len(parents) > 2 and not patch_hunks else "no_patch_hunks"
  stat = _git_stdout(repo_path, ["show", "--stat", "--oneline", sha])
  second_parent = parents[2] if len(parents) > 2 else ""
  second_parent_stat = _git_stdout(repo_path, ["show", "--stat", "--oneline", second_parent]) if second_parent else ""
  semantic_possible = False
  impossible = (
    "current packet materializes only the merge fix commit and no PatchHunk old-side line; "
    "a semantic fallback may require importing the second-parent equivalent fix commit, but this run cannot fabricate one"
  )
  if "src/lib/openjp2/tcd.c" in stat and "1 file changed" in stat:
    classification += "_with_stat_only_code_change"
  return {
    "fix_patch_classification": classification,
    "fix_patch_add_only": None,
    "fix_patch_new_file": False,
    "fix_patch_generated_file": False,
    "fix_patch_metadata_only": False,
    "parent_commit_exists": parent_exists,
    "merge_parent_count": max(0, len(parents) - 1),
    "second_parent_equivalent_fix_commit": second_parent,
    "packet_patch_hunk_count": len(patch_hunks),
    "old_side_blameable_statement_available": False,
    "old_side_verdict": "not_available_from_current_materialized_merge_commit_packet",
    "semantic_fallback_possible": semantic_possible,
    "semantic_fallback_blocked_by": "missing_materialized_patch_hunk_for_equivalent_fix_commit",
    "impossible_reason": impossible,
    "deterministic_git_notes": {
      "repo": str(repo_path),
      "fix_commit_sha": sha,
      "stat_excerpt": stat[:1000],
      "second_parent_stat_excerpt": second_parent_stat[:1000],
    },
  }


def _git_ok(repo_path: Path, args: list[str]) -> bool:
  if not repo_path.exists():
    return False
  result = subprocess.run(
    ["git", "-c", f"safe.directory={repo_path}", "-C", str(repo_path), *args],
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="ignore",
    check=False,
  )
  return result.returncode == 0


def _git_stdout(repo_path: Path, args: list[str]) -> str:
  if not repo_path.exists():
    return ""
  result = subprocess.run(
    ["git", "-c", f"safe.directory={repo_path}", "-C", str(repo_path), *args],
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="ignore",
    check=False,
  )
  return result.stdout if result.returncode == 0 else ""


def _render_report(summary: dict[str, Any]) -> str:
  lines = [
    "# VulnGraph Judge Input Readiness",
    "",
    "This is a frozen Judge input packet audit. It does not call a model, does not validate BICs, and does not infer formal affected-version results.",
    "",
    "## Summary",
    "",
    f"- cases_total: {summary['cases_total']}",
    f"- judge-ready cases: {len(summary['judge_ready_cases'])}/{summary['cases_total']}",
    f"- candidate_ready_before_fallback: {summary['candidate_ready_before_fallback']}",
    f"- candidate_ready_after_fallback: {summary['candidate_ready_after_fallback']}",
    f"- strong_candidate_ready: {summary['strong_candidate_ready']}",
    f"- fallback_candidate_ready: {summary['fallback_candidate_ready']}",
    f"- no_candidate_cases: `{summary['no_candidate_cases']}`",
    f"- strong_raw_candidate_count: {summary['strong_raw_candidate_count']}",
    f"- fallback_raw_candidate_count: {summary['fallback_raw_candidate_count']}",
    f"- avg_candidates_per_strong_case: {summary['avg_candidates_per_strong_case']:.2f}",
    f"- avg_candidates_per_fallback_case: {summary['avg_candidates_per_fallback_case']:.2f}",
    f"- max_candidates_per_case: {summary['max_candidates_per_case']}",
    "",
    "## Judge Use Guidance",
    "",
    f"- fallback / weak evidence cases: `{summary['fallback_or_weak_evidence_cases']}`",
    f"- manual anchor review cases: `{summary['manual_anchor_review_cases']}`",
    f"- failure-analysis-only cases: `{summary['failure_analysis_only_cases']}`",
    "",
    "## Main Error Sources",
    "",
    "- fallback candidates improve coverage but can be broad candidate ranges or weakly bound to root-cause predicates.",
    "- release conversion noise remains visible as release-line overreach and non-release tag noise diagnostics.",
    "- no-candidate cases should stay out of Judge result metrics unless the upstream anchor inventory is repaired.",
  ]
  return "\n".join(lines) + "\n"


def _render_fallback_quality_report(rows: list[dict[str, Any]]) -> str:
  fallback_rows = [row for row in rows if int(row["fallback_candidate_count"]) > 0]
  lines = [
    "# Fallback Candidate Quality Audit",
    "",
    f"- fallback cases: {len(fallback_rows)}",
    f"- suitable fallback cases: {sum(1 for row in fallback_rows if row['suitable_for_judge'])}",
    "",
    "| CVE | fallback candidates | top1 release F1 | root-cause/predicate binding | parent-side line | broad/context | suitable for Judge |",
    "|---|---:|---:|---|---|---|---|",
  ]
  for row in fallback_rows:
    lines.append(
      f"| {row['cve_id']} | {row['fallback_candidate_count']} | {float(row['fallback_top1_release_f1']):.4f} | "
      f"{row['has_root_cause_predicate_binding']} | {row['from_parent_side_blameable_line']} | "
      f"{row['broad_hunk_or_context_only']} | {row['suitable_for_judge']} |"
    )
  return "\n".join(lines) + "\n"


def _render_missing_or_weak(
  rows: list[dict[str, Any]],
  quality_rows: list[dict[str, Any]],
  no_candidate_analysis: dict[str, Any],
) -> str:
  lines = ["# Missing Or Weak Judge Candidates", ""]
  lines.append("## No Candidate Cases")
  lines.append("")
  for cve_id, analysis in no_candidate_analysis.items():
    lines.append(f"- {cve_id}: {analysis.get('no_candidate_reason')}; impossible_reason={analysis.get('impossible_reason')}")
  lines.extend(["", "## Fallback Or Weak Cases", ""])
  weak = [
    row
    for row in rows
    if int(row["fallback_candidate_count"]) > 0 or "weak_root_cause_binding" in str(row.get("risk_flags") or "")
  ]
  for row in weak:
    lines.append(f"- {row['cve_id']}: risks={row['risk_flags']}; suitable_for_judge={row['suitable_for_judge']}")
  lines.extend(["", "## CVE-2020-27814 Deterministic Analysis", ""])
  if "CVE-2020-27814" in no_candidate_analysis:
    lines.append("```json")
    lines.append(json.dumps(no_candidate_analysis["CVE-2020-27814"], ensure_ascii=False, indent=2))
    lines.append("```")
  return "\n".join(lines) + "\n"


def _provenance(anchor_root: Path, probe_root: Path, ten_artifact: str | Path | None) -> dict[str, Any]:
  return {
    "anchor_artifact": str(anchor_root),
    "version_probe": str(probe_root),
    "ten_cve_reference_artifact": str(ten_artifact) if ten_artifact else "",
    "model_invocation_count": 0,
    "judge_invocation_count": 0,
    "output_schema": "judge_input_packet_v0",
    "lifecycle": "raw_candidate",
  }


def _read_json(path: Path) -> dict[str, Any]:
  data = json.loads(path.read_text(encoding="utf-8"))
  if not isinstance(data, dict):
    raise ValueError(f"expected JSON object: {path}")
  return data


def _read_json_default(path: Path, default: dict[str, Any]) -> dict[str, Any]:
  if not path.exists():
    return default
  return _read_json(path)


def _read_list(path: Path) -> list[dict[str, Any]]:
  if not path.exists():
    return []
  data = json.loads(path.read_text(encoding="utf-8"))
  return data if isinstance(data, list) else []


def _write_json(path: Path, data: Any) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  if not rows:
    path.write_text("", encoding="utf-8")
    return
  columns = list(rows[0].keys())
  with path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=columns)
    writer.writeheader()
    writer.writerows(rows)
