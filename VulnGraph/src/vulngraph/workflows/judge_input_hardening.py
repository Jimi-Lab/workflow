from __future__ import annotations

import csv
import json
import statistics
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any

from vulngraph.builder.patch import build_patch_graph_from_repo
from vulngraph.services.blame_runner import run_blame_for_anchors
from vulngraph.services.pre_fix_candidates import GitPreFixSourceReader, build_pre_fix_candidate_inventory
from vulngraph.workflows.szz_fallback_candidates import (
  _annotate_candidate_commit,
  _candidate_to_anchor,
  select_fallback_inventory_candidates,
)


FORBIDDEN_BLIND_TOKENS = [
  "gt_release_tags",
  "overlap_release_tags",
  "release_metrics",
  "false_positive_taxonomy",
  "diagnostic_gt_overlap",
  "precision",
  "recall",
  "f1",
  "exact_match",
  "validated_bic",
  "correct_bic",
  "affected_versions",
]

BLIND_CANDIDATE_COLUMNS = [
  "cve_id",
  "repo",
  "fix_commit_id",
  "patch_family_id",
  "candidate_commit_sha",
  "candidate_source",
  "candidate_generation_mode",
  "evidence_level",
  "lifecycle",
  "selected_anchor_id",
  "fallback_anchor_id",
  "candidate_ids",
  "path_before",
  "old_line_start",
  "old_line_end",
  "old_line_text_hash",
  "old_line_text",
  "blame_trace",
  "root_cause_hypothesis_bindings",
  "vulnerable_predicate_bindings",
  "fix_predicate_bindings",
  "predicate_bindings",
  "predicted_release_tags_from_version_probe",
  "risk_flags",
  "uncertainty_flags",
]

JUDGE_CANDIDATE_SUMMARY_COLUMNS = [
  "cve_id",
  "candidate_commit_sha",
  "candidate_source",
  "evidence_level",
  "candidate_generation_mode",
  "fix_commit_id",
  "patch_family_id",
  "path_before",
  "old_line_start",
  "role",
  "selection_mode",
  "risk_flags",
  "predicted_release_tag_count",
  "suitable_for_judge",
  "included_in_blind_packet",
  "fallback_rank",
  "fallback_recommended",
  "fallback_deprioritized_reason",
  "blind_packet_path",
  "audit_packet_path",
]

_DEFAULT_RELEASE_TAG_INLINE_LIMIT = 40


def build_judge_input_hardening_v1(
  *,
  readiness_dir: str | Path,
  anchor_artifact: str | Path,
  version_probe: str | Path,
  dataset: str | Path,
  repo_root: str | Path,
  out_dir: str | Path,
  top_k: int = 5,
) -> dict[str, Any]:
  started = time.monotonic()
  readiness_root = Path(readiness_dir)
  anchor_root = Path(anchor_artifact)
  probe_root = Path(version_probe)
  dataset_path = Path(dataset)
  repo_root_path = Path(repo_root)
  output_root = Path(out_dir)
  output_root.mkdir(parents=True, exist_ok=True)

  readiness_summary = _read_json_default(readiness_root / "summary.json", {})
  anchor_summary = _read_json(anchor_root / "summary.json")
  probe_summary = _read_json_default(probe_root / "summary.json", {})
  per_candidate_probe = _read_json_default(probe_root / "per_candidate_probe.json", {})
  dataset_records = _read_json_default(dataset_path, {})

  results = [item for item in anchor_summary.get("results", []) if item.get("cve_id")]
  candidate_rows: list[dict[str, Any]] = []
  case_rows: list[dict[str, Any]] = []
  fallback_cases: dict[str, dict[str, Any]] = {}
  no_candidate_cases: list[dict[str, Any]] = []
  repair_report = _empty_cve_2020_27814_repair()
  cve_2020_27814_repaired = False

  for result in results:
    cve_id = str(result.get("cve_id") or "")
    record = _dataset_record(dataset_records, cve_id)
    repo = str(record.get("repo") or "")
    case_dir = output_root / cve_id
    case_dir.mkdir(parents=True, exist_ok=True)
    source_case_dir = anchor_root / cve_id
    case_inputs = _load_case_inputs(source_case_dir)
    if not case_inputs["candidates"]:
      repaired = _repair_missing_candidate_case(
        cve_id=cve_id,
        out_case_dir=case_dir,
        dataset_record=record,
        repo_root=repo_root_path,
        top_k=top_k,
      )
      if cve_id == "CVE-2020-27814":
        repair_report = repaired["report"]
      if repaired["candidates"]:
        if cve_id == "CVE-2020-27814":
          cve_2020_27814_repaired = True
        case_inputs = {
          "candidates": repaired["candidates"],
          "anchors": repaired["anchors"],
          "blame_trace": repaired["blame_trace"],
          "ingestion": repaired["ingestion"],
        }

    probe_case = per_candidate_probe.get(cve_id, {}) if isinstance(per_candidate_probe, dict) else {}
    full_blind_candidates: list[dict[str, Any]] = []
    audit_candidates: list[dict[str, Any]] = []
    for candidate in case_inputs["candidates"]:
      if candidate.get("lifecycle") != "raw_candidate":
        continue
      blind, audit = _split_candidate_packet(
        cve_id=cve_id,
        repo=repo,
        candidate=candidate,
        anchors=case_inputs["anchors"],
        blame_trace=case_inputs["blame_trace"],
        ingestion=case_inputs["ingestion"],
        probe_case=probe_case,
        probe_summary=probe_summary,
      )
      blind = _summarize_release_tags_for_blind(
        blind,
        release_tag_inline_limit=_DEFAULT_RELEASE_TAG_INLINE_LIMIT,
      )
      full_blind_candidates.append(blind)
      audit_candidates.append(audit)

    full_fallback_candidates = [item for item in full_blind_candidates if item["candidate_source"] == "fallback"]
    fallback_ranking = rank_fallback_candidates(full_fallback_candidates, top_k=top_k) if full_fallback_candidates else None
    if fallback_ranking is not None:
      fallback_cases[cve_id] = fallback_ranking
    blind_candidates, included_identities = _blind_candidates_for_case(
      full_blind_candidates,
      fallback_ranking=fallback_ranking,
    )
    fallback_metadata = _fallback_candidate_metadata(
      full_blind_candidates,
      fallback_ranking=fallback_ranking,
      included_identities=included_identities,
    )
    case_status = _case_status(blind_candidates)
    blind_packet = {
      "schema_version": "judge_blind_input_packet_v0",
      "cve_id": cve_id,
      "repo": repo,
      "case_status": case_status,
      "candidate_count": len(blind_candidates),
      "lifecycle": "raw_candidate",
      "candidates": blind_candidates,
      "notes": [
        "engineering-only Judge input packet",
        "raw_candidate commits are not validated BICs",
        "no formal affected-version conversion is included",
      ],
    }
    audit_packet = {
      "schema_version": "judge_audit_packet_v0",
      "cve_id": cve_id,
      "repo": repo,
      "case_status": case_status,
      "candidate_count": len(audit_candidates),
      "lifecycle": "raw_candidate",
      "candidates": audit_candidates,
      "diagnostic": {
        "source_readiness_dir": str(readiness_root),
        "source_anchor_artifact": str(anchor_root),
        "source_version_probe": str(probe_root),
        "source_anchor_case_dir": str(source_case_dir),
        "ground_truth_available": bool(_ground_truth_tags(probe_case)),
        "not_formal_judge_result": True,
      },
    }
    _write_json(case_dir / "judge_blind_input_packet.json", blind_packet)
    _write_json(case_dir / "judge_audit_packet.json", audit_packet)

    case_rows.append(_case_summary_row(cve_id, repo, blind_packet))
    if not blind_candidates:
      no_candidate_cases.append(
        {
          "cve_id": cve_id,
          "reason": str(case_inputs["ingestion"].get("no_fallback_candidate_reason") or "candidate_missing"),
        }
      )
    for candidate in full_blind_candidates:
      candidate_rows.append(
        _candidate_summary_row(
          cve_id=cve_id,
          candidate=candidate,
          blind_packet_path=case_dir / "judge_blind_input_packet.json",
          audit_packet_path=case_dir / "judge_audit_packet.json",
          metadata=fallback_metadata.get(_candidate_identity(candidate), {}),
        )
      )

  fallback_ranked = _fallback_ranked_document(fallback_cases, top_k=top_k)
  _write_json(output_root / "fallback_ranked_candidates.json", fallback_ranked)
  (output_root / "fallback_candidate_ranking_report.md").write_text(
    _render_fallback_ranking_report(fallback_ranked),
    encoding="utf-8",
  )
  _write_csv(output_root / "judge_candidate_summary.csv", candidate_rows, JUDGE_CANDIDATE_SUMMARY_COLUMNS)
  scan = scan_blind_packets_for_forbidden_fields(output_root)
  _write_json(output_root / "blind_packet_forbidden_field_scan.json", scan)
  (output_root / "cve_2020_27814_repair_report.md").write_text(
    _render_cve_2020_27814_repair_report(repair_report),
    encoding="utf-8",
  )

  summary = _build_summary(
    readiness_summary=readiness_summary,
    anchor_summary=anchor_summary,
    case_rows=case_rows,
    candidate_rows=candidate_rows,
    fallback_ranked=fallback_ranked,
    no_candidate_cases=no_candidate_cases,
    cve_2020_27814_repaired=cve_2020_27814_repaired,
    forbidden_scan=scan,
    duration_s=time.monotonic() - started,
  )
  _write_json(output_root / "summary.json", summary)
  _write_json(
    output_root / "provenance_manifest.json",
    _provenance_manifest(readiness_root, anchor_root, probe_root, dataset_path, repo_root_path),
  )
  (output_root / "judge_input_hardening_report.md").write_text(
    _render_hardening_report(summary, case_rows, repair_report),
    encoding="utf-8",
  )
  return summary


def rank_fallback_candidates(candidates: list[dict[str, Any]], *, top_k: int = 5) -> dict[str, Any]:
  fallback = [dict(item) for item in candidates if item.get("candidate_source") == "fallback"]
  merged: dict[str, dict[str, Any]] = {}
  duplicate_count = 0
  for item in fallback:
    sha = str(item.get("candidate_commit_sha") or "")
    if not sha:
      continue
    if sha in merged:
      duplicate_count += 1
      merged[sha] = _merge_ranked_candidate(merged[sha], item)
    else:
      ranked = dict(item)
      ranked["merged_candidate_ids"] = list(item.get("candidate_ids") or [])
      ranked["merged_anchor_ids"] = [
        value
        for value in [item.get("selected_anchor_id"), item.get("fallback_anchor_id")]
        if value
      ]
      ranked["ranking_reasons"] = _ranking_reasons(item)
      merged[sha] = ranked

  ranked_candidates = sorted(merged.values(), key=_fallback_rank_key)
  recommended = ranked_candidates[:top_k]
  high_risk = [
    {
      "candidate_commit_sha": item.get("candidate_commit_sha"),
      "risk_flags": item.get("risk_flags", []),
    }
    for item in ranked_candidates
    if _is_high_risk(item)
  ]
  reasons: list[str] = []
  if duplicate_count:
    reasons.append("duplicate_candidate_commit_merged")
  if len(ranked_candidates) > len(recommended):
    reasons.append("ranked_below_top_k")
  return {
    "original_fallback_candidate_count": len(fallback),
    "ranked_candidate_count": len(ranked_candidates),
    "recommended_top_k_limit": top_k,
    "recommended_top_k": [_public_ranked_candidate(item) for item in recommended],
    "dropped_or_deprioritized_reason": sorted(set(reasons)),
    "high_risk_candidates": high_risk,
    "all_ranked_candidates": [_public_ranked_candidate(item) for item in ranked_candidates],
  }


def _blind_candidates_for_case(
  full_candidates: list[dict[str, Any]],
  *,
  fallback_ranking: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], set[str]]:
  if not full_candidates:
    return [], set()
  fallback_only = all(item.get("candidate_source") == "fallback" for item in full_candidates)
  if not fallback_only or fallback_ranking is None:
    return list(full_candidates), {_candidate_identity(item) for item in full_candidates}

  selected: list[dict[str, Any]] = []
  selected_identities: set[str] = set()
  for recommended in fallback_ranking.get("recommended_top_k") or []:
    sha = str(recommended.get("candidate_commit_sha") or "")
    merged_ids = set(_list(recommended.get("merged_candidate_ids")))
    candidates = [
      item
      for item in full_candidates
      if str(item.get("candidate_commit_sha") or "") == sha
      and (not merged_ids or bool(set(_list(item.get("candidate_ids"))) & merged_ids))
    ]
    if not candidates:
      continue
    chosen = sorted(candidates, key=_fallback_rank_key)[0]
    identity = _candidate_identity(chosen)
    if identity not in selected_identities:
      selected.append(chosen)
      selected_identities.add(identity)
  return selected, selected_identities


def _fallback_candidate_metadata(
  full_candidates: list[dict[str, Any]],
  *,
  fallback_ranking: dict[str, Any] | None,
  included_identities: set[str],
) -> dict[str, dict[str, Any]]:
  metadata: dict[str, dict[str, Any]] = {}
  if fallback_ranking is None:
    for candidate in full_candidates:
      identity = _candidate_identity(candidate)
      metadata[identity] = {
        "included_in_blind_packet": identity in included_identities,
        "fallback_rank": "",
        "fallback_recommended": False,
        "fallback_deprioritized_reason": "",
      }
    return metadata

  rank_by_sha = {
    str(item.get("candidate_commit_sha") or ""): index
    for index, item in enumerate(fallback_ranking.get("all_ranked_candidates") or [], start=1)
  }
  recommended_sha = {
    str(item.get("candidate_commit_sha") or "")
    for item in fallback_ranking.get("recommended_top_k") or []
  }
  top_k = int(fallback_ranking.get("recommended_top_k_limit") or len(recommended_sha) or 0)
  for candidate in full_candidates:
    identity = _candidate_identity(candidate)
    is_fallback = candidate.get("candidate_source") == "fallback"
    sha = str(candidate.get("candidate_commit_sha") or "")
    rank = rank_by_sha.get(sha, "")
    included = identity in included_identities
    recommended = is_fallback and sha in recommended_sha
    reason = ""
    if is_fallback and rank and int(rank) > top_k:
      reason = "ranked_below_top_k"
    elif is_fallback and recommended and not included:
      reason = "duplicate_candidate_commit_merged"
    metadata[identity] = {
      "included_in_blind_packet": included,
      "fallback_rank": rank,
      "fallback_recommended": recommended,
      "fallback_deprioritized_reason": reason,
    }
  return metadata


def scan_blind_packets_for_forbidden_fields(root: str | Path) -> dict[str, Any]:
  root_path = Path(root)
  violations: list[dict[str, Any]] = []
  for path in sorted(root_path.rglob("judge_blind_input_packet.json")):
    data = _read_json(path)
    for token in FORBIDDEN_BLIND_TOKENS:
      for location in _find_exact_token(data, token):
        violations.append({"path": str(path), "token": token, "location": location})
  return {
    "ok": not violations,
    "forbidden_tokens": FORBIDDEN_BLIND_TOKENS,
    "violation_count": len(violations),
    "violations": violations,
    "scan_semantics": "exact JSON key or exact string value match, not substring inside commit SHA or tag names",
  }


def _split_candidate_packet(
  *,
  cve_id: str,
  repo: str,
  candidate: dict[str, Any],
  anchors: list[dict[str, Any]],
  blame_trace: dict[str, Any],
  ingestion: dict[str, Any],
  probe_case: dict[str, Any],
  probe_summary: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
  anchor = _best_anchor(candidate, anchors)
  source = _candidate_source(candidate)
  probe_result = _probe_result_for_commit(probe_case, _candidate_sha(candidate))
  provenance = [dict(item) for item in candidate.get("line_provenance") or []]
  first_line = provenance[0] if provenance else {}
  predicate_ids = _list(anchor.get("predicate_ids") or candidate.get("predicate_bindings"))
  vulnerable, fix = _split_predicate_ids(predicate_ids)
  old_text = _old_line_text(candidate, anchor, first_line)
  risk_flags = _risk_flags(
    cve_id=cve_id,
    source=source,
    candidate=candidate,
    anchor=anchor,
    ingestion=ingestion,
    probe_result=probe_result,
    probe_summary=probe_summary,
    provenance=provenance,
    old_text=old_text,
  )
  blind = {
    "cve_id": cve_id,
    "repo": repo,
    "fix_commit_id": str(anchor.get("fix_commit_id") or candidate.get("fix_commit_id") or first_line.get("fix_commit_id") or ""),
    "patch_family_id": str(anchor.get("patch_family_id") or candidate.get("patch_family_id") or first_line.get("patch_family_id") or ""),
    "candidate_commit_sha": _candidate_sha(candidate),
    "candidate_source": source,
    "candidate_generation_mode": str(candidate.get("candidate_generation_mode") or "legacy_raw_candidate"),
    "evidence_level": str(candidate.get("evidence_level") or "unknown"),
    "lifecycle": "raw_candidate",
    "selected_anchor_id": str(anchor.get("anchor_id") or "") if source == "strong" else "",
    "fallback_anchor_id": str(anchor.get("anchor_id") or "") if source == "fallback" else "",
    "candidate_ids": _list(candidate.get("candidate_ids")),
    "path_before": str(anchor.get("path_before") or first_line.get("path_before") or candidate.get("old_path") or ""),
    "old_line_start": _int(anchor.get("old_line_start") or first_line.get("old_line") or candidate.get("old_line")),
    "old_line_end": _int(anchor.get("old_line_end") or first_line.get("old_line") or candidate.get("old_line")),
    "old_line_text_hash": str(anchor.get("line_text_sha256") or first_line.get("line_text_sha256") or ""),
    "old_line_text": _truncate(old_text, 180),
    "blame_trace": {
      "status": str(blame_trace.get("status") or ""),
      "line_provenance": provenance,
      "errors": list(blame_trace.get("errors") or []),
    },
    "root_cause_hypothesis_bindings": _list(anchor.get("root_cause_hypothesis_ids")),
    "vulnerable_predicate_bindings": vulnerable,
    "fix_predicate_bindings": fix,
    "predicate_bindings": predicate_ids,
    "predicted_release_tags_from_version_probe": _list(probe_result.get("predicted_tags")),
    "risk_flags": risk_flags,
    "uncertainty_flags": _list(candidate.get("uncertainty_reasons") or anchor.get("uncertainty_reasons")),
  }
  blind = {key: blind.get(key) for key in BLIND_CANDIDATE_COLUMNS}
  audit = {
    **blind,
    "diagnostic": {
      "ground_truth_release_tags": _ground_truth_tags(probe_case),
      "gt_overlap_diagnostics": sorted(set(_list(probe_result.get("predicted_tags"))) & set(_ground_truth_tags(probe_case))),
      "release_metrics": dict(probe_result.get("metrics") or {}),
      "false_positive_taxonomy": dict(probe_result.get("false_positive_taxonomy") or {}),
      "source_candidate": candidate,
      "source_anchor": anchor,
      "not_formal_judge_result": True,
    },
  }
  return blind, audit


def _summarize_release_tags_for_blind(
  candidate: dict[str, Any],
  *,
  release_tag_inline_limit: int,
) -> dict[str, Any]:
  item = dict(candidate)
  tags = list(item.get("predicted_release_tags_from_version_probe") or [])
  if len(tags) > release_tag_inline_limit:
    item.pop("predicted_release_tags_from_version_probe", None)
    item["release_tag_summary"] = {
      "count": len(tags),
      "first": tags[:5],
      "last": tags[-5:],
      "truncated": True,
    }
    item["release_tag_artifact_ref"] = f"judge_audit_packet.json#candidate:{item.get('candidate_commit_sha')}"
  else:
    item["release_tag_summary"] = {
      "count": len(tags),
      "tags": tags,
      "truncated": False,
    }
    item["release_tag_artifact_ref"] = ""
  return item


def _repair_missing_candidate_case(
  *,
  cve_id: str,
  out_case_dir: Path,
  dataset_record: dict[str, Any],
  repo_root: Path,
  top_k: int,
) -> dict[str, Any]:
  repo = str(dataset_record.get("repo") or "")
  repo_path = repo_root / repo
  fix_commits = _dataset_fix_commits(dataset_record)
  report = {
    "cve_id": cve_id,
    "attempted": False,
    "repo": repo,
    "repo_path": str(repo_path),
    "source_fix_commits": fix_commits,
    "equivalent_fix_commit": "",
    "model_invocation_count": 0,
    "status": "not_run",
    "errors": [],
    "candidate_count": 0,
    "impossible_reason": "",
  }
  if not repo:
    report.update({"status": "blocked", "errors": ["repo_missing"], "impossible_reason": "dataset repo missing"})
    _write_repair_empty_files(out_case_dir, report)
    return {"report": report, "candidates": [], "anchors": [], "blame_trace": {}, "ingestion": _repair_ingestion(report)}
  if not repo_path.exists():
    report.update({"status": "blocked", "errors": ["repo_missing"], "impossible_reason": "repo path missing"})
    _write_repair_empty_files(out_case_dir, report)
    return {"report": report, "candidates": [], "anchors": [], "blame_trace": {}, "ingestion": _repair_ingestion(report)}
  if not fix_commits:
    report.update({"status": "blocked", "errors": ["fix_commits_missing"], "impossible_reason": "dataset fixing_commits missing"})
    _write_repair_empty_files(out_case_dir, report)
    return {"report": report, "candidates": [], "anchors": [], "blame_trace": {}, "ingestion": _repair_ingestion(report)}

  equivalent_entries = _normalise_equivalent_entries(
    _find_equivalent_fix_commits(repo_path=repo_path, fix_commits=fix_commits),
    default_source_fix_commit=fix_commits[0],
  )
  if not equivalent_entries:
    report.update(
      {
        "status": "not_applicable",
        "errors": ["no_equivalent_merge_parent"],
        "impossible_reason": "no merge second-parent equivalent fix commit found",
      }
    )
    _write_repair_empty_files(out_case_dir, report)
    return {"report": report, "candidates": [], "anchors": [], "blame_trace": {}, "ingestion": _repair_ingestion(report)}

  all_patch_hunks: list[dict[str, Any]] = []
  last_inventory: dict[str, Any] = {"candidates": [], "issues": []}
  report["attempted"] = True
  for index, entry in enumerate(equivalent_entries, start=1):
    equivalent_sha = entry["equivalent_fix_commit"]
    source_fix_sha = entry["source_fix_commit"]
    report["equivalent_fix_commit"] = equivalent_sha
    try:
      graph = build_patch_graph_from_repo(
        cve_id=cve_id,
        repo=repo,
        repo_path=repo_path,
        commit_sha=equivalent_sha,
        fix_commit_content={
          "fix_set_id": f"{cve_id}:fix-set:equivalent:{index}",
          "equivalent_to_fix_commit": source_fix_sha,
        },
      )
    except Exception as exc:  # pragma: no cover - exercised in real artifact generation when repo state is unusual.
      report["errors"].append(f"patch_materialization_failed:{equivalent_sha}:{exc}")
      continue

    patch_hunks = [node.model_dump(mode="json") for node in graph.nodes if node.type == "PatchHunk"]
    fix_nodes = [node.model_dump(mode="json") for node in graph.nodes if node.type == "FixCommit"]
    all_patch_hunks.extend(patch_hunks)
    packet = {
      "cve_id": cve_id,
      "context": {},
      "repo_navigation": [
        {
          "id": f"repo:{repo}",
          "type": "Repo",
          "content": {"repo": repo, "repo_path": str(repo_path)},
        }
      ],
      "patch_evidence": fix_nodes + patch_hunks,
    }
    try:
      inventory = build_pre_fix_candidate_inventory(
        packet=packet,
        repo_path=repo_path,
        source_reader=GitPreFixSourceReader(repo_path),
      )
      inventory_data = inventory.model_dump(mode="json")
      last_inventory = inventory_data
    except Exception as exc:  # pragma: no cover - real repo protection.
      report["errors"].append(f"candidate_inventory_failed:{equivalent_sha}:{exc}")
      last_inventory = {"candidates": [], "issues": [str(exc)]}
      continue

    selected = select_fallback_inventory_candidates(inventory_data.get("candidates") or [], top_k_per_fix_commit=top_k)
    if not selected["candidates"]:
      report["errors"].extend(list(inventory_data.get("issues") or []) + [f"no_blameable_old_side:{equivalent_sha}"])
      continue

    anchors = [_candidate_to_anchor(candidate, index=anchor_index) for anchor_index, candidate in enumerate(selected["candidates"], start=1)]
    blame = run_blame_for_anchors(repo_path, anchors)
    blame_data = blame.to_dict()
    anchor_lookup = {anchor.candidate_id: anchor for anchor in anchors}
    annotated_candidates = [
      _annotate_candidate_commit(
        candidate,
        mode="fallback_equivalent_fix_anchor",
        evidence_level="fallback",
        fallback_reason="equivalent_fix_commit_parent_side_repair",
        anchor_source="equivalent_fix_candidate_inventory",
        anchor_lookup=anchor_lookup,
      )
      for candidate in blame.candidate_commits
    ]
    blame_data["candidate_commits"] = annotated_candidates
    status = "repaired_raw_candidate" if annotated_candidates else "impossible"
    report.update(
      {
        "status": status,
        "candidate_inventory_count": len(inventory_data.get("candidates") or []),
        "selected_anchor_count": len(anchors),
        "candidate_count": len(annotated_candidates),
        "blame_status": blame.status,
        "errors": blame.errors,
        "impossible_reason": "" if annotated_candidates else _no_candidate_reason(blame.errors, blame.status),
      }
    )
    ingestion = _repair_ingestion(report)
    _write_json(out_case_dir / "equivalent_patch_hunks.json", all_patch_hunks)
    if cve_id == "CVE-2020-27814":
      _write_json(out_case_dir / "second_parent_patch_hunks.json", all_patch_hunks)
    _write_json(out_case_dir / "repaired_candidate_inventory.json", inventory_data)
    _write_repair_case_files(
      out_case_dir,
      [anchor.model_dump(mode="json") for anchor in anchors],
      annotated_candidates,
      blame_data,
      ingestion,
    )
    return {
      "report": report,
      "candidates": annotated_candidates,
      "anchors": [anchor.model_dump(mode="json") for anchor in anchors],
      "blame_trace": blame_data,
      "ingestion": ingestion,
    }

  report.update(
    {
      "status": "impossible",
      "candidate_inventory_count": len(last_inventory.get("candidates") or []),
      "impossible_reason": "equivalent fix commit produced no parent-side blameable line candidate",
    }
  )
  ingestion = _repair_ingestion(report)
  _write_json(out_case_dir / "equivalent_patch_hunks.json", all_patch_hunks)
  if cve_id == "CVE-2020-27814":
    _write_json(out_case_dir / "second_parent_patch_hunks.json", all_patch_hunks)
  _write_json(out_case_dir / "repaired_candidate_inventory.json", last_inventory)
  _write_repair_case_files(out_case_dir, [], [], {"status": "not_run", "errors": report["errors"]}, ingestion)
  return {"report": report, "candidates": [], "anchors": [], "blame_trace": {"status": "not_run", "errors": report["errors"]}, "ingestion": ingestion}


def _dataset_fix_commits(dataset_record: dict[str, Any]) -> list[str]:
  output: list[str] = []
  raw = dataset_record.get("fixing_commits") or dataset_record.get("fix_commits") or dataset_record.get("fix_commit") or []
  stack = list(raw if isinstance(raw, list) else [raw])
  while stack:
    item = stack.pop(0)
    if isinstance(item, list):
      stack = list(item) + stack
    elif isinstance(item, dict):
      for key in ("commit", "commit_sha", "sha", "fix_commit"):
        if item.get(key):
          stack.append(item[key])
          break
    elif item:
      sha = str(item).strip()
      if sha and sha not in output:
        output.append(sha)
  return output


def _find_equivalent_fix_commits(*, repo_path: Path, fix_commits: list[str]) -> list[dict[str, str]]:
  entries: list[dict[str, str]] = []
  for fix_sha in fix_commits:
    command = [
      "git",
      "-c",
      f"safe.directory={repo_path}",
      "-C",
      str(repo_path),
      "rev-list",
      "--parents",
      "-n",
      "1",
      fix_sha,
    ]
    result = subprocess.run(
      command,
      capture_output=True,
      text=True,
      encoding="utf-8",
      errors="ignore",
      check=False,
    )
    if result.returncode != 0:
      continue
    parts = result.stdout.strip().split()
    parents = parts[1:]
    for parent_sha in parents[1:]:
      entries.append({"source_fix_commit": fix_sha, "equivalent_fix_commit": parent_sha})
  return entries


def _normalise_equivalent_entries(raw_entries: list[Any], *, default_source_fix_commit: str) -> list[dict[str, str]]:
  entries: list[dict[str, str]] = []
  for item in raw_entries:
    if isinstance(item, dict):
      equivalent = str(item.get("equivalent_fix_commit") or item.get("commit_sha") or item.get("sha") or "").strip()
      source = str(item.get("source_fix_commit") or item.get("equivalent_to_fix_commit") or default_source_fix_commit).strip()
    else:
      equivalent = str(item or "").strip()
      source = default_source_fix_commit
    if equivalent:
      entries.append({"source_fix_commit": source, "equivalent_fix_commit": equivalent})
  return entries


def _load_case_inputs(source_case_dir: Path) -> dict[str, Any]:
  return {
    "candidates": _read_list(source_case_dir / "candidate_commits.json"),
    "anchors": _read_list(source_case_dir / "resolved_pre_fix_anchors.json"),
    "blame_trace": _read_json_default(source_case_dir / "blame_trace.json", {}),
    "ingestion": _read_json_default(source_case_dir / "ingestion_result.json", {}),
  }


def _best_anchor(candidate: dict[str, Any], anchors: list[dict[str, Any]]) -> dict[str, Any]:
  by_anchor = {str(anchor.get("anchor_id") or ""): anchor for anchor in anchors}
  by_candidate = {str(anchor.get("candidate_id") or ""): anchor for anchor in anchors}
  for anchor_id in candidate.get("anchor_ids") or []:
    anchor = by_anchor.get(str(anchor_id))
    if anchor:
      return anchor
  for candidate_id in candidate.get("candidate_ids") or []:
    anchor = by_candidate.get(str(candidate_id))
    if anchor:
      return anchor
  return {}


def _candidate_source(candidate: dict[str, Any]) -> str:
  mode = str(candidate.get("candidate_generation_mode") or "")
  evidence = str(candidate.get("evidence_level") or "")
  return "fallback" if mode.startswith("fallback_") or evidence == "fallback" else "strong"


def _candidate_sha(candidate: dict[str, Any]) -> str:
  return str(candidate.get("candidate_commit_sha") or candidate.get("commit_sha") or "")


def _probe_result_for_commit(probe_case: dict[str, Any], commit_sha: str) -> dict[str, Any]:
  for key in ("release_tag_universe", "diagnostic_all_tags", "all_tag_universe"):
    for item in probe_case.get(key) or []:
      if str(item.get("commit_sha") or "") == commit_sha:
        return item
  return {}


def _ground_truth_tags(probe_case: dict[str, Any]) -> list[str]:
  for key in ("ground_truth_affected_versions", "gt_release_tags"):
    value = probe_case.get(key)
    if isinstance(value, list):
      return [str(item) for item in value]
  return []


def _split_predicate_ids(predicate_ids: list[str]) -> tuple[list[str], list[str]]:
  vulnerable: list[str] = []
  fix: list[str] = []
  for predicate_id in predicate_ids:
    lower = predicate_id.lower()
    if "fix" in lower or lower.startswith("fp"):
      fix.append(predicate_id)
    elif "vul" in lower or "predicate" in lower or lower.startswith("vp"):
      vulnerable.append(predicate_id)
  return vulnerable, fix


def _old_line_text(candidate: dict[str, Any], anchor: dict[str, Any], first_line: dict[str, Any]) -> str:
  for value in (
    candidate.get("old_line_text"),
    candidate.get("old_text"),
    anchor.get("line_text"),
    first_line.get("old_text"),
    first_line.get("line_text"),
  ):
    if value is not None:
      return str(value)
  return ""


def _risk_flags(
  *,
  cve_id: str,
  source: str,
  candidate: dict[str, Any],
  anchor: dict[str, Any],
  ingestion: dict[str, Any],
  probe_result: dict[str, Any],
  probe_summary: dict[str, Any],
  provenance: list[dict[str, Any]],
  old_text: str,
) -> list[str]:
  flags: set[str] = set(candidate.get("risk_flags") or [])
  if source == "fallback":
    flags.add("fallback_candidate")
  mode = str(candidate.get("candidate_generation_mode") or "")
  if mode.startswith("fallback_"):
    flags.add("no_model_anchor")
  if (
    not anchor.get("root_cause_hypothesis_ids")
    or (ingestion.get("taxonomy") or {}).get("weak_root_cause_binding")
    or any(str(item).startswith("fallback:") for item in anchor.get("root_cause_hypothesis_ids") or [])
  ):
    flags.add("weak_root_cause_binding")
  modes = set(candidate.get("selection_modes") or [])
  selection = str(anchor.get("selection_mode") or "")
  if selection == "add_only_semantic_target" or "add_only_semantic_target" in modes:
    flags.add("add_only_semantic_anchor")
  if selection == "context_fallback" or int(candidate.get("vote_count") or 0) >= 10:
    flags.add("broad_candidate_range")
  if (probe_result.get("false_positive_taxonomy") or {}).get("release_line_overreach") or cve_id in set(probe_summary.get("release_line_overreach_cases") or []):
    flags.add("release_line_overreach")
  if (probe_result.get("false_positive_taxonomy") or {}).get("non_release_tag_noise") or cve_id in set(probe_summary.get("any_candidate_non_release_tag_noise_cases") or []):
    flags.add("non_release_tag_noise")
  if not provenance:
    flags.add("empty_or_missing_trace")
  if _is_noise_line(old_text):
    flags.add("broad_candidate_range")
  return sorted(flags)


def _fallback_ranked_document(fallback_cases: dict[str, dict[str, Any]], *, top_k: int) -> dict[str, Any]:
  original_counts = [item["original_fallback_candidate_count"] for item in fallback_cases.values()]
  recommended_counts = [len(item["recommended_top_k"]) for item in fallback_cases.values()]
  return {
    "schema_version": "fallback_ranked_candidates_v0",
    "top_k": top_k,
    "cases": fallback_cases,
    "summary": {
      "fallback_case_count": len(fallback_cases),
      "fallback_original_candidate_count": sum(original_counts),
      "fallback_recommended_candidate_count": sum(recommended_counts),
      "max_fallback_candidates_before": max(original_counts) if original_counts else 0,
      "max_fallback_candidates_after": max(recommended_counts) if recommended_counts else 0,
    },
  }


def _merge_ranked_candidate(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
  preferred, other = (incoming, existing) if _fallback_rank_key(incoming) < _fallback_rank_key(existing) else (existing, incoming)
  merged = dict(preferred)
  merged["merged_candidate_ids"] = sorted(set(_list(existing.get("merged_candidate_ids") or existing.get("candidate_ids")) + _list(incoming.get("candidate_ids"))))
  merged["merged_anchor_ids"] = sorted(
    set(_list(existing.get("merged_anchor_ids")) + _list(incoming.get("merged_anchor_ids")) + [str(incoming.get("fallback_anchor_id") or ""), str(incoming.get("selected_anchor_id") or "")])
    - {""}
  )
  merged["risk_flags"] = sorted(set(_list(existing.get("risk_flags")) + _list(incoming.get("risk_flags"))))
  merged["ranking_reasons"] = sorted(set(_list(existing.get("ranking_reasons")) + _ranking_reasons(incoming)))
  return merged


def _fallback_rank_key(candidate: dict[str, Any]) -> tuple[Any, ...]:
  provenance = candidate.get("blame_trace", {}).get("line_provenance") or []
  modes = {str(item) for item in candidate.get("selection_modes") or []}
  modes |= {str(item.get("selection_mode") or "") for item in provenance if isinstance(item, dict)}
  roles = {str(item.get("role") or "") for item in provenance if isinstance(item, dict)}
  roles |= set(candidate.get("roles") or [])
  return (
    _selection_rank(modes),
    _role_rank(roles),
    _binding_rank(candidate),
    _parent_side_rank(candidate),
    _noise_rank(candidate),
    _release_range_rank(candidate),
    str(candidate.get("candidate_commit_sha") or ""),
  )


def _selection_rank(modes: set[str]) -> int:
  if modes & {"deleted_line", "direct_deleted_line", "modified_old_side"}:
    return 0
  if modes & {"add_only_semantic_target"}:
    return 1
  if modes & {"pre_fix_function_body"}:
    return 2
  return 3


def _role_rank(roles: set[str]) -> int:
  if "dangerous_use" in roles:
    return 0
  if "missing_guard_target" in roles:
    return 1
  return 2


def _binding_rank(candidate: dict[str, Any]) -> int:
  bindings = _list(candidate.get("root_cause_hypothesis_bindings"))
  predicates = _list(candidate.get("vulnerable_predicate_bindings") or candidate.get("predicate_bindings"))
  if bindings and predicates and not any(item.startswith("fallback:") for item in bindings + predicates):
    return 0
  return 1


def _parent_side_rank(candidate: dict[str, Any]) -> int:
  return 0 if candidate.get("path_before") and _int(candidate.get("old_line_start")) > 0 else 1


def _noise_rank(candidate: dict[str, Any]) -> int:
  flags = set(_list(candidate.get("risk_flags")))
  noise = 0
  if _is_noise_line(str(candidate.get("old_line_text") or "")):
    noise += 1
  if "broad_candidate_range" in flags:
    noise += 1
  if "empty_or_missing_trace" in flags:
    noise += 2
  return noise


def _release_range_rank(candidate: dict[str, Any]) -> int:
  tag_count = len(_list(candidate.get("predicted_release_tags_from_version_probe")))
  return 1 if tag_count >= 25 or "release_line_overreach" in _list(candidate.get("risk_flags")) else 0


def _ranking_reasons(candidate: dict[str, Any]) -> list[str]:
  reasons: list[str] = []
  modes = {str(item.get("selection_mode") or "") for item in candidate.get("blame_trace", {}).get("line_provenance") or [] if isinstance(item, dict)}
  if modes & {"modified_old_side", "direct_deleted_line"}:
    reasons.append("direct_old_side")
  if modes & {"add_only_semantic_target"}:
    reasons.append("add_only_semantic_target")
  if _binding_rank(candidate) == 0:
    reasons.append("root_cause_predicate_bound")
  if _noise_rank(candidate) > 0:
    reasons.append("noise_or_broad_candidate")
  if _release_range_rank(candidate) > 0:
    reasons.append("broad_release_range")
  return reasons or ["fallback_candidate"]


def _public_ranked_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
  return {
    "candidate_commit_sha": candidate.get("candidate_commit_sha"),
    "candidate_source": candidate.get("candidate_source"),
    "candidate_generation_mode": candidate.get("candidate_generation_mode"),
    "evidence_level": candidate.get("evidence_level"),
    "lifecycle": "raw_candidate",
    "fix_commit_id": candidate.get("fix_commit_id"),
    "patch_family_id": candidate.get("patch_family_id"),
    "path_before": candidate.get("path_before"),
    "old_line_start": candidate.get("old_line_start"),
    "risk_flags": candidate.get("risk_flags", []),
    "ranking_reasons": candidate.get("ranking_reasons", _ranking_reasons(candidate)),
    "merged_candidate_ids": candidate.get("merged_candidate_ids", candidate.get("candidate_ids", [])),
    "merged_anchor_ids": candidate.get("merged_anchor_ids", []),
  }


def _is_high_risk(candidate: dict[str, Any]) -> bool:
  flags = set(_list(candidate.get("risk_flags")))
  return bool(flags & {"weak_root_cause_binding", "broad_candidate_range", "empty_or_missing_trace", "release_line_overreach"})


def _case_status(candidates: list[dict[str, Any]]) -> str:
  if not candidates:
    return "not_judge_ready"
  if all(item.get("candidate_source") == "fallback" for item in candidates):
    return "judge_ready_fallback_only"
  return "judge_ready"


def _case_summary_row(cve_id: str, repo: str, packet: dict[str, Any]) -> dict[str, Any]:
  strong = [item for item in packet["candidates"] if item["candidate_source"] == "strong"]
  fallback = [item for item in packet["candidates"] if item["candidate_source"] == "fallback"]
  return {
    "cve_id": cve_id,
    "repo": repo,
    "case_status": packet["case_status"],
    "candidate_count": len(packet["candidates"]),
    "strong_candidate_count": len(strong),
    "fallback_candidate_count": len(fallback),
    "risk_flags": ";".join(sorted({flag for item in packet["candidates"] for flag in item.get("risk_flags", [])})),
  }


def _candidate_summary_row(
  *,
  cve_id: str,
  candidate: dict[str, Any],
  blind_packet_path: Path,
  audit_packet_path: Path,
  metadata: dict[str, Any],
) -> dict[str, Any]:
  provenance = candidate.get("blame_trace", {}).get("line_provenance") or []
  first = provenance[0] if provenance else {}
  predicted_release_tag_count = len(_list(candidate.get("predicted_release_tags_from_version_probe")))
  if not predicted_release_tag_count and isinstance(candidate.get("release_tag_summary"), dict):
    predicted_release_tag_count = int(candidate.get("release_tag_summary", {}).get("count") or 0)
  return {
    "cve_id": cve_id,
    "candidate_commit_sha": candidate.get("candidate_commit_sha", ""),
    "candidate_source": candidate.get("candidate_source", ""),
    "evidence_level": candidate.get("evidence_level", ""),
    "candidate_generation_mode": candidate.get("candidate_generation_mode", ""),
    "fix_commit_id": candidate.get("fix_commit_id", ""),
    "patch_family_id": candidate.get("patch_family_id", ""),
    "path_before": candidate.get("path_before", ""),
    "old_line_start": candidate.get("old_line_start", 0),
    "role": first.get("role", ""),
    "selection_mode": first.get("selection_mode", ""),
    "risk_flags": ";".join(_list(candidate.get("risk_flags"))),
    "predicted_release_tag_count": predicted_release_tag_count,
    "suitable_for_judge": _suitable_for_judge(candidate),
    "included_in_blind_packet": bool(metadata.get("included_in_blind_packet", True)),
    "fallback_rank": metadata.get("fallback_rank", ""),
    "fallback_recommended": bool(metadata.get("fallback_recommended", False)),
    "fallback_deprioritized_reason": metadata.get("fallback_deprioritized_reason", ""),
    "blind_packet_path": str(blind_packet_path),
    "audit_packet_path": str(audit_packet_path),
  }


def _suitable_for_judge(candidate: dict[str, Any]) -> bool:
  flags = set(_list(candidate.get("risk_flags")))
  return "empty_or_missing_trace" not in flags and bool(candidate.get("candidate_commit_sha"))


def _candidate_identity(candidate: dict[str, Any]) -> str:
  candidate_ids = "|".join(_list(candidate.get("candidate_ids")))
  anchor_id = str(candidate.get("fallback_anchor_id") or candidate.get("selected_anchor_id") or "")
  return "\0".join([str(candidate.get("candidate_commit_sha") or ""), candidate_ids, anchor_id])


def _build_summary(
  *,
  readiness_summary: dict[str, Any],
  anchor_summary: dict[str, Any],
  case_rows: list[dict[str, Any]],
  candidate_rows: list[dict[str, Any]],
  fallback_ranked: dict[str, Any],
  no_candidate_cases: list[dict[str, Any]],
  cve_2020_27814_repaired: bool,
  forbidden_scan: dict[str, Any],
  duration_s: float,
) -> dict[str, Any]:
  case_count = len(case_rows)
  strong_ready = sum(1 for row in case_rows if int(row["strong_candidate_count"]) > 0)
  fallback_ready = sum(1 for row in case_rows if int(row["fallback_candidate_count"]) > 0)
  candidate_counts = [int(row["candidate_count"]) for row in case_rows]
  fallback_summary = fallback_ranked.get("summary") or {}
  actual_fallback_counts_after = [int(row["fallback_candidate_count"]) for row in case_rows]
  return {
    "cases_total": case_count,
    "blind_packet_cases": case_count,
    "audit_packet_cases": case_count,
    "judge_ready_cases_after_hardening": sum(1 for row in case_rows if int(row["candidate_count"]) > 0),
    "strong_ready_cases": strong_ready,
    "fallback_ready_cases": fallback_ready,
    "no_candidate_cases": no_candidate_cases,
    "strong_raw_candidate_count": sum(1 for row in candidate_rows if row["candidate_source"] == "strong"),
    "fallback_raw_candidate_count": sum(1 for row in candidate_rows if row["candidate_source"] == "fallback"),
    "fallback_original_candidate_count": int(fallback_summary.get("fallback_original_candidate_count") or 0),
    "fallback_recommended_candidate_count": int(fallback_summary.get("fallback_recommended_candidate_count") or 0),
    "max_fallback_candidates_before": int(fallback_summary.get("max_fallback_candidates_before") or 0),
    "max_fallback_candidates_after": max(actual_fallback_counts_after) if actual_fallback_counts_after else 0,
    "avg_candidates_per_case": statistics.mean(candidate_counts) if candidate_counts else 0.0,
    "max_candidates_per_case": max(candidate_counts) if candidate_counts else 0,
    "fallback_candidate_noise_warning_cases": _fallback_noise_cases(case_rows),
    "cve_2020_27814_repaired": cve_2020_27814_repaired,
    "model_invocation_count": 0,
    "judge_invocation_count": 0,
    "lifecycle": "raw_candidate",
    "readiness_reference_cases_total": readiness_summary.get("cases_total"),
    "anchor_reference_cases_total": anchor_summary.get("cases_total"),
    "blind_packet_forbidden_field_scan_ok": bool(forbidden_scan.get("ok")),
    "duration_s": round(duration_s, 6),
  }


def _fallback_noise_cases(rows: list[dict[str, Any]]) -> list[str]:
  output = []
  for row in rows:
    flags = str(row.get("risk_flags") or "")
    if int(row.get("fallback_candidate_count") or 0) > 0 and (
      "weak_root_cause_binding" in flags or "broad_candidate_range" in flags or "release_line_overreach" in flags
    ):
      output.append(row["cve_id"])
  return sorted(set(output))


def _render_hardening_report(summary: dict[str, Any], case_rows: list[dict[str, Any]], repair_report: dict[str, Any]) -> str:
  lines = [
    "# VulnGraph Judge Input Hardening v1",
    "",
    "This is a deterministic engineering artifact. It does not call OpenCode/DeepSeek, does not regenerate Root Cause or SZZ anchors, and does not validate BICs or infer formal affected versions.",
    "",
    "## Summary",
    "",
    f"- cases_total: {summary['cases_total']}",
    f"- blind_packet_cases: {summary['blind_packet_cases']}",
    f"- audit_packet_cases: {summary['audit_packet_cases']}",
    f"- judge_ready_cases_after_hardening: {summary['judge_ready_cases_after_hardening']}",
    f"- strong_ready_cases: {summary['strong_ready_cases']}",
    f"- fallback_ready_cases: {summary['fallback_ready_cases']}",
    f"- no_candidate_cases: `{summary['no_candidate_cases']}`",
    f"- strong_raw_candidate_count: {summary['strong_raw_candidate_count']}",
    f"- fallback_raw_candidate_count: {summary['fallback_raw_candidate_count']}",
    f"- max_fallback_candidates_before: {summary['max_fallback_candidates_before']}",
    f"- max_fallback_candidates_after: {summary['max_fallback_candidates_after']}",
    f"- cve_2020_27814_repaired: {summary['cve_2020_27814_repaired']}",
    f"- blind forbidden scan ok: {summary['blind_packet_forbidden_field_scan_ok']}",
    f"- model_invocation_count: {summary['model_invocation_count']}",
    f"- lifecycle: {summary['lifecycle']}",
    "",
    "## Per-CVE Readiness",
    "",
    "| CVE | status | candidates | strong | fallback | risks |",
    "|---|---|---:|---:|---:|---|",
  ]
  for row in case_rows:
    lines.append(
      f"| {row['cve_id']} | {row['case_status']} | {row['candidate_count']} | {row['strong_candidate_count']} | {row['fallback_candidate_count']} | {row['risk_flags']} |"
    )
  lines.extend(
    [
      "",
      "## CVE-2020-27814 Repair",
      "",
      f"- status: {repair_report.get('status')}",
      f"- candidate_count: {repair_report.get('candidate_count')}",
      f"- impossible_reason: {repair_report.get('impossible_reason')}",
      "",
      "All candidate commits remain `raw_candidate`; this report is a Judge-input readiness artifact, not a BIC or affected-version result.",
    ]
  )
  return "\n".join(lines) + "\n"


def _render_fallback_ranking_report(ranked: dict[str, Any]) -> str:
  summary = ranked["summary"]
  lines = [
    "# Fallback Candidate Ranking",
    "",
    "Fallback candidates are deterministically ranked for Judge input compression. Original candidates are not deleted; full provenance remains in per-CVE audit packets and source artifacts.",
    "",
    f"- fallback_case_count: {summary['fallback_case_count']}",
    f"- fallback_original_candidate_count: {summary['fallback_original_candidate_count']}",
    f"- fallback_recommended_candidate_count: {summary['fallback_recommended_candidate_count']}",
    f"- max_fallback_candidates_before: {summary['max_fallback_candidates_before']}",
    f"- max_fallback_candidates_after: {summary['max_fallback_candidates_after']}",
    "",
    "| CVE | original | ranked | recommended | high risk |",
    "|---|---:|---:|---:|---:|",
  ]
  for cve_id, item in ranked["cases"].items():
    lines.append(
      f"| {cve_id} | {item['original_fallback_candidate_count']} | {item['ranked_candidate_count']} | {len(item['recommended_top_k'])} | {len(item['high_risk_candidates'])} |"
    )
  return "\n".join(lines) + "\n"


def _render_cve_2020_27814_repair_report(report: dict[str, Any]) -> str:
  return "\n".join(
    [
      "# CVE-2020-27814 Deterministic Repair",
      "",
      "This local repair does not call a model and does not fabricate candidates. It materializes the equivalent second-parent fix commit, builds parent-side candidates, and runs local blame only if a parent-side line exists.",
      "",
      f"- attempted: {report.get('attempted')}",
      f"- repo: {report.get('repo')}",
      f"- equivalent_fix_commit: {report.get('equivalent_fix_commit')}",
      f"- status: {report.get('status')}",
      f"- candidate_inventory_count: {report.get('candidate_inventory_count', 0)}",
      f"- selected_anchor_count: {report.get('selected_anchor_count', 0)}",
      f"- candidate_count: {report.get('candidate_count', 0)}",
      f"- impossible_reason: {report.get('impossible_reason', '')}",
      f"- errors: `{report.get('errors', [])}`",
    ]
  ) + "\n"


def _empty_cve_2020_27814_repair() -> dict[str, Any]:
  return {
    "cve_id": "CVE-2020-27814",
    "attempted": False,
    "status": "not_needed_or_not_seen",
    "candidate_count": 0,
    "errors": [],
    "impossible_reason": "",
  }


def _repair_ingestion(report: dict[str, Any]) -> dict[str, Any]:
  return {
    "cve_id": report.get("cve_id", ""),
    "status": "ingested_raw_candidate" if int(report.get("candidate_count") or 0) > 0 else "raw_candidate_censored",
    "lifecycle": "raw_candidate",
    "candidate_generation_mode": "fallback_equivalent_fix_anchor",
    "evidence_level": "fallback",
    "fallback_reason": "equivalent_fix_commit_parent_side_repair",
    "candidate_commit_count": int(report.get("candidate_count") or 0),
    "no_fallback_candidate_reason": report.get("impossible_reason") or "",
    "errors": list(report.get("errors") or []),
  }


def _write_repair_empty_files(out_case_dir: Path, report: dict[str, Any]) -> None:
  _write_json(out_case_dir / "second_parent_patch_hunks.json", [])
  _write_json(out_case_dir / "equivalent_patch_hunks.json", [])
  _write_json(out_case_dir / "repaired_candidate_inventory.json", {"candidates": [], "issues": report.get("errors", [])})
  _write_repair_case_files(out_case_dir, [], [], {"status": "not_run", "errors": report.get("errors", [])}, _repair_ingestion(report))


def _write_repair_case_files(
  out_case_dir: Path,
  anchors: list[dict[str, Any]],
  candidates: list[dict[str, Any]],
  blame_trace: dict[str, Any],
  ingestion: dict[str, Any],
) -> None:
  _write_json(out_case_dir / "resolved_pre_fix_anchors.json", anchors)
  _write_json(out_case_dir / "candidate_commits.json", candidates)
  _write_json(out_case_dir / "blame_trace.json", blame_trace)
  _write_json(out_case_dir / "ingestion_result.json", ingestion)


def _no_candidate_reason(errors: list[str], status: str) -> str:
  if status:
    return status if status != "failed" else "blame_failed"
  for reason in ("parent_missing", "parent_path_missing", "parent_line_mismatch", "blame_failed", "shallow_history"):
    if any(reason in item for item in errors):
      return reason
  return "no_blameable_old_side"


def _dataset_record(dataset_records: dict[str, Any], cve_id: str) -> dict[str, Any]:
  record = dataset_records.get(cve_id, {}) if isinstance(dataset_records, dict) else {}
  return record if isinstance(record, dict) else {}


def _provenance_manifest(
  readiness_root: Path,
  anchor_root: Path,
  probe_root: Path,
  dataset_path: Path,
  repo_root: Path,
) -> dict[str, Any]:
  return {
    "readiness_input": str(readiness_root),
    "anchor_artifact": str(anchor_root),
    "version_probe": str(probe_root),
    "dataset": str(dataset_path),
    "repo_root": str(repo_root),
    "model_invocation_count": 0,
    "judge_invocation_count": 0,
    "root_cause_regeneration_count": 0,
    "szz_anchor_regeneration_count": 0,
    "lifecycle": "raw_candidate",
    "notes": [
      "blind packets remove GT and release metric diagnostics",
      "audit packets preserve diagnostics for offline review",
      "raw_candidate commits are not validated BICs",
    ],
  }


def _find_exact_token(data: Any, token: str, location: str = "$") -> list[str]:
  matches: list[str] = []
  if isinstance(data, dict):
    for key, value in data.items():
      child = f"{location}.{key}"
      if key == token:
        matches.append(child)
      matches.extend(_find_exact_token(value, token, child))
  elif isinstance(data, list):
    for index, value in enumerate(data):
      matches.extend(_find_exact_token(value, token, f"{location}[{index}]"))
  elif isinstance(data, str) and data == token:
    matches.append(location)
  return matches


def _list(value: Any) -> list[str]:
  if value is None:
    return []
  if isinstance(value, list):
    return [str(item) for item in value if item is not None]
  if isinstance(value, set):
    return sorted(str(item) for item in value if item is not None)
  return [str(value)]


def _int(value: Any) -> int:
  try:
    return int(value)
  except (TypeError, ValueError):
    return 0


def _truncate(value: str, limit: int) -> str:
  return value if len(value) <= limit else value[: limit - 3] + "..."


def _is_noise_line(text: str) -> bool:
  stripped = text.strip()
  return not stripped or stripped in {"{", "}", "};", ";", ")", "};"} or stripped.startswith(("//", "/*", "*", "#"))


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


def _write_csv(path: Path, rows: list[dict[str, Any]], columns: list[str]) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  with path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=columns)
    writer.writeheader()
    for row in rows:
      normalized = {column: _csv_value(row.get(column, "")) for column in columns}
      writer.writerow(normalized)


def _csv_value(value: Any) -> Any:
  if isinstance(value, (list, dict)):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
  return value
