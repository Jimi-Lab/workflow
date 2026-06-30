from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from statistics import median
from typing import Any

from vulngraph.agent_io.topk_judge_packet_schema import (
    JUDGE_EVENT_ROLE_OPTIONS,
    TOPK_JUDGE_PACKET_LIFECYCLE,
    TOPK_JUDGE_PACKET_SCHEMA_VERSION,
    scan_blind_packet_forbidden_keys,
    validate_blind_packet,
)
from vulngraph.git_graph.query import GitGraphQuery
from vulngraph.git_graph.schema import QueryStatus
from vulngraph.workflows.event_promotion_ablation_v1 import (
    _load_json,
    _percentile,
    _rank_candidates,
    _write_csv,
    _write_json,
    recommended_commits_from_label,
)
from vulngraph.workflows.history_root_boundary_v1 import (
    FEATURE_SERIES_BOUNDARY_ROLE,
    HISTORY_ROOT_BOUNDARY_ROLE,
    ORDINARY_BOUNDARY_ROLE,
    apply_history_root_boundary,
    is_invalid_primary_boundary_anchor,
)


DEV13_CVES = [
    "CVE-2020-8231",
    "CVE-2020-11647",
    "CVE-2020-13904",
    "CVE-2020-1971",
    "CVE-2020-8169",
    "CVE-2020-11984",
    "CVE-2020-12284",
    "CVE-2020-15389",
    "CVE-2020-15466",
    "CVE-2020-19667",
    "CVE-2020-25663",
    "CVE-2022-0171",
    "CVE-2022-0286",
]

KEY_EVENT_CHECKS = {
    "CVE-2020-8231": "d021f2e8a0067fc769652f27afec9024c0d02b3d",
    "CVE-2020-13904": "6cc7f1398257d4ffa89f79d52f10b2cabd9ad232",
    "CVE-2020-15466": "1e630b42e1f0573ca549643952017da315e695a0",
    "CVE-2022-0286": "18cb261afd7bf50134e5ccacc5ec91ea16efadd4",
}


def _read_json_if_exists(path: Path, default: Any) -> Any:
    return _load_json(path) if path.exists() else default


def load_promoted_events(v3_replay_root: str | Path, cve_id: str) -> list[dict[str, Any]]:
    path = Path(v3_replay_root) / cve_id / "v3_gate_decisions.json"
    events = _read_json_if_exists(path, [])
    return [item for item in events if item.get("gate_decision") == "promoted"]


def rank_promoted_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return _rank_candidates([json.loads(json.dumps(item)) for item in events], max_candidates=None)


def select_top_k(events: list[dict[str, Any]], k: int) -> list[dict[str, Any]]:
    if k < 1:
        raise ValueError("top-k must be positive")
    return [json.loads(json.dumps(item)) for item in events[:k]]


def _index_by_candidate_id(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(item.get("candidate_id") or ""): item for item in items if item.get("candidate_id")}


def _excerpt(value: Any, limit: int = 900) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[:limit] + "\n...[truncated]..."


def _compact_top_commits(section: dict[str, Any], event_sha: str) -> dict[str, Any]:
    top = [str(item) for item in section.get("top_commits") or []]
    return {
        "status": section.get("status", ""),
        "event_in_top_commits": event_sha in top,
        "top_commits": top[:5],
        "output_excerpt": _excerpt(section.get("output_excerpt", ""), 700),
        "reason": section.get("reason", ""),
    }


def _source_name(source: str) -> str:
    return {
        "direct_candidate": "direct",
        "blame_normal": "blame",
        "blame_w": "blame_w",
        "blame_M": "blame_M",
        "blame_C": "blame_C",
    }.get(source, source)


def _event_judge_role_options(event: dict[str, Any]) -> list[str]:
    roles = set(event.get("role_proposals") or [])
    options = {"uncertain"}
    if "possible_introduction_event" in roles:
        options.add("vulnerability_introduction")
    if HISTORY_ROOT_BOUNDARY_ROLE in roles:
        options.add(HISTORY_ROOT_BOUNDARY_ROLE)
    if FEATURE_SERIES_BOUNDARY_ROLE in roles:
        options.add(FEATURE_SERIES_BOUNDARY_ROLE)
    if ORDINARY_BOUNDARY_ROLE in roles or {"root_boundary", "unresolved_boundary", "branch_equivalent_event"} & roles:
        options.add(ORDINARY_BOUNDARY_ROLE)
    if "refactor_event" in roles:
        options.add("refactor")
    if "fixes_trailer_target" in roles or "prerequisite" in roles:
        options.add("prerequisite")
    return [role for role in JUDGE_EVENT_ROLE_OPTIONS if role in options]


def _coarse_role_options(options: list[str]) -> list[str]:
    coarse: list[str] = []
    if any(role in options for role in {HISTORY_ROOT_BOUNDARY_ROLE, FEATURE_SERIES_BOUNDARY_ROLE, ORDINARY_BOUNDARY_ROLE}):
        coarse.append("boundary")
    if "uncertain" in options:
        coarse.append("uncertain")
    return coarse


def _boundary_subtype_options(options: list[str]) -> list[str]:
    return [
        role
        for role in [HISTORY_ROOT_BOUNDARY_ROLE, FEATURE_SERIES_BOUNDARY_ROLE, ORDINARY_BOUNDARY_ROLE]
        if role in options
    ]


def _risk_signals(event: dict[str, Any], readiness_packets: list[dict[str, Any]]) -> dict[str, bool]:
    features = event.get("evidence_features") or {}
    roles = set(event.get("role_proposals") or [])
    sources = set(event.get("promotion_sources") or [])
    statuses: list[str] = []
    conflict_flags: dict[str, bool] = {}
    for packet in readiness_packets:
        relocation = packet.get("anchor_relocation") or {}
        candidate = relocation.get("candidate_resolution") or {}
        statuses.append(str(candidate.get("relocation_status") or ""))
        for parent in relocation.get("parent_resolutions") or []:
            statuses.append(str(parent.get("relocation_status") or ""))
        for key, value in (packet.get("conflict_flags") or {}).items():
            conflict_flags[key] = bool(conflict_flags.get(key) or value)
    return {
        "invalid_structural_anchor": int(features.get("invalid_anchor_count") or 0) > 0,
        "ambiguous_relocation": "ambiguous" in statuses,
        "not_found_path_missing_or_censored": any(status in {"not_found", "path_missing", "censored"} for status in statuses),
        "root_or_history_boundary": bool(features.get("root_or_boundary_source") or {"root_boundary", "unresolved_boundary"} & roles),
        "history_root_boundary": bool(features.get("history_root_boundary") or HISTORY_ROOT_BOUNDARY_ROLE in roles),
        "feature_series_boundary": FEATURE_SERIES_BOUNDARY_ROLE in roles,
        "log_follow_only": sources == {"log_follow"},
        "test_doc_build_only_path": int(features.get("noise_path_count") or 0) > 0,
        "formatting_or_refactor_signal": bool({"blame_w", "blame_M", "blame_C"} & sources or "refactor_event" in roles),
        "fallback_weak_binding": "fallback" in set(features.get("source_lanes") or []) or "fallback_weak_binding" in set(features.get("risk_flags") or []),
        "blame_variant_disagreement": bool(conflict_flags.get("blame_variant_disagreement")),
        "whitespace_sensitive": bool(conflict_flags.get("whitespace_sensitive")),
        "move_copy_sensitive": bool(conflict_flags.get("move_copy_sensitive")),
    }


def _root_cause_binding(
    history_packets: list[dict[str, Any]],
    readiness_packets: list[dict[str, Any]],
) -> dict[str, Any]:
    roots: set[str] = set()
    vulns: set[str] = set()
    fixes: set[str] = set()
    functions: set[str] = set()
    anchor_texts: list[str] = []
    for packet in history_packets:
        origin = packet.get("candidate_origin") or {}
        roots.update(str(item) for item in origin.get("root_cause_hypothesis_bindings") or [] if item)
        vulns.update(str(item) for item in origin.get("vulnerable_predicate_bindings") or [] if item)
        fixes.update(str(item) for item in origin.get("fix_predicate_bindings") or [] if item)
        if origin.get("function"):
            functions.add(str(origin.get("function")))
        if origin.get("function_name"):
            functions.add(str(origin.get("function_name")))
        if origin.get("old_line_text"):
            anchor_texts.append(str(origin.get("old_line_text")))
    for packet in readiness_packets:
        bindings = packet.get("root_cause_bindings") or {}
        roots.update(str(item) for item in bindings.get("root_cause_hypothesis_ids") or [] if item)
        vulns.update(str(item) for item in bindings.get("vulnerable_predicate_ids") or [] if item)
        fixes.update(str(item) for item in bindings.get("fix_predicate_ids") or [] if item)
        for key in ("function", "function_name"):
            if bindings.get(key):
                functions.add(str(bindings.get(key)))
    return {
        "root_cause_hypothesis_ids": sorted(roots),
        "vulnerable_predicate_ids": sorted(vulns),
        "fix_predicate_ids": sorted(fixes),
        "affected_functions": sorted(functions),
        "anchor_text_digests": [_excerpt(item, 160) for item in anchor_texts[:3]],
    }


def _anchor_evidence(
    source_candidate_ids: list[str],
    history_packets_by_candidate_id: dict[str, dict[str, Any]],
    readiness_packets_by_candidate_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    anchors: list[dict[str, Any]] = []
    for source_id in source_candidate_ids:
        history = history_packets_by_candidate_id.get(source_id) or {}
        readiness = readiness_packets_by_candidate_id.get(source_id) or {}
        origin = history.get("candidate_origin") or {}
        relocation = readiness.get("anchor_relocation") or {}
        candidate_resolution = relocation.get("candidate_resolution") or {}
        parent_resolutions = relocation.get("parent_resolutions") or []
        anchors.append(
            {
                "source_candidate_id": source_id,
                "anchor_path": origin.get("anchor_path") or (readiness.get("root_cause_bindings") or {}).get("anchor_path", ""),
                "old_line_start": origin.get("old_line_start", ""),
                "old_line_end": origin.get("old_line_end", ""),
                "old_anchor_text": origin.get("old_line_text", ""),
                "anchor_text_hash": origin.get("old_line_text_hash") or (readiness.get("root_cause_bindings") or {}).get("anchor_line_hash", ""),
                "evidence_role": (
                    "supporting_invalid_anchor"
                    if is_invalid_primary_boundary_anchor(origin.get("old_line_text"))
                    else "primary_anchor"
                ),
                "relocation_status": candidate_resolution.get("relocation_status", ""),
                "relocation_strategy": candidate_resolution.get("match_kind", ""),
                "parent_side_context_status": (readiness.get("parent_anchor_context") or {}).get("extraction_status", ""),
                "candidate_side_context_status": (readiness.get("candidate_anchor_context") or {}).get("extraction_status", ""),
                "parent_relocation_statuses": [item.get("relocation_status", "") for item in parent_resolutions],
                "anchor_local_diff_excerpt": _excerpt(readiness.get("anchor_path_diff_excerpt", ""), 900),
            }
        )
    return anchors


def _history_evidence(event_sha: str, history_packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for packet in history_packets:
        evidence.append(
            {
                "source_candidate_id": packet.get("candidate_id", ""),
                "blame_variant_summary": {
                    "canonical_blame_commit_sha": (packet.get("blame_variants") or {}).get("canonical_blame_commit_sha", ""),
                    "variant_agreement": (packet.get("blame_variants") or {}).get("variant_agreement", ""),
                    "unique_blamed_commit_count": (packet.get("blame_variants") or {}).get("unique_blamed_commit_count", ""),
                    "variants": [
                        {
                            "variant": item.get("variant", ""),
                            "status": item.get("status", ""),
                            "blamed_commit_sha": item.get("blamed_commit_sha", ""),
                            "boundary_marker": item.get("boundary_marker", False),
                        }
                        for item in (packet.get("blame_variants") or {}).get("variants") or []
                    ],
                },
                "log_L_evidence": _compact_top_commits((packet.get("log_history") or {}).get("log_L") or {}, event_sha),
                "pickaxe_S_evidence": _compact_top_commits((packet.get("log_history") or {}).get("log_S") or {}, event_sha),
                "pickaxe_G_evidence": _compact_top_commits((packet.get("log_history") or {}).get("log_G") or {}, event_sha),
                "path_follow_evidence": _compact_top_commits((packet.get("path_history") or {}).get("log_follow") or {}, event_sha),
                "recursive_blame": (packet.get("log_history") or {}).get("recursive_blame") or {"triggered": False, "chain": []},
            }
        )
    return evidence


def build_blind_packet(
    *,
    cve_id: str,
    repo_id: str,
    topk_events: list[dict[str, Any]],
    history_packets_by_candidate_id: dict[str, dict[str, Any]],
    readiness_packets_by_candidate_id: dict[str, dict[str, Any]],
    commit_metadata_by_sha: dict[str, dict[str, Any]],
    top_k: int,
) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for event in topk_events:
        event_sha = str(event.get("event_commit_sha") or "")
        source_ids = list(event.get("source_candidate_ids") or [])
        source_history = [history_packets_by_candidate_id[item] for item in source_ids if item in history_packets_by_candidate_id]
        source_readiness = [readiness_packets_by_candidate_id[item] for item in source_ids if item in readiness_packets_by_candidate_id]
        metadata = commit_metadata_by_sha.get(event_sha, {})
        role_options = _event_judge_role_options(event)
        candidate = {
                "candidate_id": str(event.get("event_id") or f"topk-event:{cve_id}:{event_sha[:12]}"),
                "event_commit_sha": event_sha,
                "rank": event.get("rank", ""),
                "lifecycle": TOPK_JUDGE_PACKET_LIFECYCLE,
                "gate_score": event.get("gate_score", ""),
                "gate_decision": event.get("gate_decision", ""),
                "gate_reasons": list(event.get("gate_reasons") or []),
                "promotion_sources": [_source_name(source) for source in event.get("promotion_sources") or []],
                "source_candidate_ids": source_ids,
                "commit_metadata": {
                    "subject": metadata.get("subject", ""),
                    "author_time": metadata.get("author_time", ""),
                    "commit_time": metadata.get("commit_time", metadata.get("committer_time", "")),
                    "parent_shas": metadata.get("parent_shas", []),
                    "changed_paths_summary": (metadata.get("changed_paths") or [])[:12],
                    "changed_path_count": len(metadata.get("changed_paths") or []),
                },
                "root_cause_binding": _root_cause_binding(source_history, source_readiness),
                "anchor_evidence": _anchor_evidence(source_ids, history_packets_by_candidate_id, readiness_packets_by_candidate_id),
                "history_evidence": _history_evidence(event_sha, source_history),
                "branch_ancestry_facts": {
                    "tags_containing_count": len(metadata.get("tags_containing") or []),
                    "tags_containing_sample": (metadata.get("tags_containing") or [])[:8],
                    "refs_containing_count": len(metadata.get("refs_containing") or []),
                },
                "negative_risk_signals": _risk_signals(event, source_readiness),
                "evidence_refs": [
                    ref for ref in event.get("source_refs") or []
                ],
                "judge_role_options": role_options,
                "coarse_role_options": _coarse_role_options(role_options),
                "boundary_subtype_options": _boundary_subtype_options(role_options),
                "current_system_prediction": "none_candidate_requires_judge",
            }
        if event.get("history_root_boundary"):
            candidate["history_root_boundary"] = event.get("history_root_boundary")
        candidates.append(candidate)
    packet = {
        "schema_version": TOPK_JUDGE_PACKET_SCHEMA_VERSION,
        "packet_type": "blind_history_event_judge_packet",
        "cve_id": cve_id,
        "repo_id": repo_id,
        "top_k": top_k,
        "lifecycle": TOPK_JUDGE_PACKET_LIFECYCLE,
        "candidate_count": len(candidates),
        "judge_task": {
            "task": "classify_each_history_event_role",
            "allowed_event_roles": JUDGE_EVENT_ROLE_OPTIONS,
            "must_account_for_all_candidates": True,
            "must_not_output_version_prediction": True,
            "must_not_name_event_as_final_boundary_without_evidence": True,
        },
        "candidates": candidates,
    }
    errors = validate_blind_packet(packet)
    if errors:
        packet["schema_errors"] = errors
    return packet


def build_audit_packet(*, blind_packet: dict[str, Any], label_case: dict[str, Any] | None) -> dict[str, Any]:
    label_case = label_case or {}
    recommended = recommended_commits_from_label(label_case)
    shas = [item["event_commit_sha"] for item in blind_packet.get("candidates") or []]

    def covered(k: int) -> bool | None:
        if not recommended:
            return None
        return bool(set(shas[:k]) & set(recommended))

    label_evaluation = {
        "case_verdict": label_case.get("case_verdict", ""),
        "has_preliminary_targets": bool(recommended),
        "preliminary_target_commits_for_audit": recommended,
        "covered_at_1": covered(1),
        "covered_at_3": covered(3),
        "covered_at_5": covered(5),
        "covered_at_k": covered(int(blind_packet.get("top_k") or 0)),
        "target_rank": _first_rank(shas, recommended),
    }
    known_labels = []
    for item in label_case.get("candidates") or []:
        sha = str(item.get("candidate_commit_sha") or "")
        if sha in shas:
            known_labels.append(
                {
                    "candidate_commit_sha": sha,
                    "candidate_id": item.get("candidate_id", ""),
                    "manual_event_label": item.get("manual_event_label", ""),
                    "is_recommended_intro": item.get("is_recommended_intro", ""),
                    "evidence_quality": item.get("evidence_quality", ""),
                    "notes": item.get("notes", ""),
                }
            )
    return {
        "schema_version": TOPK_JUDGE_PACKET_SCHEMA_VERSION,
        "packet_type": "audit_history_event_judge_packet",
        "cve_id": blind_packet.get("cve_id"),
        "repo_id": blind_packet.get("repo_id"),
        "top_k": blind_packet.get("top_k"),
        "blind_candidate_ids": [item.get("candidate_id") for item in blind_packet.get("candidates") or []],
        "label_evaluation": label_evaluation,
        "known_preliminary_labels_for_visible_candidates": known_labels,
        "blind_packet_forbidden_scan": scan_blind_packet_forbidden_keys(blind_packet),
    }


def _first_rank(shas: list[str], targets: list[str]) -> int | None:
    for index, sha in enumerate(shas, start=1):
        if sha in set(targets):
            return index
    return None


def summarize_packet_quality(case_packets: list[dict[str, Any]], *, top_k: int) -> dict[str, Any]:
    blind_sizes = [len(json.dumps(item["blind"], ensure_ascii=False, sort_keys=True).encode("utf-8")) for item in case_packets]
    before_counts = [int(item.get("candidates_before_topk", 0)) for item in case_packets]
    after_counts = [len(item["blind"].get("candidates") or []) for item in case_packets]
    audits = [item["audit"] for item in case_packets]
    target_audits = [item for item in audits if (item.get("label_evaluation") or {}).get("has_preliminary_targets")]

    def count_covered(key: str) -> int:
        return sum(1 for item in target_audits if (item.get("label_evaluation") or {}).get(key) is True)

    all_candidates = [candidate for item in case_packets for candidate in item["blind"].get("candidates") or []]
    risk = [candidate.get("negative_risk_signals") or {} for candidate in all_candidates]
    scan_count = sum(int((item["audit"].get("blind_packet_forbidden_scan") or {}).get("violation_count") or 0) for item in case_packets)
    return {
        "schema_version": TOPK_JUDGE_PACKET_SCHEMA_VERSION,
        "cases_total": len(case_packets),
        "top_k": top_k,
        "total_candidates_before_topk": sum(before_counts),
        "total_candidates_after_topk": sum(after_counts),
        "labeled_cases_total": len(audits),
        "target_denominator_cases": len(target_audits),
        "labeled_target_covered_at_1": count_covered("covered_at_1"),
        "labeled_target_covered_at_3": count_covered("covered_at_3"),
        "labeled_target_covered_at_5": count_covered("covered_at_5"),
        "labeled_target_covered_at_k": count_covered("covered_at_k"),
        "pool_recall_over_labeled_cases": (count_covered("covered_at_k") / len(target_audits)) if target_audits else None,
        "boundary_cases_count": sum(1 for item in case_packets if _case_has_boundary(item["blind"])),
        "unresolved_cases_count": sum(1 for item in case_packets if _case_is_unresolved(item["blind"], item["audit"])),
        "ambiguous_relocation_count": sum(1 for item in risk if item.get("ambiguous_relocation")),
        "missing_context_count": sum(1 for item in risk if item.get("not_found_path_missing_or_censored")),
        "blind_packet_forbidden_violation_count": scan_count,
        "blind_packet_size_bytes_max": max(blind_sizes) if blind_sizes else 0,
        "blind_packet_size_bytes_median": median(blind_sizes) if blind_sizes else 0,
        "blind_packet_size_bytes_min": min(blind_sizes) if blind_sizes else 0,
        "model_invocation_count": 0,
        "judge_invocation_count": 0,
        "converter_invocation_count": 0,
    }


def _case_has_boundary(blind: dict[str, Any]) -> bool:
    boundary_roles = {HISTORY_ROOT_BOUNDARY_ROLE, FEATURE_SERIES_BOUNDARY_ROLE, ORDINARY_BOUNDARY_ROLE}
    return any(
        bool(boundary_roles & set(candidate.get("judge_role_options") or []))
        or "boundary" in set(candidate.get("coarse_role_options") or [])
        for candidate in blind.get("candidates") or []
    )


def _case_is_unresolved(blind: dict[str, Any], audit: dict[str, Any]) -> bool:
    evaluation = audit.get("label_evaluation") or {}
    return not evaluation.get("has_preliminary_targets") or _case_has_boundary(blind)


def _load_labels(path: str | Path) -> dict[str, dict[str, Any]]:
    data = _load_json(Path(path))
    return {case["cve_id"]: case for case in data.get("cases", [])}


def _commit_metadata(repo_path: Path, query: GitGraphQuery | None, sha: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {"subject": "", "author_time": "", "commit_time": "", "parent_shas": [], "changed_paths": []}
    if query is not None:
        commit = query.get_commit(sha)
        if commit.status is QueryStatus.FOUND and commit.value:
            metadata["author_time"] = commit.value.get("author_time", "")
            metadata["commit_time"] = commit.value.get("committer_time", "")
        parents = query.get_parents(sha)
        if parents.status is QueryStatus.FOUND:
            metadata["parent_shas"] = parents.value or []
        changed = query.get_changed_paths(sha)
        if changed.status is QueryStatus.FOUND:
            metadata["changed_paths"] = changed.value or []
    if repo_path.exists():
        result = subprocess.run(
            ["git", "-C", str(repo_path), "show", "-s", "--format=%s", sha],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if result.returncode == 0:
            metadata["subject"] = result.stdout.strip()
    return metadata


def _load_case_inputs(
    *,
    cve_id: str,
    v3_replay_root: Path,
    reconstruction_root: Path,
    readiness_root: Path,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    promoted = rank_promoted_events(load_promoted_events(v3_replay_root, cve_id))
    history_packets = _read_json_if_exists(reconstruction_root / cve_id / "history_event_packets.json", [])
    readiness_packets = _read_json_if_exists(readiness_root / cve_id / "judge_blind_history_event_packets.json", [])
    return promoted, _index_by_candidate_id(history_packets), _index_by_candidate_id(readiness_packets)


def run_topk_judge_packet_v1(
    *,
    v3_replay_root: str | Path,
    reconstruction_root: str | Path,
    readiness_root: str | Path,
    git_graph_index: str | Path,
    repo_root: str | Path,
    labels_json: str | Path,
    out_dir: str | Path,
    top_k: int,
    cves: list[str] | None = None,
    reset: bool = False,
) -> dict[str, Any]:
    v3_replay_root = Path(v3_replay_root)
    reconstruction_root = Path(reconstruction_root)
    readiness_root = Path(readiness_root)
    git_graph_index = Path(git_graph_index)
    repo_root = Path(repo_root)
    output = Path(out_dir)
    labels = _load_labels(labels_json)
    selected_cves = cves or DEV13_CVES
    if reset and output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    case_packets: list[dict[str, Any]] = []
    quality_rows: list[dict[str, Any]] = []
    coverage_rows: list[dict[str, Any]] = []
    candidate_rows: list[dict[str, Any]] = []
    high_risk_rows: list[dict[str, Any]] = []
    query_by_repo: dict[str, GitGraphQuery | None] = {}

    for cve_id in selected_cves:
        promoted, history_by_id, readiness_by_id = _load_case_inputs(
            cve_id=cve_id,
            v3_replay_root=v3_replay_root,
            reconstruction_root=reconstruction_root,
            readiness_root=readiness_root,
        )
        repo_id = _case_repo_id(cve_id, promoted, history_by_id, labels)
        if repo_id not in query_by_repo:
            query_by_repo[repo_id] = _open_query(git_graph_index, repo_root, repo_id)
        promoted, history_boundary = apply_history_root_boundary(
            cve_id=cve_id,
            repo_id=repo_id,
            promoted_events=promoted,
            history_packets_by_candidate_id=history_by_id,
            top_k=top_k,
            git_graph_query=query_by_repo.get(repo_id),
        )
        top_events = select_top_k(promoted, top_k)
        metadata = {
            item["event_commit_sha"]: _commit_metadata(repo_root / repo_id, query_by_repo[repo_id], item["event_commit_sha"])
            for item in top_events
        }
        blind = build_blind_packet(
            cve_id=cve_id,
            repo_id=repo_id,
            topk_events=top_events,
            history_packets_by_candidate_id=history_by_id,
            readiness_packets_by_candidate_id=readiness_by_id,
            commit_metadata_by_sha=metadata,
            top_k=top_k,
        )
        audit = build_audit_packet(blind_packet=blind, label_case=labels.get(cve_id))
        case_dir = output / cve_id
        _write_json(case_dir / "judge_blind_history_event_packet.json", blind)
        _write_json(case_dir / "judge_audit_history_event_packet.json", audit)
        _write_csv(case_dir / "candidate_evidence_summary.csv", [_candidate_row(cve_id, repo_id, item) for item in blind["candidates"]])
        (case_dir / "case_packet_report_zh.md").write_text(_case_report(cve_id, blind, audit), encoding="utf-8")
        (case_dir / "raw_artifact_links.md").write_text(_raw_links(cve_id, v3_replay_root, reconstruction_root, readiness_root), encoding="utf-8")
        case_packets.append({"blind": blind, "audit": audit, "candidates_before_topk": len(promoted), "history_root_boundary": history_boundary})
        quality_rows.append(_quality_row(blind, audit, len(promoted)))
        coverage_rows.append(_coverage_row(blind, audit))
        candidate_rows.extend(_candidate_row(cve_id, repo_id, item) for item in blind["candidates"])
        high_risk_rows.append(_risk_row(blind, audit))

    summary = summarize_packet_quality(case_packets, top_k=top_k)
    key_checks = _key_event_checks(case_packets)
    stop_gates = _stop_gates(summary, case_packets, key_checks)
    summary["key_event_checks"] = key_checks
    summary["stop_gates"] = stop_gates
    summary["all_stop_gates_passed"] = all(stop_gates.values())
    blind_scan = _scan_blind_packets(output)
    summary["blind_packet_forbidden_violation_count"] = blind_scan["violation_count"]
    summary["stop_gates"]["blind_packet_forbidden_scan_zero"] = blind_scan["violation_count"] == 0
    summary["all_stop_gates_passed"] = all(summary["stop_gates"].values())

    _write_json(output / "summary.json", summary)
    _write_csv(output / "packet_quality_metrics.csv", [summary])
    _write_csv(output / "per_cve_packet_quality.csv", quality_rows)
    _write_csv(output / "topk_label_coverage.csv", coverage_rows)
    _write_json(output / "blind_packet_forbidden_scan.json", blind_scan)
    _write_json(output / "audit_label_usage_report.json", _audit_label_usage(case_packets))
    _write_csv(output / "high_risk_case_queue.csv", sorted(high_risk_rows, key=lambda row: (-int(row["risk_score"]), row["cve_id"])))
    _write_csv(output / "candidate_evidence_summary_all.csv", candidate_rows)
    (output / "topk_judge_packet_report_zh.md").write_text(_top_report(summary, high_risk_rows), encoding="utf-8")
    _write_json(
        output / "provenance_manifest.json",
        {
            "schema_version": TOPK_JUDGE_PACKET_SCHEMA_VERSION,
            "v3_replay_root": str(v3_replay_root.resolve()),
            "reconstruction_root": str(reconstruction_root.resolve()),
            "readiness_root": str(readiness_root.resolve()),
            "git_graph_index": str(git_graph_index.resolve()),
            "labels_json_for_audit_only": str(Path(labels_json).resolve()),
            "top_k": top_k,
            "candidate_generation_uses_labels": False,
            "model_invocation_count": 0,
            "judge_invocation_count": 0,
            "converter_invocation_count": 0,
        },
    )
    return summary


def _open_query(index_root: Path, repo_root: Path, repo_id: str) -> GitGraphQuery | None:
    database = index_root / repo_id / "graph.sqlite"
    repo = repo_root / repo_id
    if not database.exists() or not repo.exists():
        return None
    return GitGraphQuery(database, repo)


def _case_repo_id(cve_id: str, events: list[dict[str, Any]], history_by_id: dict[str, dict[str, Any]], labels: dict[str, dict[str, Any]]) -> str:
    if events and events[0].get("repo_id"):
        return str(events[0].get("repo_id"))
    for packet in history_by_id.values():
        if packet.get("repo_id"):
            return str(packet.get("repo_id"))
    return str((labels.get(cve_id) or {}).get("repo_id") or "")


def _candidate_row(cve_id: str, repo_id: str, item: dict[str, Any]) -> dict[str, Any]:
    risks = item.get("negative_risk_signals") or {}
    return {
        "cve_id": cve_id,
        "repo_id": repo_id,
        "candidate_id": item.get("candidate_id", ""),
        "rank": item.get("rank", ""),
        "event_commit_sha": item.get("event_commit_sha", ""),
        "gate_score": item.get("gate_score", ""),
        "gate_reasons": ";".join(item.get("gate_reasons") or []),
        "promotion_sources": ";".join(item.get("promotion_sources") or []),
        "source_candidate_ids": ";".join(item.get("source_candidate_ids") or []),
        "judge_role_options": ";".join(item.get("judge_role_options") or []),
        "risk_signals": ";".join(key for key, value in risks.items() if value),
        "anchor_count": len(item.get("anchor_evidence") or []),
    }


def _quality_row(blind: dict[str, Any], audit: dict[str, Any], before_topk: int) -> dict[str, Any]:
    evaluation = audit.get("label_evaluation") or {}
    return {
        "cve_id": blind.get("cve_id"),
        "repo_id": blind.get("repo_id"),
        "top_k": blind.get("top_k"),
        "candidates_before_topk": before_topk,
        "candidate_count": len(blind.get("candidates") or []),
        "has_preliminary_targets": evaluation.get("has_preliminary_targets"),
        "covered_at_1": evaluation.get("covered_at_1"),
        "covered_at_3": evaluation.get("covered_at_3"),
        "covered_at_5": evaluation.get("covered_at_5"),
        "covered_at_k": evaluation.get("covered_at_k"),
        "target_rank": evaluation.get("target_rank"),
        "boundary_case": _case_has_boundary(blind),
        "unresolved_case": _case_is_unresolved(blind, audit),
        "blind_packet_bytes": len(json.dumps(blind, ensure_ascii=False, sort_keys=True).encode("utf-8")),
        "forbidden_violations": (audit.get("blind_packet_forbidden_scan") or {}).get("violation_count", 0),
    }


def _coverage_row(blind: dict[str, Any], audit: dict[str, Any]) -> dict[str, Any]:
    evaluation = audit.get("label_evaluation") or {}
    return {
        "cve_id": blind.get("cve_id"),
        "repo_id": blind.get("repo_id"),
        "top_k": blind.get("top_k"),
        "preliminary_target_commits_for_audit": ";".join(evaluation.get("preliminary_target_commits_for_audit") or []),
        "covered_at_1": evaluation.get("covered_at_1"),
        "covered_at_3": evaluation.get("covered_at_3"),
        "covered_at_5": evaluation.get("covered_at_5"),
        "covered_at_k": evaluation.get("covered_at_k"),
        "target_rank": evaluation.get("target_rank"),
        "case_verdict": evaluation.get("case_verdict", ""),
    }


def _risk_row(blind: dict[str, Any], audit: dict[str, Any]) -> dict[str, Any]:
    risks = Counter()
    for candidate in blind.get("candidates") or []:
        risks.update(key for key, value in (candidate.get("negative_risk_signals") or {}).items() if value)
    risk_score = sum(risks.values())
    evaluation = audit.get("label_evaluation") or {}
    if not evaluation.get("has_preliminary_targets"):
        risk_score += 5
        risks["no_unique_preliminary_target"] += 1
    return {
        "cve_id": blind.get("cve_id"),
        "repo_id": blind.get("repo_id"),
        "risk_score": risk_score,
        "risk_signals": json.dumps(dict(sorted(risks.items())), sort_keys=True),
        "candidate_count": len(blind.get("candidates") or []),
        "target_rank": evaluation.get("target_rank"),
        "covered_at_k": evaluation.get("covered_at_k"),
    }


def _scan_blind_packets(output: Path) -> dict[str, Any]:
    violations: list[dict[str, Any]] = []
    for path in output.glob("CVE-*/judge_blind_history_event_packet.json"):
        scan = scan_blind_packet_forbidden_keys(_load_json(path))
        for item in scan["violations"]:
            violations.append({"file": str(path.relative_to(output)), **item})
    return {"violation_count": len(violations), "violations": violations}


def _key_event_checks(case_packets: list[dict[str, Any]]) -> dict[str, Any]:
    checks: dict[str, Any] = {}
    by_cve = {item["blind"]["cve_id"]: item for item in case_packets}
    for cve_id, target in KEY_EVENT_CHECKS.items():
        blind = by_cve.get(cve_id, {}).get("blind") or {}
        rank = _first_rank([item["event_commit_sha"] for item in blind.get("candidates") or []], [target])
        checks[cve_id] = {"target_commit": target, "in_top_k": rank is not None, "rank": rank}
    return checks


def _stop_gates(summary: dict[str, Any], case_packets: list[dict[str, Any]], key_checks: dict[str, Any]) -> dict[str, bool]:
    by_cve = {item["blind"]["cve_id"]: item for item in case_packets}
    cve_11647 = by_cve.get("CVE-2020-11647", {})
    cve_19667 = by_cve.get("CVE-2020-19667", {})
    return {
        "generated_13_of_13": summary["cases_total"] == 13,
        "blind_packet_forbidden_scan_zero": summary["blind_packet_forbidden_violation_count"] == 0,
        "topk_parameterized": int(summary["top_k"]) > 0,
        "topk8_recall_at5_not_below_v3": summary["top_k"] != 8 or summary["labeled_target_covered_at_5"] == summary["target_denominator_cases"],
        "cve_2020_11647_not_success_intro": not (cve_11647.get("audit", {}).get("label_evaluation") or {}).get("has_preliminary_targets", False),
        "cve_2020_19667_not_ordinary_intro": _case_has_boundary(cve_19667.get("blind") or {}),
        "audit_label_absent_from_blind": summary["blind_packet_forbidden_violation_count"] == 0,
        "no_model_judge_converter_invocation": True,
        "key_events_present": all(item["in_top_k"] for item in key_checks.values()),
    }


def _audit_label_usage(case_packets: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "labels_used_for_audit_only": True,
        "candidate_generation_uses_labels": False,
        "audit_cases": [item["blind"]["cve_id"] for item in case_packets if (item["audit"].get("label_evaluation") or {}).get("case_verdict")],
    }


def _case_report(cve_id: str, blind: dict[str, Any], audit: dict[str, Any]) -> str:
    evaluation = audit.get("label_evaluation") or {}
    lines = [
        f"# {cve_id} Top-k History Event Judge Packet v1",
        "",
        "本文件只说明 Judge 输入包质量；未运行 Judge，也不做版本预测。",
        "",
        f"- repo: `{blind.get('repo_id')}`",
        f"- top-k: `{blind.get('top_k')}`",
        f"- candidate count: `{len(blind.get('candidates') or [])}`",
        f"- preliminary target rank for audit: `{evaluation.get('target_rank')}`",
        "",
        "## Candidates",
        "",
    ]
    for candidate in blind.get("candidates") or []:
        lines.append(
            f"- rank {candidate.get('rank')}: `{candidate.get('event_commit_sha')}` "
            f"sources={','.join(candidate.get('promotion_sources') or [])} roles={','.join(candidate.get('judge_role_options') or [])}"
        )
    return "\n".join(lines) + "\n"


def _raw_links(cve_id: str, v3_root: Path, reconstruction_root: Path, readiness_root: Path) -> str:
    return "\n".join(
        [
            f"# {cve_id} Raw Artifact Links",
            "",
            f"- V3 replay: `{v3_root / cve_id}`",
            f"- History reconstruction: `{reconstruction_root / cve_id}`",
            f"- Judge readiness: `{readiness_root / cve_id}`",
            "",
        ]
    )


def _top_report(summary: dict[str, Any], high_risk_rows: list[dict[str, Any]]) -> str:
    risky = sorted(high_risk_rows, key=lambda row: (-int(row["risk_score"]), row["cve_id"]))[:5]
    lines = [
        "# VulnGraph Top-k History Event Judge Packet v1 dev13",
        "",
        "本轮只构造可交给 Judge 的 blind/audit packets；未调用模型，未运行 Judge，未运行 converter。",
        "",
        "## Stop Gates",
        "",
    ]
    for key, value in summary["stop_gates"].items():
        lines.append(f"- {key}: `{value}`")
    lines.extend(
        [
            "",
            "## Metrics",
            "",
            f"- cases_total: `{summary['cases_total']}`",
            f"- top_k: `{summary['top_k']}`",
            f"- total candidates before/after top-k: `{summary['total_candidates_before_topk']}` / `{summary['total_candidates_after_topk']}`",
            f"- target coverage @1/@3/@5/@k: `{summary['labeled_target_covered_at_1']}` / `{summary['labeled_target_covered_at_3']}` / `{summary['labeled_target_covered_at_5']}` / `{summary['labeled_target_covered_at_k']}`",
            f"- blind packet forbidden violations: `{summary['blind_packet_forbidden_violation_count']}`",
            f"- blind packet bytes median/max: `{summary['blind_packet_size_bytes_median']}` / `{summary['blind_packet_size_bytes_max']}`",
            "",
            "## High Risk Cases",
            "",
        ]
    )
    for row in risky:
        lines.append(f"- {row['cve_id']}: score={row['risk_score']}, risks={row['risk_signals']}")
    lines.extend(["", "## Key Event Checks", ""])
    for cve_id, item in summary["key_event_checks"].items():
        lines.append(f"- {cve_id}: in_top_k={item['in_top_k']}, rank={item['rank']}, commit=`{item['target_commit']}`")
    return "\n".join(lines) + "\n"


def _first_rank(shas: list[str], targets: list[str]) -> int | None:
    target_set = set(targets)
    for index, sha in enumerate(shas, start=1):
        if sha in target_set:
            return index
    return None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Top-k History Event Judge Packet v1.")
    parser.add_argument("--v3-replay-root", required=True)
    parser.add_argument("--reconstruction-root", required=True)
    parser.add_argument("--readiness-root", required=True)
    parser.add_argument("--git-graph-index", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--labels-json", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--top-k", type=int, required=True)
    parser.add_argument("--cves", nargs="*")
    parser.add_argument("--reset", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    summary = run_topk_judge_packet_v1(
        v3_replay_root=args.v3_replay_root,
        reconstruction_root=args.reconstruction_root,
        readiness_root=args.readiness_root,
        git_graph_index=args.git_graph_index,
        repo_root=args.repo_root,
        labels_json=args.labels_json,
        out_dir=args.out_dir,
        top_k=args.top_k,
        cves=args.cves,
        reset=args.reset,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("all_stop_gates_passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
