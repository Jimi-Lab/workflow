from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vulngraph.agent_io.history_event_judge_readiness_schema import (
    HISTORY_EVENT_JUDGE_READINESS_LIFECYCLE,
    HISTORY_EVENT_JUDGE_READINESS_SCHEMA_VERSION,
    validate_judge_ready_history_event_blind_packet,
)
from vulngraph.agent_io.history_event_schema import scan_forbidden_output_fields
from vulngraph.git_graph.query import GitGraphQuery
from vulngraph.git_graph.schema import QueryStatus
from vulngraph.services.history_anchor_relocator import (
    compact_resolution_for_blind_packet,
    materialize_relocated_context,
    relocate_history_event_anchor,
)
from vulngraph.workflows.history_event_reconstruction_v1 import load_dataset_metadata_without_gt


_P0_FLAGS = {
    "blame_variant_disagreement",
    "path_trace_disagreement",
}
_P1_FLAGS = {
    "whitespace_sensitive",
    "move_copy_sensitive",
    "log_L_disagreement",
}
_FORBIDDEN_TEXT_KEYS = ("affected_version", "validated_bic", "correct_bic", "ground_truth", "BIC", "bic")


def packet_size_bytes(packet: dict[str, Any]) -> int:
    return len(json.dumps(packet, ensure_ascii=False, sort_keys=True).encode("utf-8"))


def extract_line_window(file_content: str, *, line: int, radius: int = 6) -> dict[str, Any]:
    lines = file_content.splitlines()
    if line < 1 or line > len(lines):
        return {
            "start_line": line,
            "end_line": line,
            "lines": [],
            "line_hashes": [],
            "extraction_status": "line_missing",
            "reason": f"line_out_of_range:{line}:1-{len(lines)}",
        }
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    window = [
        {
            "line_no": index,
            "text": lines[index - 1],
            "sha256": _sha256_text(lines[index - 1]),
            "is_anchor_line": index == line,
        }
        for index in range(start, end + 1)
    ]
    return {
        "start_line": start,
        "end_line": end,
        "lines": window,
        "line_hashes": [item["sha256"] for item in window],
        "extraction_status": "found",
        "reason": "",
    }


def build_judge_readiness_packets_for_history_event(
    packet: dict[str, Any],
    *,
    git_query: GitGraphQuery,
    max_blind_diff_chars: int = 6000,
    context_radius: int = 6,
) -> tuple[dict[str, Any], dict[str, Any]]:
    origin = packet.get("candidate_origin", {}) or {}
    event = packet.get("candidate_event", {}) or {}
    anchor_path = str(origin.get("anchor_path") or "")
    old_line = _int(origin.get("old_line_start"), default=0)
    old_line_end = _int(origin.get("old_line_end"), default=old_line)
    candidate_sha = str(event.get("candidate_commit_sha") or "")
    parent_shas = list(event.get("parent_shas") or [])
    relocation = relocate_history_event_anchor(packet, git_query)
    parent_resolutions = list(relocation.get("parent_resolutions") or [])
    candidate_resolution = relocation.get("candidate_resolution") or {}
    selected_parent_index = _select_parent_resolution_index(parent_resolutions)
    selected_parent_resolution = (
        parent_resolutions[selected_parent_index]
        if selected_parent_index is not None
        else _missing_parent_resolution()
    )
    selected_parent_sha = str(selected_parent_resolution.get("revision_sha") or "")
    parent_contexts = [
        materialize_relocated_context(
            git_query,
            resolution,
            context_kind="parent_anchor_context",
            radius=context_radius,
        )
        for resolution in parent_resolutions
    ]
    parent_context = (
        parent_contexts[selected_parent_index]
        if selected_parent_index is not None
        else _empty_anchor_context("parent_anchor_context", "censored", "missing_parent")
    )
    candidate_context = materialize_relocated_context(
        git_query,
        candidate_resolution,
        context_kind="candidate_anchor_context",
        radius=context_radius,
    )
    before_path = _resolution_path(selected_parent_resolution, fallback=anchor_path)
    after_path = _resolution_path(candidate_resolution, fallback=anchor_path)
    path_resolution_status = _combined_path_resolution_status(
        selected_parent_resolution,
        candidate_resolution,
    )
    path_resolution_reason = _combined_path_resolution_reason(
        selected_parent_resolution,
        candidate_resolution,
    )
    local_diff = extract_anchor_local_diff(
        git_query,
        selected_parent_sha,
        candidate_sha,
        before_path=before_path,
        after_path=after_path,
        anchor_old_line=_int(selected_parent_resolution.get("relocated_line_start")),
        anchor_new_line=_int(candidate_resolution.get("relocated_line_start")),
        max_chars=max_blind_diff_chars,
    )
    function_context = extract_function_context_if_available(
        git_query=git_query,
        parent_resolution=selected_parent_resolution,
        candidate_resolution=candidate_resolution,
        function_name=origin.get("function"),
        function_id=origin.get("function_id"),
    )
    conflict_flags = _conflict_flags(packet, parent_context, candidate_context, local_diff)
    review_priority = _review_priority(packet, conflict_flags, parent_context, candidate_context, local_diff)
    blind = {
        "schema_version": HISTORY_EVENT_JUDGE_READINESS_SCHEMA_VERSION,
        "cve_id": packet.get("cve_id"),
        "repo_id": packet.get("repo_id"),
        "candidate_id": packet.get("candidate_id"),
        "source_lane": packet.get("source_lane"),
        "lifecycle": HISTORY_EVENT_JUDGE_READINESS_LIFECYCLE,
        "git_graph_snapshot_id": (packet.get("git_graph_snapshot") or {}).get("repo_snapshot_id", ""),
        "root_cause_bindings": {
            "root_cause_hypothesis_ids": list(origin.get("root_cause_hypothesis_bindings") or []),
            "vulnerable_predicate_ids": list(origin.get("vulnerable_predicate_bindings") or []),
            "fix_predicate_ids": list(origin.get("fix_predicate_bindings") or []),
            "fix_family": origin.get("fix_family") or "",
            "patch_family": origin.get("patch_family") or "",
            "anchor_path": anchor_path,
            "anchor_old_line_start": old_line,
            "anchor_old_line_end": old_line_end,
            "anchor_old_line_text": origin.get("old_line_text") or "",
            "anchor_line_hash": origin.get("old_line_text_hash") or "",
            "function": origin.get("function"),
            "function_id": origin.get("function_id"),
        },
        "candidate_event_identity": {
            "candidate_commit_sha": candidate_sha,
            "candidate_parent_shas": parent_shas,
            "selected_parent_sha": selected_parent_sha,
            "is_merge": bool(event.get("is_merge")),
            "is_root": bool(event.get("is_root")),
            "boundary_marker": bool(event.get("boundary_marker")),
            "candidate_ancestor_of_fix": event.get("is_ancestor_of_fix"),
            "fix_commit_sha": origin.get("fix_commit_sha") or "",
            "fix_parent_sha": origin.get("fix_parent_sha") or "",
        },
        "path_resolution": {
            "before_path": before_path,
            "after_path": after_path,
            "path_resolution_method": "deterministic_anchor_relocation",
            "path_resolution_status": path_resolution_status,
            "uncertainty_reason": path_resolution_reason,
        },
        "before_path": before_path,
        "after_path": after_path,
        "path_resolution_method": "deterministic_anchor_relocation",
        "path_resolution_status": path_resolution_status,
        "anchor_relocation": {
            "anchor_reference": relocation.get("anchor_reference"),
            "selected_parent_index": selected_parent_index,
            "parent_resolutions": [
                compact_resolution_for_blind_packet(item)
                for item in parent_resolutions
            ],
            "candidate_resolution": compact_resolution_for_blind_packet(
                candidate_resolution
            ),
        },
        "parent_anchor_context": parent_context,
        "parent_anchor_contexts": parent_contexts,
        "candidate_anchor_context": candidate_context,
        "anchor_path_diff_excerpt": local_diff["anchor_path_diff_excerpt"],
        "anchor_hunk_before_lines": local_diff["anchor_hunk_before_lines"],
        "anchor_hunk_after_lines": local_diff["anchor_hunk_after_lines"],
        "changed_line_roles": local_diff["changed_line_roles"],
        "diff_extraction_status": local_diff["diff_extraction_status"],
        "function_context": function_context,
        "history_reconstruction_summary": _history_reconstruction_summary(packet),
        "conflict_flags": conflict_flags,
        "uncertainty_reasons": _uncertainty_reasons(packet, parent_context, candidate_context, local_diff),
        "judge_hints": {
            "likely_noise_reason": _likely_noise_reason(packet, conflict_flags, parent_context, candidate_context, local_diff),
            "evidence_strength_score": (packet.get("deterministic_ranking_features") or {}).get("evidence_strength"),
            "conflict_count": sum(1 for value in conflict_flags.values() if value),
            "recommended_review_priority": review_priority,
        },
        "recommended_review_priority": review_priority,
    }
    schema_errors = validate_judge_ready_history_event_blind_packet(blind)
    if schema_errors:
        blind["schema_errors"] = schema_errors
    audit = {
        "schema_version": HISTORY_EVENT_JUDGE_READINESS_SCHEMA_VERSION,
        "lifecycle": HISTORY_EVENT_JUDGE_READINESS_LIFECYCLE,
        "blind_packet": blind,
        "source_history_event_packet": packet,
        "source_packet_refs": {
            "cve_id": packet.get("cve_id"),
            "candidate_id": packet.get("candidate_id"),
            "source_schema_version": packet.get("schema_version"),
            "source_lifecycle": packet.get("lifecycle"),
        },
        "anchor_relocation_trace": relocation,
        "legacy_line_hint_diagnostics": _legacy_line_hint_diagnostics(
            git_query,
            packet,
            parent_resolutions,
            candidate_resolution,
        ),
        "packet_construction_diagnostics": {
            "parent_context_status": parent_context.get("extraction_status"),
            "candidate_context_status": candidate_context.get("extraction_status"),
            "diff_extraction_status": local_diff.get("diff_extraction_status"),
            "false_same_line_accept_count": _false_same_line_accept_count(
                [
                    *zip(parent_resolutions, parent_contexts, strict=False),
                    (candidate_resolution, candidate_context),
                ]
            ),
            "blind_packet_size_bytes": packet_size_bytes(blind),
            "audit_packet_size_bytes": 0,
        },
    }
    audit["packet_construction_diagnostics"]["audit_packet_size_bytes"] = packet_size_bytes(audit)
    return blind, audit


def _select_parent_resolution_index(
    resolutions: list[dict[str, Any]],
) -> int | None:
    if not resolutions:
        return None
    order = {
        "found": 0,
        "absent_by_event": 1,
        "ambiguous": 2,
        "not_found": 3,
        "path_missing": 4,
        "censored": 5,
    }
    return min(
        range(len(resolutions)),
        key=lambda index: (
            order.get(str(resolutions[index].get("relocation_status")), 99),
            index,
        ),
    )


def _missing_parent_resolution() -> dict[str, Any]:
    return {
        "revision_sha": "",
        "path_candidates": [],
        "selected_path": None,
        "relocated_line_start": None,
        "relocation_status": "censored",
        "match_kind": "unavailable",
        "relation_to_anchor": "unknown",
        "evidence_refs": [],
        "failure_reason": "missing_parent",
    }


def _empty_anchor_context(
    context_kind: str,
    status: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "revision": "",
        "path": None,
        "context_kind": context_kind,
        "start_line": None,
        "end_line": None,
        "lines": [],
        "line_hashes": [],
        "extraction_status": status,
        "reason": reason,
        "anchor_verified": False,
    }


def _resolution_path(resolution: dict[str, Any], *, fallback: str) -> str:
    selected = str(resolution.get("selected_path") or "")
    if selected:
        return selected
    for item in resolution.get("path_candidates") or []:
        path = str(item.get("path") or "")
        if path:
            return path
    return fallback


def _combined_path_resolution_status(
    parent_resolution: dict[str, Any],
    candidate_resolution: dict[str, Any],
) -> str:
    statuses = {
        str(parent_resolution.get("relocation_status") or ""),
        str(candidate_resolution.get("relocation_status") or ""),
    }
    if statuses == {"found"}:
        return "found"
    if "found" in statuses or "absent_by_event" in statuses:
        return "partial"
    if "ambiguous" in statuses:
        return "ambiguous"
    if "censored" in statuses:
        return "censored"
    return "unresolved"


def _combined_path_resolution_reason(
    parent_resolution: dict[str, Any],
    candidate_resolution: dict[str, Any],
) -> str:
    reasons = [
        str(
            resolution.get("ambiguity_reason")
            or resolution.get("failure_reason")
            or ""
        )
        for resolution in (parent_resolution, candidate_resolution)
    ]
    return ";".join(reason for reason in reasons if reason)


def _legacy_line_hint_diagnostics(
    query: GitGraphQuery,
    packet: dict[str, Any],
    parent_resolutions: list[dict[str, Any]],
    candidate_resolution: dict[str, Any],
) -> list[dict[str, Any]]:
    origin = packet.get("candidate_origin") or {}
    path = str(origin.get("anchor_path") or "")
    line = _int(origin.get("old_line_start"))
    expected_text = str(origin.get("old_line_text") or "")
    rows: list[dict[str, Any]] = []
    for side, resolution in [
        *[("parent", item) for item in parent_resolutions],
        ("candidate", candidate_resolution),
    ]:
        revision = str(resolution.get("revision_sha") or "")
        row = {
            "side": side,
            "revision_sha": revision,
            "path": path,
            "old_line_hint": line,
            "status": "censored",
            "actual_text": "",
            "actual_text_hash": "",
            "exact_text_match": False,
            "normalized_text_match": False,
            "comment_or_blank": False,
        }
        if not revision or not path or line < 1:
            row["reason"] = "missing_legacy_coordinate"
            rows.append(row)
            continue
        blob = query.read_file_at_revision(revision, path)
        if blob.status is not QueryStatus.FOUND:
            row["status"] = (
                "path_missing"
                if blob.status is QueryStatus.NOT_FOUND
                else "censored"
            )
            row["reason"] = blob.reason or blob.status.value
            rows.append(row)
            continue
        lines = str(blob.value or "").splitlines()
        if line > len(lines):
            row["status"] = "not_found"
            row["reason"] = "old_line_hint_out_of_range"
            rows.append(row)
            continue
        actual = lines[line - 1]
        stripped = actual.lstrip()
        row.update(
            {
                "status": "found",
                "reason": "",
                "actual_text": actual,
                "actual_text_hash": _sha256_text(actual),
                "exact_text_match": actual == expected_text,
                "normalized_text_match": " ".join(actual.split())
                == " ".join(expected_text.split()),
                "comment_or_blank": not actual.strip()
                or stripped.startswith(("/*", "*", "//")),
            }
        )
        rows.append(row)
    return rows


def _false_same_line_accept_count(
    resolution_context_pairs: list[tuple[dict[str, Any], dict[str, Any]]],
) -> int:
    count = 0
    for resolution, context in resolution_context_pairs:
        if context.get("extraction_status") != "found":
            continue
        anchor_lines = [
            item for item in context.get("lines") or [] if item.get("is_anchor_line")
        ]
        if (
            len(anchor_lines) != 1
            or not context.get("anchor_verified")
            or anchor_lines[0].get("sha256") != resolution.get("matched_text_hash")
        ):
            count += 1
    return count


def run_history_event_judge_readiness(
    *,
    dataset_path: str | Path,
    repo_root: str | Path,
    git_graph_index: str | Path,
    history_event_root: str | Path,
    out_dir: str | Path,
    reset: bool = False,
    cve_ids: list[str] | None = None,
) -> dict[str, Any]:
    dataset = load_dataset_metadata_without_gt(dataset_path)
    selected_cves = sorted(cve_ids or dataset)
    unknown_cves = sorted(set(selected_cves) - set(dataset))
    if unknown_cves:
        raise ValueError(f"unknown CVE ids: {', '.join(unknown_cves)}")
    repo_root = Path(repo_root)
    index_root = Path(git_graph_index)
    history_root = Path(history_event_root)
    out = Path(out_dir)
    if reset and out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    blind_rows: list[dict[str, Any]] = []
    audit_rows: list[dict[str, Any]] = []
    manual_rows: list[dict[str, Any]] = []
    evidence_rows: list[dict[str, Any]] = []
    relocation_rows: list[dict[str, Any]] = []
    comparison_rows: list[dict[str, Any]] = []
    ambiguous_rows: list[dict[str, Any]] = []
    unresolved_rows: list[dict[str, Any]] = []
    packet_sizes: list[int] = []
    extraction_counter: Counter[str] = Counter()
    conflict_counter: Counter[str] = Counter()
    priority_counter: Counter[str] = Counter()
    parent_status_counter: Counter[str] = Counter()
    candidate_status_counter: Counter[str] = Counter()
    strategy_counter: Counter[str] = Counter()
    lane_resolution_counter: Counter[str] = Counter()
    total_blind = 0
    total_audit = 0
    total_source_candidates = 0
    false_same_line_accept_count = 0
    old_context_found_count = 0
    old_context_verified_count = 0
    old_context_false_accept_count = 0
    old_comment_or_blank_accept_count = 0
    new_verified_context_count = 0
    schema_error_count = 0
    case_outputs = 0
    case_summaries: list[dict[str, Any]] = []
    queries: dict[str, GitGraphQuery] = {}

    for cve_id in selected_cves:
        meta = dataset[cve_id]
        repo_id = str(meta.get("repo") or "")
        case_input = history_root / cve_id / "history_event_packets.json"
        case_dir = out / cve_id
        case_dir.mkdir(parents=True, exist_ok=True)
        if not case_input.exists():
            summary = {"cve_id": cve_id, "repo_id": repo_id, "status": "missing_history_event_packets", "blind_packet_count": 0, "audit_packet_count": 0}
            _write_case_outputs(case_dir, [], [], summary)
            case_summaries.append(summary)
            continue
        packets = json.loads(case_input.read_text(encoding="utf-8"))
        total_source_candidates += len(packets)
        blind_packets: list[dict[str, Any]] = []
        audit_packets: list[dict[str, Any]] = []
        relocation_traces: list[dict[str, Any]] = []
        for packet in packets:
            repo_id = str(packet.get("repo_id") or repo_id)
            if repo_id not in queries:
                queries[repo_id] = GitGraphQuery(
                    index_root / repo_id / "graph.sqlite",
                    repo_root / repo_id,
                )
            blind, audit = build_judge_readiness_packets_for_history_event(
                packet,
                git_query=queries[repo_id],
            )
            blind_packets.append(blind)
            audit_packets.append(audit)
            schema_error_count += len(blind.get("schema_errors") or [])
            relocation = audit.get("anchor_relocation_trace") or {}
            relocation_traces.append(relocation)
            total_blind += 1
            total_audit += 1
            false_same_line_accept_count += _int(
                (audit.get("packet_construction_diagnostics") or {}).get(
                    "false_same_line_accept_count"
                )
            )
            packet_size = packet_size_bytes(blind)
            packet_sizes.append(packet_size)
            statuses = _packet_extraction_statuses(blind)
            for status in statuses:
                extraction_counter[status] += 1
            for flag, value in (blind.get("conflict_flags") or {}).items():
                if value:
                    conflict_counter[flag] += 1
            priority = str(blind.get("recommended_review_priority") or "")
            priority_counter[priority] += 1
            blind_rows.append(_blind_summary_row(blind, packet_size))
            audit_rows.append(_audit_summary_row(audit))
            evidence_rows.append(_evidence_quality_row(blind, packet_size))
            manual_rows.append(_manual_review_row(blind))
            legacy_rows = audit.get("legacy_line_hint_diagnostics") or []
            old_context_found_count += sum(
                1 for item in legacy_rows if item.get("status") == "found"
            )
            old_context_verified_count += sum(
                1
                for item in legacy_rows
                if item.get("status") == "found"
                and (
                    item.get("exact_text_match")
                    or item.get("normalized_text_match")
                )
            )
            old_context_false_accept_count += sum(
                1
                for item in legacy_rows
                if item.get("status") == "found"
                and not (
                    item.get("exact_text_match")
                    or item.get("normalized_text_match")
                )
            )
            old_comment_or_blank_accept_count += sum(
                1
                for item in legacy_rows
                if item.get("status") == "found"
                and item.get("comment_or_blank")
            )
            parent_resolutions = relocation.get("parent_resolutions") or []
            candidate_resolution = relocation.get("candidate_resolution") or {}
            contexts = [
                *(
                    blind.get("parent_anchor_contexts")
                    or [blind.get("parent_anchor_context") or {}]
                ),
                blind.get("candidate_anchor_context") or {},
            ]
            new_verified_context_count += sum(
                1
                for context in contexts
                if context.get("extraction_status") == "found"
                and context.get("anchor_verified")
            )
            for side, resolution in [
                *[("parent", item) for item in parent_resolutions],
                ("candidate", candidate_resolution),
            ]:
                status = str(resolution.get("relocation_status") or "missing")
                if side == "parent":
                    parent_status_counter[status] += 1
                else:
                    candidate_status_counter[status] += 1
                lane_resolution_counter[
                    f"{blind.get('source_lane')}:{side}:{status}"
                ] += 1
                if status == "found":
                    strategy_counter[
                        str(resolution.get("match_kind") or "unavailable")
                    ] += 1
                row = _relocation_summary_row(blind, side, resolution)
                relocation_rows.append(row)
                if status == "ambiguous":
                    ambiguous_rows.append(row)
                elif status in {"not_found", "path_missing", "censored"}:
                    unresolved_rows.append(row)
            comparison_rows.extend(
                _old_new_comparison_rows(blind, audit)
            )
        summary = _case_summary(cve_id, repo_id, blind_packets, audit_packets)
        _write_case_outputs(
            case_dir,
            blind_packets,
            audit_packets,
            summary,
            relocation_traces=relocation_traces,
        )
        case_summaries.append(summary)
        case_outputs += 1

    _write_csv(out / "judge_blind_packet_summary.csv", blind_rows)
    _write_csv(out / "judge_audit_packet_summary.csv", audit_rows)
    _write_csv(out / "manual_history_event_review_queue.csv", sorted(manual_rows, key=lambda row: (row["review_priority"], row["cve_id"], row["candidate_id"])))
    _write_csv(out / "manual_history_event_review_template.csv", [_manual_template_row(row) for row in manual_rows])
    _write_csv(out / "evidence_quality_metrics.csv", evidence_rows)
    _write_csv(out / "per_candidate_anchor_relocation.csv", relocation_rows)
    _write_csv(
        out / "relocation_strategy_metrics.csv",
        [
            {"match_kind": key, "found_resolution_count": value}
            for key, value in sorted(strategy_counter.items())
        ],
    )
    _write_csv(
        out / "relocation_status_metrics.csv",
        [
            {"side": "parent", "relocation_status": key, "count": value}
            for key, value in sorted(parent_status_counter.items())
        ]
        + [
            {"side": "candidate", "relocation_status": key, "count": value}
            for key, value in sorted(candidate_status_counter.items())
        ],
    )
    _write_csv(out / "old_vs_new_context_comparison.csv", comparison_rows)
    _write_csv(out / "ambiguous_anchor_review_queue.csv", ambiguous_rows)
    _write_csv(out / "unresolved_anchor_review_queue.csv", unresolved_rows)
    provenance = {
        "schema_version": HISTORY_EVENT_JUDGE_READINESS_SCHEMA_VERSION,
        "dataset_path": str(Path(dataset_path).resolve()),
        "dataset_sha256": hashlib.sha256(Path(dataset_path).read_bytes()).hexdigest(),
        "repo_root": str(repo_root.resolve()),
        "git_graph_index": str(Path(git_graph_index).resolve()),
        "history_event_root": str(history_root.resolve()),
        "out_dir": str(out.resolve()),
        "model_invocation_count": 0,
        "judge_invocation_count": 0,
        "converter_invocation_count": 0,
        "created_at": datetime.now(UTC).isoformat(),
    }
    _write_json(out / "provenance_manifest.json", provenance)
    summary = {
        "schema_version": HISTORY_EVENT_JUDGE_READINESS_SCHEMA_VERSION,
        "cases_total": len(selected_cves),
        "cases_with_outputs": case_outputs,
        "candidates_total": total_source_candidates,
        "candidate_count": total_blind,
        "blind_packet_count": total_blind,
        "audit_packet_count": total_audit,
        "strong_candidate_count": sum(1 for row in blind_rows if row["source_lane"] == "strong"),
        "fallback_candidate_count": sum(1 for row in blind_rows if row["source_lane"] == "fallback"),
        "parent_context_found": sum(1 for row in blind_rows if row["parent_context_status"] == "found"),
        "candidate_context_found": sum(1 for row in blind_rows if row["candidate_context_status"] == "found"),
        "anchor_local_diff_found": sum(1 for row in blind_rows if row["diff_extraction_status"] == "found"),
        "function_context_available": sum(1 for row in blind_rows if row["function_context_status"] != "unavailable"),
        "parent_relocation_status_counts": dict(sorted(parent_status_counter.items())),
        "candidate_relocation_status_counts": dict(
            sorted(candidate_status_counter.items())
        ),
        "parent_resolution_count": sum(parent_status_counter.values()),
        "candidate_resolution_count": sum(candidate_status_counter.values()),
        "per_strategy_success_counts": dict(sorted(strategy_counter.items())),
        "exact_match_count": strategy_counter["exact_hash"]
        + strategy_counter["exact_text"],
        "normalized_match_count": strategy_counter["normalized_unique"],
        "diff_hunk_mapped_count": strategy_counter["diff_hunk_mapped"],
        "context_fingerprint_count": strategy_counter["context_fingerprint"],
        "ambiguous_count": parent_status_counter["ambiguous"]
        + candidate_status_counter["ambiguous"],
        "absent_by_event_count": parent_status_counter["absent_by_event"]
        + candidate_status_counter["absent_by_event"],
        "not_found_count": parent_status_counter["not_found"]
        + candidate_status_counter["not_found"],
        "path_missing_count": parent_status_counter["path_missing"]
        + candidate_status_counter["path_missing"],
        "censored_count": parent_status_counter["censored"]
        + candidate_status_counter["censored"],
        "false_same_line_accept_count": false_same_line_accept_count,
        "old_context_found_count": old_context_found_count,
        "old_context_verified_count": old_context_verified_count,
        "old_context_false_accept_count": old_context_false_accept_count,
        "old_comment_or_blank_accept_count": old_comment_or_blank_accept_count,
        "new_verified_context_count": new_verified_context_count,
        "schema_error_count": schema_error_count,
        "candidate_accounting_rate": (
            total_blind / total_source_candidates if total_source_candidates else 1.0
        ),
        "strong_fallback_relocation_counts": dict(
            sorted(lane_resolution_counter.items())
        ),
        "extraction_failure_taxonomy": dict(sorted(extraction_counter.items())),
        "conflict_taxonomy": dict(sorted(conflict_counter.items())),
        "manual_review_queue_by_priority": dict(sorted(priority_counter.items())),
        "packet_size_summary": _size_summary(packet_sizes),
        "forbidden_scan_ok": False,
        "highest_lifecycle": HISTORY_EVENT_JUDGE_READINESS_LIFECYCLE,
        "model_invocation_count": 0,
        "judge_invocation_count": 0,
        "converter_invocation_count": 0,
        "case_summaries": case_summaries,
    }
    _write_json(out / "summary.json", summary)
    report = _report(summary)
    (out / "anchor_relocation_report.md").write_text(report, encoding="utf-8")
    (out / "judge_readiness_report.md").write_text(report, encoding="utf-8")
    _write_cve_2020_8231_report(out, blind_rows, comparison_rows)
    forbidden_scan = _scan_output_directory(out)
    _write_json(out / "forbidden_field_scan.json", forbidden_scan)
    summary["forbidden_scan_ok"] = not forbidden_scan["has_forbidden_terms"]
    _write_json(out / "summary.json", summary)
    return summary


def extract_anchor_local_diff(
    git_query: GitGraphQuery,
    parent: str,
    candidate: str,
    *,
    before_path: str,
    after_path: str,
    anchor_old_line: int = 0,
    anchor_new_line: int = 0,
    max_chars: int = 6000,
    max_hunk_lines: int = 32,
) -> dict[str, Any]:
    if not parent:
        return _empty_diff_status("censored", "missing_parent")
    if not candidate:
        return _empty_diff_status("censored", "missing_candidate")
    paths = list(dict.fromkeys(path for path in (before_path, after_path) if path))
    if not paths:
        return _empty_diff_status("censored", "missing_path")
    result = git_query.diff_between_revisions(
        parent,
        candidate,
        paths=paths,
        unified=40,
    )
    if result.status is not QueryStatus.FOUND:
        return _empty_diff_status(
            "not_found" if result.status is QueryStatus.NOT_FOUND else "censored",
            result.reason or result.status.value,
        )
    diff = _select_relevant_diff_hunk(
        str(result.value or ""),
        anchor_old_line,
        anchor_new_line=anchor_new_line,
        before_path=before_path,
        after_path=after_path,
    )
    if not diff.strip():
        return _empty_diff_status("empty", "no_path_diff")
    excerpt = _truncate(diff, max_chars)
    before_lines, after_lines, roles = _parse_diff_lines(excerpt)
    before_lines = _cap_hunk_lines(before_lines, anchor_old_line, max_hunk_lines)
    after_lines = _cap_hunk_lines(
        after_lines,
        anchor_new_line or anchor_old_line,
        max_hunk_lines,
    )
    return {
        "anchor_path_diff_excerpt": excerpt,
        "anchor_hunk_before_lines": before_lines,
        "anchor_hunk_after_lines": after_lines,
        "changed_line_roles": roles,
        "diff_extraction_status": "found",
        "reason": "",
    }


def extract_function_context_if_available(
    *,
    git_query: GitGraphQuery,
    parent_resolution: dict[str, Any],
    candidate_resolution: dict[str, Any],
    function_name: Any,
    function_id: Any,
) -> dict[str, Any]:
    if not function_name and not function_id:
        return {
            "function_context_status": "unavailable",
            "reason": "function_identity_unavailable",
            "parent_function_context": {},
            "candidate_function_context": {},
        }
    parent = materialize_relocated_context(
        git_query,
        parent_resolution,
        context_kind="parent_function_context",
        radius=20,
    )
    candidate = materialize_relocated_context(
        git_query,
        candidate_resolution,
        context_kind="candidate_function_context",
        radius=20,
    )
    status = "found" if parent.get("extraction_status") == "found" or candidate.get("extraction_status") == "found" else "unavailable"
    return {
        "function_context_status": status,
        "function": function_name,
        "function_id": function_id,
        "context_method": "verified_relocated_anchor_window",
        "parent_function_context": parent,
        "candidate_function_context": candidate,
    }


def _history_reconstruction_summary(packet: dict[str, Any]) -> dict[str, Any]:
    event = packet.get("candidate_event") or {}
    log_history = packet.get("log_history") or {}
    path_history = packet.get("path_history") or {}
    return {
        "blame_variants": [
            {
                "variant": item.get("variant"),
                "status": item.get("status"),
                "blamed_commit_sha": item.get("blamed_commit_sha"),
                "blamed_original_path": item.get("blamed_original_path"),
                "blamed_original_line": item.get("blamed_original_line"),
                "boundary_marker": item.get("boundary_marker"),
            }
            for item in ((packet.get("blame_variants") or {}).get("variants") or [])
        ],
        "canonical_blame_commit": (packet.get("blame_variants") or {}).get("canonical_blame_commit_sha") or "",
        "variant_agreement": (packet.get("blame_variants") or {}).get("variant_agreement") or "",
        "log_L_top_commits": (log_history.get("log_L") or {}).get("top_commits") or [],
        "log_S_top_commits": (log_history.get("log_S") or {}).get("top_commits") or [],
        "log_G_top_commits": (log_history.get("log_G") or {}).get("top_commits") or [],
        "log_follow_top_commits": (path_history.get("log_follow") or {}).get("top_commits") or [],
        "recursive_blame_summary": log_history.get("recursive_blame") or {},
        "per_parent_merge_diff_summary": [
            {
                "parent_sha": item.get("parent_sha"),
                "status": item.get("status"),
                "excerpt_sha256": _sha256_text(str(item.get("diff_excerpt") or "")),
            }
            for item in event.get("per_parent_diffs") or []
        ],
        "stable_patch_id": event.get("stable_patch_id") or "",
        "changed_paths_summary": {
            "count": len(event.get("changed_paths") or []),
            "paths": list(event.get("changed_paths") or [])[:20],
        },
    }


def _conflict_flags(packet: dict[str, Any], parent_context: dict[str, Any], candidate_context: dict[str, Any], local_diff: dict[str, Any]) -> dict[str, bool]:
    flags = {key: bool(value) for key, value in ((packet.get("conflicts") or {}).items())}
    event = packet.get("candidate_event") or {}
    flags["merge_candidate"] = bool(event.get("is_merge"))
    flags["root_candidate"] = bool(event.get("is_root"))
    flags["boundary_candidate"] = bool(event.get("boundary_marker"))
    flags["parent_context_not_found"] = parent_context.get("extraction_status") != "found"
    flags["candidate_context_not_found"] = candidate_context.get("extraction_status") != "found"
    flags["anchor_diff_not_found"] = local_diff.get("diff_extraction_status") != "found"
    return flags


def _review_priority(packet: dict[str, Any], flags: dict[str, bool], parent_context: dict[str, Any], candidate_context: dict[str, Any], local_diff: dict[str, Any]) -> str:
    if packet.get("source_lane") == "fallback":
        return "P0"
    if any(flags.get(flag) for flag in _P0_FLAGS):
        return "P0"
    if flags.get("merge_candidate") or flags.get("root_candidate") or flags.get("boundary_candidate"):
        return "P0"
    if parent_context.get("extraction_status") != "found" or candidate_context.get("extraction_status") != "found" or local_diff.get("diff_extraction_status") != "found":
        return "P0"
    if any(flags.get(flag) for flag in _P1_FLAGS):
        return "P1"
    risk_flags = {str(flag) for flag in ((packet.get("candidate_origin") or {}).get("risk_flags") or [])}
    if risk_flags & {"add_only_semantic_anchor", "add-only", "multi_fix", "multi-fix"}:
        return "P1"
    return "P2"


def _uncertainty_reasons(packet: dict[str, Any], parent_context: dict[str, Any], candidate_context: dict[str, Any], local_diff: dict[str, Any]) -> list[str]:
    reasons = set((packet.get("uncertainty") or {}).get("reasons") or [])
    for name, context in (("parent", parent_context), ("candidate", candidate_context)):
        if context.get("extraction_status") != "found":
            reasons.add(f"{name}_context_{context.get('extraction_status')}")
    if local_diff.get("diff_extraction_status") != "found":
        reasons.add(f"anchor_diff_{local_diff.get('diff_extraction_status')}")
    return sorted(reasons)


def _likely_noise_reason(packet: dict[str, Any], flags: dict[str, bool], parent_context: dict[str, Any], candidate_context: dict[str, Any], local_diff: dict[str, Any]) -> str:
    if packet.get("source_lane") == "fallback":
        return "fallback_candidate_requires_manual_review"
    if flags.get("blame_variant_disagreement"):
        return "blame_variant_disagreement"
    if parent_context.get("extraction_status") != "found" or candidate_context.get("extraction_status") != "found":
        return "anchor_context_unavailable"
    if local_diff.get("diff_extraction_status") != "found":
        return "anchor_diff_unavailable"
    return ""


def _empty_diff_status(status: str, reason: str) -> dict[str, Any]:
    return {
        "anchor_path_diff_excerpt": "",
        "anchor_hunk_before_lines": [],
        "anchor_hunk_after_lines": [],
        "changed_line_roles": {"context": 0, "added": 0, "deleted": 0},
        "diff_extraction_status": status,
        "reason": reason,
    }


def _parse_diff_lines(diff_text: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    before: list[dict[str, Any]] = []
    after: list[dict[str, Any]] = []
    roles = {"context": 0, "added": 0, "deleted": 0}
    old_line = 0
    new_line = 0
    for raw in diff_text.splitlines():
        if raw.startswith("@@"):
            old_line, new_line = _parse_hunk_header(raw)
            continue
        if raw.startswith("diff --git") or raw.startswith("index ") or raw.startswith("---") or raw.startswith("+++"):
            continue
        if raw.startswith("-"):
            text = raw[1:]
            before.append({"line_no": old_line if old_line else None, "role": "deleted", "text": text, "sha256": _sha256_text(text)})
            old_line += 1
            roles["deleted"] += 1
        elif raw.startswith("+"):
            text = raw[1:]
            after.append({"line_no": new_line if new_line else None, "role": "added", "text": text, "sha256": _sha256_text(text)})
            new_line += 1
            roles["added"] += 1
        elif raw.startswith(" "):
            text = raw[1:]
            before.append({"line_no": old_line if old_line else None, "role": "context", "text": text, "sha256": _sha256_text(text)})
            after.append({"line_no": new_line if new_line else None, "role": "context", "text": text, "sha256": _sha256_text(text)})
            old_line += 1
            new_line += 1
            roles["context"] += 1
    return before, after, roles


def _parse_hunk_header(header: str) -> tuple[int, int]:
    try:
        old_part, new_part = header.split()[1:3]
        return int(old_part.split(",")[0].lstrip("-")), int(new_part.split(",")[0].lstrip("+"))
    except Exception:
        return 0, 0


def _select_relevant_diff_hunk(
    diff_text: str,
    anchor_old_line: int,
    *,
    anchor_new_line: int = 0,
    before_path: str = "",
    after_path: str = "",
) -> str:
    sections = _split_file_diff_sections(diff_text)
    if sections:
        matching = [
            section
            for section in sections
            if _file_diff_matches_paths(section, before_path, after_path)
        ]
        diff_text = "\n".join(matching[0] if matching else sections[0]) + "\n"
    if not anchor_old_line and not anchor_new_line:
        return diff_text
    lines = diff_text.splitlines()
    file_header: list[str] = []
    hunks: list[list[str]] = []
    current: list[str] | None = None
    for line in lines:
        if line.startswith("diff --git") or line.startswith("index ") or line.startswith("--- ") or line.startswith("+++ "):
            if current is None:
                file_header.append(line)
            else:
                current.append(line)
            continue
        if line.startswith("@@"):
            if current:
                hunks.append(current)
            current = [line]
        elif current is not None:
            current.append(line)
        else:
            file_header.append(line)
    if current:
        hunks.append(current)
    if not hunks:
        return diff_text
    selected = hunks[0]
    for hunk in hunks:
        old_start, old_count = _parse_old_hunk_range(hunk[0])
        old_end = old_start + max(old_count - 1, 0)
        new_start, new_count = _parse_new_hunk_range(hunk[0])
        new_end = new_start + max(new_count - 1, 0)
        old_match = bool(anchor_old_line) and old_start <= anchor_old_line <= old_end
        new_match = bool(anchor_new_line) and new_start <= anchor_new_line <= new_end
        if old_match or new_match:
            selected = hunk
            break
    return "\n".join([*file_header[:4], *selected]) + "\n"


def _parse_old_hunk_range(header: str) -> tuple[int, int]:
    try:
        old_part = header.split()[1].lstrip("-")
        if "," in old_part:
            start, count = old_part.split(",", 1)
            return int(start), int(count)
        return int(old_part), 1
    except Exception:
        return 0, 0


def _parse_new_hunk_range(header: str) -> tuple[int, int]:
    try:
        new_part = header.split()[2].lstrip("+")
        if "," in new_part:
            start, count = new_part.split(",", 1)
            return int(start), int(count)
        return int(new_part), 1
    except Exception:
        return 0, 0


def _split_file_diff_sections(diff_text: str) -> list[list[str]]:
    sections: list[list[str]] = []
    current: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("diff --git ") and current:
            sections.append(current)
            current = [line]
        else:
            current.append(line)
    if current and any(line.startswith("diff --git ") for line in current):
        sections.append(current)
    return sections


def _file_diff_matches_paths(
    section: list[str],
    before_path: str,
    after_path: str,
) -> bool:
    old_path = ""
    new_path = ""
    for line in section:
        if line.startswith("--- "):
            value = line[4:]
            old_path = "" if value == "/dev/null" else value.removeprefix("a/")
        elif line.startswith("+++ "):
            value = line[4:]
            new_path = "" if value == "/dev/null" else value.removeprefix("b/")
    before_ok = not before_path or old_path == before_path
    after_ok = not after_path or new_path == after_path
    return before_ok and after_ok


def _cap_hunk_lines(lines: list[dict[str, Any]], anchor_line: int, max_lines: int) -> list[dict[str, Any]]:
    if len(lines) <= max_lines:
        return lines
    if not anchor_line:
        return lines[:max_lines]
    scored = [
        (abs((item.get("line_no") or anchor_line) - anchor_line), index, item)
        for index, item in enumerate(lines)
    ]
    keep_indexes = {index for _distance, index, _item in sorted(scored)[:max_lines]}
    return [item for index, item in enumerate(lines) if index in keep_indexes]


def _packet_extraction_statuses(blind: dict[str, Any]) -> list[str]:
    statuses = [
        f"parent:{blind['parent_anchor_context'].get('extraction_status')}",
        f"candidate:{blind['candidate_anchor_context'].get('extraction_status')}",
        f"diff:{blind.get('diff_extraction_status')}",
    ]
    function_status = (blind.get("function_context") or {}).get("function_context_status")
    if function_status:
        statuses.append(f"function:{function_status}")
    return statuses


def _blind_summary_row(blind: dict[str, Any], packet_size: int) -> dict[str, Any]:
    bindings = blind.get("root_cause_bindings") or {}
    identity = blind.get("candidate_event_identity") or {}
    return {
        "cve_id": blind.get("cve_id"),
        "repo_id": blind.get("repo_id"),
        "candidate_id": blind.get("candidate_id"),
        "source_lane": blind.get("source_lane"),
        "candidate_commit_sha": identity.get("candidate_commit_sha"),
        "selected_parent_sha": identity.get("selected_parent_sha"),
        "anchor_path": bindings.get("anchor_path"),
        "anchor_old_line_start": bindings.get("anchor_old_line_start"),
        "parent_context_status": (blind.get("parent_anchor_context") or {}).get("extraction_status"),
        "candidate_context_status": (blind.get("candidate_anchor_context") or {}).get("extraction_status"),
        "diff_extraction_status": blind.get("diff_extraction_status"),
        "function_context_status": (blind.get("function_context") or {}).get("function_context_status"),
        "review_priority": blind.get("recommended_review_priority"),
        "packet_size_bytes": packet_size,
    }


def _audit_summary_row(audit: dict[str, Any]) -> dict[str, Any]:
    blind = audit.get("blind_packet") or {}
    diagnostics = audit.get("packet_construction_diagnostics") or {}
    return {
        "cve_id": blind.get("cve_id"),
        "repo_id": blind.get("repo_id"),
        "candidate_id": blind.get("candidate_id"),
        "audit_packet_size_bytes": diagnostics.get("audit_packet_size_bytes"),
        "has_source_history_event_packet": "source_history_event_packet" in audit,
    }


def _evidence_quality_row(blind: dict[str, Any], packet_size: int) -> dict[str, Any]:
    return {
        "cve_id": blind.get("cve_id"),
        "candidate_id": blind.get("candidate_id"),
        "source_lane": blind.get("source_lane"),
        "parent_context_found": (blind.get("parent_anchor_context") or {}).get("extraction_status") == "found",
        "candidate_context_found": (blind.get("candidate_anchor_context") or {}).get("extraction_status") == "found",
        "anchor_diff_found": blind.get("diff_extraction_status") == "found",
        "function_context_status": (blind.get("function_context") or {}).get("function_context_status"),
        "conflict_count": (blind.get("judge_hints") or {}).get("conflict_count"),
        "packet_size_bytes": packet_size,
    }


def _manual_review_row(blind: dict[str, Any]) -> dict[str, Any]:
    summary = blind.get("history_reconstruction_summary") or {}
    bindings = blind.get("root_cause_bindings") or {}
    identity = blind.get("candidate_event_identity") or {}
    variants = {item.get("variant"): item.get("blamed_commit_sha") for item in summary.get("blame_variants") or []}
    active_flags = [flag for flag, value in (blind.get("conflict_flags") or {}).items() if value]
    return {
        "cve_id": blind.get("cve_id"),
        "repo_id": blind.get("repo_id"),
        "candidate_id": blind.get("candidate_id"),
        "source_lane": blind.get("source_lane"),
        "anchor_path": bindings.get("anchor_path"),
        "anchor_old_line": bindings.get("anchor_old_line_start"),
        "anchor_old_line_text": bindings.get("anchor_old_line_text"),
        "candidate_commit_sha": identity.get("candidate_commit_sha"),
        "selected_parent_sha": identity.get("selected_parent_sha"),
        "canonical_blame_commit": summary.get("canonical_blame_commit"),
        "blame_w_commit": variants.get("w") or "",
        "blame_M_commit": variants.get("M") or "",
        "blame_C_commit": variants.get("C") or "",
        "log_L_top_commits": " ".join(summary.get("log_L_top_commits") or []),
        "changed_paths_summary": json.dumps(summary.get("changed_paths_summary") or {}, sort_keys=True),
        "conflict_flags": ",".join(active_flags),
        "extraction_status": ";".join(_packet_extraction_statuses(blind)),
        "review_priority": blind.get("recommended_review_priority"),
    }


def _manual_template_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        **row,
        "reviewer_label": "",
        "reviewer_confidence": "",
        "reviewer_notes": "",
    }


def _relocation_summary_row(
    blind: dict[str, Any],
    side: str,
    resolution: dict[str, Any],
) -> dict[str, Any]:
    return {
        "cve_id": blind.get("cve_id"),
        "repo_id": blind.get("repo_id"),
        "candidate_id": blind.get("candidate_id"),
        "source_lane": blind.get("source_lane"),
        "side": side,
        "revision_sha": resolution.get("revision_sha"),
        "original_line_hint": resolution.get("original_line_hint"),
        "selected_path": resolution.get("selected_path"),
        "relocated_line_start": resolution.get("relocated_line_start"),
        "relocation_status": resolution.get("relocation_status"),
        "match_kind": resolution.get("match_kind"),
        "relation_to_anchor": resolution.get("relation_to_anchor"),
        "evidence_ref_count": len(resolution.get("evidence_refs") or []),
        "candidate_match_count": len(resolution.get("candidate_matches") or []),
        "ambiguity_reason": resolution.get("ambiguity_reason"),
        "failure_reason": resolution.get("failure_reason"),
    }


def _old_new_comparison_rows(
    blind: dict[str, Any],
    audit: dict[str, Any],
) -> list[dict[str, Any]]:
    relocation = audit.get("anchor_relocation_trace") or {}
    resolutions = [
        *[("parent", item) for item in relocation.get("parent_resolutions") or []],
        ("candidate", relocation.get("candidate_resolution") or {}),
    ]
    legacy = audit.get("legacy_line_hint_diagnostics") or []
    rows: list[dict[str, Any]] = []
    for index, (side, resolution) in enumerate(resolutions):
        old = legacy[index] if index < len(legacy) else {}
        rows.append(
            {
                "cve_id": blind.get("cve_id"),
                "candidate_id": blind.get("candidate_id"),
                "source_lane": blind.get("source_lane"),
                "side": side,
                "revision_sha": resolution.get("revision_sha"),
                "old_line_hint": old.get("old_line_hint"),
                "old_status": old.get("status"),
                "old_actual_text": old.get("actual_text"),
                "old_exact_text_match": old.get("exact_text_match"),
                "old_normalized_text_match": old.get("normalized_text_match"),
                "old_comment_or_blank": old.get("comment_or_blank"),
                "new_relocation_status": resolution.get("relocation_status"),
                "new_selected_path": resolution.get("selected_path"),
                "new_relocated_line": resolution.get("relocated_line_start"),
                "new_match_kind": resolution.get("match_kind"),
                "new_relation_to_anchor": resolution.get("relation_to_anchor"),
                "new_matched_text": resolution.get("matched_text"),
                "new_evidence_ref_count": len(resolution.get("evidence_refs") or []),
            }
        )
    return rows


def _case_summary(cve_id: str, repo_id: str, blind_packets: list[dict[str, Any]], audit_packets: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "cve_id": cve_id,
        "repo_id": repo_id,
        "status": "ok",
        "blind_packet_count": len(blind_packets),
        "audit_packet_count": len(audit_packets),
        "strong_candidate_count": sum(1 for item in blind_packets if item.get("source_lane") == "strong"),
        "fallback_candidate_count": sum(1 for item in blind_packets if item.get("source_lane") == "fallback"),
        "parent_context_found": sum(1 for item in blind_packets if item.get("parent_anchor_context", {}).get("extraction_status") == "found"),
        "candidate_context_found": sum(1 for item in blind_packets if item.get("candidate_anchor_context", {}).get("extraction_status") == "found"),
        "anchor_local_diff_found": sum(1 for item in blind_packets if item.get("diff_extraction_status") == "found"),
        "false_same_line_accept_count": sum(
            _int(
                (item.get("packet_construction_diagnostics") or {}).get(
                    "false_same_line_accept_count"
                )
            )
            for item in audit_packets
        ),
    }


def _write_case_outputs(
    case_dir: Path,
    blind_packets: list[dict[str, Any]],
    audit_packets: list[dict[str, Any]],
    case_summary: dict[str, Any],
    *,
    relocation_traces: list[dict[str, Any]] | None = None,
) -> None:
    _write_json(case_dir / "judge_blind_history_event_packets.json", blind_packets)
    _write_json(case_dir / "judge_audit_history_event_packets.json", audit_packets)
    _write_json(
        case_dir / "anchor_relocation_trace.json",
        relocation_traces or [],
    )
    _write_json(case_dir / "judge_readiness_case_summary.json", case_summary)
    lines = [f"# {case_summary['cve_id']} Judge-Readiness Conflict Report", ""]
    for packet in blind_packets:
        active = [key for key, value in (packet.get("conflict_flags") or {}).items() if value]
        lines.append(f"- `{packet.get('candidate_id')}`: {', '.join(active) if active else 'none'}")
    (case_dir / "judge_readiness_conflict_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_cve_2020_8231_report(
    output: Path,
    blind_rows: list[dict[str, Any]],
    comparison_rows: list[dict[str, Any]],
) -> None:
    rows = [
        row for row in comparison_rows if row.get("cve_id") == "CVE-2020-8231"
    ]
    lines = [
        "# CVE-2020-8231 Anchor Relocation Regression",
        "",
        "The old absolute line is treated only as a hint. A found context now requires relocated text/hash or diff evidence.",
        "",
    ]
    for row in rows:
        lines.append(
            "- `{candidate}` {side}: old `{old}` -> new `{status}` "
            "`{path}:{line}` `{kind}` `{text}`".format(
                candidate=row.get("candidate_id"),
                side=row.get("side"),
                old=row.get("old_actual_text") or "<unavailable>",
                status=row.get("new_relocation_status"),
                path=row.get("new_selected_path") or "<none>",
                line=row.get("new_relocated_line") or "-",
                kind=row.get("new_match_kind"),
                text=row.get("new_matched_text") or "<unavailable>",
            )
        )
    lines.extend(
        [
            "",
            f"- Candidate summaries: {sum(1 for row in blind_rows if row.get('cve_id') == 'CVE-2020-8231')}",
        ]
    )
    (output / "cve_2020_8231_regression_report.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def _scan_output_directory(output: Path) -> dict[str, Any]:
    violations: list[dict[str, Any]] = []
    for path in output.rglob("*"):
        if path.is_dir():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = None
        if parsed is not None:
            for field in scan_forbidden_output_fields(parsed):
                violations.append({"path": str(path.relative_to(output)), "kind": "json_key", "field_hash": _sha256_text(field)})
        else:
            for forbidden in _FORBIDDEN_TEXT_KEYS:
                if forbidden in text:
                    violations.append({"path": str(path.relative_to(output)), "kind": "text", "field_hash": _sha256_text(forbidden)})
    return {"has_forbidden_terms": bool(violations), "violation_count": len(violations), "violations": violations}


def _report(summary: dict[str, Any]) -> str:
    lines = [
        "# History Event Anchor Relocation Hardening v1",
        "",
        "This deterministic artifact relocates immutable anchor references independently in each candidate parent and candidate revision before materializing Judge-ready context.",
        "",
        f"- Cases total: {summary['cases_total']}",
        f"- Candidates accounted: {summary['candidate_count']} / {summary['candidates_total']}",
        f"- Blind packets: {summary['blind_packet_count']}",
        f"- Audit packets: {summary['audit_packet_count']}",
        f"- Strong/Fallback: {summary['strong_candidate_count']} / {summary['fallback_candidate_count']}",
        f"- Old context found (unverified coordinate behavior): {summary['old_context_found_count']}",
        f"- Old context text/hash verified: {summary['old_context_verified_count']}",
        f"- Old false same-line accepts: {summary['old_context_false_accept_count']}",
        f"- New verified contexts: {summary['new_verified_context_count']}",
        f"- Parent/Candidate resolutions: {summary['parent_resolution_count']} / {summary['candidate_resolution_count']}",
        f"- Parent relocation statuses: {json.dumps(summary['parent_relocation_status_counts'], sort_keys=True)}",
        f"- Candidate relocation statuses: {json.dumps(summary['candidate_relocation_status_counts'], sort_keys=True)}",
        f"- Relocation strategies: {json.dumps(summary['per_strategy_success_counts'], sort_keys=True)}",
        f"- False same-line accepts: {summary['false_same_line_accept_count']}",
        f"- Candidate accounting rate: {summary['candidate_accounting_rate']:.6f}",
        f"- Anchor-local diff found: {summary['anchor_local_diff_found']}",
        f"- Function context available: {summary['function_context_available']}",
        "",
        "No model call, Judge invocation, or downstream conversion is performed. Lifecycles remain `judge_ready_history_event_candidate`.",
        "A found relocation proves only a text/hash/diff relationship at a bounded provenance path; it does not prove that the event is a true vulnerability introduction.",
    ]
    return "\n".join(lines) + "\n"


def _size_summary(values: list[int]) -> dict[str, Any]:
    if not values:
        return {"min": 0, "median": 0, "max": 0, "total": 0}
    sorted_values = sorted(values)
    return {
        "min": sorted_values[0],
        "median": sorted_values[len(sorted_values) // 2],
        "max": sorted_values[-1],
        "total": sum(sorted_values),
    }


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _int(value: Any, *, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _truncate(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    return value[:max_chars] + "\n...[truncated]..."


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build Judge-ready HistoryEventPacketV1 blind/audit packets.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--git-graph-index", required=True)
    parser.add_argument("--history-event-root", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--cves", nargs="*")
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args(argv)
    summary = run_history_event_judge_readiness(
        dataset_path=args.dataset,
        repo_root=args.repo_root,
        git_graph_index=args.git_graph_index,
        history_event_root=args.history_event_root,
        out_dir=args.out_dir,
        reset=args.reset,
        cve_ids=args.cves,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0
