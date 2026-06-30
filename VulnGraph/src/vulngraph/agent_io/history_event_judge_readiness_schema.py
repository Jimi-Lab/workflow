from __future__ import annotations

from typing import Any

from vulngraph.agent_io.history_event_schema import scan_forbidden_output_fields


HISTORY_EVENT_JUDGE_READINESS_SCHEMA_VERSION = (
    "history_event_judge_readiness_v1_1_anchor_relocation"
)
HISTORY_EVENT_JUDGE_READINESS_LIFECYCLE = "judge_ready_history_event_candidate"
RELOCATION_STATUSES = {
    "found",
    "absent_by_event",
    "ambiguous",
    "not_found",
    "path_missing",
    "censored",
}

REQUIRED_BLIND_FIELDS = {
    "schema_version",
    "cve_id",
    "repo_id",
    "candidate_id",
    "source_lane",
    "lifecycle",
    "git_graph_snapshot_id",
    "root_cause_bindings",
    "candidate_event_identity",
    "anchor_relocation",
    "parent_anchor_context",
    "parent_anchor_contexts",
    "candidate_anchor_context",
    "anchor_path_diff_excerpt",
    "history_reconstruction_summary",
    "conflict_flags",
    "recommended_review_priority",
}


def validate_judge_ready_history_event_blind_packet(packet: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = sorted(REQUIRED_BLIND_FIELDS - set(packet))
    errors.extend(f"missing_field:{field}" for field in missing)
    if packet.get("schema_version") != HISTORY_EVENT_JUDGE_READINESS_SCHEMA_VERSION:
        errors.append("invalid_schema_version")
    if packet.get("lifecycle") != HISTORY_EVENT_JUDGE_READINESS_LIFECYCLE:
        errors.append("invalid_lifecycle")
    if packet.get("source_lane") not in {"strong", "fallback"}:
        errors.append("invalid_source_lane")
    relocation = packet.get("anchor_relocation") or {}
    parent_resolutions = relocation.get("parent_resolutions") or []
    candidate_resolution = relocation.get("candidate_resolution") or {}
    expected_parents = (
        packet.get("candidate_event_identity") or {}
    ).get("candidate_parent_shas") or []
    if len(parent_resolutions) != len(expected_parents):
        errors.append("parent_resolution_accounting_mismatch")
    for label, resolution in [
        *[
            (f"parent_resolution:{index}", value)
            for index, value in enumerate(parent_resolutions)
        ],
        ("candidate_resolution", candidate_resolution),
    ]:
        status = resolution.get("relocation_status")
        if status not in RELOCATION_STATUSES:
            errors.append(f"{label}:invalid_relocation_status")
        if status == "found":
            if not resolution.get("selected_path"):
                errors.append(f"{label}:found_missing_path")
            if not resolution.get("relocated_line_start"):
                errors.append(f"{label}:found_missing_line")
            if not resolution.get("matched_text_hash"):
                errors.append(f"{label}:found_missing_text_hash")
            if not resolution.get("evidence_refs"):
                errors.append(f"{label}:found_missing_evidence_refs")
        if status == "ambiguous" and resolution.get("selected_path"):
            errors.append(f"{label}:ambiguous_selected_path")
    for label, context in [
        *[
            (f"parent_context:{index}", value)
            for index, value in enumerate(packet.get("parent_anchor_contexts") or [])
        ],
        ("candidate_context", packet.get("candidate_anchor_context") or {}),
    ]:
        if context.get("extraction_status") != "found":
            continue
        anchor_lines = [
            line for line in context.get("lines") or [] if line.get("is_anchor_line")
        ]
        if not context.get("anchor_verified"):
            errors.append(f"{label}:found_context_not_verified")
        if len(anchor_lines) != 1:
            errors.append(f"{label}:found_context_anchor_line_count")
    if scan_forbidden_output_fields(packet):
        for field in scan_forbidden_output_fields(packet):
            errors.append(f"forbidden_field:{field}")
    return errors
