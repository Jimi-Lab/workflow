from __future__ import annotations

from typing import Any


HISTORY_EVENT_SCHEMA_VERSION = "history_event_packet_v1"
HISTORY_EVENT_LIFECYCLE = "raw_history_event_candidate"

FORBIDDEN_OUTPUT_FIELDS = {
    "affected_version",
    "validated_bic",
    "correct_bic",
    "ground_truth",
    "BIC",
    "bic",
}

REQUIRED_TOP_LEVEL_FIELDS = {
    "schema_version",
    "cve_id",
    "repo_id",
    "candidate_id",
    "source_lane",
    "lifecycle",
    "candidate_origin",
    "git_graph_snapshot",
    "blame_variants",
    "log_history",
    "path_history",
    "candidate_event",
    "conflicts",
    "deterministic_ranking_features",
    "uncertainty",
}


def scan_forbidden_output_fields(value: Any) -> list[str]:
    found: set[str] = set()

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if str(key) in FORBIDDEN_OUTPUT_FIELDS:
                    found.add(str(key))
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)
    return sorted(found)


def validate_history_event_packet_v1(packet: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = sorted(REQUIRED_TOP_LEVEL_FIELDS - set(packet))
    errors.extend(f"missing_field:{field}" for field in missing)
    if packet.get("schema_version") != HISTORY_EVENT_SCHEMA_VERSION:
        errors.append("invalid_schema_version")
    if packet.get("lifecycle") != HISTORY_EVENT_LIFECYCLE:
        errors.append("invalid_lifecycle")
    if packet.get("source_lane") not in {"strong", "fallback"}:
        errors.append("invalid_source_lane")
    snapshot = packet.get("git_graph_snapshot")
    if isinstance(snapshot, dict):
        if not snapshot.get("repo_snapshot_id"):
            errors.append("missing_repo_snapshot_id")
        if "query_provenance_ids" not in snapshot:
            errors.append("missing_query_provenance_ids")
    elif "git_graph_snapshot" in packet:
        errors.append("invalid_git_graph_snapshot")
    variants = packet.get("blame_variants")
    if isinstance(variants, dict):
        if not isinstance(variants.get("variants", []), list):
            errors.append("invalid_blame_variants")
    elif "blame_variants" in packet:
        errors.append("invalid_blame_variants")
    for field in scan_forbidden_output_fields(packet):
        errors.append(f"forbidden_field:{field}")
    return errors
