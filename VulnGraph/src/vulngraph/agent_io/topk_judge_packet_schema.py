from __future__ import annotations

from typing import Any


TOPK_JUDGE_PACKET_SCHEMA_VERSION = "topk_history_event_judge_packet_v1"
TOPK_JUDGE_PACKET_LIFECYCLE = "raw_history_event_candidate"

JUDGE_EVENT_ROLE_OPTIONS = [
    "vulnerability_introduction",
    "prerequisite",
    "refactor",
    "fix_series",
    "unrelated",
    "history_root_boundary",
    "feature_series_boundary",
    "ordinary_boundary",
    "uncertain",
]

BLIND_PACKET_FORBIDDEN_KEYS = {
    "ground_truth",
    "manual_event_label",
    "is_recommended_intro",
    "recommended_introduction_commits",
    "missing_history_event",
    "affected_version",
    "affected_versions",
    "validated_bic",
    "correct_bic",
    "bic",
    "BIC",
    "oracle",
    "exact_match",
    "TP",
    "FP",
    "FN",
}


def scan_blind_packet_forbidden_keys(value: Any) -> dict[str, Any]:
    violations: list[dict[str, str]] = []

    def walk(item: Any, path: str) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if str(key) in BLIND_PACKET_FORBIDDEN_KEYS:
                    violations.append({"path": path or ".", "key": str(key)})
                walk(child, f"{path}.{key}" if path else str(key))
        elif isinstance(item, list):
            for index, child in enumerate(item):
                walk(child, f"{path}[{index}]")

    walk(value, "")
    return {
        "has_forbidden_keys": bool(violations),
        "violation_count": len(violations),
        "violations": violations,
    }


def validate_blind_packet(packet: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "packet_type",
        "cve_id",
        "repo_id",
        "top_k",
        "lifecycle",
        "judge_task",
        "candidates",
    }
    for field in sorted(required - set(packet)):
        errors.append(f"missing_field:{field}")
    if packet.get("schema_version") != TOPK_JUDGE_PACKET_SCHEMA_VERSION:
        errors.append("invalid_schema_version")
    if packet.get("packet_type") != "blind_history_event_judge_packet":
        errors.append("invalid_packet_type")
    if packet.get("lifecycle") != TOPK_JUDGE_PACKET_LIFECYCLE:
        errors.append("invalid_lifecycle")
    if not isinstance(packet.get("top_k"), int) or int(packet.get("top_k") or 0) < 1:
        errors.append("invalid_top_k")
    candidates = packet.get("candidates")
    if not isinstance(candidates, list):
        errors.append("invalid_candidates")
    else:
        seen: set[str] = set()
        for index, candidate in enumerate(candidates):
            candidate_id = str(candidate.get("candidate_id") or "")
            if not candidate_id:
                errors.append(f"candidate:{index}:missing_candidate_id")
            if candidate_id in seen:
                errors.append(f"candidate:{index}:duplicate_candidate_id")
            seen.add(candidate_id)
            if candidate.get("lifecycle") != TOPK_JUDGE_PACKET_LIFECYCLE:
                errors.append(f"candidate:{index}:invalid_lifecycle")
            if not candidate.get("event_commit_sha"):
                errors.append(f"candidate:{index}:missing_event_commit_sha")
            if not candidate.get("evidence_refs"):
                errors.append(f"candidate:{index}:missing_evidence_refs")
    scan = scan_blind_packet_forbidden_keys(packet)
    for item in scan["violations"]:
        errors.append(f"forbidden_key:{item['key']}:{item['path']}")
    return errors
