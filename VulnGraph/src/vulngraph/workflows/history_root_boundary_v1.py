from __future__ import annotations

import copy
import re
from typing import Any

from vulngraph.git_graph.schema import QueryStatus


HISTORY_ROOT_BOUNDARY_ROLE = "history_root_boundary"
FEATURE_SERIES_BOUNDARY_ROLE = "feature_series_boundary"
ORDINARY_BOUNDARY_ROLE = "ordinary_boundary"
RELATED_STATE_EXPANSION_ROLE = "related_state_expansion"
PREREQUISITE_OR_RELATED_ROLE = "prerequisite"
UNCERTAIN_ROLE = "uncertain"
LIFECYCLE = "raw_history_event_candidate"
_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b")
_NOISE_IDENTIFIERS = {
    "char",
    "const",
    "diff",
    "git",
    "index",
    "int",
    "return",
    "sizeof",
    "static",
    "void",
}


def is_invalid_primary_boundary_anchor(text: Any) -> bool:
    stripped = str(text or "").strip()
    if not stripped:
        return True
    if stripped in {"}", "};", "{", "{;", "break;", "continue;", "else"}:
        return True
    if stripped.startswith("//"):
        return True
    if stripped.startswith("/*") and stripped.endswith("*/"):
        return True
    if stripped.startswith("*") and stripped.endswith("*/"):
        return True
    return False


def _source_history_packets(
    event: dict[str, Any],
    history_packets_by_candidate_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        history_packets_by_candidate_id[source_id]
        for source_id in event.get("source_candidate_ids") or []
        if source_id in history_packets_by_candidate_id
    ]


def _packet_event_sha(packet: dict[str, Any]) -> str:
    candidate_event = packet.get("candidate_event") or {}
    return str(candidate_event.get("candidate_commit_sha") or "")


def _packet_is_root(packet: dict[str, Any]) -> bool:
    candidate_event = packet.get("candidate_event") or {}
    parents = candidate_event.get("parent_shas")
    return bool(candidate_event.get("is_root") or candidate_event.get("boundary_marker") or parents == [])


def _event_has_root_signal(event: dict[str, Any]) -> bool:
    roles = set(event.get("role_proposals") or [])
    features = event.get("evidence_features") or {}
    return bool(
        HISTORY_ROOT_BOUNDARY_ROLE in roles
        or "root_boundary" in roles
        or features.get("root_or_boundary_source")
    )


def _candidate_anchor_ref(packet: dict[str, Any]) -> dict[str, Any]:
    origin = packet.get("candidate_origin") or {}
    return {
        "candidate_id": packet.get("candidate_id", ""),
        "anchor_path": origin.get("anchor_path", ""),
        "old_line_start": origin.get("old_line_start", ""),
        "old_line_end": origin.get("old_line_end", ""),
        "old_line_text": origin.get("old_line_text", ""),
    }


def _ordered_unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        item = str(value or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def _identifiers(text: str) -> list[str]:
    return _ordered_unique(
        [
            token
            for token in _IDENTIFIER_RE.findall(text or "")
            if token not in _NOISE_IDENTIFIERS and not token.startswith("MagickMin")
        ]
    )


def _excerpt_ref(text: str, term: str, *, source: str, limit: int = 180) -> dict[str, Any] | None:
    if not text or not term:
        return None
    index = text.find(term)
    if index < 0:
        return None
    start = max(0, index - limit // 2)
    end = min(len(text), index + len(term) + limit // 2)
    return {"source": source, "term": term, "excerpt": text[start:end].replace("\r", "")}


def _extract_added_hardening_terms(diff_text: str) -> list[str]:
    terms: list[str] = []
    for line in (diff_text or "").splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        added = line[1:]
        for token in _identifiers(added):
            if token in {"memset", "ResetMagickMemory", "CopyMagickString", "ThrowReaderException", "break"}:
                terms.append(token)
    return _ordered_unique(terms)


def extract_boundary_verification_inputs(history_packets_by_candidate_id: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    paths: list[str] = []
    fix_commits: list[str] = []
    fix_parents: list[str] = []
    terms: list[str] = []
    for packet in history_packets_by_candidate_id.values():
        origin = packet.get("candidate_origin") or {}
        if origin.get("anchor_path"):
            paths.append(str(origin.get("anchor_path")))
        if origin.get("path_at_fix_parent"):
            paths.append(str(origin.get("path_at_fix_parent")))
        if origin.get("fix_commit_sha"):
            fix_commits.append(str(origin.get("fix_commit_sha")))
        if origin.get("fix_parent_sha"):
            fix_parents.append(str(origin.get("fix_parent_sha")))
        if origin.get("old_line_text"):
            terms.extend(_identifiers(str(origin.get("old_line_text"))))
        for key in ("function", "function_name"):
            if origin.get(key):
                terms.append(str(origin.get(key)))
        for item in origin.get("vulnerable_predicate_bindings") or []:
            terms.extend(_identifiers(str(item).replace(":", " ")))
    return {
        "fix_relevant_paths": _ordered_unique(paths),
        "fix_commit_shas": _ordered_unique(fix_commits),
        "fix_parent_shas": _ordered_unique(fix_parents),
        "source_terms": _ordered_unique(terms)[:24],
    }


def _root_count(query: Any) -> int | None:
    if not hasattr(query, "iter_commits"):
        return None
    try:
        return sum(1 for commit in query.iter_commits() if bool(commit.get("is_root")))
    except Exception:
        return None


def _query_commit_parent_count(query: Any, sha: str) -> tuple[int | None, bool | None, str]:
    commit = query.get_commit(sha)
    if commit.status is not QueryStatus.FOUND or not commit.value:
        return None, None, commit.reason or str(commit.status)
    value = commit.value
    parent_count = value.get("parent_count")
    is_root = value.get("is_root")
    if parent_count is None and hasattr(query, "get_parents"):
        parents = query.get_parents(sha)
        if parents.status is QueryStatus.FOUND:
            parent_count = len(parents.value or [])
    return (int(parent_count) if parent_count is not None else None, bool(is_root) if is_root is not None else None, "")


def _read_path(query: Any, revision: str, path: str) -> tuple[bool, str, str]:
    result = query.read_file_at_revision(revision, path, max_bytes=1024 * 1024)
    if result.status is QueryStatus.FOUND:
        return True, str(result.value or ""), ""
    return False, "", result.reason or str(result.status)


def _boundary_to_fix_ancestry(
    query: Any,
    boundary_commit_sha: str,
    fix_commit_shas: list[str],
    supplied_fix_parent_shas: list[str],
) -> tuple[list[dict[str, Any]], bool, bool]:
    ledger: list[dict[str, Any]] = []
    any_verified = False
    any_descendant = False
    fix_shas = _ordered_unique(fix_commit_shas)
    for fix_sha in fix_shas:
        parents_result = query.get_parents(fix_sha)
        if parents_result.status is QueryStatus.FOUND:
            parent_shas = _ordered_unique([str(item) for item in parents_result.value or []])
        elif len(fix_shas) == 1:
            parent_shas = _ordered_unique(supplied_fix_parent_shas)
        else:
            parent_shas = []

        fix_result = query.is_ancestor(boundary_commit_sha, fix_sha)
        fix_verified = fix_result.status is QueryStatus.FOUND
        fix_descendant = bool(fix_result.value) if fix_verified else False
        any_verified = any_verified or fix_verified

        parent_ancestry: list[dict[str, Any]] = []
        if not fix_descendant:
            for parent_sha in parent_shas:
                parent_result = query.is_ancestor(boundary_commit_sha, parent_sha)
                parent_verified = parent_result.status is QueryStatus.FOUND
                parent_descendant = bool(parent_result.value) if parent_verified else False
                any_verified = any_verified or parent_verified
                parent_ancestry.append(
                    {
                        "fix_parent_sha": parent_sha,
                        "query_status": parent_result.status.value,
                        "is_descendant_of_boundary": parent_descendant if parent_verified else None,
                        "reason": parent_result.reason or "",
                    }
                )
        lineage_descendant = fix_descendant or any(
            item.get("is_descendant_of_boundary") is True for item in parent_ancestry
        )
        any_descendant = any_descendant or lineage_descendant
        ledger.append(
            {
                "fix_commit_sha": fix_sha,
                "fix_parent_shas": parent_shas,
                "fix_commit_query_status": fix_result.status.value,
                "fix_commit_is_descendant_of_boundary": fix_descendant if fix_verified else None,
                "fix_parent_ancestry": parent_ancestry,
                "is_descendant_of_boundary": lineage_descendant,
            }
        )
    return ledger, any_verified, any_descendant


def _unverified_source_state(
    fix_relevant_paths: list[str],
    reason: str,
) -> dict[str, Any]:
    return {
        "fix_relevant_paths": _ordered_unique(fix_relevant_paths),
        "path_exists_at_root": False,
        "path_exists_at_fix_parent": False,
        "relevant_code_state_at_root": "unknown",
        "vulnerable_predicate_state_at_root": "not_verified",
        "fix_predicate_state_at_root": "not_verified",
        "mechanism_signature_terms_present": [],
        "fix_hardening_terms_present_at_root": False,
        "parser_state_terms_observed": [],
        "root_source_excerpt_refs": [],
        "fix_diff_excerpt_refs": [],
        "evidence_status": "unverified",
        "reason": reason,
    }


def verify_history_root_boundary_evidence(
    *,
    cve_id: str,
    repo_id: str,
    boundary_commit_sha: str,
    fix_relevant_paths: list[str],
    fix_commit_shas: list[str],
    fix_parent_shas: list[str],
    source_terms: list[str],
    query: Any,
) -> dict[str, Any]:
    parent_count, is_root, parent_reason = _query_commit_parent_count(query, boundary_commit_sha)
    root_count = _root_count(query)
    git_graph_evidence = {
        "parent_count": parent_count,
        "is_repo_root": parent_count == 0 and (is_root is not False),
        "repo_root_verification_source": "git_graph_index",
        "root_commit_count_for_repo": root_count,
        "reason": parent_reason,
        "boundary_to_fix_ancestry": [],
    }
    if git_graph_evidence["parent_count"] != 0 or git_graph_evidence["is_repo_root"] is not True:
        source_state = _unverified_source_state(fix_relevant_paths, "git_graph_root_verification_failed")
        source_state["evidence_status"] = "failed"
        return {
            "verification_status": "failed",
            "reason": "git_graph_root_verification_failed",
            "git_graph_evidence": git_graph_evidence,
            "source_state_evidence": source_state,
            "state_at_boundary": "unknown",
            "evidence_refs": [{"source": "git_graph_index", "status": "failed", "reason": "git_graph_root_verification_failed"}],
        }

    ancestry_ledger, ancestry_verified, ancestry_descendant = _boundary_to_fix_ancestry(
        query,
        boundary_commit_sha,
        fix_commit_shas,
        fix_parent_shas,
    )
    git_graph_evidence["boundary_to_fix_ancestry"] = ancestry_ledger
    if not ancestry_ledger:
        reason = "no_related_fix_commit_for_ancestry"
        return {
            "verification_status": "unverified",
            "reason": reason,
            "git_graph_evidence": git_graph_evidence,
            "source_state_evidence": _unverified_source_state(fix_relevant_paths, reason),
            "state_at_boundary": "unknown",
            "evidence_refs": [{"source": "git_graph_index", "status": "unverified", "reason": reason}],
        }
    if not ancestry_verified:
        reason = "root_to_fix_ancestry_unverified"
        return {
            "verification_status": "unverified",
            "reason": reason,
            "git_graph_evidence": git_graph_evidence,
            "source_state_evidence": _unverified_source_state(fix_relevant_paths, reason),
            "state_at_boundary": "unknown",
            "evidence_refs": [{"source": "git_graph_index", "status": "unverified", "reason": reason}],
        }
    if not ancestry_descendant:
        reason = "root_not_ancestor_of_any_related_fix"
        source_state = _unverified_source_state(fix_relevant_paths, reason)
        source_state["evidence_status"] = "failed"
        return {
            "verification_status": "failed",
            "reason": reason,
            "git_graph_evidence": git_graph_evidence,
            "source_state_evidence": source_state,
            "state_at_boundary": "unknown",
            "evidence_refs": [{"source": "git_graph_index", "status": "failed", "reason": reason}],
        }

    paths = _ordered_unique(fix_relevant_paths)
    root_contents: dict[str, str] = {}
    root_reasons: list[str] = []
    for path in paths:
        exists, content, reason = _read_path(query, boundary_commit_sha, path)
        if exists:
            root_contents[path] = content
        elif reason:
            root_reasons.append(f"{path}:{reason}")
    path_exists_at_root = bool(root_contents)

    resolved_fix_parent_shas = list(fix_parent_shas)
    if not resolved_fix_parent_shas:
        for fix_sha in fix_commit_shas:
            parents = query.get_parents(fix_sha)
            if parents.status is QueryStatus.FOUND:
                resolved_fix_parent_shas.extend(str(parent) for parent in parents.value or [])
    fix_parent_contents: dict[str, str] = {}
    fix_parent_reasons: list[str] = []
    for parent_sha in _ordered_unique(resolved_fix_parent_shas):
        for path in paths:
            exists, content, reason = _read_path(query, parent_sha, path)
            if exists:
                fix_parent_contents[f"{parent_sha}:{path}"] = content
            elif reason:
                fix_parent_reasons.append(f"{parent_sha}:{path}:{reason}")
    path_exists_at_fix_parent = bool(fix_parent_contents)

    fix_diffs: list[str] = []
    for fix_sha in _ordered_unique(fix_commit_shas):
        diff = query.get_commit_diff(fix_sha)
        if diff.status is QueryStatus.FOUND:
            fix_diffs.append(str(diff.value or ""))
    fix_diff_text = "\n".join(fix_diffs)
    hardening_terms = _extract_added_hardening_terms(fix_diff_text)
    if not hardening_terms and "memset" in fix_diff_text:
        hardening_terms = ["memset"]

    root_text = "\n".join(root_contents.values())
    terms = _ordered_unique([*source_terms, *[term for term in _identifiers(fix_diff_text) if term not in hardening_terms]])[:40]
    observed_terms = [term for term in terms if term and term in root_text]
    relevant_code_state = "present" if path_exists_at_root and observed_terms else "unknown"
    root_source_excerpt_refs = [
        ref
        for term in observed_terms[:8]
        for ref in [_excerpt_ref(root_text, term, source="root_source")]
        if ref is not None
    ]
    fix_diff_excerpt_refs = [
        ref
        for term in hardening_terms[:8]
        for ref in [_excerpt_ref(fix_diff_text, term, source="fix_diff")]
        if ref is not None
    ]
    fix_hardening_terms_present_at_root = bool(hardening_terms) and all(
        term in root_text for term in hardening_terms
    )

    if not path_exists_at_root:
        verification_status = "failed"
        state_at_boundary = "unknown"
        reason = "fix_relevant_path_absent_at_root"
    elif relevant_code_state == "present":
        verification_status = "accepted"
        state_at_boundary = "vulnerability_relevant_code_present_at_root"
        reason = "root_relevant_source_terms_observed"
    else:
        verification_status = "failed"
        state_at_boundary = "unknown"
        reason = "root_source_terms_not_observed"

    source_state_evidence = {
        "fix_relevant_paths": paths,
        "path_exists_at_root": path_exists_at_root,
        "path_exists_at_fix_parent": path_exists_at_fix_parent,
        "relevant_code_state_at_root": relevant_code_state,
        "vulnerable_predicate_state_at_root": "not_verified",
        "fix_predicate_state_at_root": "not_verified",
        "mechanism_signature_terms_present": observed_terms,
        "fix_hardening_terms_present_at_root": fix_hardening_terms_present_at_root,
        "parser_state_terms_observed": observed_terms,
        "root_source_excerpt_refs": root_source_excerpt_refs,
        "fix_diff_excerpt_refs": fix_diff_excerpt_refs,
        "hardening_terms_observed_in_fix_diff": hardening_terms,
        "evidence_status": verification_status,
        "reason": reason,
        "root_read_reasons": root_reasons,
        "fix_parent_read_reasons": fix_parent_reasons,
    }
    return {
        "verification_status": verification_status,
        "reason": reason,
        "git_graph_evidence": git_graph_evidence,
        "source_state_evidence": source_state_evidence,
        "state_at_boundary": state_at_boundary,
        "evidence_refs": [
            {
                "source": "git_graph_index",
                "status": "found",
                "boundary_commit_sha": boundary_commit_sha,
                "parent_count": parent_count,
                "is_repo_root": git_graph_evidence["is_repo_root"],
            },
            {
                "source": "bounded_source_state_verifier",
                "status": verification_status,
                "fix_relevant_paths": paths,
                "observed_terms": observed_terms[:12],
            },
        ],
    }


def detect_history_root_boundary(
    *,
    cve_id: str,
    repo_id: str,
    promoted_events: list[dict[str, Any]],
    history_packets_by_candidate_id: dict[str, dict[str, Any]],
    git_graph_query: Any | None = None,
) -> dict[str, Any] | None:
    root_commit_sha = ""
    root_event_ids: list[str] = []
    evidence_refs: list[dict[str, Any]] = []
    invalid_anchor_refs: list[dict[str, Any]] = []
    visible_paths: set[str] = set()
    supporting_candidate_ids: list[str] = []

    for event in promoted_events:
        source_packets = _source_history_packets(event, history_packets_by_candidate_id)
        packet_roots = [packet for packet in source_packets if _packet_is_root(packet)]
        if not packet_roots and not _event_has_root_signal(event):
            continue
        candidate_sha = str(event.get("event_commit_sha") or "")
        packet_sha = _packet_event_sha(packet_roots[0]) if packet_roots else ""
        root_commit_sha = packet_sha or candidate_sha
        if not root_commit_sha:
            continue
        root_event_ids.append(str(event.get("event_id") or ""))
        supporting_candidate_ids.extend(
            source_id
            for source_id in event.get("source_candidate_ids") or []
            if source_id in history_packets_by_candidate_id
        )
        evidence_refs.append(
            {
                "source": "promoted_history_event",
                "event_id": event.get("event_id", ""),
                "event_commit_sha": candidate_sha,
                "role_proposals": list(event.get("role_proposals") or []),
            }
        )
        for ref in event.get("source_refs") or []:
            evidence_refs.append(copy.deepcopy(ref))
        for packet in source_packets:
            origin = packet.get("candidate_origin") or {}
            path = str(origin.get("anchor_path") or "")
            if path:
                visible_paths.add(path)
            anchor_ref = _candidate_anchor_ref(packet)
            if is_invalid_primary_boundary_anchor(anchor_ref.get("old_line_text")):
                invalid_anchor_refs.append(anchor_ref)
            evidence_refs.append(
                {
                    "source": "history_event_packet",
                    "candidate_id": packet.get("candidate_id", ""),
                    "event_commit_sha": _packet_event_sha(packet),
                    "is_root": _packet_is_root(packet),
                    "anchor_path": path,
                }
            )
        break

    if not root_commit_sha:
        return None

    if git_graph_query is None:
        return None
    inputs = extract_boundary_verification_inputs(history_packets_by_candidate_id)
    verification = verify_history_root_boundary_evidence(
        cve_id=cve_id,
        repo_id=repo_id,
        boundary_commit_sha=root_commit_sha,
        fix_relevant_paths=inputs["fix_relevant_paths"],
        fix_commit_shas=inputs["fix_commit_shas"],
        fix_parent_shas=inputs["fix_parent_shas"],
        source_terms=inputs["source_terms"],
        query=git_graph_query,
    )
    if verification.get("verification_status") != "accepted":
        return None

    boundary = {
        "boundary_type": HISTORY_ROOT_BOUNDARY_ROLE,
        "boundary_subtype": "repository_import_snapshot",
        "boundary_commit_sha": root_commit_sha,
        "repo_root_commit": True,
        "state_before_boundary": "unknown_outside_local_history",
        "state_at_boundary": verification.get("state_at_boundary"),
        "ordinary_introduction_not_observable": True,
        "projection_hint": {
            "first_observed_vulnerable_boundary": root_commit_sha,
            "introduction_status": "censored_before_or_at_boundary",
            "introduction_commit_verified": False,
        },
        "evidence_refs": [
            {"source": "git_root_commit", "commit_sha": root_commit_sha, "repo_id": repo_id, "cve_id": cve_id},
            *evidence_refs,
        ],
        "visible_paths_at_boundary": sorted(visible_paths),
        "root_event_ids": [event_id for event_id in root_event_ids if event_id],
        "supporting_candidate_ids": _ordered_unique(supporting_candidate_ids),
        "invalid_primary_anchor_refs": invalid_anchor_refs,
    }
    boundary["git_graph_evidence"] = verification["git_graph_evidence"]
    boundary["source_state_evidence"] = verification["source_state_evidence"]
    boundary["verification_status"] = verification["verification_status"]
    boundary["verification_reason"] = verification["reason"]
    boundary["evidence_refs"].extend(verification.get("evidence_refs") or [])
    return boundary


def build_synthetic_history_root_boundary_event(
    cve_id: str,
    repo_id: str,
    boundary: dict[str, Any],
) -> dict[str, Any]:
    root_sha = str(boundary.get("boundary_commit_sha") or "")
    short = root_sha[:12] or "unknown"
    return {
        "cve_id": cve_id,
        "repo_id": repo_id,
        "event_id": f"history-boundary:{cve_id}:root:{short}",
        "event_commit_sha": root_sha,
        "rank": 1,
        "gate_score": 1000,
        "gate_decision": "promoted",
        "gate_reasons": [HISTORY_ROOT_BOUNDARY_ROLE, "repository_import_snapshot"],
        "promotion_sources": [HISTORY_ROOT_BOUNDARY_ROLE],
        "role_proposals": [HISTORY_ROOT_BOUNDARY_ROLE, UNCERTAIN_ROLE],
        "source_candidate_ids": list(boundary.get("supporting_candidate_ids") or []),
        "source_refs": list(boundary.get("evidence_refs") or []),
        "evidence_features": {
            "root_or_boundary_source": True,
            "history_root_boundary": True,
            "invalid_anchor_count": len(boundary.get("invalid_primary_anchor_refs") or []),
            "trace_only": False,
            "direct_source": False,
            "risk_flags": [HISTORY_ROOT_BOUNDARY_ROLE],
            "conflict_flags": [],
        },
        "history_root_boundary": copy.deepcopy(boundary),
        "lifecycle": LIFECYCLE,
    }


def _downgrade_related_roles(event: dict[str, Any]) -> dict[str, Any]:
    item = copy.deepcopy(event)
    roles = [role for role in item.get("role_proposals") or [] if role != "possible_introduction_event"]
    if HISTORY_ROOT_BOUNDARY_ROLE in roles:
        roles = [role for role in roles if role != HISTORY_ROOT_BOUNDARY_ROLE]
    if "root_boundary" in roles:
        roles = [role for role in roles if role != "root_boundary"]
    if "unresolved_boundary" in roles and ORDINARY_BOUNDARY_ROLE not in roles:
        roles.append(ORDINARY_BOUNDARY_ROLE)
    if not roles:
        roles = [PREREQUISITE_OR_RELATED_ROLE, UNCERTAIN_ROLE]
    elif PREREQUISITE_OR_RELATED_ROLE not in roles and UNCERTAIN_ROLE not in roles and RELATED_STATE_EXPANSION_ROLE not in roles:
        roles.append(RELATED_STATE_EXPANSION_ROLE)
    item["role_proposals"] = roles
    item["gate_reasons"] = list(item.get("gate_reasons") or []) + ["downgraded_by_history_root_boundary"]
    return item


def apply_history_root_boundary(
    *,
    cve_id: str,
    repo_id: str,
    promoted_events: list[dict[str, Any]],
    history_packets_by_candidate_id: dict[str, dict[str, Any]],
    top_k: int,
    git_graph_query: Any | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    boundary = detect_history_root_boundary(
        cve_id=cve_id,
        repo_id=repo_id,
        promoted_events=promoted_events,
        history_packets_by_candidate_id=history_packets_by_candidate_id,
        git_graph_query=git_graph_query,
    )
    if boundary is None:
        return [copy.deepcopy(event) for event in promoted_events[:top_k]], None

    boundary_sha = str(boundary.get("boundary_commit_sha") or "")
    synthetic = build_synthetic_history_root_boundary_event(cve_id, repo_id, boundary)
    transformed = [synthetic]
    for event in promoted_events:
        if str(event.get("event_commit_sha") or "") == boundary_sha and _event_has_root_signal(event):
            continue
        transformed.append(_downgrade_related_roles(event))
        if len(transformed) >= top_k:
            break

    for index, event in enumerate(transformed, start=1):
        event["rank"] = index
    return transformed, boundary
