from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from typing import Any

from vulngraph.git_graph.query import GitGraphQuery
from vulngraph.git_graph.schema import QueryStatus


_HUNK_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@"
)
_MAX_BLOB_BYTES = 4 * 1024 * 1024
_MAX_FILE_LINES = 300_000
_MAX_PATH_CANDIDATES = 16
_MAX_RECORDED_MATCHES = 128


@dataclass(frozen=True)
class CoordinateHint:
    revision_sha: str
    path: str
    line: int
    source: str


@dataclass(frozen=True)
class NeighborContextHash:
    offset: int
    text_hash: str
    normalized_hash: str


@dataclass(frozen=True)
class AnchorReference:
    fix_parent_sha: str
    original_path: str
    old_line_start: int
    old_line_end: int
    old_line_text: str
    old_line_text_hash: str
    source_line_text_hash: str
    normalized_line_text: str
    normalized_line_hash: str
    candidate_id: str
    fix_commit_sha: str
    patch_family_id: str
    function_id: str | None
    neighboring_context_hashes: tuple[NeighborContextHash, ...]
    coordinate_hints: tuple[CoordinateHint, ...]
    provenance_refs: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_anchor_reference(
    packet: dict[str, Any],
    query: GitGraphQuery,
    *,
    context_radius: int = 3,
) -> AnchorReference:
    origin = packet.get("candidate_origin") or {}
    text = str(origin.get("old_line_text") or "")
    normalized = normalize_line(text)
    original_path = str(origin.get("anchor_path") or "")
    fix_parent_sha = str(origin.get("fix_parent_sha") or "")
    old_line_start = _as_int(origin.get("old_line_start"))
    old_line_end = _as_int(origin.get("old_line_end"), default=old_line_start)
    coordinate_hints: list[CoordinateHint] = []
    if fix_parent_sha and original_path and old_line_start > 0:
        coordinate_hints.append(
            CoordinateHint(
                revision_sha=fix_parent_sha,
                path=original_path,
                line=old_line_start,
                source="fix_parent_anchor_coordinate",
            )
        )
    for item in ((packet.get("blame_variants") or {}).get("variants") or []):
        revision = str(item.get("blamed_commit_sha") or "")
        path = str(item.get("blamed_original_path") or "")
        line = _as_int(item.get("blamed_original_line"))
        if item.get("status") == "found" and revision and path and line > 0:
            coordinate_hints.append(
                CoordinateHint(
                    revision_sha=revision,
                    path=path,
                    line=line,
                    source=f"blame_variant:{item.get('variant') or 'unknown'}",
                )
            )

    neighboring: list[NeighborContextHash] = []
    if fix_parent_sha and original_path and text:
        blob = query.read_file_at_revision(
            fix_parent_sha,
            original_path,
            max_bytes=_MAX_BLOB_BYTES,
        )
        if blob.status is QueryStatus.FOUND:
            lines = str(blob.value or "").splitlines()
            reference_line = _verified_reference_line(
                lines,
                text=text,
                old_line_hint=old_line_start,
            )
            if reference_line is not None:
                for line_no in range(
                    max(1, reference_line - context_radius),
                    min(len(lines), reference_line + context_radius) + 1,
                ):
                    if line_no == reference_line:
                        continue
                    value = lines[line_no - 1]
                    if not value.strip():
                        continue
                    neighboring.append(
                        NeighborContextHash(
                            offset=line_no - reference_line,
                            text_hash=_sha256(value),
                            normalized_hash=_sha256(normalize_line(value)),
                        )
                    )

    return AnchorReference(
        fix_parent_sha=fix_parent_sha,
        original_path=original_path,
        old_line_start=old_line_start,
        old_line_end=old_line_end,
        old_line_text=text,
        old_line_text_hash=_sha256(text),
        source_line_text_hash=str(origin.get("old_line_text_hash") or ""),
        normalized_line_text=normalized,
        normalized_line_hash=_sha256(normalized),
        candidate_id=str(packet.get("candidate_id") or ""),
        fix_commit_sha=str(origin.get("fix_commit_sha") or ""),
        patch_family_id=str(origin.get("patch_family") or ""),
        function_id=str(origin.get("function_id")) if origin.get("function_id") else None,
        neighboring_context_hashes=tuple(neighboring),
        coordinate_hints=tuple(coordinate_hints),
        provenance_refs=tuple(
            value
            for value in (
                str(origin.get("selected_anchor_id") or ""),
                str(origin.get("fallback_anchor_id") or ""),
                str(origin.get("fix_commit_id") or ""),
                str(origin.get("patch_family") or ""),
            )
            if value
        ),
    )


def relocate_history_event_anchor(
    packet: dict[str, Any],
    query: GitGraphQuery,
) -> dict[str, Any]:
    reference = build_anchor_reference(packet, query)
    event = packet.get("candidate_event") or {}
    candidate_sha = str(event.get("candidate_commit_sha") or "")
    parent_shas = [str(value) for value in (event.get("parent_shas") or []) if value]
    path_inventory = _build_path_inventory(packet, query, parent_shas, candidate_sha)

    parent_resolutions = [
        _resolve_revision(
            reference,
            revision_sha=parent_sha,
            path_candidates=path_inventory["parent_paths"].get(parent_sha, []),
            query=query,
        )
        for parent_sha in parent_shas
    ]
    candidate_resolution = _resolve_revision(
        reference,
        revision_sha=candidate_sha,
        path_candidates=path_inventory["candidate_paths"],
        query=query,
    )

    diff_traces: list[dict[str, Any]] = []
    mapped_candidate_resolutions: list[dict[str, Any]] = []
    for index, parent_sha in enumerate(parent_shas):
        diff_trace = _analyze_parent_candidate_diff(
            reference=reference,
            parent_sha=parent_sha,
            candidate_sha=candidate_sha,
            parent_resolution=parent_resolutions[index],
            candidate_resolution=candidate_resolution,
            path_inventory=path_inventory,
            query=query,
        )
        diff_traces.append(diff_trace)
        if diff_trace.get("parent_resolution_override"):
            parent_resolutions[index] = diff_trace["parent_resolution_override"]
        if diff_trace.get("candidate_resolution_override"):
            mapped_candidate_resolutions.append(diff_trace["candidate_resolution_override"])

    if mapped_candidate_resolutions and candidate_resolution["relocation_status"] not in {
        "found",
        "ambiguous",
    }:
        candidate_resolution = _merge_mapped_candidate_resolutions(
            candidate_resolution,
            mapped_candidate_resolutions,
        )
    elif candidate_resolution["relocation_status"] == "found":
        relations = {
            trace.get("candidate_relation")
            for trace in diff_traces
            if trace.get("candidate_relation")
        }
        if len(relations) == 1:
            candidate_resolution = {
                **candidate_resolution,
                "relation_to_anchor": next(iter(relations)),
            }

    for index, resolution in enumerate(parent_resolutions):
        if resolution["relocation_status"] == "not_found":
            fingerprint = _resolve_by_context_fingerprint(
                reference,
                revision_sha=resolution["revision_sha"],
                path_candidates=resolution["path_candidates"],
                query=query,
                attempts=resolution["attempts"],
            )
            if fingerprint is not None:
                parent_resolutions[index] = fingerprint
    if candidate_resolution["relocation_status"] == "not_found":
        fingerprint = _resolve_by_context_fingerprint(
            reference,
            revision_sha=candidate_resolution["revision_sha"],
            path_candidates=candidate_resolution["path_candidates"],
            query=query,
            attempts=candidate_resolution["attempts"],
        )
        if fingerprint is not None:
            candidate_resolution = fingerprint

    return {
        "anchor_reference": reference.to_dict(),
        "candidate_revision_sha": candidate_sha,
        "parent_revision_shas": parent_shas,
        "path_mapping": path_inventory["path_mapping"],
        "parent_resolutions": parent_resolutions,
        "candidate_resolution": candidate_resolution,
        "diff_traces": diff_traces,
        "all_resolutions_accounted": len(parent_resolutions) == len(parent_shas)
        and bool(candidate_resolution),
    }


def materialize_relocated_context(
    query: GitGraphQuery,
    resolution: dict[str, Any],
    *,
    context_kind: str,
    radius: int = 6,
) -> dict[str, Any]:
    base = {
        "revision": resolution.get("revision_sha"),
        "path": resolution.get("selected_path"),
        "context_kind": context_kind,
        "relocation_status": resolution.get("relocation_status"),
        "match_kind": resolution.get("match_kind"),
        "relation_to_anchor": resolution.get("relation_to_anchor"),
        "evidence_refs": list(resolution.get("evidence_refs") or []),
        "relocated_line_start": resolution.get("relocated_line_start"),
        "relocated_line_end": resolution.get("relocated_line_end"),
        "anchor_verified": False,
    }
    if resolution.get("relocation_status") != "found":
        return {
            **base,
            "start_line": None,
            "end_line": None,
            "lines": [],
            "line_hashes": [],
            "extraction_status": resolution.get("relocation_status"),
            "reason": resolution.get("failure_reason")
            or resolution.get("ambiguity_reason")
            or "anchor_not_relocated",
        }
    revision = str(resolution.get("revision_sha") or "")
    path = str(resolution.get("selected_path") or "")
    line = _as_int(resolution.get("relocated_line_start"))
    blob = query.read_file_at_revision(revision, path, max_bytes=_MAX_BLOB_BYTES)
    if blob.status is not QueryStatus.FOUND:
        return {
            **base,
            "start_line": None,
            "end_line": None,
            "lines": [],
            "line_hashes": [],
            "extraction_status": _query_failure_status(blob.status),
            "reason": blob.reason,
        }
    lines = str(blob.value or "").splitlines()
    if line < 1 or line > len(lines):
        return {
            **base,
            "start_line": None,
            "end_line": None,
            "lines": [],
            "line_hashes": [],
            "extraction_status": "not_found",
            "reason": "relocated_line_out_of_range",
        }
    actual = lines[line - 1]
    if _sha256(actual) != resolution.get("matched_text_hash"):
        return {
            **base,
            "start_line": None,
            "end_line": None,
            "lines": [],
            "line_hashes": [],
            "extraction_status": "not_found",
            "reason": "relocated_line_hash_mismatch",
        }
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    window = [
        {
            "line_no": line_no,
            "text": lines[line_no - 1],
            "sha256": _sha256(lines[line_no - 1]),
            "is_anchor_line": line_no == line,
        }
        for line_no in range(start, end + 1)
    ]
    return {
        **base,
        "start_line": start,
        "end_line": end,
        "lines": window,
        "line_hashes": [item["sha256"] for item in window],
        "extraction_status": "found",
        "reason": "",
        "anchor_verified": True,
    }


def compact_resolution_for_blind_packet(resolution: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "revision_sha",
        "path_candidates",
        "selected_path",
        "original_line_hint",
        "relocated_line_start",
        "relocated_line_end",
        "matched_text",
        "matched_text_hash",
        "normalized_hash",
        "relocation_status",
        "match_kind",
        "relation_to_anchor",
        "evidence_refs",
        "ambiguity_reason",
        "failure_reason",
    }
    return {key: value for key, value in resolution.items() if key in allowed}


def normalize_line(value: str) -> str:
    return " ".join(value.split())


def _build_path_inventory(
    packet: dict[str, Any],
    query: GitGraphQuery,
    parent_shas: list[str],
    candidate_sha: str,
) -> dict[str, Any]:
    origin = packet.get("candidate_origin") or {}
    path_history = packet.get("path_history") or {}
    event = packet.get("candidate_event") or {}
    known: list[dict[str, str]] = []

    def add(path: Any, source: str) -> None:
        value = str(path or "")
        if value and all(item["path"] != value for item in known):
            if len(known) < _MAX_PATH_CANDIDATES:
                known.append({"path": value, "source": source})

    add(origin.get("anchor_path"), "anchor_reference")
    add(path_history.get("path_at_candidate"), "path_history_candidate")
    add(path_history.get("path_at_fix_parent"), "path_history_fix_parent")
    for item in ((packet.get("blame_variants") or {}).get("variants") or []):
        if item.get("status") == "found":
            add(item.get("blamed_original_path"), f"blame_variant:{item.get('variant')}")
    anchor_basename = str(origin.get("anchor_path") or "").replace("\\", "/").rsplit("/", 1)[-1]
    for path in event.get("changed_paths") or []:
        normalized = str(path or "")
        if normalized and normalized.replace("\\", "/").rsplit("/", 1)[-1] == anchor_basename:
            add(normalized, "changed_path_same_basename")

    parent_paths = {parent: list(known) for parent in parent_shas}
    candidate_paths = list(known)
    mappings: list[dict[str, Any]] = []
    for parent in parent_shas:
        result = query.name_status_between_revisions(parent, candidate_sha)
        if result.status is not QueryStatus.FOUND:
            mappings.append(
                {
                    "parent_sha": parent,
                    "status": _query_failure_status(result.status),
                    "reason": result.reason,
                    "renames": [],
                }
            )
            continue
        renames = _parse_rename_status(str(result.value or ""))
        mappings.append(
            {
                "parent_sha": parent,
                "status": "found",
                "reason": "",
                "renames": renames,
            }
        )
        known_paths = {item["path"] for item in known}
        for rename in renames:
            before = rename["before_path"]
            after = rename["after_path"]
            if before in known_paths or after in known_paths:
                _append_path(parent_paths[parent], before, "rename_before")
                _append_path(candidate_paths, after, "rename_after")
    return {
        "parent_paths": parent_paths,
        "candidate_paths": candidate_paths,
        "path_mapping": mappings,
    }


def _resolve_revision(
    reference: AnchorReference,
    *,
    revision_sha: str,
    path_candidates: list[dict[str, str]],
    query: GitGraphQuery,
) -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []
    if not revision_sha:
        return _empty_resolution(
            revision_sha,
            path_candidates,
            "censored",
            failure_reason="missing_revision",
            attempts=attempts,
        )
    commit = query.get_commit(revision_sha)
    if commit.status is not QueryStatus.FOUND:
        return _empty_resolution(
            revision_sha,
            path_candidates,
            "censored",
            failure_reason=f"revision_{commit.status.value}:{commit.reason or ''}".rstrip(":"),
            attempts=attempts,
        )
    if not path_candidates:
        return _empty_resolution(
            revision_sha,
            path_candidates,
            "path_missing",
            failure_reason="no_provenance_path_candidates",
            attempts=attempts,
        )

    exact_matches: list[dict[str, Any]] = []
    normalized_matches: list[dict[str, Any]] = []
    found_file_count = 0
    missing_path_count = 0
    censored_count = 0
    for path_item in path_candidates[:_MAX_PATH_CANDIDATES]:
        path = path_item["path"]
        blob = query.read_file_at_revision(
            revision_sha,
            path,
            max_bytes=_MAX_BLOB_BYTES,
        )
        evidence_ref = _blob_evidence_ref(query, revision_sha, path)
        if blob.status is QueryStatus.NOT_FOUND:
            missing_path_count += 1
            attempts.append(
                {
                    "strategy": "path_probe",
                    "path": path,
                    "status": "path_missing",
                    "reason": blob.reason,
                    "evidence_refs": [evidence_ref],
                }
            )
            continue
        if blob.status is not QueryStatus.FOUND:
            censored_count += 1
            attempts.append(
                {
                    "strategy": "path_probe",
                    "path": path,
                    "status": "censored",
                    "reason": blob.reason or blob.status.value,
                    "evidence_refs": [evidence_ref],
                }
            )
            continue
        found_file_count += 1
        lines = str(blob.value or "").splitlines()
        if len(lines) > _MAX_FILE_LINES:
            censored_count += 1
            attempts.append(
                {
                    "strategy": "bounded_line_scan",
                    "path": path,
                    "status": "censored",
                    "reason": f"line_limit_exceeded:{len(lines)}>{_MAX_FILE_LINES}",
                    "evidence_refs": [evidence_ref],
                }
            )
            continue
        for line_no, text in enumerate(lines, start=1):
            if _sha256(text) == reference.old_line_text_hash:
                exact_matches.append(
                    _match(
                        path,
                        line_no,
                        text,
                        "exact_hash",
                        evidence_ref,
                        _context_support(reference, lines, line_no),
                    )
                )
            elif normalize_line(text) == reference.normalized_line_text:
                normalized_matches.append(
                    _match(
                        path,
                        line_no,
                        text,
                        "normalized_unique",
                        evidence_ref,
                        _context_support(reference, lines, line_no),
                    )
                )
        attempts.append(
            {
                "strategy": "exact_and_normalized_scan",
                "path": path,
                "status": "completed",
                "exact_match_count": sum(1 for item in exact_matches if item["path"] == path),
                "normalized_match_count": sum(
                    1 for item in normalized_matches if item["path"] == path
                ),
                "evidence_refs": [evidence_ref],
            }
        )

    exact_matches = exact_matches[:_MAX_RECORDED_MATCHES]
    normalized_matches = normalized_matches[:_MAX_RECORDED_MATCHES]
    if len(exact_matches) == 1:
        return _found_resolution(
            reference,
            revision_sha,
            path_candidates,
            exact_matches[0],
            attempts,
        )
    if len(exact_matches) > 1:
        hinted = _coordinate_verified_matches(
            reference,
            revision_sha=revision_sha,
            matches=exact_matches,
        )
        if len(hinted) == 1:
            selected = {
                **hinted[0],
                "match_kind": "blame_coordinate_verified",
            }
            return _found_resolution(
                reference,
                revision_sha,
                path_candidates,
                selected,
                attempts,
            )
        contextual = _unique_context_match(exact_matches)
        if contextual is not None:
            selected = {**contextual, "match_kind": "context_fingerprint"}
            return _found_resolution(
                reference,
                revision_sha,
                path_candidates,
                selected,
                attempts,
            )
        return _empty_resolution(
            revision_sha,
            path_candidates,
            "ambiguous",
            ambiguity_reason=f"duplicate_exact_matches:{len(exact_matches)}",
            candidate_matches=exact_matches,
            attempts=attempts,
        )

    if len(normalized_matches) == 1 and normalized_matches[0]["context_support_count"] >= 1:
        return _found_resolution(
            reference,
            revision_sha,
            path_candidates,
            normalized_matches[0],
            attempts,
        )
    if normalized_matches:
        reason = (
            f"duplicate_normalized_matches:{len(normalized_matches)}"
            if len(normalized_matches) > 1
            else "normalized_match_lacks_context_support"
        )
        return _empty_resolution(
            revision_sha,
            path_candidates,
            "ambiguous",
            ambiguity_reason=reason,
            candidate_matches=normalized_matches,
            attempts=attempts,
        )
    if found_file_count:
        return _empty_resolution(
            revision_sha,
            path_candidates,
            "not_found",
            failure_reason="anchor_text_not_found_in_provenance_paths",
            attempts=attempts,
        )
    if censored_count:
        return _empty_resolution(
            revision_sha,
            path_candidates,
            "censored",
            failure_reason="all_path_probes_censored",
            attempts=attempts,
        )
    return _empty_resolution(
        revision_sha,
        path_candidates,
        "path_missing",
        failure_reason=f"all_provenance_paths_missing:{missing_path_count}",
        attempts=attempts,
    )


def _analyze_parent_candidate_diff(
    *,
    reference: AnchorReference,
    parent_sha: str,
    candidate_sha: str,
    parent_resolution: dict[str, Any],
    candidate_resolution: dict[str, Any],
    path_inventory: dict[str, Any],
    query: GitGraphQuery,
) -> dict[str, Any]:
    paths = [
        item["path"]
        for item in [
            *path_inventory["parent_paths"].get(parent_sha, []),
            *path_inventory["candidate_paths"],
        ]
    ]
    paths = list(dict.fromkeys(paths))[:32]
    diff = query.diff_between_revisions(
        parent_sha,
        candidate_sha,
        paths=paths,
        unified=12,
    )
    evidence_ref = _diff_evidence_ref(query, parent_sha, candidate_sha, paths, 12)
    trace: dict[str, Any] = {
        "parent_sha": parent_sha,
        "candidate_sha": candidate_sha,
        "status": _query_failure_status(diff.status),
        "reason": diff.reason or "",
        "evidence_refs": [evidence_ref],
        "path_candidates": paths,
        "candidate_relation": "",
    }
    if diff.status is not QueryStatus.FOUND:
        return trace
    files = _parse_unified_diff(str(diff.value or ""))
    trace["status"] = "found"
    trace["file_diff_count"] = len(files)
    trace["file_diffs"] = _public_file_diffs(files)

    parent_match = _find_diff_entry_for_resolution(files, parent_resolution, side="old")
    candidate_match = _find_diff_entry_for_resolution(files, candidate_resolution, side="new")
    if candidate_resolution.get("relocation_status") == "found" and candidate_match:
        if candidate_match["role"] == "added" and parent_resolution.get(
            "relocation_status"
        ) in {"not_found", "path_missing"}:
            trace["parent_resolution_override"] = _event_absence_resolution(
                parent_resolution,
                relation="introduced_in_candidate",
                evidence_ref=evidence_ref,
            )
            trace["candidate_relation"] = "introduced_in_candidate"
        else:
            trace["candidate_relation"] = "same_statement"

    if parent_resolution.get("relocation_status") == "found" and parent_match:
        if parent_match["role"] == "deleted":
            replacement = _replacement_for_deleted_entry(parent_match)
            if replacement is not None:
                relation = (
                    "same_statement"
                    if replacement["normalized_hash"] == reference.normalized_line_hash
                    else "structurally_changed"
                )
                trace["candidate_resolution_override"] = _diff_mapped_resolution(
                    reference,
                    candidate_resolution,
                    replacement,
                    evidence_ref=evidence_ref,
                    relation=relation,
                )
                trace["candidate_relation"] = relation
            elif candidate_resolution.get("relocation_status") not in {
                "found",
                "ambiguous",
            }:
                trace["candidate_resolution_override"] = _event_absence_resolution(
                    candidate_resolution,
                    relation="removed_in_candidate",
                    evidence_ref=evidence_ref,
                )
                trace["candidate_relation"] = "removed_in_candidate"
        elif parent_match["role"] == "context":
            trace["candidate_relation"] = "same_statement"
    return trace


def _resolve_by_context_fingerprint(
    reference: AnchorReference,
    *,
    revision_sha: str,
    path_candidates: list[dict[str, str]],
    query: GitGraphQuery,
    attempts: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if len(reference.neighboring_context_hashes) < 2:
        return None
    candidates: list[dict[str, Any]] = []
    for path_item in path_candidates[:_MAX_PATH_CANDIDATES]:
        path = path_item["path"]
        blob = query.read_file_at_revision(revision_sha, path, max_bytes=_MAX_BLOB_BYTES)
        if blob.status is not QueryStatus.FOUND:
            continue
        lines = str(blob.value or "").splitlines()
        if len(lines) > _MAX_FILE_LINES:
            continue
        evidence_ref = _blob_evidence_ref(query, revision_sha, path)
        for line_no, text in enumerate(lines, start=1):
            support = _context_support(reference, lines, line_no)
            if support >= 2:
                candidates.append(
                    _match(
                        path,
                        line_no,
                        text,
                        "context_fingerprint",
                        evidence_ref,
                        support,
                    )
                )
    attempts.append(
        {
            "strategy": "context_fingerprint",
            "status": "completed",
            "candidate_count": len(candidates),
        }
    )
    selected = _unique_context_match(candidates)
    if selected is None:
        return None
    return _found_resolution(
        reference,
        revision_sha,
        path_candidates,
        {**selected, "match_kind": "context_fingerprint"},
        attempts,
        relation="structurally_changed",
    )


def _parse_unified_diff(diff_text: str) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    current_file: dict[str, Any] | None = None
    current_hunk: dict[str, Any] | None = None
    old_line = 0
    new_line = 0
    for raw in diff_text.splitlines():
        if raw.startswith("diff --git "):
            if current_file:
                files.append(current_file)
            parts = raw.split(" ", 3)
            old_path = parts[2][2:] if len(parts) > 2 and parts[2].startswith("a/") else ""
            new_path = parts[3][2:] if len(parts) > 3 and parts[3].startswith("b/") else ""
            current_file = {
                "old_path": old_path,
                "new_path": new_path,
                "hunks": [],
            }
            current_hunk = None
            continue
        if current_file is None:
            continue
        if raw.startswith("--- "):
            value = raw[4:]
            current_file["old_path"] = "" if value == "/dev/null" else value.removeprefix("a/")
            continue
        if raw.startswith("+++ "):
            value = raw[4:]
            current_file["new_path"] = "" if value == "/dev/null" else value.removeprefix("b/")
            continue
        match = _HUNK_RE.match(raw)
        if match:
            old_line = int(match.group("old_start"))
            new_line = int(match.group("new_start"))
            current_hunk = {
                "header": raw,
                "old_start": old_line,
                "new_start": new_line,
                "entries": [],
            }
            current_file["hunks"].append(current_hunk)
            continue
        if current_hunk is None:
            continue
        entry: dict[str, Any] | None = None
        if raw.startswith("-") and not raw.startswith("---"):
            entry = {
                "role": "deleted",
                "old_line": old_line,
                "new_line": None,
                "text": raw[1:],
            }
            old_line += 1
        elif raw.startswith("+") and not raw.startswith("+++"):
            entry = {
                "role": "added",
                "old_line": None,
                "new_line": new_line,
                "text": raw[1:],
            }
            new_line += 1
        elif raw.startswith(" "):
            entry = {
                "role": "context",
                "old_line": old_line,
                "new_line": new_line,
                "text": raw[1:],
            }
            old_line += 1
            new_line += 1
        if entry is not None:
            entry["text_hash"] = _sha256(entry["text"])
            entry["normalized_hash"] = _sha256(normalize_line(entry["text"]))
            entry["old_path"] = current_file["old_path"]
            entry["new_path"] = current_file["new_path"]
            entry["hunk_header"] = current_hunk["header"]
            entry["_hunk_entries"] = current_hunk["entries"]
            current_hunk["entries"].append(entry)
    if current_file:
        files.append(current_file)
    return files


def _public_file_diffs(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "old_path": file_diff["old_path"],
            "new_path": file_diff["new_path"],
            "hunks": [
                {
                    "header": hunk["header"],
                    "old_start": hunk["old_start"],
                    "new_start": hunk["new_start"],
                    "entries": [
                        {
                            key: value
                            for key, value in entry.items()
                            if not key.startswith("_")
                        }
                        for entry in hunk["entries"]
                    ],
                }
                for hunk in file_diff["hunks"]
            ],
        }
        for file_diff in files
    ]


def _find_diff_entry_for_resolution(
    files: list[dict[str, Any]],
    resolution: dict[str, Any],
    *,
    side: str,
) -> dict[str, Any] | None:
    if resolution.get("relocation_status") != "found":
        return None
    selected_path = resolution.get("selected_path")
    selected_line = resolution.get("relocated_line_start")
    text_hash = resolution.get("matched_text_hash")
    for file_diff in files:
        path = file_diff["old_path"] if side == "old" else file_diff["new_path"]
        if path != selected_path:
            continue
        line_key = "old_line" if side == "old" else "new_line"
        for hunk in file_diff["hunks"]:
            for entry in hunk["entries"]:
                if entry.get(line_key) == selected_line and entry.get("text_hash") == text_hash:
                    return entry
    return None


def _replacement_for_deleted_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    entries = entry.get("_hunk_entries") or []
    try:
        index = entries.index(entry)
    except ValueError:
        return None
    start = index
    while start > 0 and entries[start - 1]["role"] in {"deleted", "added"}:
        start -= 1
    end = index
    while end + 1 < len(entries) and entries[end + 1]["role"] in {"deleted", "added"}:
        end += 1
    block = entries[start : end + 1]
    deleted = [item for item in block if item["role"] == "deleted"]
    added = [item for item in block if item["role"] == "added"]
    if not added:
        return None
    try:
        offset = deleted.index(entry)
    except ValueError:
        offset = 0
    if len(added) == len(deleted) and offset < len(added):
        return added[offset]
    if len(added) == 1:
        return added[0]
    return None


def _diff_mapped_resolution(
    reference: AnchorReference,
    base: dict[str, Any],
    entry: dict[str, Any],
    *,
    evidence_ref: str,
    relation: str,
) -> dict[str, Any]:
    match = {
        "path": entry["new_path"],
        "line": entry["new_line"],
        "text": entry["text"],
        "text_hash": entry["text_hash"],
        "normalized_hash": entry["normalized_hash"],
        "match_kind": "diff_hunk_mapped",
        "evidence_refs": [evidence_ref],
        "context_support_count": 0,
        "hunk_header": entry["hunk_header"],
    }
    return _found_resolution(
        reference,
        str(base.get("revision_sha") or ""),
        list(base.get("path_candidates") or []),
        match,
        list(base.get("attempts") or []),
        relation=relation,
    )


def _event_absence_resolution(
    base: dict[str, Any],
    *,
    relation: str,
    evidence_ref: str,
) -> dict[str, Any]:
    return {
        **base,
        "selected_path": None,
        "relocated_line_start": None,
        "relocated_line_end": None,
        "matched_text": "",
        "matched_text_hash": "",
        "normalized_hash": "",
        "relocation_status": "absent_by_event",
        "match_kind": "diff_hunk_mapped",
        "relation_to_anchor": relation,
        "evidence_refs": sorted(set([*base.get("evidence_refs", []), evidence_ref])),
        "ambiguity_reason": "",
        "failure_reason": "",
    }


def _merge_mapped_candidate_resolutions(
    base: dict[str, Any],
    mapped: list[dict[str, Any]],
) -> dict[str, Any]:
    identities = {
        (
            item.get("relocation_status"),
            item.get("selected_path"),
            item.get("relocated_line_start"),
            item.get("matched_text_hash"),
        )
        for item in mapped
    }
    if len(identities) == 1:
        return mapped[0]
    return _empty_resolution(
        str(base.get("revision_sha") or ""),
        list(base.get("path_candidates") or []),
        "ambiguous",
        ambiguity_reason="merge_parent_diff_mapping_disagreement",
        candidate_matches=[
            {
                "path": item.get("selected_path"),
                "line": item.get("relocated_line_start"),
                "text": item.get("matched_text"),
                "text_hash": item.get("matched_text_hash"),
                "match_kind": item.get("match_kind"),
                "evidence_refs": item.get("evidence_refs"),
            }
            for item in mapped
        ],
        attempts=list(base.get("attempts") or []),
    )


def _found_resolution(
    reference: AnchorReference,
    revision_sha: str,
    path_candidates: list[dict[str, str]],
    match: dict[str, Any],
    attempts: list[dict[str, Any]],
    *,
    relation: str = "same_statement",
) -> dict[str, Any]:
    return {
        "revision_sha": revision_sha,
        "path_candidates": path_candidates,
        "selected_path": match["path"],
        "original_line_hint": reference.old_line_start,
        "relocated_line_start": match["line"],
        "relocated_line_end": match["line"],
        "matched_text": match["text"],
        "matched_text_hash": match["text_hash"],
        "normalized_hash": match["normalized_hash"],
        "relocation_status": "found",
        "match_kind": match["match_kind"],
        "relation_to_anchor": relation,
        "evidence_refs": list(match.get("evidence_refs") or []),
        "candidate_matches": [match],
        "attempts": attempts,
        "ambiguity_reason": "",
        "failure_reason": "",
    }


def _empty_resolution(
    revision_sha: str,
    path_candidates: list[dict[str, str]],
    status: str,
    *,
    failure_reason: str = "",
    ambiguity_reason: str = "",
    candidate_matches: list[dict[str, Any]] | None = None,
    attempts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "revision_sha": revision_sha,
        "path_candidates": path_candidates,
        "selected_path": None,
        "original_line_hint": None,
        "relocated_line_start": None,
        "relocated_line_end": None,
        "matched_text": "",
        "matched_text_hash": "",
        "normalized_hash": "",
        "relocation_status": status,
        "match_kind": "unavailable",
        "relation_to_anchor": "unknown",
        "evidence_refs": [],
        "candidate_matches": candidate_matches or [],
        "attempts": attempts or [],
        "ambiguity_reason": ambiguity_reason,
        "failure_reason": failure_reason,
    }


def _match(
    path: str,
    line: int,
    text: str,
    match_kind: str,
    evidence_ref: str,
    context_support_count: int,
) -> dict[str, Any]:
    return {
        "path": path,
        "line": line,
        "text": text,
        "text_hash": _sha256(text),
        "normalized_hash": _sha256(normalize_line(text)),
        "match_kind": match_kind,
        "evidence_refs": [evidence_ref],
        "context_support_count": context_support_count,
    }


def _coordinate_verified_matches(
    reference: AnchorReference,
    *,
    revision_sha: str,
    matches: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    hints = [
        hint
        for hint in reference.coordinate_hints
        if hint.revision_sha == revision_sha
    ]
    return [
        match
        for match in matches
        if any(hint.path == match["path"] and hint.line == match["line"] for hint in hints)
    ]


def _unique_context_match(matches: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not matches:
        return None
    highest = max(_as_int(item.get("context_support_count")) for item in matches)
    if highest < 2:
        return None
    winners = [
        item for item in matches if _as_int(item.get("context_support_count")) == highest
    ]
    return winners[0] if len(winners) == 1 else None


def _context_support(
    reference: AnchorReference,
    lines: list[str],
    line_no: int,
) -> int:
    support = 0
    for item in reference.neighboring_context_hashes:
        target = line_no + item.offset
        if target < 1 or target > len(lines):
            continue
        value = lines[target - 1]
        if _sha256(value) == item.text_hash or _sha256(normalize_line(value)) == item.normalized_hash:
            support += 1
    return support


def _verified_reference_line(
    lines: list[str],
    *,
    text: str,
    old_line_hint: int,
) -> int | None:
    if 1 <= old_line_hint <= len(lines):
        value = lines[old_line_hint - 1]
        if value == text or normalize_line(value) == normalize_line(text):
            return old_line_hint
    exact = [index for index, value in enumerate(lines, start=1) if value == text]
    if len(exact) == 1:
        return exact[0]
    normalized = [
        index
        for index, value in enumerate(lines, start=1)
        if normalize_line(value) == normalize_line(text)
    ]
    return normalized[0] if len(normalized) == 1 else None


def _parse_rename_status(value: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in value.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0].startswith(("R", "C")):
            rows.append(
                {
                    "status": parts[0],
                    "before_path": parts[1],
                    "after_path": parts[2],
                }
            )
    return rows


def _append_path(paths: list[dict[str, str]], path: str, source: str) -> None:
    if path and all(item["path"] != path for item in paths) and len(paths) < _MAX_PATH_CANDIDATES:
        paths.append({"path": path, "source": source})


def _blob_evidence_ref(query: GitGraphQuery, revision: str, path: str) -> str:
    key = query.evidence_cache_key(
        "show_file",
        {"revision": revision, "path": path, "max_bytes": _MAX_BLOB_BYTES},
        revision=revision,
        path=path,
    )
    return f"git-cache:show_file:{key}"


def _diff_evidence_ref(
    query: GitGraphQuery,
    parent_sha: str,
    candidate_sha: str,
    paths: list[str],
    unified: int,
) -> str:
    key = query.evidence_cache_key(
        "revision_diff",
        {
            "parent_sha": parent_sha,
            "candidate_sha": candidate_sha,
            "paths": paths,
            "unified": unified,
        },
        revision=candidate_sha,
        path="\n".join(paths) if paths else None,
    )
    return f"git-cache:revision_diff:{key}"


def _query_failure_status(status: QueryStatus) -> str:
    if status is QueryStatus.FOUND:
        return "found"
    if status is QueryStatus.NOT_FOUND:
        return "not_found"
    return "censored"


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _as_int(value: Any, *, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
