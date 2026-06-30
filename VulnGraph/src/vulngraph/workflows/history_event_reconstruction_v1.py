from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vulngraph.agent_io.history_event_schema import (
    HISTORY_EVENT_LIFECYCLE,
    HISTORY_EVENT_SCHEMA_VERSION,
    scan_forbidden_output_fields,
    validate_history_event_packet_v1,
)
from vulngraph.git_graph.query import GitGraphQuery
from vulngraph.git_graph.schema import QueryResult, QueryStatus
from vulngraph.services.blame_runner import parse_blame_porcelain


_SHA_RE = re.compile(r"[0-9a-fA-F]{40}")
_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
_BLAME_VARIANTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("normal", ()),
    ("w", ("-w",)),
    ("M", ("-M",)),
    ("C", ("-C",)),
)


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


def load_dataset_metadata_without_gt(dataset_path: str | Path) -> dict[str, dict[str, Any]]:
    data = json.loads(Path(dataset_path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        iterator = ((str(item.get("cve_id") or item.get("CVE") or item.get("id")), item) for item in data)
    else:
        iterator = data.items()
    output: dict[str, dict[str, Any]] = {}
    for cve_id, record in iterator:
        if not cve_id or not isinstance(record, dict):
            continue
        output[cve_id] = {
            "repo": record.get("repo") or record.get("repository") or "",
            "fixing_commits": record.get("fixing_commits") or [],
            "CWE": record.get("CWE") or record.get("cwe") or [],
        }
    return output


def build_history_event_packet_for_candidate(
    *,
    cve_id: str,
    repo_id: str,
    candidate: dict[str, Any],
    query: GitGraphQuery,
    graph_index_root: str | Path,
    detailed_candidate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    detailed_candidate = detailed_candidate or {}
    identity = detailed_candidate.get("candidate_identity", {}) if isinstance(detailed_candidate, dict) else {}
    source_lane = _source_lane(candidate, identity)
    candidate_id = str(candidate.get("candidate_id") or identity.get("candidate_id") or _candidate_fallback_id(candidate))
    candidate_sha = _extract_sha(candidate.get("candidate_commit_sha") or identity.get("candidate_commit_sha"))
    fix_sha = _extract_sha(identity.get("fix_commit_sha") or candidate.get("fix_commit_sha") or candidate.get("fix_commit_id"))
    path = str(candidate.get("path_before") or identity.get("path_before") or "")
    start_line = int(candidate.get("old_line_start") or identity.get("old_line_start") or 0)
    end_line = int(candidate.get("old_line_end") or identity.get("old_line_end") or start_line or 0)
    old_text = str(candidate.get("old_line_text") or candidate.get("line_text") or "")
    old_hash = str(candidate.get("old_line_text_hash") or candidate.get("line_text_hash") or identity.get("old_line_text_hash") or "")
    fix_parent = _find_fix_parent(candidate, fix_sha, query)

    provenance_ids: list[str] = []
    uncertainty_reasons: list[str] = []
    censored_reasons: list[str] = []

    snapshot = query.get_snapshot_manifest()
    snapshot_value = snapshot.value or {}

    commit = query.get_commit(candidate_sha) if candidate_sha else QueryResult(QueryStatus.INVALID_INPUT, reason="missing candidate sha")
    if commit.status is not QueryStatus.FOUND:
        censored_reasons.append("candidate_commit_not_found")
    parents = query.get_parents(candidate_sha) if candidate_sha else QueryResult(QueryStatus.INVALID_INPUT, reason="missing candidate sha")
    parent_shas = list(parents.value or []) if parents.status is QueryStatus.FOUND else []
    changed_paths = query.get_changed_paths(candidate_sha) if commit.status is QueryStatus.FOUND else QueryResult(QueryStatus.NOT_FOUND)
    if changed_paths.status is QueryStatus.FOUND:
        provenance_ids.append(_cache_key(query, "changed_paths", {"sha": candidate_sha}, revision=candidate_sha))
    diff = query.get_commit_diff(candidate_sha) if commit.status is QueryStatus.FOUND else QueryResult(QueryStatus.NOT_FOUND)
    if diff.status is QueryStatus.FOUND:
        provenance_ids.append(_cache_key(query, "commit_diff", {"sha": candidate_sha}, revision=candidate_sha))
    patch_id = query.stable_patch_id(candidate_sha) if commit.status is QueryStatus.FOUND else QueryResult(QueryStatus.NOT_FOUND)
    if patch_id.status is QueryStatus.FOUND:
        provenance_ids.extend([
            _cache_key(query, "stable_patch_id_diff", {"sha": candidate_sha}, revision=candidate_sha),
            _cache_key(query, "stable_patch_id", {"sha": candidate_sha}, revision=candidate_sha),
        ])
    ancestor = query.is_ancestor(candidate_sha, fix_sha) if candidate_sha and fix_sha else QueryResult(QueryStatus.INVALID_INPUT, reason="missing sha")
    if ancestor.status is QueryStatus.FOUND:
        provenance_ids.append(_cache_key(query, "is_ancestor", {"ancestor": candidate_sha, "descendant": fix_sha}))

    blame_revision = fix_parent or (f"{fix_sha}^" if fix_sha else "HEAD")
    blame_variants = []
    for variant_name, options in _BLAME_VARIANTS:
        result = query.blame(path, blame_revision, start_line, end_line, options=options)
        provenance_ids.append(
            _cache_key(
                query,
                "blame" if not options else "blame_" + "_".join(option.lstrip("-") for option in options),
                {"path": path, "revision": blame_revision, "start_line": start_line, "end_line": end_line, "options": list(options)},
                revision=blame_revision,
                path=path,
            )
        )
        blame_variants.append(_blame_variant_record(variant_name, result))
        if result.status is QueryStatus.CENSORED:
            censored_reasons.append(f"blame_{variant_name}_censored")
    successful_shas = [item.get("blamed_commit_sha") for item in blame_variants if item.get("status") == "found" and item.get("blamed_commit_sha")]
    unique_successful_shas = sorted(set(successful_shas))

    log_l = query.log_l(path, blame_revision, start_line, end_line, max_count=20) if path and start_line > 0 else QueryResult(QueryStatus.INVALID_INPUT)
    if log_l.status in {QueryStatus.FOUND, QueryStatus.CENSORED}:
        provenance_ids.append(_cache_key(query, "log_L", {"path": path, "revision": blame_revision, "start_line": start_line, "end_line": end_line, "max_count": 20}, revision=blame_revision, path=path))
    token = _stable_token(old_text)
    log_s = query.log_pickaxe(token, revision=blame_revision, mode="S", path=path, max_count=20) if token else QueryResult(QueryStatus.INVALID_INPUT)
    log_g = query.log_pickaxe(token, revision=blame_revision, mode="G", path=path, max_count=20) if token else QueryResult(QueryStatus.INVALID_INPUT)
    if token:
        provenance_ids.append(_cache_key(query, "log_S", {"needle": token, "revision": blame_revision, "mode": "S", "path": path, "max_count": 20}, revision=blame_revision, path=path))
        provenance_ids.append(_cache_key(query, "log_G", {"needle": token, "revision": blame_revision, "mode": "G", "path": path, "max_count": 20}, revision=blame_revision, path=path))
    log_follow = query.log_follow(path, revision=blame_revision, max_count=20) if path else QueryResult(QueryStatus.INVALID_INPUT)
    if path:
        provenance_ids.append(_cache_key(query, "log_follow", {"path": path, "revision": blame_revision, "max_count": 20}, revision=blame_revision, path=path))

    per_parent_diffs = []
    for parent_sha in parent_shas:
        parent_diff = query.per_parent_diff(candidate_sha, parent_sha)
        if parent_diff.status is QueryStatus.FOUND:
            provenance_ids.append(_cache_key(query, "per_parent_diff", {"commit_sha": candidate_sha, "parent_sha": parent_sha}, revision=candidate_sha))
        per_parent_diffs.append({"parent_sha": parent_sha, "status": parent_diff.status.value, "diff_excerpt": _excerpt(str(parent_diff.value or ""), 1200), "reason": parent_diff.reason})

    normal_sha = _variant_sha(blame_variants, "normal")
    w_sha = _variant_sha(blame_variants, "w")
    m_sha = _variant_sha(blame_variants, "M")
    c_sha = _variant_sha(blame_variants, "C")
    conflicts = {
        "blame_variant_disagreement": len(unique_successful_shas) > 1,
        "whitespace_sensitive": bool(normal_sha and w_sha and normal_sha != w_sha),
        "move_copy_sensitive": bool(normal_sha and ((m_sha and normal_sha != m_sha) or (c_sha and normal_sha != c_sha))),
        "log_L_disagreement": bool(log_l.status is QueryStatus.FOUND and candidate_sha and candidate_sha not in _hashes(str(log_l.value or ""))),
        "path_trace_disagreement": False,
        "fix_series_suspicion": bool(candidate_sha and fix_sha and candidate_sha == fix_sha),
        "fallback_weakness": source_lane == "fallback",
    }
    conflict_count = sum(1 for value in conflicts.values() if value)
    success_count = len(unique_successful_shas)
    variant_agreement_score = 1.0 if not successful_shas else max(Counter(successful_shas).values()) / len(successful_shas)
    changed_path_values = list(changed_paths.value or []) if changed_paths.status is QueryStatus.FOUND else []
    path_consistency_score = 1.0 if path in changed_path_values else 0.5 if changed_path_values else 0.0
    log_l_hashes = _hashes(str(log_l.value or "")) if log_l.status is QueryStatus.FOUND else []

    if not path:
        censored_reasons.append("missing_path")
    if start_line <= 0:
        censored_reasons.append("missing_line")
    if not fix_parent:
        uncertainty_reasons.append("fix_parent_not_resolved")

    packet = {
        "schema_version": HISTORY_EVENT_SCHEMA_VERSION,
        "cve_id": cve_id,
        "repo_id": repo_id,
        "candidate_id": candidate_id,
        "source_lane": source_lane,
        "lifecycle": HISTORY_EVENT_LIFECYCLE,
        "candidate_origin": {
            "anchor_path": path,
            "old_line_start": start_line,
            "old_line_end": end_line,
            "old_line_text": old_text,
            "old_line_text_hash": old_hash,
            "function": candidate.get("function") or identity.get("function"),
            "function_id": candidate.get("function_id") or identity.get("function_id"),
            "fix_commit_id": candidate.get("fix_commit_id") or identity.get("fix_commit_id"),
            "fix_commit_sha": fix_sha,
            "fix_parent_sha": fix_parent,
            "fix_family": candidate.get("fix_family_id") or candidate.get("fix_set_id") or "",
            "patch_family": candidate.get("patch_family_id") or identity.get("patch_family_id") or "",
            "selected_anchor_id": candidate.get("selected_anchor_id") or "",
            "fallback_anchor_id": candidate.get("fallback_anchor_id") or "",
            "root_cause_hypothesis_bindings": candidate.get("root_cause_hypothesis_bindings") or candidate.get("root_cause_binding_refs") or [],
            "vulnerable_predicate_bindings": candidate.get("vulnerable_predicate_bindings") or candidate.get("vulnerable_predicate_refs") or candidate.get("predicate_bindings") or [],
            "fix_predicate_bindings": candidate.get("fix_predicate_bindings") or candidate.get("fix_predicate_refs") or [],
            "risk_flags": [flag for flag in candidate.get("risk_flags", []) if flag not in {"release_line_overreach"}],
        },
        "git_graph_snapshot": {
            "repo_snapshot_id": snapshot_value.get("snapshot_id", ""),
            "graph_index_root": str(Path(graph_index_root)),
            "query_provenance_ids": sorted(set(provenance_ids)),
        },
        "blame_variants": {
            "variants": blame_variants,
            "success_count": success_count,
            "failure_count": len([item for item in blame_variants if item.get("status") != "found"]),
            "unique_blamed_commit_count": len(unique_successful_shas),
            "canonical_blame_commit_sha": normal_sha or (unique_successful_shas[0] if unique_successful_shas else ""),
            "variant_agreement": "all_same" if len(unique_successful_shas) <= 1 else "disagreement",
        },
        "log_history": {
            "log_L": _log_record(log_l),
            "log_S": _log_record(log_s),
            "log_G": _log_record(log_g),
            "recursive_blame": {"triggered": conflict_count > 0, "chain": []},
        },
        "path_history": {
            "log_follow": _log_record(log_follow),
            "rename_move_copy_hints": _hashes(str(log_follow.value or ""))[:10] if log_follow.status is QueryStatus.FOUND else [],
            "path_at_candidate": path,
            "path_at_fix_parent": path,
            "path_tracing_uncertainty": [] if log_follow.status is QueryStatus.FOUND else ["path_follow_unavailable"],
        },
        "candidate_event": {
            "candidate_commit_sha": candidate_sha,
            "parent_shas": parent_shas,
            "before_code": _excerpt(str(diff.value or ""), 1200),
            "after_code": _excerpt(str(diff.value or ""), 1200),
            "changed_paths": changed_path_values,
            "diff_summary": _diff_summary(str(diff.value or "")),
            "diff_excerpt": _excerpt(str(diff.value or ""), 2500),
            "per_parent_diffs": per_parent_diffs,
            "stable_patch_id": patch_id.value if patch_id.status is QueryStatus.FOUND else "",
            "is_ancestor_of_fix": ancestor.value if ancestor.status is QueryStatus.FOUND else None,
            "is_in_fix_series_if_detectable": conflicts["fix_series_suspicion"],
            "is_merge": bool((commit.value or {}).get("is_merge")) if commit.status is QueryStatus.FOUND else False,
            "is_root": bool((commit.value or {}).get("is_root")) if commit.status is QueryStatus.FOUND else False,
            "boundary_marker": any(item.get("boundary_marker") for item in blame_variants),
            "query_status": commit.status.value,
        },
        "conflicts": conflicts,
        "deterministic_ranking_features": {
            "source_lane_weight": 1.0 if source_lane == "strong" else 0.5,
            "evidence_strength": round(success_count / len(_BLAME_VARIANTS), 4),
            "variant_agreement_score": round(variant_agreement_score, 4),
            "path_consistency_score": path_consistency_score,
            "history_depth": len(log_l_hashes),
            "conflict_count": conflict_count,
            "needs_judge": bool(conflict_count > 0 or source_lane == "fallback" or (commit.value or {}).get("is_merge") or (commit.value or {}).get("is_root")),
        },
        "uncertainty": {
            "reasons": sorted(set(uncertainty_reasons)),
            "censored_reasons": sorted(set(censored_reasons)),
            "missing_evidence_reasons": sorted({reason for reason in censored_reasons if reason.startswith("missing_")}),
        },
    }
    schema_errors = validate_history_event_packet_v1(packet)
    if schema_errors:
        packet["schema_errors"] = schema_errors
    return packet


def run_history_event_reconstruction(
    *,
    dataset_path: str | Path,
    repo_root: str | Path,
    git_graph_index: str | Path,
    judge_packet_root: str | Path,
    detailed_szz_root: str | Path,
    out_dir: str | Path,
    reset: bool = False,
) -> dict[str, Any]:
    dataset = load_dataset_metadata_without_gt(dataset_path)
    repo_root = Path(repo_root)
    index_root = Path(git_graph_index)
    judge_root = Path(judge_packet_root)
    detailed_root = Path(detailed_szz_root)
    output = Path(out_dir)
    if reset and output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    packets: list[dict[str, Any]] = []
    summary_rows: list[dict[str, Any]] = []
    conflict_rows: list[dict[str, Any]] = []
    manual_rows: list[dict[str, Any]] = []
    case_summaries: dict[str, dict[str, Any]] = {}
    errors: list[dict[str, Any]] = []

    queries: dict[str, GitGraphQuery] = {}
    for cve_id in sorted(dataset):
        meta = dataset[cve_id]
        repo_id = str(meta.get("repo") or "")
        case_dir = output / cve_id
        case_dir.mkdir(parents=True, exist_ok=True)
        input_packet_path = judge_root / cve_id / "judge_blind_input_packet.json"
        if not input_packet_path.exists():
            case_summary = _empty_case_summary(cve_id, repo_id, "missing_judge_packet")
            _write_case_outputs(case_dir, [], case_summary)
            case_summaries[cve_id] = case_summary
            errors.append({"cve_id": cve_id, "reason": "missing_judge_packet"})
            continue
        input_packet = json.loads(input_packet_path.read_text(encoding="utf-8"))
        candidates = list(input_packet.get("candidates") or [])
        detail_candidates = _load_detailed_candidates(detailed_root / cve_id)
        if repo_id not in queries:
            queries[repo_id] = GitGraphQuery(index_root / repo_id / "graph.sqlite", repo_root / repo_id)
        query = queries[repo_id]
        case_packets = []
        for candidate in candidates:
            detail = _match_detailed_candidate(candidate, detail_candidates)
            packet = build_history_event_packet_for_candidate(
                cve_id=cve_id,
                repo_id=repo_id,
                candidate=candidate,
                query=query,
                graph_index_root=index_root,
                detailed_candidate=detail,
            )
            case_packets.append(packet)
            packets.append(packet)
            summary_rows.append(_summary_row(packet))
            conflict_rows.append(_conflict_row(packet))
            if _needs_manual_review(packet):
                manual_rows.append(_manual_review_row(packet))
        case_summary = _case_summary(cve_id, repo_id, case_packets, len(candidates))
        _write_case_outputs(case_dir, case_packets, case_summary)
        case_summaries[cve_id] = case_summary

    history_jsonl = output / "history_event_packets.jsonl"
    with history_jsonl.open("w", encoding="utf-8") as handle:
        for packet in packets:
            handle.write(json.dumps(packet, sort_keys=True) + "\n")
    _write_csv(output / "history_event_summary.csv", summary_rows)
    _write_csv(output / "conflict_summary.csv", conflict_rows)
    _write_csv(output / "manual_history_event_review_queue.csv", manual_rows)
    _write_csv(output / "manual_history_event_review_template.csv", [_manual_template_row(row) for row in manual_rows])
    strong_fallback_rows = _strong_vs_fallback_metrics(summary_rows, conflict_rows)
    _write_csv(output / "strong_vs_fallback_metrics.csv", strong_fallback_rows)
    cache_usage = _query_cache_usage(index_root)
    _write_csv(output / "query_cache_usage.csv", cache_usage)
    forbidden_scan = _scan_output_directory(output)
    _write_json(output / "forbidden_field_scan.json", forbidden_scan)
    provenance = {
        "schema_version": HISTORY_EVENT_SCHEMA_VERSION,
        "dataset_path": str(Path(dataset_path).resolve()),
        "dataset_sha256": hashlib.sha256(Path(dataset_path).read_bytes()).hexdigest(),
        "repo_root": str(repo_root.resolve()),
        "git_graph_index": str(index_root.resolve()),
        "judge_packet_root": str(judge_root.resolve()),
        "detailed_szz_root": str(detailed_root.resolve()),
        "output_dir": str(output.resolve()),
        "llm_calls": 0,
        "judge_calls": 0,
        "created_at": datetime.now(UTC).isoformat(),
    }
    _write_json(output / "provenance_manifest.json", provenance)

    summary = {
        "schema_version": HISTORY_EVENT_SCHEMA_VERSION,
        "cases_total": len(dataset),
        "cases_with_artifacts": len([case for case in case_summaries.values() if case["status"] != "missing_judge_packet"]),
        "input_candidate_count": sum(case["input_candidate_count"] for case in case_summaries.values()),
        "history_event_packet_count": len(packets),
        "strong_candidate_count": sum(1 for row in summary_rows if row["source_lane"] == "strong"),
        "fallback_candidate_count": sum(1 for row in summary_rows if row["source_lane"] == "fallback"),
        "blame_variant_disagreement_count": sum(1 for row in conflict_rows if row["blame_variant_disagreement"]),
        "log_L_usage_count": sum(1 for row in summary_rows if row["log_L_status"] == "found"),
        "log_S_usage_count": sum(1 for row in summary_rows if row["log_S_status"] == "found"),
        "log_G_usage_count": sum(1 for row in summary_rows if row["log_G_status"] == "found"),
        "recursive_blame_usage_count": sum(1 for row in summary_rows if row["recursive_blame_triggered"]),
        "rename_path_tracing_usage_count": sum(1 for row in summary_rows if row["log_follow_status"] == "found"),
        "merge_root_boundary_candidate_count": sum(1 for row in summary_rows if row["is_merge"] or row["is_root"] or row["boundary_marker"]),
        "needs_judge_count": sum(1 for row in summary_rows if row["needs_judge"]),
        "censored_packet_count": sum(1 for row in summary_rows if row["censored_reason_count"] > 0),
        "case_failures": errors,
        "forbidden_scan_ok": not forbidden_scan["has_forbidden_terms"],
        "highest_lifecycle": HISTORY_EVENT_LIFECYCLE,
    }
    _write_json(output / "summary.json", summary)
    (output / "history_event_reconstruction_report.md").write_text(_report(summary, strong_fallback_rows), encoding="utf-8")
    return summary


def _extract_sha(value: Any) -> str:
    match = _SHA_RE.search(str(value or ""))
    return match.group(0).lower() if match else ""


def _source_lane(candidate: dict[str, Any], identity: dict[str, Any]) -> str:
    value = str(candidate.get("candidate_source") or identity.get("candidate_source") or candidate.get("evidence_level") or "").lower()
    return "strong" if value == "strong" else "fallback"


def _candidate_fallback_id(candidate: dict[str, Any]) -> str:
    payload = json.dumps(candidate, sort_keys=True, default=str)
    return "candidate:" + hashlib.sha256(payload.encode()).hexdigest()[:16]


def _find_fix_parent(candidate: dict[str, Any], fix_sha: str, query: GitGraphQuery) -> str:
    for item in (candidate.get("blame_trace", {}) or {}).get("line_provenance", []) or []:
        parent = _extract_sha(item.get("parent_sha"))
        item_fix = _extract_sha(item.get("fix_commit_sha") or item.get("fix_commit_id"))
        if parent and (not fix_sha or not item_fix or item_fix == fix_sha):
            return parent
    if fix_sha:
        parents = query.get_parents(fix_sha)
        if parents.status is QueryStatus.FOUND and parents.value:
            return parents.value[0]
    return ""


def _blame_variant_record(variant: str, result: QueryResult[str]) -> dict[str, Any]:
    record: dict[str, Any] = {"variant": variant, "status": result.status.value, "reason": result.reason}
    if result.status is not QueryStatus.FOUND:
        return record
    parsed = parse_blame_porcelain(result.value or "")
    if not parsed:
        record["status"] = "censored"
        record["reason"] = "empty_blame_porcelain"
        return record
    item = parsed[0]
    record.update({
        "blamed_commit_sha": item.get("blamed_commit_sha", ""),
        "blamed_original_path": item.get("blamed_original_path", ""),
        "blamed_original_line": item.get("blamed_original_line"),
        "old_line": item.get("old_line"),
        "author_time": item.get("author_time"),
        "committer_time": item.get("committer_time"),
        "boundary_marker": bool(item.get("boundary_marker")),
        "line_text_hash": hashlib.sha256(str(item.get("line_text") or "").encode()).hexdigest(),
    })
    return record


def _cache_key(query: GitGraphQuery, operation: str, arguments: dict[str, Any], *, revision: str | None = None, path: str | None = None) -> str:
    return query.evidence_cache_key(operation, arguments, revision=revision, path=path)


def _variant_sha(variants: list[dict[str, Any]], name: str) -> str:
    for item in variants:
        if item.get("variant") == name:
            return str(item.get("blamed_commit_sha") or "")
    return ""


def _hashes(text: str) -> list[str]:
    return _SHA_RE.findall(text or "")


def _stable_token(text: str) -> str:
    tokens = sorted(set(_TOKEN_RE.findall(text or "")), key=lambda item: (-len(item), item))
    for token in tokens:
        if token not in {"int", "void", "return", "static", "const", "char", "struct"}:
            return token
    return tokens[0] if tokens else ""


def _log_record(result: QueryResult[str]) -> dict[str, Any]:
    return {
        "status": result.status.value,
        "top_commits": _hashes(str(result.value or ""))[:20] if result.status is QueryStatus.FOUND else [],
        "output_excerpt": _excerpt(str(result.value or ""), 1200) if result.status is QueryStatus.FOUND else "",
        "reason": result.reason,
    }


def _excerpt(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "\n...[truncated]..."


def _diff_summary(diff_text: str) -> dict[str, Any]:
    files = [line[10:] for line in diff_text.splitlines() if line.startswith("diff --git ")]
    return {
        "file_count": len(files),
        "added_line_count": sum(1 for line in diff_text.splitlines() if line.startswith("+") and not line.startswith("+++")),
        "deleted_line_count": sum(1 for line in diff_text.splitlines() if line.startswith("-") and not line.startswith("---")),
    }


def _load_detailed_candidates(case_dir: Path) -> list[dict[str, Any]]:
    path = case_dir / "judge_szz_evidence_packet.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return list(data.get("candidates") or [])


def _match_detailed_candidate(candidate: dict[str, Any], records: list[dict[str, Any]]) -> dict[str, Any]:
    candidate_id = str(candidate.get("candidate_id") or "")
    sha = str(candidate.get("candidate_commit_sha") or "")
    path = str(candidate.get("path_before") or "")
    line = candidate.get("old_line_start")
    for record in records:
        identity = record.get("candidate_identity", {})
        if candidate_id and identity.get("candidate_id") == candidate_id:
            return record
    for record in records:
        identity = record.get("candidate_identity", {})
        if identity.get("candidate_commit_sha") == sha and identity.get("path_before") == path and identity.get("old_line_start") == line:
            return record
    return {}


def _empty_case_summary(cve_id: str, repo_id: str, status: str) -> dict[str, Any]:
    return {"cve_id": cve_id, "repo_id": repo_id, "status": status, "input_candidate_count": 0, "packet_count": 0}


def _case_summary(cve_id: str, repo_id: str, packets: list[dict[str, Any]], input_count: int) -> dict[str, Any]:
    return {
        "cve_id": cve_id,
        "repo_id": repo_id,
        "status": "ok",
        "input_candidate_count": input_count,
        "packet_count": len(packets),
        "strong_candidate_count": sum(1 for packet in packets if packet["source_lane"] == "strong"),
        "fallback_candidate_count": sum(1 for packet in packets if packet["source_lane"] == "fallback"),
        "conflict_count": sum(packet["deterministic_ranking_features"]["conflict_count"] for packet in packets),
        "needs_judge_count": sum(1 for packet in packets if packet["deterministic_ranking_features"]["needs_judge"]),
    }


def _write_case_outputs(case_dir: Path, packets: list[dict[str, Any]], case_summary: dict[str, Any]) -> None:
    _write_json(case_dir / "history_event_packets.json", packets)
    _write_json(case_dir / "candidate_event_chains.json", [{"candidate_id": p["candidate_id"], "candidate_event": p["candidate_event"]} for p in packets])
    _write_json(case_dir / "blame_variant_trace.json", [{"candidate_id": p["candidate_id"], "blame_variants": p["blame_variants"]} for p in packets])
    _write_json(case_dir / "log_history_trace.json", [{"candidate_id": p["candidate_id"], "log_history": p["log_history"]} for p in packets])
    _write_json(case_dir / "path_history_trace.json", [{"candidate_id": p["candidate_id"], "path_history": p["path_history"]} for p in packets])
    _write_json(case_dir / "case_summary.json", case_summary)
    lines = [f"# {case_summary['cve_id']} Conflict Report", ""]
    for packet in packets:
        active = [key for key, value in packet["conflicts"].items() if value]
        lines.append(f"- `{packet['candidate_id']}`: {', '.join(active) if active else 'none'}")
    (case_dir / "conflict_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _summary_row(packet: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve_id": packet["cve_id"],
        "repo_id": packet["repo_id"],
        "candidate_id": packet["candidate_id"],
        "source_lane": packet["source_lane"],
        "candidate_commit_sha": packet["candidate_event"]["candidate_commit_sha"],
        "normal_blame_sha": _variant_sha(packet["blame_variants"]["variants"], "normal"),
        "blame_w_sha": _variant_sha(packet["blame_variants"]["variants"], "w"),
        "blame_M_sha": _variant_sha(packet["blame_variants"]["variants"], "M"),
        "blame_C_sha": _variant_sha(packet["blame_variants"]["variants"], "C"),
        "blame_success_count": packet["blame_variants"]["success_count"],
        "variant_agreement": packet["blame_variants"]["variant_agreement"],
        "log_L_status": packet["log_history"]["log_L"]["status"],
        "log_S_status": packet["log_history"]["log_S"]["status"],
        "log_G_status": packet["log_history"]["log_G"]["status"],
        "log_follow_status": packet["path_history"]["log_follow"]["status"],
        "recursive_blame_triggered": packet["log_history"]["recursive_blame"]["triggered"],
        "is_merge": packet["candidate_event"]["is_merge"],
        "is_root": packet["candidate_event"]["is_root"],
        "boundary_marker": packet["candidate_event"]["boundary_marker"],
        "needs_judge": packet["deterministic_ranking_features"]["needs_judge"],
        "conflict_count": packet["deterministic_ranking_features"]["conflict_count"],
        "censored_reason_count": len(packet["uncertainty"]["censored_reasons"]),
    }


def _conflict_row(packet: dict[str, Any]) -> dict[str, Any]:
    return {"cve_id": packet["cve_id"], "candidate_id": packet["candidate_id"], "source_lane": packet["source_lane"], **packet["conflicts"]}


def _needs_manual_review(packet: dict[str, Any]) -> bool:
    return (
        packet["source_lane"] == "fallback"
        or packet["deterministic_ranking_features"]["conflict_count"] > 0
        or packet["candidate_event"]["is_merge"]
        or packet["candidate_event"]["is_root"]
        or packet["candidate_event"]["boundary_marker"]
    )


def _manual_review_row(packet: dict[str, Any]) -> dict[str, Any]:
    log_commits = packet["log_history"]["log_L"].get("top_commits") or []
    reason = []
    if packet["source_lane"] == "fallback":
        reason.append("fallback")
    reason.extend([key for key, value in packet["conflicts"].items() if value])
    return {
        "cve_id": packet["cve_id"],
        "repo_id": packet["repo_id"],
        "candidate_id": packet["candidate_id"],
        "source_lane": packet["source_lane"],
        "anchor_summary": f"{packet['candidate_origin']['anchor_path']}:{packet['candidate_origin']['old_line_start']}",
        "candidate_commit": packet["candidate_event"]["candidate_commit_sha"],
        "candidate_parent": " ".join(packet["candidate_event"]["parent_shas"]),
        "normal_blame_commit": _variant_sha(packet["blame_variants"]["variants"], "normal"),
        "blame_w_commit": _variant_sha(packet["blame_variants"]["variants"], "w"),
        "blame_M_commit": _variant_sha(packet["blame_variants"]["variants"], "M"),
        "blame_C_commit": _variant_sha(packet["blame_variants"]["variants"], "C"),
        "log_L_top_commits": " ".join(log_commits[:5]),
        "path_trace_summary": packet["path_history"]["log_follow"]["status"],
        "deterministic_rank": packet["deterministic_ranking_features"]["source_lane_weight"] - packet["deterministic_ranking_features"]["conflict_count"],
        "review_priority_reason": ",".join(reason) if reason else "strong_sample",
    }


def _manual_template_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        **row,
        "reviewer_label": "",
        "reviewer_notes": "",
    }


def _strong_vs_fallback_metrics(summary_rows: list[dict[str, Any]], conflict_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    conflicts_by_id = {row["candidate_id"]: row for row in conflict_rows}
    rows = []
    for lane in ("strong", "fallback"):
        lane_rows = [row for row in summary_rows if row["source_lane"] == lane]
        rows.append({
            "source_lane": lane,
            "candidate_count": len(lane_rows),
            "packet_generation_success": len(lane_rows),
            "blame_variant_success": sum(1 for row in lane_rows if int(row["blame_success_count"]) > 0),
            "blame_variant_disagreement": sum(1 for row in lane_rows if conflicts_by_id[row["candidate_id"]].get("blame_variant_disagreement")),
            "log_L_available": sum(1 for row in lane_rows if row["log_L_status"] == "found"),
            "recursive_blame_depth": sum(1 for row in lane_rows if row["recursive_blame_triggered"]),
            "path_tracing_needed": sum(1 for row in lane_rows if row["needs_judge"]),
            "path_tracing_success": sum(1 for row in lane_rows if row["log_follow_status"] == "found"),
            "merge_root_boundary_count": sum(1 for row in lane_rows if row["is_merge"] or row["is_root"] or row["boundary_marker"]),
            "fix_series_suspicion_count": sum(1 for row in lane_rows if conflicts_by_id[row["candidate_id"]].get("fix_series_suspicion")),
            "conflict_count": sum(int(row["conflict_count"]) for row in lane_rows),
            "needs_judge_count": sum(1 for row in lane_rows if row["needs_judge"]),
            "censored_count": sum(1 for row in lane_rows if int(row["censored_reason_count"]) > 0),
        })
    return rows


def _query_cache_usage(index_root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for database in sorted(index_root.glob("*/graph.sqlite")):
        repo_id = database.parent.name
        try:
            import sqlite3
            with sqlite3.connect(database) as connection:
                for operation, count in connection.execute("SELECT operation, COUNT(*) FROM evidence_cache GROUP BY operation ORDER BY operation"):
                    rows.append({"repo_id": repo_id, "operation": operation, "cache_entry_count": count})
        except Exception as exc:
            rows.append({"repo_id": repo_id, "operation": "cache_query_failed", "cache_entry_count": 0, "error": str(exc)})
    return rows


def _scan_output_directory(output: Path) -> dict[str, Any]:
    violations: list[dict[str, Any]] = []
    for path in output.rglob("*"):
        if path.is_dir() or path.suffix in {".sqlite", ".db", ".wal", ".shm"}:
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
            fields = scan_forbidden_output_fields(parsed)
            for field in fields:
                violations.append({"path": str(path.relative_to(output)), "kind": "json_key", "field_hash": hashlib.sha256(field.encode()).hexdigest()})
        else:
            for forbidden in ("affected_version", "validated_bic", "correct_bic", "ground_truth", "BIC"):
                if forbidden in text:
                    violations.append({"path": str(path.relative_to(output)), "kind": "text", "field_hash": hashlib.sha256(forbidden.encode()).hexdigest()})
    return {"has_forbidden_terms": bool(violations), "violation_count": len(violations), "violations": violations}


def _report(summary: dict[str, Any], lane_rows: list[dict[str, Any]]) -> str:
    lines = [
        "# VulnGraph History Event Reconstruction v1",
        "",
        "This engineering artifact reconstructs wrapper-owned history event evidence from existing raw candidates and the reusable Git Graph Index.",
        "",
        f"- Cases: {summary['cases_total']}",
        f"- Input candidates: {summary['input_candidate_count']}",
        f"- HistoryEventPacketV1 generated: {summary['history_event_packet_count']}",
        f"- Strong candidates: {summary['strong_candidate_count']}",
        f"- Fallback candidates: {summary['fallback_candidate_count']}",
        f"- Blame variant disagreements: {summary['blame_variant_disagreement_count']}",
        f"- Needs later event judgment: {summary['needs_judge_count']}",
        f"- Censored packets: {summary['censored_packet_count']}",
        f"- Forbidden scan ok: {summary['forbidden_scan_ok']}",
        "",
        "## Strong vs Fallback",
        "",
    ]
    for row in lane_rows:
        lines.append(f"- {row['source_lane']}: candidates={row['candidate_count']}, disagreements={row['blame_variant_disagreement']}, needs_judge={row['needs_judge_count']}, censored={row['censored_count']}")
    lines.extend([
        "",
        "No model call, event judgment, final boundary validation, or version-state propagation is performed in this run.",
        "All generated candidate lifecycles remain raw_history_event_candidate.",
    ])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build Git Graph Index-backed HistoryEventPacketV1 artifacts.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--git-graph-index", required=True)
    parser.add_argument("--judge-packet-root", required=True)
    parser.add_argument("--detailed-szz-root", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args(argv)
    summary = run_history_event_reconstruction(
        dataset_path=args.dataset,
        repo_root=args.repo_root,
        git_graph_index=args.git_graph_index,
        judge_packet_root=args.judge_packet_root,
        detailed_szz_root=args.detailed_szz_root,
        out_dir=args.out_dir,
        reset=args.reset,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0
