from __future__ import annotations

from vulngraph.agent_io.topk_judge_packet_schema import scan_blind_packet_forbidden_keys
from vulngraph.workflows.topk_judge_packet_v1 import (
    build_audit_packet,
    build_blind_packet,
    _commit_metadata,
    rank_promoted_events,
    select_top_k,
    summarize_packet_quality,
)
from vulngraph.workflows.history_root_boundary_v1 import build_synthetic_history_root_boundary_event
from vulngraph.git_graph.schema import QueryResult, QueryStatus


def _event(sha: str, *, rank: int, score: int = 90, roles: list[str] | None = None) -> dict:
    return {
        "cve_id": "CVE-TEST",
        "repo_id": "demo",
        "event_id": f"event:{sha[:12]}",
        "event_commit_sha": sha,
        "rank": rank,
        "gate_score": score,
        "gate_decision": "promoted",
        "gate_reasons": ["direct_candidate"],
        "promotion_sources": ["direct_candidate"],
        "role_proposals": roles or ["possible_introduction_event"],
        "source_candidate_ids": [f"source-{rank}"],
        "source_refs": [{"candidate_id": f"source-{rank}", "source": "direct_candidate", "anchor_path": "src/a.c"}],
        "evidence_features": {
            "anchor_paths": ["src/a.c"],
            "invalid_anchor_count": 0,
            "noise_path_count": 0,
            "root_or_boundary_source": False,
            "trace_only": False,
            "direct_source": True,
            "risk_flags": [],
            "conflict_flags": [],
        },
        "lifecycle": "raw_history_event_candidate",
    }


def _history_packet(sha: str, candidate_id: str = "source-1") -> dict:
    return {
        "candidate_id": candidate_id,
        "candidate_origin": {
            "anchor_path": "src/a.c",
            "old_line_start": 10,
            "old_line_end": 10,
            "old_line_text": "dangerous_call(ptr);",
            "old_line_text_hash": "hash1",
            "root_cause_hypothesis_bindings": ["hyp1"],
            "vulnerable_predicate_bindings": ["vp1"],
            "fix_predicate_bindings": ["fp1"],
            "function": "dangerous_function",
            "risk_flags": ["fallback_weak_binding"],
        },
        "candidate_event": {
            "candidate_commit_sha": sha,
            "parent_shas": ["p" * 40],
            "changed_paths": ["src/a.c"],
            "diff_excerpt": "diff --git a/src/a.c b/src/a.c\n+dangerous_call(ptr);",
            "is_merge": False,
            "is_root": False,
            "boundary_marker": False,
        },
        "blame_variants": {
            "variant_agreement": "all_same",
            "variants": [{"variant": "normal", "status": "found", "blamed_commit_sha": sha}],
        },
        "log_history": {
            "log_L": {"status": "found", "top_commits": [sha], "output_excerpt": "log L hit"},
            "log_S": {"status": "found", "top_commits": [sha], "output_excerpt": "pickaxe S hit"},
            "log_G": {"status": "found", "top_commits": [], "output_excerpt": ""},
        },
        "path_history": {"log_follow": {"status": "found", "top_commits": [], "output_excerpt": ""}},
        "conflicts": {"blame_variant_disagreement": False},
    }


def _readiness_packet(candidate_id: str = "source-1") -> dict:
    return {
        "candidate_id": candidate_id,
        "root_cause_bindings": {
            "root_cause_hypothesis_ids": ["hyp1"],
            "vulnerable_predicate_ids": ["vp1"],
            "fix_predicate_ids": ["fp1"],
            "anchor_path": "src/a.c",
            "anchor_old_line_text": "dangerous_call(ptr);",
            "anchor_line_hash": "hash1",
        },
        "candidate_event_identity": {"selected_parent_sha": "p" * 40, "candidate_parent_shas": ["p" * 40]},
        "anchor_relocation": {
            "candidate_resolution": {"relocation_status": "found", "match_kind": "exact_hash"},
            "parent_resolutions": [{"relocation_status": "found", "match_kind": "exact_hash"}],
        },
        "parent_anchor_context": {"extraction_status": "found"},
        "candidate_anchor_context": {"extraction_status": "found"},
        "anchor_path_diff_excerpt": "diff excerpt",
        "history_reconstruction_summary": {"canonical_blame_commit_sha": "a" * 40},
        "conflict_flags": {"whitespace_sensitive": False},
        "recommended_review_priority": "P1",
    }


def test_topk_selection_is_parameterized_not_hardcoded_to_8() -> None:
    events = [_event(f"{index + 1:040x}", rank=index + 1, score=100 - index) for index in range(10)]

    assert len(select_top_k(rank_promoted_events(events), 5)) == 5
    assert len(select_top_k(rank_promoted_events(events), 8)) == 8


def test_blind_packet_excludes_manual_labels_and_forbidden_keys() -> None:
    sha = "a" * 40
    blind = build_blind_packet(
        cve_id="CVE-TEST",
        repo_id="demo",
        topk_events=[_event(sha, rank=1)],
        history_packets_by_candidate_id={"source-1": _history_packet(sha)},
        readiness_packets_by_candidate_id={"source-1": _readiness_packet()},
        commit_metadata_by_sha={sha: {"subject": "subject", "parent_shas": ["p" * 40], "changed_paths": ["src/a.c"]}},
        top_k=5,
    )

    assert blind["judge_task"]["allowed_event_roles"] == [
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
    assert scan_blind_packet_forbidden_keys(blind)["violation_count"] == 0


def test_audit_packet_can_record_label_coverage_without_changing_blind_packet() -> None:
    sha = "a" * 40
    blind = build_blind_packet(
        cve_id="CVE-TEST",
        repo_id="demo",
        topk_events=[_event(sha, rank=1)],
        history_packets_by_candidate_id={"source-1": _history_packet(sha)},
        readiness_packets_by_candidate_id={"source-1": _readiness_packet()},
        commit_metadata_by_sha={sha: {"subject": "subject", "parent_shas": ["p" * 40], "changed_paths": ["src/a.c"]}},
        top_k=5,
    )

    audit = build_audit_packet(
        blind_packet=blind,
        label_case={"recommended_introduction_commits": [sha], "case_verdict": "ok", "candidates": []},
    )

    assert audit["label_evaluation"]["covered_at_1"] is True
    assert "label_evaluation" not in blind
    assert scan_blind_packet_forbidden_keys(blind)["violation_count"] == 0


def test_boundary_case_is_preserved_as_judge_task_not_current_prediction() -> None:
    sha = "b" * 40
    blind = build_blind_packet(
        cve_id="CVE-2020-19667",
        repo_id="ImageMagick",
        topk_events=[_event(sha, rank=1, roles=["unresolved_boundary", "root_boundary"])],
        history_packets_by_candidate_id={"source-1": _history_packet(sha)},
        readiness_packets_by_candidate_id={"source-1": _readiness_packet()},
        commit_metadata_by_sha={sha: {"subject": "subject", "parent_shas": ["p" * 40], "changed_paths": ["src/a.c"]}},
        top_k=8,
    )

    candidate = blind["candidates"][0]
    assert "ordinary_boundary" in candidate["judge_role_options"]
    assert "boundary" in candidate["coarse_role_options"]
    assert candidate["current_system_prediction"] == "none_candidate_requires_judge"
    assert "vulnerability_introduction" not in candidate
    assert candidate["negative_risk_signals"]["feature_series_boundary"] is False


def test_history_root_boundary_blind_packet_carries_bindings_and_verification_evidence() -> None:
    sha = "3" * 40
    boundary = {
        "boundary_type": "history_root_boundary",
        "boundary_commit_sha": sha,
        "supporting_candidate_ids": ["source-1"],
        "git_graph_evidence": {"parent_count": 0, "is_repo_root": True},
        "source_state_evidence": {"path_exists_at_root": True, "path_exists_at_fix_parent": True},
        "evidence_refs": [{"source": "git_graph_index", "status": "found"}],
    }
    event = build_synthetic_history_root_boundary_event("CVE-TEST", "demo", boundary)
    blind = build_blind_packet(
        cve_id="CVE-TEST",
        repo_id="demo",
        topk_events=[event],
        history_packets_by_candidate_id={"source-1": _history_packet(sha)},
        readiness_packets_by_candidate_id={"source-1": _readiness_packet()},
        commit_metadata_by_sha={sha: {"subject": "subject", "parent_shas": [], "changed_paths": ["src/a.c"]}},
        top_k=8,
    )

    candidate = blind["candidates"][0]
    assert candidate["history_root_boundary"]["git_graph_evidence"]["parent_count"] == 0
    assert candidate["history_root_boundary"]["source_state_evidence"]["path_exists_at_root"] is True
    assert "history_root_boundary" in candidate["judge_role_options"]
    assert candidate["root_cause_binding"]["root_cause_hypothesis_ids"] == ["hyp1"]
    assert candidate["root_cause_binding"]["vulnerable_predicate_ids"] == ["vp1"]
    assert candidate["root_cause_binding"]["fix_predicate_ids"] == ["fp1"]
    assert candidate["root_cause_binding"]["affected_functions"] == ["dangerous_function"]
    assert scan_blind_packet_forbidden_keys(blind)["violation_count"] == 0


def test_invalid_structural_boundary_anchor_is_supporting_not_primary() -> None:
    sha = "3" * 40
    history = _history_packet(sha)
    history["candidate_origin"]["old_line_text"] = "break;"
    boundary = {
        "boundary_type": "history_root_boundary",
        "boundary_commit_sha": sha,
        "supporting_candidate_ids": ["source-1"],
        "invalid_primary_anchor_refs": [{"candidate_id": "source-1", "old_line_text": "break;"}],
        "evidence_refs": [{"source": "git_graph_index", "status": "found"}],
    }
    event = build_synthetic_history_root_boundary_event("CVE-TEST", "demo", boundary)

    blind = build_blind_packet(
        cve_id="CVE-TEST",
        repo_id="demo",
        topk_events=[event],
        history_packets_by_candidate_id={"source-1": history},
        readiness_packets_by_candidate_id={"source-1": _readiness_packet()},
        commit_metadata_by_sha={sha: {"subject": "subject", "parent_shas": [], "changed_paths": ["src/a.c"]}},
        top_k=8,
    )

    assert blind["candidates"][0]["anchor_evidence"][0]["evidence_role"] == "supporting_invalid_anchor"


def test_non_boundary_candidate_does_not_receive_boundary_role_option() -> None:
    sha = "d" * 40
    blind = build_blind_packet(
        cve_id="CVE-TEST",
        repo_id="demo",
        topk_events=[_event(sha, rank=1, roles=["possible_introduction_event"])],
        history_packets_by_candidate_id={"source-1": _history_packet(sha)},
        readiness_packets_by_candidate_id={"source-1": _readiness_packet()},
        commit_metadata_by_sha={sha: {"subject": "subject", "parent_shas": ["p" * 40], "changed_paths": ["src/a.c"]}},
        top_k=8,
    )

    assert "vulnerability_introduction" in blind["candidates"][0]["judge_role_options"]
    assert "ordinary_boundary" not in blind["candidates"][0]["judge_role_options"]
    assert "boundary" not in blind["candidates"][0]["coarse_role_options"]


def test_summarize_packet_quality_reports_sizes_and_recall() -> None:
    sha = "c" * 40
    blind = build_blind_packet(
        cve_id="CVE-TEST",
        repo_id="demo",
        topk_events=[_event(sha, rank=1)],
        history_packets_by_candidate_id={"source-1": _history_packet(sha)},
        readiness_packets_by_candidate_id={"source-1": _readiness_packet()},
        commit_metadata_by_sha={sha: {"subject": "subject", "parent_shas": ["p" * 40], "changed_paths": ["src/a.c"]}},
        top_k=5,
    )
    audit = build_audit_packet(blind_packet=blind, label_case={"recommended_introduction_commits": [sha], "candidates": []})
    summary = summarize_packet_quality([{"blind": blind, "audit": audit}], top_k=5)

    assert summary["top_k"] == 5
    assert summary["labeled_target_covered_at_k"] == 1
    assert summary["blind_packet_size_bytes_max"] >= summary["blind_packet_size_bytes_median"]


def test_commit_metadata_does_not_call_unbounded_ref_containment(tmp_path) -> None:
    class FakeQuery:
        def get_commit(self, sha: str) -> QueryResult:
            return QueryResult(QueryStatus.FOUND, {"author_time": 1, "committer_time": 2})

        def get_parents(self, sha: str) -> QueryResult:
            return QueryResult(QueryStatus.FOUND, ["p" * 40])

        def get_changed_paths(self, sha: str) -> QueryResult:
            return QueryResult(QueryStatus.FOUND, ["src/a.c"])

        def refs_containing(self, sha: str) -> QueryResult:
            raise AssertionError("refs_containing is intentionally unbounded for packet construction")

        def tags_containing(self, sha: str) -> QueryResult:
            raise AssertionError("tags_containing is intentionally unbounded for packet construction")

    metadata = _commit_metadata(tmp_path / "missing-repo", FakeQuery(), "a" * 40)

    assert metadata["parent_shas"] == ["p" * 40]
    assert metadata["changed_paths"] == ["src/a.c"]
