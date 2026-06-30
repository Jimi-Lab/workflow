from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from git_graph_helpers import git

from vulngraph.agent_io.history_event_schema import scan_forbidden_output_fields
from vulngraph.git_graph.builder import GitGraphBuilder
from vulngraph.git_graph.query import GitGraphQuery
from vulngraph.workflows.history_event_judge_readiness_v1 import (
    build_judge_readiness_packets_for_history_event,
    packet_size_bytes,
)


def _commit_all(repo: Path, message: str) -> str:
    git(repo, "add", ".")
    git(repo, "commit", "-m", message)
    return git(repo, "rev-parse", "HEAD")


def _make_multifile_repo(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    (repo / "lib").mkdir()
    (repo / "lib" / "connect.c").write_text(
        "\n".join(
            [
                "int connect_it(void) {",
                "  int state = 0;",
                "  safe_connect(state);",
                "  return state;",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (repo / "Makefile").write_text("all:\n\tcc lib/connect.c\n", encoding="utf-8")
    parent = _commit_all(repo, "parent")
    (repo / "Makefile").write_text("all:\n\tcc lib/connect.c -DNEW\n", encoding="utf-8")
    (repo / "lib" / "connect.c").write_text(
        "\n".join(
            [
                "int connect_it(void) {",
                "  int state = 0;",
                "  vulnerable_connect(state);",
                "  return state;",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    candidate = _commit_all(repo, "candidate")
    return repo, parent, candidate


def _query(repo: Path, tmp_path: Path) -> GitGraphQuery:
    output = tmp_path / "index"
    GitGraphBuilder().build(repo, output, repo_id="curl", reset=True)
    return GitGraphQuery(output / "graph.sqlite", repo)


def _history_event_packet(parent: str, candidate: str, *, source_lane: str = "strong") -> dict:
    line_text = "  safe_connect(state);"
    return {
        "schema_version": "history_event_packet_v1",
        "cve_id": "CVE-TEST-READINESS",
        "repo_id": "curl",
        "candidate_id": "candidate-1",
        "source_lane": source_lane,
        "lifecycle": "raw_history_event_candidate",
        "candidate_origin": {
            "anchor_path": "lib/connect.c",
            "old_line_start": 3,
            "old_line_end": 3,
            "old_line_text": line_text,
            "old_line_text_hash": hashlib.sha256(line_text.encode()).hexdigest(),
            "function": "connect_it",
            "function_id": "function:connect_it",
            "fix_commit_sha": "a" * 40,
            "fix_parent_sha": "b" * 40,
            "fix_family": "fix-family:test",
            "patch_family": "patch-family:test",
            "selected_anchor_id": "anchor-1",
            "root_cause_hypothesis_bindings": ["rch-1"],
            "vulnerable_predicate_bindings": ["vp-1"],
            "fix_predicate_bindings": ["fp-1"],
            "risk_flags": [],
        },
        "git_graph_snapshot": {
            "repo_snapshot_id": "snapshot-1",
            "query_provenance_ids": ["query-1"],
        },
        "blame_variants": {
            "canonical_blame_commit_sha": candidate,
            "variant_agreement": "all_same",
            "variants": [
                {"variant": "normal", "status": "found", "blamed_commit_sha": candidate},
                {"variant": "w", "status": "found", "blamed_commit_sha": candidate},
                {"variant": "M", "status": "found", "blamed_commit_sha": candidate},
                {"variant": "C", "status": "found", "blamed_commit_sha": candidate},
            ],
        },
        "log_history": {
            "log_L": {"status": "found", "top_commits": [candidate], "output_excerpt": ""},
            "log_S": {"status": "found", "top_commits": [candidate], "output_excerpt": ""},
            "log_G": {"status": "found", "top_commits": [candidate], "output_excerpt": ""},
            "recursive_blame": {"triggered": False, "chain": []},
        },
        "path_history": {
            "log_follow": {"status": "found", "top_commits": [candidate], "output_excerpt": ""},
            "rename_move_copy_hints": [],
            "path_at_candidate": "lib/connect.c",
            "path_at_fix_parent": "lib/connect.c",
            "path_tracing_uncertainty": [],
        },
        "candidate_event": {
            "candidate_commit_sha": candidate,
            "parent_shas": [parent],
            "before_code": "diff --git a/Makefile b/Makefile\nfull diff is not context",
            "after_code": "diff --git a/Makefile b/Makefile\nfull diff is not context",
            "changed_paths": ["Makefile", "lib/connect.c"],
            "diff_excerpt": "diff --git a/Makefile b/Makefile\nirrelevant full commit diff",
            "per_parent_diffs": [
                {
                    "parent_sha": parent,
                    "status": "found",
                    "diff_excerpt": "diff --git a/Makefile b/Makefile\nirrelevant parent diff",
                }
            ],
            "stable_patch_id": "patch-id-1",
            "is_ancestor_of_fix": True,
            "is_merge": False,
            "is_root": False,
            "boundary_marker": False,
        },
        "conflicts": {
            "blame_variant_disagreement": False,
            "whitespace_sensitive": False,
            "move_copy_sensitive": False,
            "log_L_disagreement": False,
            "path_trace_disagreement": False,
            "fix_series_suspicion": False,
            "fallback_weakness": source_lane == "fallback",
        },
        "deterministic_ranking_features": {
            "needs_judge": source_lane == "fallback",
            "conflict_count": 1 if source_lane == "fallback" else 0,
            "evidence_strength": 1.0,
        },
        "uncertainty": {"reasons": [], "censored_reasons": [], "missing_evidence_reasons": []},
    }


def test_blind_packet_uses_revision_context_not_history_diff_excerpt(tmp_path):
    repo, parent, candidate = _make_multifile_repo(tmp_path)
    packet = _history_event_packet(parent, candidate)

    blind, audit = build_judge_readiness_packets_for_history_event(
        packet,
        git_query=_query(repo, tmp_path),
    )

    assert blind["parent_anchor_context"]["extraction_status"] == "found"
    assert blind["candidate_anchor_context"]["extraction_status"] == "found"
    assert "safe_connect(state)" in json.dumps(blind["parent_anchor_context"])
    assert "vulnerable_connect(state)" in json.dumps(blind["candidate_anchor_context"])
    assert "full diff is not context" not in json.dumps(blind)
    assert blind["parent_anchor_context"] != blind["candidate_anchor_context"]
    assert blind["parent_anchor_context"]["anchor_verified"] is True
    assert blind["candidate_anchor_context"]["anchor_verified"] is True
    assert blind["anchor_relocation"]["candidate_resolution"]["relocated_line_start"] == 3
    assert "source_history_event_packet" in audit
    assert "anchor_relocation_trace" in audit


def test_anchor_local_diff_prefers_anchor_path_over_full_commit_diff(tmp_path):
    repo, parent, candidate = _make_multifile_repo(tmp_path)
    packet = _history_event_packet(parent, candidate)

    blind, _audit = build_judge_readiness_packets_for_history_event(
        packet,
        git_query=_query(repo, tmp_path),
    )

    assert blind["diff_extraction_status"] == "found"
    assert "diff --git a/lib/connect.c b/lib/connect.c" in blind["anchor_path_diff_excerpt"]
    assert "diff --git a/Makefile b/Makefile" not in blind["anchor_path_diff_excerpt"]
    assert any("safe_connect" in line["text"] for line in blind["anchor_hunk_before_lines"])
    assert any("vulnerable_connect" in line["text"] for line in blind["anchor_hunk_after_lines"])


def test_missing_path_is_explicitly_censored_and_does_not_fabricate_code(tmp_path):
    repo, parent, candidate = _make_multifile_repo(tmp_path)
    packet = _history_event_packet(parent, candidate)
    packet["candidate_origin"]["anchor_path"] = "lib/missing.c"
    packet["path_history"]["path_at_candidate"] = "lib/missing.c"
    packet["path_history"]["path_at_fix_parent"] = "lib/missing.c"
    packet["candidate_event"]["changed_paths"] = ["lib/missing.c"]

    blind, _audit = build_judge_readiness_packets_for_history_event(
        packet,
        git_query=_query(repo, tmp_path),
    )

    assert blind["parent_anchor_context"]["extraction_status"] == "path_missing"
    assert blind["candidate_anchor_context"]["extraction_status"] == "path_missing"
    assert blind["parent_anchor_context"]["lines"] == []
    assert blind["candidate_anchor_context"]["lines"] == []
    assert blind["path_resolution_status"] == "unresolved"


def test_fallback_lane_and_conflict_flags_are_retained(tmp_path):
    repo, parent, candidate = _make_multifile_repo(tmp_path)
    packet = _history_event_packet(parent, candidate, source_lane="fallback")
    packet["conflicts"]["blame_variant_disagreement"] = True

    blind, _audit = build_judge_readiness_packets_for_history_event(
        packet,
        git_query=_query(repo, tmp_path),
    )

    assert blind["source_lane"] == "fallback"
    assert blind["conflict_flags"]["fallback_weakness"] is True
    assert blind["conflict_flags"]["blame_variant_disagreement"] is True
    assert blind["recommended_review_priority"] == "P0"


def test_blind_packet_has_size_cap_and_no_forbidden_fields(tmp_path):
    repo, parent, candidate = _make_multifile_repo(tmp_path)
    packet = _history_event_packet(parent, candidate)
    packet["candidate_event"]["diff_excerpt"] = "diff --git a/huge b/huge\n" + ("x" * 200_000)

    blind, audit = build_judge_readiness_packets_for_history_event(
        packet,
        git_query=_query(repo, tmp_path),
        max_blind_diff_chars=1200,
    )

    assert len(blind["anchor_path_diff_excerpt"]) <= 1400
    assert packet_size_bytes(blind) < 60_000
    assert scan_forbidden_output_fields(blind) == []
    assert scan_forbidden_output_fields(audit) == []


def test_existing_dev30_history_event_root_has_61_candidate_packets():
    root = Path("runs/batches/vulngraph-history-event-reconstruction-v1-dev30")
    packets = []
    for case_file in root.glob("CVE-*/history_event_packets.json"):
        packets.extend(json.loads(case_file.read_text(encoding="utf-8")))

    assert len(packets) == 61


def test_generated_dev30_judge_readiness_has_61_blind_and_audit_packets_if_present():
    root = Path("runs/batches/vulngraph-history-event-judge-readiness-v1-dev30")
    if not root.exists():
        pytest.skip("dev30 judge-readiness artifact not generated")

    blind_count = 0
    audit_count = 0
    for case_dir in root.glob("CVE-*"):
        blind_path = case_dir / "judge_blind_history_event_packets.json"
        audit_path = case_dir / "judge_audit_history_event_packets.json"
        if blind_path.exists():
            blind_count += len(json.loads(blind_path.read_text(encoding="utf-8")))
        if audit_path.exists():
            audit_count += len(json.loads(audit_path.read_text(encoding="utf-8")))

    assert blind_count == 61
    assert audit_count == 61


def test_generated_cve_2020_8231_blind_packet_uses_connect_c_not_makefile_if_present():
    path = Path(
        "runs/batches/vulngraph-history-event-judge-readiness-v1-1-anchor-relocation-dev30/"
        "CVE-2020-8231/judge_blind_history_event_packets.json"
    )
    if not path.exists():
        pytest.skip("dev30 judge-readiness artifact not generated")

    packets = json.loads(path.read_text(encoding="utf-8"))
    connect_packets = [
        packet for packet in packets
        if packet.get("root_cause_bindings", {}).get("anchor_path") == "lib/connect.c"
    ]

    assert connect_packets
    for packet in connect_packets:
        assert "diff --git a/lib/connect.c b/lib/connect.c" in packet["anchor_path_diff_excerpt"]
        assert "diff --git a/lib/Makefile.inc b/lib/Makefile.inc" not in packet["anchor_path_diff_excerpt"]
        for context_name in ("parent_anchor_context", "candidate_anchor_context"):
            context = packet[context_name]
            if context["extraction_status"] == "found":
                anchor_lines = [line for line in context["lines"] if line["is_anchor_line"]]
                assert len(anchor_lines) == 1
                assert anchor_lines[0]["text"].strip()
                assert not anchor_lines[0]["text"].lstrip().startswith(("/*", "*", "//"))
                assert context["anchor_verified"] is True
