from __future__ import annotations

import hashlib
import json
from pathlib import Path

from vulngraph.agent_io.history_event_schema import (
    validate_history_event_packet_v1,
    scan_forbidden_output_fields,
)
from vulngraph.git_graph.builder import GitGraphBuilder
from vulngraph.git_graph.query import GitGraphQuery
from vulngraph.workflows.history_event_reconstruction_v1 import (
    build_history_event_packet_for_candidate,
    load_dataset_metadata_without_gt,
    run_history_event_reconstruction,
)

from git_graph_helpers import make_linear_repo


def _candidate(repo_id: str, commits: list[str], *, source: str = "strong", sha: str | None = None) -> dict:
    line = "second"
    return {
        "cve_id": "CVE-TEST-0001",
        "repo": repo_id,
        "candidate_id": f"{source}-candidate-1",
        "candidate_commit_sha": sha or commits[1],
        "candidate_source": source,
        "evidence_level": source,
        "lifecycle": "raw_candidate",
        "selected_anchor_id": "anchor-1" if source == "strong" else "",
        "fallback_anchor_id": "fallback-anchor-1" if source == "fallback" else "",
        "path_before": "second.txt",
        "old_line_start": 1,
        "old_line_end": 1,
        "old_line_text": line,
        "old_line_text_hash": hashlib.sha256(line.encode()).hexdigest(),
        "fix_commit_id": f"fix-commit:{repo_id}:{commits[2]}",
        "patch_family_id": "patch-family:test",
        "root_cause_hypothesis_bindings": ["rch-1"],
        "vulnerable_predicate_bindings": ["vp-1"],
        "fix_predicate_bindings": ["fp-1"],
        "risk_flags": [],
    }


def test_history_event_packet_schema_rejects_forbidden_output_fields():
    packet = {
        "schema_version": "history_event_packet_v1",
        "cve_id": "CVE-TEST-0001",
        "repo_id": "openjpeg",
        "candidate_id": "candidate-1",
        "source_lane": "strong",
        "lifecycle": "raw_history_event_candidate",
        "candidate_origin": {},
        "git_graph_snapshot": {"repo_snapshot_id": "snapshot", "query_provenance_ids": []},
        "blame_variants": {"variants": []},
        "log_history": {},
        "path_history": {},
        "candidate_event": {},
        "conflicts": {},
        "deterministic_ranking_features": {},
        "uncertainty": {"reasons": []},
    }

    assert validate_history_event_packet_v1(packet) == []
    assert scan_forbidden_output_fields(packet) == []

    forbidden = {**packet, "diagnostic": {"affected_version": ["v1.0.0"]}}
    errors = validate_history_event_packet_v1(forbidden)
    assert any("forbidden_field:affected_version" in item for item in errors)
    assert scan_forbidden_output_fields(forbidden) == ["affected_version"]


def test_build_history_event_packet_uses_git_graph_query_and_keeps_candidate_lane(tmp_path):
    repo, commits = make_linear_repo(tmp_path)
    index = tmp_path / "index" / "openjpeg"
    GitGraphBuilder().build(repo, index, repo_id="openjpeg", reset=True)
    query = GitGraphQuery(index / "graph.sqlite", repo)

    packet = build_history_event_packet_for_candidate(
        cve_id="CVE-TEST-0001",
        repo_id="openjpeg",
        candidate=_candidate("openjpeg", commits, source="fallback"),
        query=query,
        graph_index_root=tmp_path / "index",
    )

    assert validate_history_event_packet_v1(packet) == []
    assert packet["source_lane"] == "fallback"
    assert packet["lifecycle"] == "raw_history_event_candidate"
    assert {item["variant"] for item in packet["blame_variants"]["variants"]} >= {"normal", "w", "M", "C"}
    assert packet["candidate_event"]["candidate_commit_sha"] == commits[1]
    assert packet["candidate_event"]["parent_shas"] == [commits[0]]
    assert packet["candidate_event"]["is_ancestor_of_fix"] is True
    assert packet["git_graph_snapshot"]["repo_snapshot_id"]
    assert packet["git_graph_snapshot"]["query_provenance_ids"]
    assert scan_forbidden_output_fields(packet) == []


def test_missing_commit_or_path_generates_censored_packet_not_exception(tmp_path):
    repo, commits = make_linear_repo(tmp_path)
    index = tmp_path / "index" / "openjpeg"
    GitGraphBuilder().build(repo, index, repo_id="openjpeg", reset=True)
    query = GitGraphQuery(index / "graph.sqlite", repo)

    bad = _candidate("openjpeg", commits, source="fallback", sha="f" * 40)
    bad["path_before"] = "missing.txt"
    packet = build_history_event_packet_for_candidate(
        cve_id="CVE-TEST-0001",
        repo_id="openjpeg",
        candidate=bad,
        query=query,
        graph_index_root=tmp_path / "index",
    )

    assert validate_history_event_packet_v1(packet) == []
    assert packet["source_lane"] == "fallback"
    assert "candidate_commit_not_found" in packet["uncertainty"]["censored_reasons"]
    assert "normal" in {item["variant"] for item in packet["blame_variants"]["variants"]}
    assert packet["deterministic_ranking_features"]["needs_judge"] is True


def test_dataset_loader_does_not_expose_affected_version(tmp_path):
    dataset = tmp_path / "dataset.json"
    dataset.write_text(
        json.dumps(
            {
                "CVE-TEST-0001": {
                    "repo": "openjpeg",
                    "fixing_commits": [["abc"]],
                    "CWE": ["CWE-787"],
                    "affected_version": ["must-not-leak"],
                }
            }
        ),
        encoding="utf-8",
    )

    metadata = load_dataset_metadata_without_gt(dataset)
    assert metadata["CVE-TEST-0001"]["repo"] == "openjpeg"
    assert "affected_version" not in metadata["CVE-TEST-0001"]


def test_reconstruction_workflow_loads_dev_candidate_artifact_and_writes_packets(tmp_path):
    repo, commits = make_linear_repo(tmp_path)
    repo_root = tmp_path / "repos"
    repo_root.mkdir()
    target_repo = repo_root / "openjpeg"
    repo.rename(target_repo)
    index_root = tmp_path / "index"
    GitGraphBuilder().build(target_repo, index_root / "openjpeg", repo_id="openjpeg", reset=True)

    dataset = tmp_path / "dataset.json"
    dataset.write_text(
        json.dumps(
            {
                "CVE-TEST-0001": {
                    "repo": "openjpeg",
                    "fixing_commits": [[commits[2]]],
                    "affected_version": ["must-not-leak"],
                }
            }
        ),
        encoding="utf-8",
    )
    judge_root = tmp_path / "judge"
    case_dir = judge_root / "CVE-TEST-0001"
    case_dir.mkdir(parents=True)
    (case_dir / "judge_blind_input_packet.json").write_text(
        json.dumps({"cve_id": "CVE-TEST-0001", "repo": "openjpeg", "candidates": [_candidate("openjpeg", commits)]}),
        encoding="utf-8",
    )
    detailed_root = tmp_path / "detailed"
    (detailed_root / "CVE-TEST-0001").mkdir(parents=True)
    (detailed_root / "CVE-TEST-0001" / "judge_szz_evidence_packet.json").write_text(
        json.dumps({"candidates": []}),
        encoding="utf-8",
    )

    out_dir = tmp_path / "out"
    summary = run_history_event_reconstruction(
        dataset_path=dataset,
        repo_root=repo_root,
        git_graph_index=index_root,
        judge_packet_root=judge_root,
        detailed_szz_root=detailed_root,
        out_dir=out_dir,
        reset=True,
    )

    assert summary["cases_total"] == 1
    assert summary["input_candidate_count"] == 1
    assert summary["history_event_packet_count"] == 1
    assert (out_dir / "CVE-TEST-0001" / "history_event_packets.json").exists()
    output_text = (out_dir / "history_event_packets.jsonl").read_text(encoding="utf-8")
    assert "affected_version" not in output_text
