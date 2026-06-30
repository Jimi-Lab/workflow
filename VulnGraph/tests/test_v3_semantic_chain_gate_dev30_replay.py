from __future__ import annotations

from vulngraph.workflows.v3_semantic_chain_gate_dev30_replay import (
    build_v3_replay_case,
    summarize_replay_cases,
)


def _packet(
    *,
    candidate_id: str = "candidate-1",
    sha: str = "a" * 40,
    anchor_text: str = "dangerous_call(ptr);",
    anchor_path: str = "src/demo.c",
    source_lane: str = "strong",
    is_root: bool = False,
    log_l: list[str] | None = None,
    log_g: list[str] | None = None,
    log_s: list[str] | None = None,
    log_follow: list[str] | None = None,
) -> dict:
    return {
        "cve_id": "CVE-TEST",
        "repo_id": "demo",
        "candidate_id": candidate_id,
        "source_lane": source_lane,
        "candidate_origin": {
            "anchor_path": anchor_path,
            "old_line_text": anchor_text,
            "risk_flags": [],
            "root_cause_hypothesis_bindings": ["h1"],
            "vulnerable_predicate_bindings": ["v1"],
            "fix_predicate_bindings": ["f1"],
        },
        "candidate_event": {
            "candidate_commit_sha": sha,
            "is_root": is_root,
            "boundary_marker": False,
        },
        "blame_variants": {
            "variants": [
                {"variant": "normal", "status": "found", "blamed_commit_sha": sha},
                {"variant": "w", "status": "found", "blamed_commit_sha": sha},
            ]
        },
        "log_history": {
            "log_L": {"status": "found", "top_commits": log_l or []},
            "log_S": {"status": "found", "top_commits": log_s or []},
            "log_G": {"status": "found", "top_commits": log_g or []},
        },
        "path_history": {"log_follow": {"status": "found", "top_commits": log_follow or []}},
        "conflicts": {},
    }


def test_v3_replay_case_reports_pre_truncation_without_exceeding_top8() -> None:
    packets = []
    for index in range(12):
        sha = f"{index + 1:040x}"
        packets.append(_packet(candidate_id=f"candidate-{index}", sha=sha, log_l=[sha], log_g=[sha]))

    case = build_v3_replay_case(
        cve_id="CVE-TEST",
        repo_id="demo",
        history_packets=packets,
        fixes_trailer_targets=[],
        label_case=None,
    )

    assert len(case["candidates"]) == 8
    assert case["metrics"]["pre_truncation_promoted_count"] >= 12
    assert case["metrics"]["truncated_event_count"] >= 4


def test_v3_replay_candidate_generation_ignores_manual_labels() -> None:
    packet = _packet(sha="b" * 40, log_l=["c" * 40], log_g=["c" * 40])
    without_labels = build_v3_replay_case(
        cve_id="CVE-TEST",
        repo_id="demo",
        history_packets=[packet],
        fixes_trailer_targets=[],
        label_case=None,
    )
    with_labels = build_v3_replay_case(
        cve_id="CVE-TEST",
        repo_id="demo",
        history_packets=[packet],
        fixes_trailer_targets=[],
        label_case={"recommended_introduction_commits": ["d" * 40], "candidates": []},
    )

    assert [item["event_commit_sha"] for item in without_labels["candidates"]] == [
        item["event_commit_sha"] for item in with_labels["candidates"]
    ]
    assert without_labels["regression"] is None
    assert with_labels["regression"]["recall_at_5"] is False


def test_v3_replay_preserves_root_boundary_unresolved_semantics() -> None:
    case = build_v3_replay_case(
        cve_id="CVE-2020-19667",
        repo_id="ImageMagick",
        history_packets=[_packet(sha="3ed852eea50f9d4cd633efb8c2b054b8e33c2530", anchor_text="}", is_root=True)],
        fixes_trailer_targets=[],
        label_case=None,
    )

    roles = {role for item in case["candidates"] for role in item.get("role_proposals", [])}
    assert "unresolved_boundary" in roles
    assert "possible_introduction_event" not in roles
    assert case["metrics"]["root_or_boundary_case"] is True
    assert case["metrics"]["unresolved_case"] is True


def test_summarize_replay_cases_enforces_no_backend_and_topk_gate() -> None:
    case = build_v3_replay_case(
        cve_id="CVE-TEST",
        repo_id="demo",
        history_packets=[_packet(sha="e" * 40)],
        fixes_trailer_targets=[],
        label_case=None,
    )

    summary = summarize_replay_cases(
        cases=[case],
        expected_cases_total=1,
        previous_v3_recall_at_5=1.0,
        label_leakage={"has_leakage": False, "leakage_count": 0, "leaks": []},
        forbidden={"has_forbidden_terms": False, "violation_count": 0, "violations": []},
    )

    assert summary["cases_total"] == 1
    assert summary["model_invocation_count"] == 0
    assert summary["judge_invocation_count"] == 0
    assert summary["converter_invocation_count"] == 0
    assert summary["hard_gates"]["post_truncation_max_le_8"] is True
