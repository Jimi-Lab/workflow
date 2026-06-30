from __future__ import annotations

from vulngraph.workflows.event_promotion_ablation_v1 import (
    build_case_ablation_variants,
    evaluate_candidates,
    scan_candidate_payload_for_label_leakage,
)


def _packet(
    *,
    candidate_id: str = "candidate-1",
    sha: str = "a" * 40,
    anchor_text: str = "dangerous_call(ptr);",
    anchor_path: str = "src/demo.c",
    source_lane: str = "strong",
    is_root: bool = False,
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
            "log_L": {"status": "found", "top_commits": []},
            "log_S": {"status": "found", "top_commits": []},
            "log_G": {"status": "found", "top_commits": []},
        },
        "path_history": {"log_follow": {"status": "found", "top_commits": []}},
        "conflicts": {},
    }


def test_v3_promotes_cross_hit_trace_event_that_v2_gate_only_cannot_recover() -> None:
    direct_sha = "b" * 40
    trace_sha = "1e630b42e1f0573ca549643952017da315e695a0"
    packet = _packet(sha=direct_sha)
    packet["log_history"]["log_L"]["top_commits"] = [trace_sha]
    packet["log_history"]["log_G"]["top_commits"] = [trace_sha]

    variants = build_case_ablation_variants(
        cve_id="CVE-2020-15466",
        repo_id="wireshark",
        history_packets=[packet],
        broad_candidates=[],
        fixes_trailer_targets=[],
    )

    assert trace_sha not in {item["event_commit_sha"] for item in variants["V2_gate_only"]}
    assert trace_sha in {item["event_commit_sha"] for item in variants["V3_semantic_chain_plus_gate"]}
    metrics = evaluate_candidates(variants["V3_semantic_chain_plus_gate"], [trace_sha])
    assert metrics["recall_at_1"] is True


def test_fixes_trailer_target_is_high_priority_v3_candidate() -> None:
    direct_sha = "bdfd2d1fa79acd03e18d1683419572f3682b39fd"
    fixes_sha = "18cb261afd7bf50134e5ccacc5ec91ea16efadd4"
    variants = build_case_ablation_variants(
        cve_id="CVE-2022-0286",
        repo_id="linux",
        history_packets=[_packet(sha=direct_sha)],
        broad_candidates=[],
        fixes_trailer_targets=[fixes_sha],
    )

    v3 = variants["V3_semantic_chain_plus_gate"]
    assert v3[0]["event_commit_sha"] == fixes_sha
    assert "fixes_trailer_direct" in v3[0]["gate_reasons"]
    assert evaluate_candidates(v3, [fixes_sha])["recall_at_1"] is True


def test_history_root_boundary_is_not_ordinary_introduction_candidate() -> None:
    variants = build_case_ablation_variants(
        cve_id="CVE-2020-19667",
        repo_id="ImageMagick",
        history_packets=[_packet(sha="3ed852eea50f9d4cd633efb8c2b054b8e33c2530", anchor_text="}", is_root=True)],
        broad_candidates=[],
        fixes_trailer_targets=[],
    )

    roles = {role for item in variants["V3_semantic_chain_plus_gate"] for role in item["role_proposals"]}
    assert "root_boundary" in roles
    assert "possible_introduction_event" not in roles


def test_candidate_payload_has_no_manual_label_leakage() -> None:
    variants = build_case_ablation_variants(
        cve_id="CVE-TEST",
        repo_id="demo",
        history_packets=[_packet()],
        broad_candidates=[],
        fixes_trailer_targets=[],
    )

    scan = scan_candidate_payload_for_label_leakage({"candidates": variants["V3_semantic_chain_plus_gate"]})
    assert scan["has_leakage"] is False
