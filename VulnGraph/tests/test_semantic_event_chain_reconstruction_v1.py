from __future__ import annotations

from vulngraph.workflows.semantic_event_chain_reconstruction_v1 import (
    build_case_event_chain,
    parse_fixes_trailer_targets,
)


def _history_packet(
    *,
    candidate_id: str = "candidate-1",
    candidate_sha: str = "a" * 40,
    anchor_text: str = "dangerous_call(ptr);",
    source_lane: str = "strong",
) -> dict:
    return {
        "cve_id": "CVE-TEST-0001",
        "repo_id": "demo",
        "candidate_id": candidate_id,
        "source_lane": source_lane,
        "lifecycle": "raw_history_event_candidate",
        "candidate_origin": {
            "anchor_path": "src/demo.c",
            "old_line_start": 42,
            "old_line_text": anchor_text,
            "root_cause_hypothesis_bindings": ["h1"],
            "vulnerable_predicate_bindings": ["v1"],
            "fix_predicate_bindings": ["f1"],
        },
        "candidate_event": {
            "candidate_commit_sha": candidate_sha,
            "is_root": False,
            "boundary_marker": False,
            "is_merge": False,
            "changed_paths": ["src/demo.c"],
        },
        "blame_variants": {
            "variants": [
                {"variant": "normal", "status": "found", "blamed_commit_sha": candidate_sha},
                {"variant": "w", "status": "found", "blamed_commit_sha": candidate_sha},
                {"variant": "M", "status": "found", "blamed_commit_sha": candidate_sha},
                {"variant": "C", "status": "found", "blamed_commit_sha": candidate_sha},
            ],
            "variant_agreement": "all_same",
        },
        "log_history": {
            "log_L": {"status": "found", "top_commits": []},
            "log_S": {"status": "found", "top_commits": []},
            "log_G": {"status": "found", "top_commits": []},
        },
        "path_history": {"log_follow": {"status": "found", "top_commits": []}},
        "conflicts": {},
        "deterministic_ranking_features": {},
        "uncertainty": {"reasons": []},
    }


def test_log_l_commit_is_promoted_ahead_of_direct_refactor_when_history_trace_contains_it() -> None:
    true_intro = "1e630b42e1f0573ca549643952017da315e695a0"
    packet = _history_packet(candidate_sha="e7e4dc5d98869f91af3e649324d726217b2a8861")
    packet["log_history"]["log_L"]["top_commits"] = [true_intro, packet["candidate_event"]["candidate_commit_sha"]]

    result = build_case_event_chain(
        cve_id="CVE-2020-15466",
        repo_id="wireshark",
        history_packets=[packet],
        label_case={
            "recommended_introduction_commits": [true_intro],
            "case_verdict": "candidate_pool_misses_true_loop_progress_introduction_event",
        },
        fixes_trailer_targets=[],
    )

    promoted = {event["event_commit_sha"]: event for event in result["promoted_history_events"]}
    assert true_intro in promoted
    assert promoted[true_intro]["promotion_sources"] == ["log_L"]
    assert "log_l_promoted_event" in promoted[true_intro]["role_proposals"]
    assert result["regression_gate_result"]["passed"] is True


def test_fixes_trailer_target_is_promoted_as_high_priority_raw_candidate() -> None:
    target = "18cb261afd7bf50134e5ccacc5ec91ea16efadd4"
    packet = _history_packet(candidate_sha="bdfd2d1fa79acd03e18d1683419572f3682b39fd")

    result = build_case_event_chain(
        cve_id="CVE-2022-0286",
        repo_id="linux",
        history_packets=[packet],
        label_case={"recommended_introduction_commits": [target]},
        fixes_trailer_targets=[target],
    )

    event = {item["event_commit_sha"]: item for item in result["promoted_history_events"]}[target]
    assert event["lifecycle"] == "raw_history_event_candidate"
    assert event["promotion_sources"] == ["fixes_trailer"]
    assert "fixes_trailer_target" in event["role_proposals"]
    assert result["regression_gate_result"]["passed"] is True


def test_invalid_structural_anchor_is_downgraded_without_deleting_trace() -> None:
    packet = _history_packet(anchor_text="} else {", source_lane="fallback")
    result = build_case_event_chain(
        cve_id="CVE-2020-12284",
        repo_id="FFmpeg",
        history_packets=[packet],
        label_case={"recommended_introduction_commits": [packet["candidate_event"]["candidate_commit_sha"]]},
        fixes_trailer_targets=[],
    )

    event = result["promoted_history_events"][0]
    assert event["event_commit_sha"] == packet["candidate_event"]["candidate_commit_sha"]
    assert "unrelated_or_invalid_anchor" in event["role_proposals"]
    assert event["priority"] < 50
    assert result["metrics"]["invalid_anchor_downgraded_count"] == 1


def test_root_boundary_case_does_not_pass_as_plain_introduction() -> None:
    packet = _history_packet(candidate_sha="3ed852eea50f9d4cd633efb8c2b054b8e33c2530", anchor_text="}")
    packet["candidate_event"]["is_root"] = True
    non_root_trace = _history_packet(
        candidate_id="candidate-2",
        candidate_sha="bd45f324084453a2fb279c5c9b5c5c075bce2904",
        anchor_text="count=CopyXPMColor(key,p,MagickMin(width,MagickPathExtent-1));",
    )
    non_root_trace["log_history"]["log_L"]["top_commits"] = ["151b66dffc9e3c2e8c4f8cdaca37ff987ca0f497"]

    result = build_case_event_chain(
        cve_id="CVE-2020-19667",
        repo_id="ImageMagick",
        history_packets=[packet, non_root_trace],
        label_case={"recommended_introduction_commits": [], "case_verdict": "history_censored_at_repository_root_no_validated_introduction_candidate"},
        fixes_trailer_targets=[],
    )

    all_roles = [role for event in result["promoted_history_events"] for role in event["role_proposals"]]
    assert "root_boundary" in all_roles
    assert "possible_introduction_event" not in all_roles
    assert result["regression_gate_result"]["passed"] is True


def test_parse_fixes_trailer_targets_expands_short_and_full_hashes() -> None:
    messages = [
        "net: bonding: fix crash\n\nFixes: 18cb261afd7b (\"bonding: support ipsec offload\")\n",
        "Fixes: 0123456789abcdef0123456789abcdef01234567\n",
    ]
    targets = parse_fixes_trailer_targets(messages, expand_short_sha=lambda value: {"18cb261afd7b": "18cb261afd7bf50134e5ccacc5ec91ea16efadd4"}.get(value, value))
    assert targets == [
        "18cb261afd7bf50134e5ccacc5ec91ea16efadd4",
        "0123456789abcdef0123456789abcdef01234567",
    ]

