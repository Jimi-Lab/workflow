from __future__ import annotations

from tests.simulate_dynamic_line_activation_scheduler import (
    DynamicPolicy,
    _line_rank_key,
    _required_policy_names,
    _summarize,
)


def test_required_dynamic_policies_are_present():
    assert _required_policy_names() == [
        "control_transition_scout_s4_expand2_allfixfile_s4",
        "family_interval_closure_only",
        "evidence_ranked_scout_queue",
        "late_all_fix_file_scout",
        "ranked_positive_neighbor",
        "hybrid_dynamic_scheduler",
    ]


def test_line_rank_key_prioritizes_high_evidence_then_family_order():
    evidence = {
        "1.0": {"score": 0.2},
        "1.1": {"score": 0.8},
        "1.2": {"score": 0.8},
    }
    family_index = {"1.0": 0, "1.1": 1, "1.2": 2}
    ranked = sorted(evidence, key=lambda line: _line_rank_key(line, evidence, family_index))
    assert ranked == ["1.1", "1.2", "1.0"]


def test_summary_tracks_irrelevant_reason_and_fn_sources():
    rows = [
        {
            "strategy": "x",
            "repo": "r",
            "probe_count": 2,
            "visited_line_count": 2,
            "affected_line_count": 1,
            "irrelevant_active_line_count": 1,
            "tp": 1,
            "fp": 0,
            "fn": 1,
            "tn": 3,
            "exact_match": False,
            "has_fn": True,
            "has_fp": False,
            "fn_sources": {
                "source_counts": {
                    "skipped_affected_line": 1,
                    "active_line_missed_asbs_or_sparse": 0,
                }
            },
            "irrelevant_activation_by_primary_reason": {"scout_stride": 1},
            "activation_reason_counts": {"scout_stride": 1},
        }
    ]
    summary = _summarize(rows, policy=DynamicPolicy(name="x"))
    assert summary["avg_probes"] == 2
    assert summary["irrelevant_primary_reason_counts"] == {"scout_stride": 1}
    assert summary["fn_source_counts"]["skipped_affected_line"] == 1
