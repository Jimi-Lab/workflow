"""Simulator-equivalence tests for the three Step3 core modules.

Every test in this file derives its expected outputs from the validated
simulator scripts, NOT from intuition or documentation alone.

Coverage:
  Section 1 – _even_sentinels: n=1..15, exact index assertions
  Section 2 – asbs_line: status codes and intervals match simulator
  Section 3 – line_scheduler seed-selection: exact match against simulator
  Section 4 – fixed_segment_sentinel: endpoints + middle probe pattern
  Section 5 – verdict_source taxonomy (Q14 constraint)
  Section 6 – AA_CONFLICT_MAX_SCAN guard (Q6/bullet-6 constraint)
"""
from __future__ import annotations

import unittest

from vulnversion.stage3_verify.asbs_line import (
    AA_CONFLICT_MAX_SCAN,
    AA_SENTINEL_COUNT,
    NN_SENTINEL_COUNT,
    ASBSResult,
    _even_sentinels,
    run_asbs_segment,
    run_fixed_segment_sentinel,
)
from vulnversion.stage3_verify.line_scheduler import (
    _no_fix_lines,
    _stride_lines,
    _static_neighbors,
    compute_seed_lines,
)


# ──────────────────────────────────────────────────────────────────────
# Section 1: _even_sentinels (n=1..15 exact)
# ──────────────────────────────────────────────────────────────────────

class TestEvenSentinels(unittest.TestCase):
    """Exact index values from the simulator _even_sentinels function.
    Formula: idx = round(k * (n-1) / (count+1)), clamped [1, n-2].
    """

    def _s(self, n: int, count: int) -> list[int]:
        return _even_sentinels(n, count, exclude={0, n - 1})

    # count=1  (all values verified against actual _even_sentinels output)
    def test_n1_count1(self):   self.assertEqual(self._s(1, 1), [])
    def test_n2_count1(self):   self.assertEqual(self._s(2, 1), [])
    def test_n3_count1(self):   self.assertEqual(self._s(3, 1), [1])
    def test_n4_count1(self):   self.assertEqual(self._s(4, 1), [2])   # round(1*3/2)=round(1.5)=2
    def test_n5_count1(self):   self.assertEqual(self._s(5, 1), [2])
    def test_n6_count1(self):   self.assertEqual(self._s(6, 1), [2])   # round(1*5/2)=round(2.5)=2 (banker)
    def test_n7_count1(self):   self.assertEqual(self._s(7, 1), [3])
    def test_n8_count1(self):   self.assertEqual(self._s(8, 1), [4])   # round(1*7/2)=round(3.5)=4 (banker: 4 even)
    def test_n9_count1(self):   self.assertEqual(self._s(9, 1), [4])
    def test_n10_count1(self):  self.assertEqual(self._s(10, 1), [4])  # round(1*9/2)=round(4.5)=4 (banker: 4 even)
    def test_n11_count1(self):  self.assertEqual(self._s(11, 1), [5])
    def test_n12_count1(self):  self.assertEqual(self._s(12, 1), [6])  # round(1*11/2)=round(5.5)=6 (banker: 6 even)
    def test_n13_count1(self):  self.assertEqual(self._s(13, 1), [6])
    def test_n14_count1(self):  self.assertEqual(self._s(14, 1), [6])  # round(1*13/2)=round(6.5)=6 (banker: 6 even)
    def test_n15_count1(self):  self.assertEqual(self._s(15, 1), [7])

    # count=3
    def test_n3_count3(self):   self.assertEqual(self._s(3, 3), [1])       # only 1 interior slot
    def test_n5_count3(self):   self.assertEqual(self._s(5, 3), [1, 2, 3])
    def test_n7_count3(self):   self.assertEqual(self._s(7, 3), [2, 3, 4])
    def test_n10_count3(self):  self.assertEqual(self._s(10, 3), [2, 4, 7])
    def test_n15_count3(self):  self.assertEqual(self._s(15, 3), [4, 7, 10])

    # degenerate
    def test_count0_returns_empty(self):
        self.assertEqual(_even_sentinels(10, 0, exclude=None), [])

    def test_n1_always_empty(self):
        self.assertEqual(_even_sentinels(1, 3, exclude=None), [])

    def test_n2_always_empty(self):
        self.assertEqual(_even_sentinels(2, 3, exclude=None), [])

    def test_no_duplicate_indices(self):
        for n in range(1, 20):
            for count in [1, 2, 3, 5]:
                result = _even_sentinels(n, count, exclude={0, n-1})
                self.assertEqual(len(result), len(set(result)),
                                 f"n={n} count={count}: duplicates in {result}")

    def test_all_indices_in_interior(self):
        for n in range(3, 20):
            for count in [1, 2, 3]:
                result = _even_sentinels(n, count, exclude={0, n-1})
                for idx in result:
                    self.assertGreater(idx, 0, f"n={n}: idx={idx} not interior")
                    self.assertLess(idx, n - 1, f"n={n}: idx={idx} not interior")

    def test_n4_count1_exact(self):
        # round(1 * 3 / 2) = round(1.5) – Python banker's round → 2; clamp(2, 1, 2)=2
        self.assertEqual(self._s(4, 1), [2])


class TestDesignConstants(unittest.TestCase):
    """Locked constants must match the selected cost-aware Step3 profile."""

    def test_asbs_default_constants(self):
        self.assertEqual(NN_SENTINEL_COUNT, 3)
        self.assertEqual(AA_SENTINEL_COUNT, 1)
        self.assertEqual(AA_CONFLICT_MAX_SCAN, 200)


# ──────────────────────────────────────────────────────────────────────
# Helpers for ASBS tests
# ──────────────────────────────────────────────────────────────────────

def _make_verdict_fn(verdicts: dict[str, str]):
    def fn(tag: str) -> str | None:
        return verdicts.get(tag)
    return fn


# ──────────────────────────────────────────────────────────────────────
# Section 2: ASBS status codes and intervals
# ──────────────────────────────────────────────────────────────────────

class TestASBSLineStatuses(unittest.TestCase):

    def test_singleton_affected(self):
        tags = ["v1"]
        r = run_asbs_segment(tags, _make_verdict_fn({"v1": "AFFECTED"}))
        self.assertEqual(r.status, "singleton")
        self.assertEqual(r.predicted_affected, ["v1"])
        self.assertEqual(r.probe_tags, ["v1"])
        self.assertEqual(r.verdict_sources["v1"], "agent")

    def test_singleton_not_affected(self):
        tags = ["v1"]
        r = run_asbs_segment(tags, _make_verdict_fn({"v1": "NOT_AFFECTED"}))
        self.assertEqual(r.status, "singleton")
        self.assertEqual(r.predicted_affected, [])

    def test_empty_segment(self):
        r = run_asbs_segment([], _make_verdict_fn({}))
        self.assertEqual(r.status, "empty_segment")

    def test_na_suffix(self):
        # N...A → binary search for first AFFECTED
        tags = ["v1", "v2", "v3", "v4", "v5"]
        verdicts = {"v1": "NOT_AFFECTED", "v2": "NOT_AFFECTED", "v3": "AFFECTED", "v4": "AFFECTED", "v5": "AFFECTED"}
        r = run_asbs_segment(tags, _make_verdict_fn(verdicts))
        self.assertEqual(r.status, "na_suffix_boundary")
        self.assertEqual(r.predicted_affected, ["v3", "v4", "v5"])
        # v3, v4, v5 inferred; only boundary tags probed
        self.assertIn("v1", r.probe_tags)
        self.assertIn("v5", r.probe_tags)
        for t in ["v4", "v5"]:
            if t not in r.probe_tags:
                self.assertEqual(r.verdict_sources.get(t), "inferred_interval")

    def test_an_prefix(self):
        tags = ["v1", "v2", "v3", "v4", "v5"]
        verdicts = {"v1": "AFFECTED", "v2": "AFFECTED", "v3": "AFFECTED", "v4": "NOT_AFFECTED", "v5": "NOT_AFFECTED"}
        r = run_asbs_segment(tags, _make_verdict_fn(verdicts))
        self.assertEqual(r.status, "an_prefix_boundary")
        self.assertEqual(r.predicted_affected, ["v1", "v2", "v3"])

    def test_nn_no_affected_all_sentinels_na(self):
        # N...N: 5 tags, nn_sentinel_count=3, even sentinels = [1,2,3]
        tags = ["v0", "v1", "v2", "v3", "v4"]
        verdicts = {t: "NOT_AFFECTED" for t in tags}
        r = run_asbs_segment(tags, _make_verdict_fn(verdicts),
                              nn_sentinel_count=3)
        self.assertEqual(r.status, "nn_no_affected_inferred")
        self.assertEqual(r.predicted_affected, [])
        for t in tags:
            if t not in r.probe_tags:
                self.assertEqual(r.verdict_sources[t], "inferred_no_affected")

    def test_nn_middle_interval_inferred(self):
        # N...N but middle is AFFECTED
        tags = ["v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9"]
        # v0,v9 = N (endpoints); v4,v5 AFFECTED (middle)
        verdicts = {t: "NOT_AFFECTED" for t in tags}
        verdicts["v4"] = "AFFECTED"
        verdicts["v5"] = "AFFECTED"
        r = run_asbs_segment(tags, _make_verdict_fn(verdicts), nn_sentinel_count=3)
        self.assertEqual(r.status, "nn_middle_interval_inferred")
        self.assertIn("v4", r.predicted_affected)
        self.assertIn("v5", r.predicted_affected)
        self.assertNotIn("v0", r.predicted_affected)
        self.assertNotIn("v9", r.predicted_affected)

    def test_aa_full_line_inferred_no_conflict(self):
        tags = ["v0", "v1", "v2", "v3", "v4"]
        verdicts = {t: "AFFECTED" for t in tags}
        r = run_asbs_segment(tags, _make_verdict_fn(verdicts), aa_sentinel_count=1)
        self.assertEqual(r.status, "aa_full_line_inferred")
        self.assertEqual(sorted(r.predicted_affected), sorted(tags))
        # unprobed tags get inferred_full_line_affected
        for t in tags:
            if t not in r.probe_tags:
                self.assertEqual(r.verdict_sources.get(t), "inferred_full_line_affected")

    def test_aa_conflict_small_line_full_scan(self):
        # A...A but sentinel hit is NOT_AFFECTED → conflict → full scan (n ≤ max_scan)
        # n=5, aa_sentinel_count=1: sentinel at idx=2 (_even_sentinels(5,1,{0,4})=[2])
        # So set v2=NOT_AFFECTED to trigger conflict
        tags = ["v0", "v1", "v2", "v3", "v4"]
        verdicts = {"v0": "AFFECTED", "v1": "AFFECTED", "v2": "NOT_AFFECTED", "v3": "AFFECTED", "v4": "AFFECTED"}
        r = run_asbs_segment(tags, _make_verdict_fn(verdicts),
                              aa_sentinel_count=1, aa_conflict_max_scan=50)
        self.assertEqual(r.status, "aa_conflict_fallback_scan")
        self.assertIn("v0", r.predicted_affected)
        self.assertNotIn("v2", r.predicted_affected)

    def test_aa_conflict_guard_triggered_large_line(self):
        # A...A conflict on a very large line (n > max_scan guard)
        # n=10, aa_sentinel_count=1: sentinel at idx=4 (_even_sentinels(10,1,{0,9})=[4])
        # Set v4=NOT_AFFECTED to trigger conflict at sentinel, max_scan=5 < n=10
        tags = [f"v{i}" for i in range(10)]
        verdicts = {t: "AFFECTED" for t in tags}
        verdicts["v4"] = "NOT_AFFECTED"   # conflict at sentinel index 4
        r = run_asbs_segment(tags, _make_verdict_fn(verdicts),
                              aa_sentinel_count=1, aa_conflict_max_scan=5)
        self.assertEqual(r.status, "aa_conflict_exceeds_max_scan")
        self.assertEqual(r.predicted_affected, [])

    def test_probe_tags_are_agent_sourced(self):
        # All actually-probed tags must have verdict_source="agent".
        # Provide full verdicts so binary-search midpoints don't return None.
        tags = ["v0", "v1", "v2", "v3", "v4"]
        verdicts = {
            "v0": "NOT_AFFECTED",
            "v1": "NOT_AFFECTED",
            "v2": "AFFECTED",
            "v3": "AFFECTED",
            "v4": "AFFECTED",
        }
        r = run_asbs_segment(tags, _make_verdict_fn(verdicts))
        self.assertEqual(r.status, "na_suffix_boundary")
        for t in r.probe_tags:
            self.assertEqual(r.verdict_sources.get(t), "agent",
                             f"probed tag {t} should have verdict_source=agent")


# ──────────────────────────────────────────────────────────────────────
# Section 3: fixed_segment_sentinel
# ──────────────────────────────────────────────────────────────────────

class TestFixedSegmentSentinel(unittest.TestCase):

    def test_empty_fixed_segment(self):
        r = run_fixed_segment_sentinel([], _make_verdict_fn({}))
        self.assertEqual(r.status, "empty_fixed_segment")

    def test_singleton_fixed_probe(self):
        r = run_fixed_segment_sentinel(["v0"], _make_verdict_fn({"v0": "NOT_AFFECTED"}))
        self.assertEqual(r.status, "fixed_segment_probe_clear")
        self.assertEqual(r.probe_tags, ["v0"])
        self.assertEqual(r.verdict_sources["v0"], "agent")

    def test_two_tag_probes_both_endpoints(self):
        tags = ["v0", "v1"]
        r = run_fixed_segment_sentinel(tags, _make_verdict_fn({"v0": "NOT_AFFECTED", "v1": "NOT_AFFECTED"}))
        self.assertIn("v0", r.probe_tags)
        self.assertIn("v1", r.probe_tags)
        self.assertEqual(r.status, "fixed_segment_probe_clear")

    def test_three_tag_probes_endpoints_plus_middle(self):
        # n=3, fixed_seg_sentinel=1: probe {0, 1, 2}
        tags = ["v0", "v1", "v2"]
        verdicts = {"v0": "NOT_AFFECTED", "v1": "NOT_AFFECTED", "v2": "NOT_AFFECTED"}
        r = run_fixed_segment_sentinel(tags, _make_verdict_fn(verdicts), fixed_seg_sentinel=1)
        self.assertIn("v0", r.probe_tags)
        self.assertIn("v1", r.probe_tags)   # middle sentinel
        self.assertIn("v2", r.probe_tags)
        self.assertEqual(r.status, "fixed_segment_probe_clear")

    def test_hit_detection(self):
        tags = ["v0", "v1", "v2", "v3", "v4"]
        verdicts = {t: "NOT_AFFECTED" for t in tags}
        verdicts["v2"] = "AFFECTED"  # middle sentinel will catch this (n=5, sentinel at idx=2)
        r = run_fixed_segment_sentinel(tags, _make_verdict_fn(verdicts), fixed_seg_sentinel=1)
        self.assertEqual(r.status, "fixed_segment_probe_hit")

    def test_clear_unprobed_tags_get_fixed_segment_clear_source(self):
        tags = ["v0", "v1", "v2", "v3", "v4"]
        verdicts = {t: "NOT_AFFECTED" for t in tags}
        r = run_fixed_segment_sentinel(tags, _make_verdict_fn(verdicts), fixed_seg_sentinel=1)
        self.assertEqual(r.status, "fixed_segment_probe_clear")
        for t in tags:
            if t not in r.probe_tags:
                self.assertEqual(r.verdict_sources.get(t), "fixed_segment_clear",
                                 f"unprobed {t} should be fixed_segment_clear")

    def test_predicted_affected_always_empty(self):
        # Even on hit, predicted_affected is empty (caller decides to escalate)
        tags = ["v0", "v1", "v2"]
        verdicts = {"v0": "AFFECTED", "v1": "AFFECTED", "v2": "AFFECTED"}
        r = run_fixed_segment_sentinel(tags, _make_verdict_fn(verdicts), fixed_seg_sentinel=1)
        self.assertEqual(r.status, "fixed_segment_probe_hit")
        self.assertEqual(r.predicted_affected, [])


# ──────────────────────────────────────────────────────────────────────
# Section 4: line_scheduler seed selection
# ──────────────────────────────────────────────────────────────────────

class TestLineSchedulerSeeds(unittest.TestCase):

    def _make_obf(self, family_lines: dict[str, list[str]]) -> dict[str, list[str]]:
        """ordered_by_family mock."""
        return dict(family_lines)

    def test_stride3_includes_idx0_idx3_last(self):
        # For 7 lines [l0..l6], stride=3: idx 0,3 + always last (l6)
        obf = {"f1": ["l0", "l1", "l2", "l3", "l4", "l5", "l6"]}
        result = _stride_lines(obf, 3)
        self.assertIn("l0", result)   # idx=0
        self.assertIn("l3", result)   # idx=3
        self.assertIn("l6", result)   # last
        self.assertNotIn("l1", result)
        self.assertNotIn("l2", result)

    def test_stride3_always_includes_last_even_if_not_divisible(self):
        obf = {"f1": ["l0", "l1", "l2", "l3", "l4"]}  # 5 lines
        result = _stride_lines(obf, 3)
        self.assertIn("l0", result)
        self.assertIn("l3", result)
        self.assertIn("l4", result)  # last must be included

    def test_no_fix_lines_correct(self):
        release = {
            "l1": ["t1", "t2", "t3"],
            "l2": ["t4", "t5"],      # all fix-containing
            "l3": ["t6", "t7"],      # one fix-containing
        }
        fix_tags = {"t4", "t5", "t6"}
        result = _no_fix_lines(release, fix_tags)
        self.assertIn("l1", result)   # all tags free of fix
        self.assertNotIn("l2", result)  # all fix-containing
        self.assertIn("l3", result)   # t7 not in fix_tags

    def test_static_neighbors_radius1(self):
        lines = ["l0", "l1", "l2", "l3", "l4"]
        seeds = {"l2"}
        result = _static_neighbors(lines, seeds, 1)
        self.assertIn("l1", result)
        self.assertIn("l2", result)
        self.assertIn("l3", result)
        self.assertNotIn("l0", result)
        self.assertNotIn("l4", result)

    def test_static_neighbors_boundary(self):
        lines = ["l0", "l1", "l2"]
        seeds = {"l0"}
        result = _static_neighbors(lines, seeds, 1)
        self.assertIn("l0", result)
        self.assertIn("l1", result)
        self.assertNotIn("l2", result)

    def test_compute_seed_lines_nofix_stride3_file(self):
        # Minimal 3-family setup: no-fix stride + file-endpoint seeds
        release = {
            "l1": ["t1", "t2", "t3"],   # no fix tags
            "l2": ["t4", "t5"],         # fix-containing
            "l3": ["t6", "t7"],         # no fix tags + file endpoint
            "l4": ["t8"],               # no fix tags
            "l5": ["t9", "t10"],        # no fix tags
        }
        fix_containing = {"t4", "t5"}
        file_endpoints = {"l3"}   # l3 has a fix-touched file in endpoint tags
        obf = {"default": ["l1", "l2", "l3", "l4", "l5"]}  # 1 family

        seeds = compute_seed_lines(
            repo_name="curl",
            release_lines=release,
            ordered_by_family=obf,
            fix_containing_tags=fix_containing,
            file_endpoint_lines=file_endpoints,
            stride=3,
            file_neighbor_radius=1,
        )
        # file-neighbor: l3 ±1 → l2, l3, l4
        self.assertIn("l3", seeds)   # file endpoint itself
        self.assertIn("l2", seeds)   # neighbor -1
        self.assertIn("l4", seeds)   # neighbor +1
        # stride-3 over no-fix lines [l1,l3,l4,l5]: idx 0 (l1), 3 (l5) + last (l5)
        self.assertIn("l1", seeds)


# ──────────────────────────────────────────────────────────────────────
# Section 5: verdict_source taxonomy (Q14)
# ──────────────────────────────────────────────────────────────────────

class TestVerdictSourceTaxonomy(unittest.TestCase):
    """Verify that verdict_source values are assigned according to Q14 rules."""

    VALID_SOURCES = {
        "agent",
        "inferred_interval",
        "inferred_no_affected",
        "inferred_full_line_affected",
        "fixed_segment_clear",
        "probe_error",
        # "aa_conflict_scan" is NOT a verdict_source: it lives in certificate.rule only
    }

    def _all_sources_valid(self, r: ASBSResult) -> None:
        for tag, src in r.verdict_sources.items():
            self.assertIn(src, self.VALID_SOURCES,
                          f"tag {tag} has unknown verdict_source={src!r}")

    def test_nn_no_affected_sources(self):
        tags = ["v0", "v1", "v2", "v3", "v4"]
        verdicts = {t: "NOT_AFFECTED" for t in tags}
        r = run_asbs_segment(tags, _make_verdict_fn(verdicts), nn_sentinel_count=3)
        self._all_sources_valid(r)
        for t in tags:
            if t not in r.probe_tags:
                self.assertEqual(r.verdict_sources[t], "inferred_no_affected")

    def test_suffix_sources(self):
        tags = ["v0", "v1", "v2", "v3"]
        verdicts = {"v0": "NOT_AFFECTED", "v1": "AFFECTED", "v2": "AFFECTED", "v3": "AFFECTED"}
        r = run_asbs_segment(tags, _make_verdict_fn(verdicts))
        self._all_sources_valid(r)
        for t in r.probe_tags:
            self.assertEqual(r.verdict_sources[t], "agent")
        for t in tags:
            if t not in r.probe_tags and t in r.predicted_affected:
                self.assertEqual(r.verdict_sources[t], "inferred_interval")

    def test_aa_full_line_sources(self):
        tags = [f"v{i}" for i in range(10)]
        verdicts = {t: "AFFECTED" for t in tags}
        r = run_asbs_segment(tags, _make_verdict_fn(verdicts), aa_sentinel_count=1)
        self._all_sources_valid(r)

    def test_fixed_segment_clear_sources(self):
        tags = ["v0", "v1", "v2", "v3", "v4"]
        verdicts = {t: "NOT_AFFECTED" for t in tags}
        r = run_fixed_segment_sentinel(tags, _make_verdict_fn(verdicts), fixed_seg_sentinel=1)
        for tag, src in r.verdict_sources.items():
            self.assertIn(src, {"agent", "fixed_segment_clear"})
        for t in r.probe_tags:
            self.assertEqual(r.verdict_sources[t], "agent")
        for t in tags:
            if t not in r.probe_tags:
                self.assertEqual(r.verdict_sources.get(t), "fixed_segment_clear")


# ──────────────────────────────────────────────────────────────────────
# Section 6: AA_CONFLICT_MAX_SCAN guard
# ──────────────────────────────────────────────────────────────────────

class TestAAConflictGuard(unittest.TestCase):

    def test_guard_constant_is_200(self):
        self.assertEqual(AA_CONFLICT_MAX_SCAN, 200)

    def test_small_conflict_full_scan(self):
        # n=10, sentinel at idx=4 (verified: _even_sentinels(10,1,{0,9})=[4])
        # Set v4=NOT_AFFECTED → conflict detected at sentinel → full scan (10 ≤ 200 guard)
        tags = [f"v{i}" for i in range(10)]
        verdicts = {t: "AFFECTED" for t in tags}
        verdicts["v4"] = "NOT_AFFECTED"
        r = run_asbs_segment(tags, _make_verdict_fn(verdicts),
                              aa_sentinel_count=1, aa_conflict_max_scan=200)
        self.assertEqual(r.status, "aa_conflict_fallback_scan")
        self.assertEqual(len(r.probe_tags), 10)

    def test_large_conflict_guard_triggered(self):
        # n=201, sentinel at idx=100 (round(1*200/2)=100)
        # v100=NOT_AFFECTED → conflict at sentinel → guard triggers (201 > 200)
        tags = [f"v{i}" for i in range(201)]
        verdicts = {t: "AFFECTED" for t in tags}
        verdicts["v100"] = "NOT_AFFECTED"
        r = run_asbs_segment(tags, _make_verdict_fn(verdicts),
                              aa_sentinel_count=1, aa_conflict_max_scan=200)
        self.assertEqual(r.status, "aa_conflict_exceeds_max_scan")
        self.assertEqual(r.predicted_affected, [])
        # Only endpoint (v0, v200) + sentinel (v100) probed
        self.assertEqual(len(r.probe_tags), 3)

    def test_n_equals_guard_does_full_scan(self):
        # n=200 = guard → full scan allowed (≤ 200)
        # n=200: sentinel idx = round(1*199/2) = round(99.5) = 100 (banker: 100 even)
        tags = [f"v{i}" for i in range(200)]
        verdicts = {t: "AFFECTED" for t in tags}
        verdicts["v100"] = "NOT_AFFECTED"
        r = run_asbs_segment(tags, _make_verdict_fn(verdicts),
                              aa_sentinel_count=1, aa_conflict_max_scan=200)
        self.assertEqual(r.status, "aa_conflict_fallback_scan")
        self.assertEqual(len(r.probe_tags), 200)

    def test_certificate_records_guard_info(self):
        tags = [f"v{i}" for i in range(201)]
        verdicts = {t: "AFFECTED" for t in tags}
        verdicts["v100"] = "NOT_AFFECTED"
        r = run_asbs_segment(tags, _make_verdict_fn(verdicts),
                              aa_sentinel_count=1, aa_conflict_max_scan=200)
        self.assertEqual(r.status, "aa_conflict_exceeds_max_scan")
        cert = r.certificate
        self.assertIn("max_scan_guard", cert)
        self.assertEqual(cert["max_scan_guard"], 200)
        self.assertIn("note", cert)


# ────────────────────────────────────────────────────────────────────
# Section 7: invalid verdict handling (issue 1)
# ────────────────────────────────────────────────────────────────────

class TestInvalidVerdictHandling(unittest.TestCase):
    """If verdict_fn returns anything outside VALID_VERDICTS, ASBS must
    stop inference and return a *_probe_error status. No tag may receive
    an inferred source when any probe failure has occurred."""

    def _none_fn(self):
        return _make_verdict_fn({})  # all tags → None

    def test_endpoint_left_none_returns_probe_error(self):
        tags = ["v0", "v1", "v2"]
        r = run_asbs_segment(tags, self._none_fn())
        self.assertIn("probe_error", r.status)
        self.assertEqual(r.predicted_affected, [])

    def test_endpoint_right_none_returns_probe_error(self):
        def vf(t: str) -> str | None:
            return "AFFECTED" if t == "v0" else None
        r = run_asbs_segment(["v0", "v1", "v2"], vf)
        self.assertIn("probe_error", r.status)
        self.assertEqual(r.predicted_affected, [])

    def test_nn_sentinel_none_returns_probe_error(self):
        # Both endpoints NOT_AFFECTED but sentinel returns None
        def vf(t: str) -> str | None:
            if t in ("v0", "v4"):
                return "NOT_AFFECTED"
            return None  # sentinel v2 → None
        r = run_asbs_segment(["v0", "v1", "v2", "v3", "v4"], vf, nn_sentinel_count=1)
        self.assertIn("probe_error", r.status)
        self.assertEqual(r.predicted_affected, [])

    def test_na_binary_search_none_midpoint_returns_probe_error(self):
        # N...A: endpoints valid, but midpoint during binary search returns None
        call_count = {"n": 0}
        def vf(t: str) -> str | None:
            call_count["n"] += 1
            if t == "v0":
                return "NOT_AFFECTED"
            if t == "v4":
                return "AFFECTED"
            return None  # any mid-point probe → failure
        r = run_asbs_segment(["v0", "v1", "v2", "v3", "v4"], vf)
        self.assertIn("probe_error", r.status)
        self.assertEqual(r.predicted_affected, [])

    def test_aa_sentinel_none_stops_inference(self):
        # Both endpoints AFFECTED but sentinel returns None
        def vf(t: str) -> str | None:
            if t in ("v0", "v4"):
                return "AFFECTED"
            return None
        r = run_asbs_segment(["v0", "v1", "v2", "v3", "v4"], vf, aa_sentinel_count=1)
        self.assertIn("probe_error", r.status)
        self.assertEqual(r.predicted_affected, [])

    def test_invalid_string_verdict_treated_as_failure(self):
        # TIMEOUT, UNKNOWN, empty string are not AFFECTED/NOT_AFFECTED
        for bad in ("TIMEOUT", "UNKNOWN", "", "unknown", "INCONCLUSIVE"):
            def vf(t: str, bad=bad) -> str | None:
                return bad
            r = run_asbs_segment(["v0", "v1"], vf)
            self.assertIn("probe_error", r.status,
                          f"bad verdict {bad!r} should cause probe_error")
            self.assertEqual(r.predicted_affected, [])

    def test_exception_in_verdict_fn_treated_as_none(self):
        def vf(t: str) -> str | None:
            raise RuntimeError("agent crash")
        r = run_asbs_segment(["v0", "v1", "v2"], vf)
        self.assertIn("probe_error", r.status)
        self.assertEqual(r.predicted_affected, [])

    def test_probe_error_verdict_source_on_failed_tag(self):
        r = run_asbs_segment(["v0", "v1"], _make_verdict_fn({}))
        self.assertEqual(r.verdict_sources.get("v0"), "probe_error")

    def test_fixed_segment_sentinel_none_returns_probe_error(self):
        r = run_fixed_segment_sentinel(["v0", "v1", "v2"], _make_verdict_fn({}))
        self.assertEqual(r.status, "fixed_segment_probe_error")
        self.assertEqual(r.predicted_affected, [])
        # failed tag gets probe_error source
        failed = next(iter(r.verdict_sources.values()))
        self.assertEqual(failed, "probe_error")


# ────────────────────────────────────────────────────────────────────
# Section 8: aa_conflict_scan is NOT a verdict_source (issue 2)
# ────────────────────────────────────────────────────────────────────

class TestAAConflictScanSource(unittest.TestCase):
    """In aa_conflict_fallback_scan, all probed tags are verdict_source='agent'.
    'aa_conflict_scan' must only appear in certificate.rule, never in verdict_source."""

    def test_aa_conflict_all_probed_tags_are_agent_sourced(self):
        # n=5, sentinel at idx=2; set v2=NOT_AFFECTED to trigger conflict
        tags = ["v0", "v1", "v2", "v3", "v4"]
        verdicts = {"v0": "AFFECTED", "v1": "AFFECTED", "v2": "NOT_AFFECTED",
                    "v3": "AFFECTED", "v4": "AFFECTED"}
        r = run_asbs_segment(tags, _make_verdict_fn(verdicts),
                              aa_sentinel_count=1, aa_conflict_max_scan=200)
        self.assertEqual(r.status, "aa_conflict_fallback_scan")
        # All probed tags → agent
        for t in r.probe_tags:
            self.assertEqual(r.verdict_sources.get(t), "agent",
                             f"probed tag {t} in fallback scan must be 'agent'")

    def test_aa_conflict_no_aa_conflict_scan_in_verdict_sources(self):
        tags = ["v0", "v1", "v2", "v3", "v4"]
        verdicts = {"v0": "AFFECTED", "v1": "AFFECTED", "v2": "NOT_AFFECTED",
                    "v3": "AFFECTED", "v4": "AFFECTED"}
        r = run_asbs_segment(tags, _make_verdict_fn(verdicts),
                              aa_sentinel_count=1, aa_conflict_max_scan=200)
        for t, src in r.verdict_sources.items():
            self.assertNotEqual(src, "aa_conflict_scan",
                                f"tag {t} must not have verdict_source='aa_conflict_scan'")

    def test_aa_conflict_scan_in_certificate_rule_only(self):
        tags = ["v0", "v1", "v2", "v3", "v4"]
        verdicts = {"v0": "AFFECTED", "v1": "AFFECTED", "v2": "NOT_AFFECTED",
                    "v3": "AFFECTED", "v4": "AFFECTED"}
        r = run_asbs_segment(tags, _make_verdict_fn(verdicts),
                              aa_sentinel_count=1, aa_conflict_max_scan=200)
        self.assertEqual(r.status, "aa_conflict_fallback_scan")
        self.assertEqual(r.certificate.get("rule"), "aa_conflict_full_scan")

    def test_full_scan_probes_all_tags(self):
        tags = [f"v{i}" for i in range(10)]
        verdicts = {t: "AFFECTED" for t in tags}
        verdicts["v4"] = "NOT_AFFECTED"
        r = run_asbs_segment(tags, _make_verdict_fn(verdicts),
                              aa_sentinel_count=1, aa_conflict_max_scan=200)
        self.assertEqual(r.status, "aa_conflict_fallback_scan")
        self.assertEqual(len(r.probe_tags), 10)
        self.assertEqual(set(r.probe_tags), set(tags))


# ────────────────────────────────────────────────────────────────────
# Section 9: line_scheduler OpenSSL family isolation (issue 5)
# ────────────────────────────────────────────────────────────────────

class TestOpenSSLFamilyIsolation(unittest.TestCase):
    """OpenSSL mainline / fips / engine must never be mixed into one family."""

    def _make_openssl_lines(self) -> dict[str, list[str]]:
        return {
            "1.0.0": ["OpenSSL_1_0_0"], "1.1.1": ["openssl-1.1.1"],
            "3.0": ["openssl-3.0.0"], "3.1": ["openssl-3.1.0"],
            "fips-1.0": ["OpenSSL-fips-1.0"], "fips-2.0": ["OpenSSL-fips-2.0"],
            "engine-1.0": ["OpenSSL-engine-1.0"],
        }

    def test_openssl_families_are_separate(self):
        from vulnversion.stage3_verify.line_scheduler import _ordered_by_family
        release_lines = self._make_openssl_lines()
        obf = _ordered_by_family("openssl", release_lines)
        families = list(obf.keys())
        mainline_present = any("mainline" in f for f in families)
        fips_present = any("fips" in f for f in families)
        engine_present = any("engine" in f for f in families)
        self.assertTrue(mainline_present, f"openssl-mainline not found in {families}")
        self.assertTrue(fips_present, f"openssl-fips not found in {families}")
        self.assertTrue(engine_present, f"openssl-engine not found in {families}")

    def test_fips_lines_not_in_mainline_family(self):
        from vulnversion.stage3_verify.line_scheduler import _ordered_by_family
        release_lines = self._make_openssl_lines()
        obf = _ordered_by_family("openssl", release_lines)
        mainline_lines = set(obf.get("openssl-mainline", []))
        fips_lines = set(obf.get("openssl-fips", []))
        engine_lines = set(obf.get("openssl-engine", []))
        self.assertFalse(mainline_lines & fips_lines,
                         "fips lines leaked into mainline")
        self.assertFalse(mainline_lines & engine_lines,
                         "engine lines leaked into mainline")
        self.assertFalse(fips_lines & engine_lines,
                         "engine lines leaked into fips")

    def test_openssl_mainline_internally_sorted_newest_first(self):
        from vulnversion.stage3_verify.line_scheduler import _ordered_by_family
        release_lines = {
            "1.0.0": [], "1.1.1": [], "3.0": [], "3.1": [],
        }
        obf = _ordered_by_family("openssl", release_lines)
        mainline = obf.get("openssl-mainline", [])
        # newest first: 3.1 at index 0, 3.0 at index 1, then older lines
        self.assertEqual(mainline[0], "3.1", f"3.1 should be first (newest): {mainline}")
        self.assertLess(mainline.index("3.1"), mainline.index("3.0"),
                        "3.1 should come before 3.0 (newest first)")
        self.assertLess(mainline.index("3.0"), mainline.index("1.1.1"),
                        "3.0 should come before 1.1.1")

    def test_non_openssl_repos_single_family(self):
        from vulnversion.stage3_verify.line_scheduler import _ordered_by_family
        for repo in ("FFmpeg", "linux", "qemu", "curl", "httpd",
                     "ImageMagick", "openjpeg", "wireshark"):
            lines = {"1.0": [], "2.0": [], "3.0": []}
            obf = _ordered_by_family(repo, lines)
            self.assertEqual(len(obf), 1,
                             f"{repo} should have 1 family, got {list(obf.keys())}")


# ────────────────────────────────────────────────────────────────────
# Section 10: artifact_eval.py (issue 6)
# ────────────────────────────────────────────────────────────────────

class TestArtifactEval(unittest.TestCase):
    """fixed_segment_clear must participate in official CM;
    ablation metric excludes it."""

    def _make_rows(self, tag_verdicts: dict[str, tuple[str | None, str]]) -> list[dict]:
        """Build tag_rows from {tag: (verdict, verdict_source)}."""
        rows = []
        for tag, (verdict, src) in tag_verdicts.items():
            rows.append({"tag": tag, "verdict": verdict, "verdict_source": src})
        return rows

    def test_fixed_segment_clear_correct_becomes_tn_in_official(self):
        from vulnversion.stage3_verify.artifact_eval import evaluate_step3_output
        rows = self._make_rows({
            "v1": ("AFFECTED", "agent"),
            "v2": (None, "fixed_segment_clear"),   # GT: NOT_AFFECTED → should be TN
        })
        result = evaluate_step3_output(
            tag_rows=rows,
            all_release_tags=["v1", "v2"],
            gt_affected_tags=["v1"],
        )
        cm = result.official_metrics.cm
        self.assertEqual(cm.tp, 1)
        self.assertEqual(cm.tn, 1, "fixed_segment_clear correct → TN in official")
        self.assertEqual(cm.fp, 0)
        self.assertEqual(cm.fn, 0)

    def test_fixed_segment_clear_wrong_becomes_fn_in_official(self):
        from vulnversion.stage3_verify.artifact_eval import evaluate_step3_output
        rows = self._make_rows({
            "v1": ("NOT_AFFECTED", "agent"),
            "v2": (None, "fixed_segment_clear"),   # GT: AFFECTED → should be FN
        })
        result = evaluate_step3_output(
            tag_rows=rows,
            all_release_tags=["v1", "v2"],
            gt_affected_tags=["v2"],   # v2 is GT affected but clear → FN
        )
        cm = result.official_metrics.cm
        self.assertEqual(cm.fn, 1, "fixed_segment_clear wrong → FN in official")

    def test_fixed_segment_clear_excluded_from_ablation_cm(self):
        from vulnversion.stage3_verify.artifact_eval import evaluate_step3_output
        rows = self._make_rows({
            "v1": ("AFFECTED", "agent"),
            "v2": (None, "fixed_segment_clear"),
        })
        result = evaluate_step3_output(
            tag_rows=rows,
            all_release_tags=["v1", "v2"],
            gt_affected_tags=["v1"],
        )
        abl = result.ablation_metrics.cm
        # ablation: only v1 is resolved; v2 is in UNK
        self.assertEqual(abl.tp + abl.fp + abl.fn + abl.tn, 1)
        self.assertGreater(abl.unk, 0, "fixed_segment_clear should count as UNK in ablation")

    def test_agent_error_never_in_cm_cells(self):
        from vulnversion.stage3_verify.artifact_eval import evaluate_step3_output
        rows = self._make_rows({
            "v1": ("AFFECTED", "agent"),
            "v2": (None, "agent_error"),   # GT affected
        })
        result = evaluate_step3_output(
            tag_rows=rows,
            all_release_tags=["v1", "v2"],
            gt_affected_tags=["v1", "v2"],
        )
        cm = result.official_metrics.cm
        # v2 is agent_error → FN_execution, not FN
        self.assertEqual(cm.fn, 0, "agent_error must NOT count as FN in CM cells")
        self.assertEqual(cm.fn_execution, 1)

    def test_missing_row_is_unresolved_not_agent_error(self):
        from vulnversion.stage3_verify.artifact_eval import evaluate_step3_output
        rows = self._make_rows({
            "v1": ("AFFECTED", "agent"),
        })
        result = evaluate_step3_output(
            tag_rows=rows,
            all_release_tags=["v1", "v2"],
            gt_affected_tags=["v1", "v2"],
        )
        self.assertIn("v2", result.unresolved_tags)
        self.assertNotIn("v2", result.agent_error_tags)
        cm = result.official_metrics.cm
        self.assertEqual(cm.fn_execution, 0)
        self.assertEqual(cm.fn_unresolved, 1)

    def test_deferred_row_is_separate_from_agent_error(self):
        from vulnversion.stage3_verify.artifact_eval import evaluate_step3_output
        rows = self._make_rows({
            "v1": ("AFFECTED", "agent"),
            "v2": (None, "deferred"),
        })
        result = evaluate_step3_output(
            tag_rows=rows,
            all_release_tags=["v1", "v2"],
            gt_affected_tags=["v1", "v2"],
        )
        self.assertIn("v2", result.deferred_tags)
        self.assertNotIn("v2", result.agent_error_tags)
        cm = result.official_metrics.cm
        self.assertEqual(cm.fn_execution, 0)
        self.assertEqual(cm.fn_deferred, 1)

    def test_both_metric_sets_in_to_dict(self):
        from vulnversion.stage3_verify.artifact_eval import evaluate_step3_output
        rows = self._make_rows({"v1": ("AFFECTED", "agent")})
        result = evaluate_step3_output(
            tag_rows=rows,
            all_release_tags=["v1"],
            gt_affected_tags=["v1"],
        )
        d = result.to_dict()
        self.assertIn("official_metrics", d)
        self.assertIn("ablation_metrics_without_fixed_segment_clear", d)
        self.assertIn("unresolved_tags", d)
        self.assertIn("deferred_tags", d)


if __name__ == "__main__":
    unittest.main()
