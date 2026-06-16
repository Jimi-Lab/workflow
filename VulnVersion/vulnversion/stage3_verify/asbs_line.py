"""asbs_line.py – Adaptive Binary Search per release line.

Faithful implementation of the ASBS algorithm as validated in:
  tests/simulate_step3_gt_scheduler.py      (line-local interval logic)
  tests/simulate_git_guided_scheduler.py    (fixed-segment sentinel logic)

Empirical results (BaseDataOrder.json, 1128 CVEs, GT-oracle simulation):
  all_lines_asbs  sentinel=3:       exact=1083/1128  micro_F1=0.997270  avg_probes=87.20
  git_guided_soft s=3, fs=1:        exact=1114/1128  micro_F1=0.999882  avg_probes=85.55
  staged_nofix_stride3_file r=1:
    AA=1 cost-aware default:         exact=1112/1128  micro_F1=0.999822  avg_probes=68.34
    AA=3 high-precision reference:  exact=1114/1128  micro_F1=0.999882  avg_probes=70.53

Design constants (derived from 1128-CVE full simulation):
  NN_SENTINEL_COUNT    = 3    # N…N middle-risk probe count
  AA_SENTINEL_COUNT    = 1    # A…A conflict-check probe count
  FIXED_SEG_SENTINEL   = 1    # fixed-segment probe: endpoints + 1 mid
  AA_CONFLICT_MAX_SCAN = 200  # guard: skip full-scan if n > this threshold

Invalid-verdict contract (issue 1):
  verdict_fn is permitted to return ONLY "AFFECTED" or "NOT_AFFECTED".
  Any other value (None, "", UNKNOWN, TIMEOUT, or an exception) is treated
  as a probe failure. ASBS stops inference at that point and returns a
  *_probe_error status. No tag is ever inferred when a probe failure exists.
  verdict_source for a failed probe is "probe_error".

aa_conflict_scan (issue 2):
  In an A…A conflict fallback-scan, every tag IS probed by the agent.
  verdict_source = "agent" for all probed tags.
  "aa_conflict_full_scan" appears in certificate.rule ONLY, never in
  verdict_source.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

VerdictFn = Callable[[str], str | None]

# ──────────────────────────────────────────────────────────────────────
# Valid verdict values
# ──────────────────────────────────────────────────────────────────────

VALID_VERDICTS: frozenset[str] = frozenset({"AFFECTED", "NOT_AFFECTED"})

# ──────────────────────────────────────────────────────────────────────
# Design constants
# ──────────────────────────────────────────────────────────────────────

NN_SENTINEL_COUNT: int = 3
AA_SENTINEL_COUNT: int = 1
FIXED_SEG_SENTINEL: int = 1
AA_CONFLICT_MAX_SCAN: int = 200


# ──────────────────────────────────────────────────────────────────────
# Helper: even-sentinel placement (exact copy from simulator)
# ──────────────────────────────────────────────────────────────────────

def _even_sentinels(
    n: int,
    count: int,
    *,
    exclude: frozenset[int] | set[int] | None = None,
) -> list[int]:
    """Return up to *count* evenly-spaced interior indices in [0, n-1],
    excluding any index in *exclude*.

    Index placement formula (exact copy from simulator):
        idx = round(k * (n - 1) / (count + 1))   for k in 1..count
        clamped to [1, n-2]

    Python 3 banker's rounding applies (round(0.5)=0, round(1.5)=2, …).

    Degenerate cases:
        n <= 2  → []  (no interior index)
        count <= 0 → []
    """
    if n <= 2 or count <= 0:
        return []
    excluded: set[int] = set(exclude) if exclude else set()
    out: list[int] = []
    for k in range(1, count + 1):
        idx = round(k * (n - 1) / (count + 1))
        idx = max(1, min(n - 2, idx))
        if idx not in excluded and idx not in out:
            out.append(idx)
    return out


# ──────────────────────────────────────────────────────────────────────
# Output dataclass
# ──────────────────────────────────────────────────────────────────────

@dataclass
class ASBSResult:
    """Result of running ASBS on one line or segment."""

    status: str
    predicted_affected: list[str]
    probe_tags: list[str]
    verdicts: dict[str, str | None] = field(default_factory=dict)
    certificate: dict[str, Any] = field(default_factory=dict)
    verdict_sources: dict[str, str] = field(default_factory=dict)

    # verdict_source taxonomy (Q14):
    #   "agent"                      – tag verdict from agent call
    #   "inferred_interval"          – N…A / A…N binary-search interval tag
    #   "inferred_no_affected"       – N…N, all sentinels NOT_AFFECTED
    #   "inferred_full_line_affected"– A…A, no sentinel conflict
    #   "fixed_segment_clear"        – fix-containing seg, sentinel clear
    #   "probe_error"                – verdict_fn returned invalid value

    @property
    def probe_count(self) -> int:
        return len(self.probe_tags)

    @property
    def predicted_count(self) -> int:
        return len(self.predicted_affected)


# ──────────────────────────────────────────────────────────────────────
# Internal: validated probe wrapper
# ──────────────────────────────────────────────────────────────────────

class _ProbeFailure(Exception):
    """Raised internally when verdict_fn returns an invalid value."""
    def __init__(self, tag: str, raw_value: Any):
        super().__init__(f"invalid verdict for {tag!r}: {raw_value!r}")
        self.tag = tag
        self.raw_value = raw_value


def _validate_verdict(tag: str, raw: Any) -> str:
    """Return raw if it is AFFECTED/NOT_AFFECTED, else raise _ProbeFailure."""
    if raw in VALID_VERDICTS:
        return raw  # type: ignore[return-value]
    raise _ProbeFailure(tag, raw)


def _probe_error_result(
    tags: list[str],
    probe_tags: list[str],
    verdicts: dict[str, str | None],
    verdict_sources: dict[str, str],
    failure: _ProbeFailure,
    *,
    status_prefix: str = "",
) -> ASBSResult:
    """Build a probe_error result. All probed tags are agent-sourced;
    the failed tag gets verdict_source='probe_error'."""
    verdict_sources[failure.tag] = "probe_error"
    prefix = f"{status_prefix}_" if status_prefix else ""
    return ASBSResult(
        status=f"{prefix}probe_error",
        predicted_affected=[],
        probe_tags=list(probe_tags),
        verdicts=dict(verdicts),
        certificate={
            "rule": "probe_error",
            "failed_tag": failure.tag,
            "raw_value": repr(failure.raw_value),
        },
        verdict_sources=dict(verdict_sources),
    )


# ──────────────────────────────────────────────────────────────────────
# Binary search helpers (exact copy from simulator)
# ──────────────────────────────────────────────────────────────────────

def _binary_first_true(
    lo_false: int,
    hi_true: int,
    probe_fn: Callable[[int], bool],
) -> int:
    lo, hi = lo_false, hi_true
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if probe_fn(mid):
            hi = mid
        else:
            lo = mid
    return hi


def _binary_first_false(
    lo_true: int,
    hi_false: int,
    probe_fn: Callable[[int], bool],
) -> int:
    lo, hi = lo_true, hi_false
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if probe_fn(mid):
            lo = mid
        else:
            hi = mid
    return hi


# ──────────────────────────────────────────────────────────────────────
# Core ASBS for a no-fix segment
# ──────────────────────────────────────────────────────────────────────

def run_asbs_segment(
    tags: list[str],
    verdict_fn: VerdictFn,
    *,
    nn_sentinel_count: int = NN_SENTINEL_COUNT,
    aa_sentinel_count: int = AA_SENTINEL_COUNT,
    aa_conflict_max_scan: int = AA_CONFLICT_MAX_SCAN,
) -> ASBSResult:
    """Run ASBS on a single no-fix segment (oldest→newest ordering).

    Invalid verdict contract:
      If verdict_fn returns any value outside {"AFFECTED","NOT_AFFECTED"},
      ASBS returns immediately with status *_probe_error and
      predicted_affected=[]. No inference is performed on a partial result.

    Implements 5 endpoint patterns:
      A…A  : aa_sentinel_count interior points; full-scan on conflict
      N…A  : binary search for first AFFECTED (suffix interval)
      A…N  : binary search for last AFFECTED  (prefix interval)
      N…N  : nn_sentinel_count sentinels; middle interval if any AFFECTED
      single: probe the single tag directly
    """
    n = len(tags)
    known: dict[str, str | None] = {}
    probed: list[str] = []
    vsources: dict[str, str] = {}

    def do_probe(tag: str) -> str:
        """Probe tag, record to known+probed, raise _ProbeFailure if invalid."""
        try:
            raw = verdict_fn(tag)
        except Exception as exc:
            raw = None
            _ = exc
        v = raw if raw in VALID_VERDICTS else None
        known[tag] = v
        probed.append(tag)
        vsources[tag] = "agent"
        if v is None:
            raise _ProbeFailure(tag, raw)
        return v  # type: ignore[return-value]

    def probe_idx(idx: int) -> str:
        return do_probe(tags[idx])

    # ─ empty ─────────────────────────────────────────────────────────
    if n == 0:
        return ASBSResult(
            status="empty_segment",
            predicted_affected=[],
            probe_tags=[],
            certificate={"rule": "empty_segment"},
        )

    # ─ singleton ─────────────────────────────────────────────────────
    if n == 1:
        try:
            v = probe_idx(0)
        except _ProbeFailure as pf:
            return _probe_error_result(tags, probed, known, vsources, pf, status_prefix="singleton")
        predicted = [tags[0]] if v == "AFFECTED" else []
        return ASBSResult(
            status="singleton",
            predicted_affected=predicted,
            probe_tags=list(probed),
            verdicts=dict(known),
            certificate={"rule": "singleton", "tag": tags[0], "verdict": v},
            verdict_sources=dict(vsources),
        )

    # ─ probe endpoints ───────────────────────────────────────────────
    try:
        left = probe_idx(0)
    except _ProbeFailure as pf:
        return _probe_error_result(tags, probed, known, vsources, pf, status_prefix="left_endpoint")
    try:
        right = probe_idx(n - 1)
    except _ProbeFailure as pf:
        return _probe_error_result(tags, probed, known, vsources, pf, status_prefix="right_endpoint")

    # ─ A…A ───────────────────────────────────────────────────────────
    if left == "AFFECTED" and right == "AFFECTED":
        conflict = False
        for idx in _even_sentinels(n, aa_sentinel_count, exclude={0, n - 1}):
            try:
                v = probe_idx(idx)
            except _ProbeFailure as pf:
                return _probe_error_result(tags, probed, known, vsources, pf, status_prefix="aa_sentinel")
            if v != "AFFECTED":
                conflict = True
                break

        if not conflict:
            predicted = list(tags)
            for t in tags:
                if t not in vsources:
                    vsources[t] = "inferred_full_line_affected"
            return ASBSResult(
                status="aa_full_line_inferred",
                predicted_affected=predicted,
                probe_tags=list(probed),
                verdicts=dict(known),
                certificate={
                    "rule": "aa_all_probed_points_affected",
                    "n": n,
                    "probe_count": len(probed),
                },
                verdict_sources=dict(vsources),
            )

        # Conflict: do full-scan if n ≤ guard
        if n <= aa_conflict_max_scan:
            for idx in range(n):
                if tags[idx] not in {t for t in probed}:
                    try:
                        probe_idx(idx)
                    except _ProbeFailure as pf:
                        return _probe_error_result(
                            tags, probed, known, vsources, pf, status_prefix="aa_conflict_scan"
                        )
            predicted = [t for t in tags if known.get(t) == "AFFECTED"]
            # All probed tags are agent; no tag has a non-agent source
            for t in probed:
                vsources[t] = "agent"   # already set, but be explicit
            return ASBSResult(
                status="aa_conflict_fallback_scan",
                predicted_affected=predicted,
                probe_tags=list(probed),
                verdicts=dict(known),
                certificate={
                    "rule": "aa_conflict_full_scan",   # NOT verdict_source
                    "n": n,
                    "max_scan_guard": aa_conflict_max_scan,
                },
                verdict_sources=dict(vsources),
            )

        # Guard triggered: can't full-scan
        return ASBSResult(
            status="aa_conflict_exceeds_max_scan",
            predicted_affected=[],
            probe_tags=list(probed),
            verdicts=dict(known),
            certificate={
                "rule": "aa_conflict_guard_triggered",
                "n": n,
                "max_scan_guard": aa_conflict_max_scan,
                "note": "line too large for conflict full-scan; interval uncertain",
            },
            verdict_sources=dict(vsources),
        )

    # ─ N…A (suffix interval) ─────────────────────────────────────────
    if left == "NOT_AFFECTED" and right == "AFFECTED":
        try:
            def _is_affected(idx: int) -> bool:
                return probe_idx(idx) == "AFFECTED"
            first = _binary_first_true(0, n - 1, _is_affected)
        except _ProbeFailure as pf:
            return _probe_error_result(
                tags, probed, known, vsources, pf, status_prefix="na_binary_search"
            )
        predicted = list(tags[first:])
        for t in predicted:
            if t not in vsources:
                vsources[t] = "inferred_interval"
        return ASBSResult(
            status="na_suffix_boundary",
            predicted_affected=predicted,
            probe_tags=list(probed),
            verdicts=dict(known),
            certificate={
                "rule": "na_binary_search_first_affected",
                "first_affected_index": first,
                "last_not_affected_index": first - 1,
            },
            verdict_sources=dict(vsources),
        )

    # ─ A…N (prefix interval) ─────────────────────────────────────────
    if left == "AFFECTED" and right == "NOT_AFFECTED":
        try:
            def _is_affected_an(idx: int) -> bool:
                return probe_idx(idx) == "AFFECTED"
            first_false = _binary_first_false(0, n - 1, _is_affected_an)
        except _ProbeFailure as pf:
            return _probe_error_result(
                tags, probed, known, vsources, pf, status_prefix="an_binary_search"
            )
        predicted = list(tags[:first_false])
        for t in predicted:
            if t not in vsources:
                vsources[t] = "inferred_interval"
        return ASBSResult(
            status="an_prefix_boundary",
            predicted_affected=predicted,
            probe_tags=list(probed),
            verdicts=dict(known),
            certificate={
                "rule": "an_binary_search_last_affected",
                "last_affected_index": first_false - 1,
                "first_not_affected_index": first_false,
            },
            verdict_sources=dict(vsources),
        )

    # ─ N…N (middle or no affected) ───────────────────────────────────
    sentinels = _even_sentinels(n, nn_sentinel_count, exclude={0, n - 1})
    affected_sentinels: list[int] = []
    for idx in sentinels:
        try:
            v = probe_idx(idx)
        except _ProbeFailure as pf:
            return _probe_error_result(
                tags, probed, known, vsources, pf, status_prefix="nn_sentinel"
            )
        if v == "AFFECTED":
            affected_sentinels.append(idx)

    if not affected_sentinels:
        for t in tags:
            if t not in vsources:
                vsources[t] = "inferred_no_affected"
        return ASBSResult(
            status="nn_no_affected_inferred",
            predicted_affected=[],
            probe_tags=list(probed),
            verdicts=dict(known),
            certificate={
                "rule": "nn_all_sentinels_not_affected",
                "sentinel_indices": sentinels,
                "sentinel_count_used": len(sentinels),
                "nn_sentinel_count": nn_sentinel_count,
            },
            verdict_sources=dict(vsources),
        )

    # Middle interval: binary search boundaries
    left_a = min(affected_sentinels)
    right_a = max(affected_sentinels)
    known_idx = {i: known[tags[i]] for i in range(n) if tags[i] in known}
    left_false_cands = [i for i, v in known_idx.items() if i < left_a and v == "NOT_AFFECTED"]
    right_false_cands = [i for i, v in known_idx.items() if i > right_a and v == "NOT_AFFECTED"]
    lo_false = max(left_false_cands) if left_false_cands else 0
    hi_false = min(right_false_cands) if right_false_cands else n - 1

    try:
        def _is_aff_mid(idx: int) -> bool:
            return probe_idx(idx) == "AFFECTED"
        first = _binary_first_true(lo_false, left_a, _is_aff_mid)
        first_false_right = _binary_first_false(right_a, hi_false, _is_aff_mid)
    except _ProbeFailure as pf:
        return _probe_error_result(
            tags, probed, known, vsources, pf, status_prefix="nn_middle_binary_search"
        )

    predicted = list(tags[first:first_false_right])
    for t in predicted:
        if t not in vsources:
            vsources[t] = "inferred_interval"
    return ASBSResult(
        status="nn_middle_interval_inferred",
        predicted_affected=predicted,
        probe_tags=list(probed),
        verdicts=dict(known),
        certificate={
            "rule": "nn_middle_interval_binary_search",
            "sentinel_indices": sentinels,
            "affected_sentinel_indices": affected_sentinels,
            "first_affected_index": first,
            "first_not_affected_after_index": first_false_right,
        },
        verdict_sources=dict(vsources),
    )


# ──────────────────────────────────────────────────────────────────────
# Fixed-segment sentinel
# ──────────────────────────────────────────────────────────────────────

def run_fixed_segment_sentinel(
    tags: list[str],
    verdict_fn: VerdictFn,
    *,
    fixed_seg_sentinel: int = FIXED_SEG_SENTINEL,
) -> ASBSResult:
    """Probe a fix-containing segment with minimal probes.

    Probes endpoints + _even_sentinels(n, fixed_seg_sentinel) interior points.
    If any probe returns AFFECTED → status=fixed_segment_probe_hit.
    If all probes NOT_AFFECTED → status=fixed_segment_probe_clear.
    If any probe returns invalid → status=fixed_segment_probe_error.

    predicted_affected is always [] (caller escalates on hit).

    verdict_source per tag:
      probed tags            → "agent"
      unprobed (clear only)  → "fixed_segment_clear"
      invalid probe          → "probe_error" (stops immediately)
    """
    n = len(tags)
    if n == 0:
        return ASBSResult(
            status="empty_fixed_segment",
            predicted_affected=[],
            probe_tags=[],
            certificate={"rule": "empty_fixed_segment"},
        )

    probe_indices: set[int] = {0, n - 1}
    probe_indices.update(_even_sentinels(n, fixed_seg_sentinel, exclude={0, n - 1}))

    known: dict[str, str | None] = {}
    probed: list[str] = []
    vsources: dict[str, str] = {}
    hit = False

    for idx in sorted(probe_indices):
        tag = tags[idx]
        try:
            raw = verdict_fn(tag)
        except Exception:
            raw = None
        if raw not in VALID_VERDICTS:
            known[tag] = None
            probed.append(tag)
            vsources[tag] = "probe_error"
            return ASBSResult(
                status="fixed_segment_probe_error",
                predicted_affected=[],
                probe_tags=list(probed),
                verdicts=dict(known),
                certificate={
                    "rule": "fixed_segment_probe_error",
                    "failed_tag": tag,
                    "raw_value": repr(raw),
                },
                verdict_sources=dict(vsources),
            )
        known[tag] = raw
        probed.append(tag)
        vsources[tag] = "agent"
        if raw == "AFFECTED":
            hit = True

    if not hit:
        for t in tags:
            if t not in vsources:
                vsources[t] = "fixed_segment_clear"

    return ASBSResult(
        status="fixed_segment_probe_hit" if hit else "fixed_segment_probe_clear",
        predicted_affected=[],
        probe_tags=list(probed),
        verdicts=dict(known),
        certificate={
            "rule": "fixed_segment_sentinel",
            "probe_indices": sorted(probe_indices),
            "probe_hit": hit,
            "fixed_seg_sentinel": fixed_seg_sentinel,
        },
        verdict_sources=dict(vsources),
    )
