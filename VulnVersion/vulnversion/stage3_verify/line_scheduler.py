"""line_scheduler.py – staged line scheduler for Step3 (staged_nofix_stride3_file).

Implements the deterministic line selection + dynamic BFS expansion validated
by the GT-oracle and git-guided simulators on 1128 CVEs (BaseDataOrder.json).

Empirical results (GT-oracle simulation, BaseDataOrder.json, 1128 CVEs):
  Strategy                   | avg probes | exact CVEs | micro_F1
  all_lines_soft (upper bound)    85.55      1114/1128   0.999882
  staged_nofix_stride3_file AA=1  68.34      1112/1128   0.999822
  staged_nofix_stride3_file AA=3  70.53      1114/1128   0.999882
  oracle_affected_lines (lower)   29.03      1114/1128   0.999882

  AA=1 is the current cost-aware default. AA=3 is retained as a
  high-precision reference profile.

Policy: staged_nofix_stride3_file + expansion_radius=1
  seed = file_endpoint_lines_±1 ∪ stride-3 over no-fix-only lines
  expansion: BFS, each positive line queues ±1 same-family neighbors (radius=1)
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable

from vulnversion.stage3_verify.version_registry import line_family_key
from vulnversion.stage3_verify.vuln_tree import _line_family_rank, _line_version


# ──────────────────────────────────────────────────────────────────────
# Data types
# ──────────────────────────────────────────────────────────────────────

@dataclass
class LineSchedulePlan:
    """Output of build_schedule: the ordered set of lines to probe."""

    seed_lines: list[str]          # deterministic initial lines
    repo_name: str
    ordered_by_family: dict[str, list[str]]    # family → [lines oldest→newest]
    fix_containing_tags: set[str]              # tags reachable from fix commits
    file_endpoint_lines: set[str]              # lines whose endpoint tags contain fix-touched file
    all_lines: dict[str, list[str]]            # line → [tags oldest→newest]


# ──────────────────────────────────────────────────────────────────────
# Helper functions (faithful copies from simulator scripts)
# ──────────────────────────────────────────────────────────────────────

def _line_to_family(ordered_by_family: dict[str, list[str]]) -> dict[str, str]:
    """Invert ordered_by_family: line → family."""
    return {
        line: family
        for family, lines in ordered_by_family.items()
        for line in lines
    }


def _family_neighbors(
    ordered_by_family: dict[str, list[str]],
    line_to_family: dict[str, str],
    line: str,
    radius: int,
) -> set[str]:
    """Return lines within *radius* hops in the same family (±radius steps)."""
    family = line_to_family.get(line)
    if family is None:
        return set()
    lines = ordered_by_family.get(family, [])
    idx_by_line = {v: i for i, v in enumerate(lines)}
    idx = idx_by_line.get(line)
    if idx is None:
        return set()
    out: set[str] = set()
    for delta in range(1, radius + 1):
        if idx - delta >= 0:
            out.add(lines[idx - delta])
        if idx + delta < len(lines):
            out.add(lines[idx + delta])
    return out


def _static_neighbors(
    lines_in_family: list[str],
    seeds: set[str],
    radius: int,
) -> set[str]:
    """Expand a seed set within a family list by ±radius steps."""
    if radius <= 0 or not seeds:
        return set(seeds)
    out = set(seeds)
    idx_by_line = {line: idx for idx, line in enumerate(lines_in_family)}
    for line in seeds:
        idx = idx_by_line.get(line)
        if idx is None:
            continue
        for delta in range(1, radius + 1):
            if idx - delta >= 0:
                out.add(lines_in_family[idx - delta])
            if idx + delta < len(lines_in_family):
                out.add(lines_in_family[idx + delta])
    return out


def _no_fix_lines(
    release_lines: dict[str, list[str]],
    fix_containing_tags: set[str],
) -> set[str]:
    """Lines that have at least one tag NOT reachable from any fix commit."""
    return {
        line
        for line, tags in release_lines.items()
        if any(tag not in fix_containing_tags for tag in tags)
    }


def _stride_lines(
    ordered_by_family: dict[str, list[str]],
    stride: int,
    *,
    lines_subset: set[str] | None = None,
) -> set[str]:
    """Select every *stride*-th line per family (always including last line).

    Faithful copy of simulator _stride_lines:
      for each family:
        scoped = lines filtered by lines_subset (or all)
        select indices 0, stride, 2*stride, ... plus always the last
    """
    if stride <= 0:
        return set()
    out: set[str] = set()
    for _, lines in ordered_by_family.items():
        scoped = [line for line in lines if lines_subset is None or line in lines_subset]
        for idx, line in enumerate(scoped):
            if idx % stride == 0:
                out.add(line)
        if scoped:
            out.add(scoped[-1])
    return out


def _file_endpoint_lines(
    release_lines: dict[str, list[str]],
    fix_touched_files: set[str],
    file_exists_fn: Callable[[str, str], bool],
) -> set[str]:
    """Lines whose oldest or newest tag contains any fix-touched file.

    Args:
        release_lines: line → [tags oldest→newest]
        fix_touched_files: set of file paths touched by fix commits
        file_exists_fn: (tag, file_path) → bool  (uses git_ops.repo)
    """
    out: set[str] = set()
    for line, tags in release_lines.items():
        if not tags:
            continue
        endpoints = [tags[0], tags[-1]]
        for tag in endpoints:
            for fpath in fix_touched_files:
                if file_exists_fn(tag, fpath):
                    out.add(line)
                    break
            if line in out:
                break
    return out


def _ordered_by_family(
    repo_name: str,
    release_lines: dict[str, list[str]],
) -> dict[str, list[str]]:
    """Group release lines into families and sort newest→oldest within each family.

    Uses version_registry.line_family_key for family assignment and
    vuln_tree._line_version for per-line version ordering — exactly matching
    build_base_vuln_tree() so stride/neighbor logic is consistent with VulnTree.

    Families are ordered by _line_family_rank so the returned dict iteration
    order is meaningful for multi-family repos (e.g. openssl mainline / fips /
    engine are kept in separate families and never mixed into one chain).
    """
    groups: dict[str, list[str]] = {}
    for line in release_lines:
        fk = line_family_key(repo_name, line)
        groups.setdefault(fk, []).append(line)
    # Sort within each family: newest first (reverse=True matches VulnTree)
    for fk, lines in groups.items():
        groups[fk] = sorted(
            lines,
            key=lambda line: _line_version(repo_name, line),
            reverse=True,
        )
    # Return in family-rank order so callers iterating the dict get a
    # deterministic, semantically ordered result (mainline before fips/engine).
    ordered_families = sorted(groups.keys(), key=lambda fk: _line_family_rank(repo_name, fk))
    return {fk: groups[fk] for fk in ordered_families}


# ──────────────────────────────────────────────────────────────────────
# Seed-line selection: staged_nofix_stride3_file
# ──────────────────────────────────────────────────────────────────────

def compute_seed_lines(
    *,
    repo_name: str,
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    fix_containing_tags: set[str],
    file_endpoint_lines: set[str],
    stride: int = 3,
    file_neighbor_radius: int = 1,
) -> set[str]:
    """Compute seed lines for staged_nofix_stride3_file policy.

    seed = file_endpoint_lines_±1 ∪ stride-3 over no-fix-only lines

    This matches simulate_staged_expansion_scheduler._initial_lines_for_policy
    with policy="staged_nofix_stride3_file".
    """
    no_fix = _no_fix_lines(release_lines, fix_containing_tags)

    # file-neighbor seeds: lines touching endpoint tags that contain fix files ±1 hop
    file_neighbor_seeds: set[str] = set()
    for family, lines in ordered_by_family.items():
        seeds_in_family = set(lines) & file_endpoint_lines
        file_neighbor_seeds.update(_static_neighbors(lines, seeds_in_family, file_neighbor_radius))

    # stride seeds over no-fix lines only
    stride_seeds = _stride_lines(ordered_by_family, stride, lines_subset=no_fix)

    return file_neighbor_seeds | stride_seeds


# ──────────────────────────────────────────────────────────────────────
# BFS staged expansion
# ──────────────────────────────────────────────────────────────────────

@dataclass
class LineRunResult:
    """Result of running a single line through git_guided ASBS."""
    line: str
    is_positive: bool               # any predicted AFFECTED tag or probed AFFECTED tag
    predicted_affected: list[str]
    probe_tags: list[str]
    verdict_sources: dict[str, str]
    statuses: dict[str, int]        # ASBS status → count
    fix_containing_count: int


@dataclass
class SchedulerState:
    """Mutable BFS state across all lines for one CVE."""
    visited: set[str] = field(default_factory=set)
    predicted_affected: set[str] = field(default_factory=set)
    all_probe_tags: set[str] = field(default_factory=set)
    all_verdict_sources: dict[str, str] = field(default_factory=dict)
    positive_lines: set[str] = field(default_factory=set)
    line_results: dict[str, LineRunResult] = field(default_factory=dict)
    status_counts: dict[str, int] = field(default_factory=dict)


def run_staged_scheduler(
    *,
    seed_lines: set[str],
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    fix_containing_tags: set[str],
    run_line_fn: Callable[[str, list[str]], LineRunResult],
    expansion_radius: int = 1,
    fallback_mode: str = "none",
) -> SchedulerState:
    """Execute BFS staged expansion over lines.

    For each line processed by run_line_fn:
      - If positive (has predicted AFFECTED or probed AFFECTED):
          → queue all same-family ±radius neighbors not yet visited

    fallback_mode:
      "none"        – no fallback if no positive seeds
      "nohit_nofix" – if stage-1 has no positives, add all no-fix lines as fallback
      "nohit_all"   – if stage-1 has no positives, add all lines as fallback

    Implements the BFS logic from simulate_staged_expansion_scheduler._simulate_staged_cve.
    """
    state = SchedulerState()
    line_to_family = _line_to_family(ordered_by_family)
    all_lines = set(release_lines.keys())
    queue: deque[str] = deque(sorted(seed_lines))

    def process(line: str) -> None:
        if line in state.visited:
            return
        tags = release_lines.get(line, [])
        state.visited.add(line)
        result = run_line_fn(line, tags)
        state.line_results[line] = result
        state.predicted_affected.update(result.predicted_affected)
        state.all_probe_tags.update(result.probe_tags)
        state.all_verdict_sources.update(result.verdict_sources)
        for k, v in result.statuses.items():
            state.status_counts[k] = state.status_counts.get(k, 0) + v
        if result.is_positive:
            state.positive_lines.add(line)
            for neighbor in _family_neighbors(ordered_by_family, line_to_family, line, expansion_radius):
                if neighbor not in state.visited:
                    queue.append(neighbor)

    while queue:
        process(queue.popleft())

    # Fallback if zero positive lines after stage-1
    if not state.positive_lines and fallback_mode in {"nohit_nofix", "nohit_all"}:
        if fallback_mode == "nohit_nofix":
            fallback_lines = _no_fix_lines(release_lines, fix_containing_tags)
        else:
            fallback_lines = all_lines
        for line in sorted(fallback_lines):
            queue.append(line)
        while queue:
            process(queue.popleft())

    return state
