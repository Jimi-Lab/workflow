"""Global-state line scheduler simulator for Step3.

This experiment targets the current dominant Step3 cost source: too many
irrelevant release lines are activated and sent to tag-level probes.

The simulator keeps the VulnTree line/family graph intact.  It does not delete
lines or tags.  Instead it maintains per-line runtime state and tests dynamic
activation policies:

  1. seed high-value lines from patch-file and fix-transition evidence;
  2. run ASBS only on activated lines;
  3. use positive evidence to expand to same-family neighbors;
  4. optionally scout remaining no-fix lines cheaply before full ASBS.

Ground truth is used only as the simulated selected-probe oracle and final
metric evaluator.  It is never used to select lines or probes.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = ROOT / "tests"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from vulnversion.git_ops.repo import map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.git_reachability import batch_tags_containing
from vulnversion.stage3_verify.line_scheduler import (
    _no_fix_lines,
    _static_neighbors,
    _stride_lines,
    compute_seed_lines,
)

from simulate_module_backed_step3 import (
    _batch_path_exists,
    _changed_files_for_commits,
    _flatten_fixing_commits,
    _release_context,
    _run_git_guided_line_module,
)


DEFAULT_DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
DEFAULT_REPO_ROOT = ROOT / "repo"
DEFAULT_OUT_DIR = ROOT / "tests" / "global_state_line_scheduler_simulator"


@dataclass(frozen=True)
class SchedulerConfig:
    """One global-state activation policy."""

    name: str
    initial: str
    scout_stride: int = 0
    scout_scope: str = "none"
    scout_nn_sentinel: int = 0
    nohit_fallback: str = "none"
    positive_expand_radius: int = 1
    file_neighbor_radius: int = 1
    transition_neighbor_radius: int = 1
    all_fix_file_scout_stride: int = 0


@dataclass
class LineRuntime:
    """Runtime state for one line in one CVE simulation."""

    line: str
    state: str = "UNKNOWN"
    activation_reasons: list[str] = field(default_factory=list)
    modes: list[str] = field(default_factory=list)
    probe_tags: set[str] = field(default_factory=set)
    predicted_affected: set[str] = field(default_factory=set)
    is_positive: bool = False
    status_counts: Counter[str] = field(default_factory=Counter)

    def activate(self, reason: str) -> None:
        if reason not in self.activation_reasons:
            self.activation_reasons.append(reason)
        if self.state == "UNKNOWN":
            self.state = "QUEUED"

    def update_from_result(self, *, mode: str, result: Any) -> None:
        if mode not in self.modes:
            self.modes.append(mode)
        self.probe_tags.update(result.probe_tags)
        self.predicted_affected.update(result.predicted_affected)
        self.status_counts.update(result.statuses)
        self.is_positive = self.is_positive or result.is_positive
        self.state = "POSITIVE" if self.is_positive else "CLOSED_NO_AFFECTED"


def _load_dataset(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _repo_name(rec: dict[str, Any]) -> str:
    return str(rec.get("repo") or "").strip()


def _commits(rec: dict[str, Any]) -> list[str]:
    return _flatten_fixing_commits(
        rec.get("fixing_commits") or rec.get("fixing_commit") or rec.get("fix_commit")
    )


def _affected_set(rec: dict[str, Any], release_tags: list[str]) -> set[str]:
    mapped, _unmapped = map_gt_tags_to_repo_tags(
        sorted(str(t) for t in (rec.get("affected_version") or [])),
        release_tags,
        mode="loose",
    )
    return set(mapped)


def _line_to_family(ordered_by_family: dict[str, list[str]]) -> dict[str, str]:
    return {
        line: family
        for family, lines in ordered_by_family.items()
        for line in lines
    }


def _line_neighbors(
    ordered_by_family: dict[str, list[str]],
    line_to_family: dict[str, str],
    line: str,
    radius: int,
) -> set[str]:
    if radius <= 0:
        return set()
    family = line_to_family.get(line)
    if family is None:
        return set()
    lines = ordered_by_family.get(family, [])
    return _static_neighbors(lines, {line}, radius) - {line}


def _file_neighbor_lines(
    ordered_by_family: dict[str, list[str]],
    file_endpoint_lines: set[str],
    radius: int,
) -> set[str]:
    out: set[str] = set()
    for lines in ordered_by_family.values():
        out.update(_static_neighbors(lines, set(lines) & file_endpoint_lines, radius))
    return out


def _transition_lines(
    release_lines: dict[str, list[str]],
    fix_containing_tags: set[str],
) -> set[str]:
    out: set[str] = set()
    for line, tags in release_lines.items():
        if not tags:
            continue
        has_fix = any(tag in fix_containing_tags for tag in tags)
        has_no_fix = any(tag not in fix_containing_tags for tag in tags)
        if has_fix and has_no_fix:
            out.add(line)
    return out


def _transition_neighbor_lines(
    ordered_by_family: dict[str, list[str]],
    transition_lines: set[str],
    radius: int,
) -> set[str]:
    out: set[str] = set()
    for lines in ordered_by_family.values():
        out.update(_static_neighbors(lines, set(lines) & transition_lines, radius))
    return out


def _build_file_endpoint_lines(
    *,
    release_lines: dict[str, list[str]],
    files: list[str],
    path_exists: dict[tuple[str, str], bool],
) -> set[str]:
    out: set[str] = set()
    for line, tags in release_lines.items():
        endpoints = tags[:1] + tags[-1:] if tags else []
        if any(path_exists.get((tag, path), False) for tag in endpoints for path in files):
            out.add(line)
    return out


def _initial_lines(
    *,
    config: SchedulerConfig,
    repo_name: str,
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    fix_containing_tags: set[str],
    file_endpoint_lines: set[str],
) -> tuple[set[str], dict[str, str]]:
    """Return initial lines and one primary activation reason per line."""
    transition = _transition_lines(release_lines, fix_containing_tags)
    file_neighbors = _file_neighbor_lines(
        ordered_by_family,
        file_endpoint_lines,
        config.file_neighbor_radius,
    )
    transition_neighbors = _transition_neighbor_lines(
        ordered_by_family,
        transition,
        config.transition_neighbor_radius,
    )

    reasons: dict[str, str] = {}
    lines: set[str]
    if config.initial == "current":
        lines = compute_seed_lines(
            repo_name=repo_name,
            release_lines=release_lines,
            ordered_by_family=ordered_by_family,
            fix_containing_tags=fix_containing_tags,
            file_endpoint_lines=file_endpoint_lines,
            stride=3,
            file_neighbor_radius=1,
        )
        reasons.update({line: "current_staged_seed" for line in lines})
        return lines, reasons

    if config.initial == "file":
        lines = set(file_neighbors)
        reasons.update({line: "file_endpoint_neighbor" for line in lines})
        return lines, reasons

    if config.initial == "transition":
        lines = set(transition_neighbors)
        reasons.update({line: "fix_transition_neighbor" for line in lines})
        return lines, reasons

    if config.initial == "file_transition":
        lines = set(file_neighbors) | set(transition_neighbors)
        for line in file_neighbors:
            reasons.setdefault(line, "file_endpoint_neighbor")
        for line in transition_neighbors:
            reasons.setdefault(line, "fix_transition_neighbor")
        return lines, reasons

    raise ValueError(f"unknown initial mode: {config.initial}")


def _scout_lines(
    *,
    config: SchedulerConfig,
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    fix_containing_tags: set[str],
    visited_full: set[str],
    positive_lines: set[str],
) -> set[str]:
    if config.scout_stride <= 0 or config.scout_scope == "none":
        return set()
    no_fix = _no_fix_lines(release_lines, fix_containing_tags)
    candidates = no_fix - visited_full
    if config.scout_scope == "families_without_positive":
        line_to_family = _line_to_family(ordered_by_family)
        positive_families = {line_to_family[line] for line in positive_lines if line in line_to_family}
        candidates = {
            line for line in candidates
            if line_to_family.get(line) not in positive_families
        }
    elif config.scout_scope != "all_unvisited":
        raise ValueError(f"unknown scout scope: {config.scout_scope}")
    return _stride_lines(ordered_by_family, config.scout_stride, lines_subset=candidates)


def _all_fix_file_scout_lines(
    *,
    config: SchedulerConfig,
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    fix_containing_tags: set[str],
    file_endpoint_lines: set[str],
    visited_full: set[str],
) -> set[str]:
    """Select suspicious all-fix lines that still carry the touched file.

    This specifically tests the CVE-2023-5178-style failure mode where
    affected singleton Linux lines all contain the fix commit and are therefore
    excluded from no-fix scout.
    """
    if config.all_fix_file_scout_stride <= 0:
        return set()
    candidates = {
        line
        for line, tags in release_lines.items()
        if line in file_endpoint_lines
        and line not in visited_full
        and tags
        and all(tag in fix_containing_tags for tag in tags)
    }
    return _stride_lines(
        ordered_by_family,
        config.all_fix_file_scout_stride,
        lines_subset=candidates,
    )


def _run_line(
    *,
    line: str,
    mode: str,
    release_lines: dict[str, list[str]],
    affected_set: set[str],
    fix_containing_tags: set[str],
    config: SchedulerConfig,
) -> Any:
    nn = 3 if mode == "full" else config.scout_nn_sentinel
    return _run_git_guided_line_module(
        line=line,
        tags=release_lines.get(line, []),
        affected_set=affected_set,
        fix_containing_tags=fix_containing_tags,
        nn_sentinel_count=nn,
        aa_sentinel_count=1,
        fixed_segment_sentinel=1,
    )


def _simulate_config(
    *,
    repo_name: str,
    cve_id: str,
    rec: dict[str, Any],
    release_tags: list[str],
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    fix_containing_tags: set[str],
    file_endpoint_lines: set[str],
    config: SchedulerConfig,
) -> dict[str, Any]:
    affected_set = _affected_set(rec, release_tags)
    release_set = set(release_tags)
    affected_lines = {
        line for line, tags in release_lines.items()
        if set(tags) & affected_set
    }
    line_to_family = _line_to_family(ordered_by_family)
    runtime = {line: LineRuntime(line=line) for line in release_lines}
    queue: deque[tuple[str, str, str]] = deque()
    visited_full: set[str] = set()
    predicted: set[str] = set()
    probes: set[str] = set()
    positive_lines: set[str] = set()
    reason_counts: Counter[str] = Counter()
    mode_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()

    seeds, reasons = _initial_lines(
        config=config,
        repo_name=repo_name,
        release_lines=release_lines,
        ordered_by_family=ordered_by_family,
        fix_containing_tags=fix_containing_tags,
        file_endpoint_lines=file_endpoint_lines,
    )
    for line in sorted(seeds):
        reason = reasons.get(line, "initial")
        runtime[line].activate(reason)
        queue.append((line, "full", reason))

    def process_queue() -> None:
        while queue:
            line, mode, reason = queue.popleft()
            if line not in release_lines:
                continue
            if mode == "full" and line in visited_full:
                continue
            if mode == "scout" and "full" in runtime[line].modes:
                continue
            runtime[line].activate(reason)
            result = _run_line(
                line=line,
                mode=mode,
                release_lines=release_lines,
                affected_set=affected_set,
                fix_containing_tags=fix_containing_tags,
                config=config,
            )
            runtime[line].update_from_result(mode=mode, result=result)
            mode_counts[mode] += 1
            reason_counts[reason] += 1
            status_counts.update(result.statuses)
            probes.update(result.probe_tags)
            predicted.update(result.predicted_affected)
            if mode == "full":
                visited_full.add(line)
            if result.is_positive:
                positive_lines.add(line)
                if mode == "scout" and line not in visited_full:
                    queue.append((line, "full", "scout_positive"))
                for neighbor in _line_neighbors(
                    ordered_by_family,
                    line_to_family,
                    line,
                    config.positive_expand_radius,
                ):
                    if neighbor not in visited_full:
                        runtime[neighbor].activate("positive_neighbor")
                        queue.append((neighbor, "full", "positive_neighbor"))

    process_queue()

    scouts = _scout_lines(
        config=config,
        release_lines=release_lines,
        ordered_by_family=ordered_by_family,
        fix_containing_tags=fix_containing_tags,
        visited_full=visited_full,
        positive_lines=positive_lines,
    )
    for line in sorted(scouts):
        if line not in visited_full:
            runtime[line].activate("scout_stride")
            queue.append((line, "scout", "scout_stride"))
    process_queue()

    fixed_file_scouts = _all_fix_file_scout_lines(
        config=config,
        release_lines=release_lines,
        ordered_by_family=ordered_by_family,
        fix_containing_tags=fix_containing_tags,
        file_endpoint_lines=file_endpoint_lines,
        visited_full=visited_full,
    )
    for line in sorted(fixed_file_scouts):
        if line not in visited_full:
            runtime[line].activate("all_fix_file_scout")
            queue.append((line, "scout", "all_fix_file_scout"))
    process_queue()

    if not positive_lines and config.nohit_fallback in {"nofix", "all"}:
        fallback = _no_fix_lines(release_lines, fix_containing_tags)
        if config.nohit_fallback == "all":
            fallback = set(release_lines)
        for line in sorted(fallback):
            if line not in visited_full:
                runtime[line].activate("nohit_fallback")
                queue.append((line, "full", "nohit_fallback"))
        process_queue()

    visited_lines = {line for line, state in runtime.items() if state.modes}
    full_lines = {line for line, state in runtime.items() if "full" in state.modes}
    scout_lines = {line for line, state in runtime.items() if "scout" in state.modes}
    tp = len(predicted & affected_set)
    fp = len(predicted - affected_set)
    fn = len(affected_set - predicted)
    tn = len(release_set - affected_set - predicted)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    skipped_affected_lines = affected_lines - visited_lines
    irrelevant_active_lines = visited_lines - affected_lines

    return {
        "strategy": config.name,
        "repo": repo_name,
        "cve": cve_id,
        "release_tag_count": len(release_tags),
        "line_count": len(release_lines),
        "affected_line_count": len(affected_lines),
        "visited_line_count": len(visited_lines),
        "full_line_count": len(full_lines),
        "scout_line_count": len(scout_lines),
        "deferred_line_count": len(set(release_lines) - visited_lines),
        "positive_line_count": len(positive_lines),
        "irrelevant_active_line_count": len(irrelevant_active_lines),
        "skipped_affected_line_count": len(skipped_affected_lines),
        "probe_count": len(probes),
        "predicted_count": len(predicted),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "exact_match": fp == 0 and fn == 0,
        "has_fn": fn > 0,
        "has_fp": fp > 0,
        "fn_tags": sorted(affected_set - predicted),
        "fp_tags": sorted(predicted - affected_set),
        "skipped_affected_lines": sorted(skipped_affected_lines),
        "activation_reason_counts": dict(reason_counts),
        "mode_counts": dict(mode_counts),
        "status_counts": dict(status_counts),
    }


def _percentile(values: list[int], pct: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    idx = round((len(ordered) - 1) * pct)
    return int(ordered[idx])


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    cm = Counter()
    repos: dict[str, list[dict[str, Any]]] = defaultdict(list)
    probes = [int(row["probe_count"]) for row in rows]
    for row in rows:
        cm.update({"TP": row["tp"], "FP": row["fp"], "FN": row["fn"], "TN": row["tn"]})
        repos[row["repo"]].append(row)
    precision = cm["TP"] / (cm["TP"] + cm["FP"]) if cm["TP"] + cm["FP"] else 1.0
    recall = cm["TP"] / (cm["TP"] + cm["FN"]) if cm["TP"] + cm["FN"] else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    def avg(key: str) -> float:
        return statistics.mean(float(row[key]) for row in rows) if rows else 0.0

    return {
        "cves": len(rows),
        "avg_probes": avg("probe_count"),
        "p50_probes": _percentile(probes, 0.50),
        "p95_probes": _percentile(probes, 0.95),
        "exact_cves": sum(1 for row in rows if row["exact_match"]),
        "fn_cves": sum(1 for row in rows if row["has_fn"]),
        "fp_cves": sum(1 for row in rows if row["has_fp"]),
        "avg_affected_lines": avg("affected_line_count"),
        "avg_visited_lines": avg("visited_line_count"),
        "avg_full_lines": avg("full_line_count"),
        "avg_scout_lines": avg("scout_line_count"),
        "avg_deferred_lines": avg("deferred_line_count"),
        "avg_irrelevant_active_lines": avg("irrelevant_active_line_count"),
        "irrelevant_active_line_ratio": (
            sum(row["irrelevant_active_line_count"] for row in rows)
            / sum(row["visited_line_count"] for row in rows)
            if sum(row["visited_line_count"] for row in rows)
            else 0.0
        ),
        "skipped_affected_line_cves": sum(
            1 for row in rows if row["skipped_affected_line_count"] > 0
        ),
        "version": {
            "TP": cm["TP"],
            "FP": cm["FP"],
            "FN": cm["FN"],
            "TN": cm["TN"],
            "precision": precision,
            "recall": recall,
            "f1": f1,
        },
        "by_repo": {
            repo: {
                "cves": len(rs),
                "avg_probes": statistics.mean(float(r["probe_count"]) for r in rs),
                "avg_visited_lines": statistics.mean(float(r["visited_line_count"]) for r in rs),
                "avg_affected_lines": statistics.mean(float(r["affected_line_count"]) for r in rs),
                "avg_irrelevant_active_lines": statistics.mean(float(r["irrelevant_active_line_count"]) for r in rs),
                "exact_cves": sum(1 for r in rs if r["exact_match"]),
                "fn_cves": sum(1 for r in rs if r["has_fn"]),
                "fp_cves": sum(1 for r in rs if r["has_fp"]),
            }
            for repo, rs in sorted(repos.items())
        },
    }


def _configs() -> list[SchedulerConfig]:
    return [
        SchedulerConfig(
            name="control_current",
            initial="current",
            scout_stride=0,
            scout_scope="none",
            nohit_fallback="none",
        ),
        SchedulerConfig(
            name="file_first_nohit_nofix",
            initial="file",
            scout_stride=0,
            scout_scope="none",
            nohit_fallback="nofix",
        ),
        SchedulerConfig(
            name="file_first_no_fallback",
            initial="file",
            scout_stride=0,
            scout_scope="none",
            nohit_fallback="none",
        ),
        SchedulerConfig(
            name="transition_first_nohit_nofix",
            initial="transition",
            scout_stride=0,
            scout_scope="none",
            nohit_fallback="nofix",
        ),
        SchedulerConfig(
            name="transition_first_no_fallback",
            initial="transition",
            scout_stride=0,
            scout_scope="none",
            nohit_fallback="none",
        ),
        SchedulerConfig(
            name="file_transition_nohit_nofix",
            initial="file_transition",
            scout_stride=0,
            scout_scope="none",
            nohit_fallback="nofix",
        ),
        SchedulerConfig(
            name="file_transition_no_fallback",
            initial="file_transition",
            scout_stride=0,
            scout_scope="none",
            nohit_fallback="none",
        ),
        SchedulerConfig(
            name="transition_scout_s3_all",
            initial="transition",
            scout_stride=3,
            scout_scope="all_unvisited",
            scout_nn_sentinel=0,
            nohit_fallback="nofix",
        ),
        SchedulerConfig(
            name="transition_scout_s4_all",
            initial="transition",
            scout_stride=4,
            scout_scope="all_unvisited",
            scout_nn_sentinel=0,
            nohit_fallback="nofix",
        ),
        SchedulerConfig(
            name="transition_scout_s2_all",
            initial="transition",
            scout_stride=2,
            scout_scope="all_unvisited",
            scout_nn_sentinel=0,
            nohit_fallback="nofix",
        ),
        SchedulerConfig(
            name="transition_scout_s1_all",
            initial="transition",
            scout_stride=1,
            scout_scope="all_unvisited",
            scout_nn_sentinel=0,
            nohit_fallback="nofix",
        ),
        SchedulerConfig(
            name="transition_scout_s4_all_expand2",
            initial="transition",
            scout_stride=4,
            scout_scope="all_unvisited",
            scout_nn_sentinel=0,
            nohit_fallback="nofix",
            positive_expand_radius=2,
        ),
        SchedulerConfig(
            name="transition_scout_s4_expand2_allfixfile_s4",
            initial="transition",
            scout_stride=4,
            scout_scope="all_unvisited",
            scout_nn_sentinel=0,
            nohit_fallback="nofix",
            positive_expand_radius=2,
            all_fix_file_scout_stride=4,
        ),
        SchedulerConfig(
            name="transition_scout_s4_expand2_allfixfile_s2",
            initial="transition",
            scout_stride=4,
            scout_scope="all_unvisited",
            scout_nn_sentinel=0,
            nohit_fallback="nofix",
            positive_expand_radius=2,
            all_fix_file_scout_stride=2,
        ),
        SchedulerConfig(
            name="transition_scout_s3_all_expand2",
            initial="transition",
            scout_stride=3,
            scout_scope="all_unvisited",
            scout_nn_sentinel=0,
            nohit_fallback="nofix",
            positive_expand_radius=2,
        ),
        SchedulerConfig(
            name="transition_scout_s2_all_expand2",
            initial="transition",
            scout_stride=2,
            scout_scope="all_unvisited",
            scout_nn_sentinel=0,
            nohit_fallback="nofix",
            positive_expand_radius=2,
        ),
        SchedulerConfig(
            name="global_scout_s4_all",
            initial="file_transition",
            scout_stride=4,
            scout_scope="all_unvisited",
            scout_nn_sentinel=0,
            nohit_fallback="nofix",
        ),
        SchedulerConfig(
            name="global_scout_s3_all",
            initial="file_transition",
            scout_stride=3,
            scout_scope="all_unvisited",
            scout_nn_sentinel=0,
            nohit_fallback="nofix",
        ),
        SchedulerConfig(
            name="global_scout_s3_families_without_positive",
            initial="file_transition",
            scout_stride=3,
            scout_scope="families_without_positive",
            scout_nn_sentinel=0,
            nohit_fallback="nofix",
        ),
        SchedulerConfig(
            name="global_scout_s2_families_without_positive",
            initial="file_transition",
            scout_stride=2,
            scout_scope="families_without_positive",
            scout_nn_sentinel=0,
            nohit_fallback="nofix",
        ),
    ]


def run(dataset: Path, repo_root: Path, out_dir: Path, limit: int | None = None) -> dict[str, Any]:
    data = _load_dataset(dataset)
    items = sorted(data.items())
    if limit is not None:
        items = items[:limit]

    by_repo: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for cve, rec in items:
        repo_name = _repo_name(rec)
        if repo_name:
            by_repo[repo_name].append((cve, rec))

    rows: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    configs = _configs()

    for repo_name, records in sorted(by_repo.items()):
        context = _release_context(repo_name, repo_root / repo_name)
        repo = context["repo"]
        release_tags = context["release_tags"]
        release_lines = context["release_lines"]
        ordered_by_family = context["ordered_by_family"]
        all_commits = {commit for _cve, rec in records for commit in _commits(rec)}
        contains = batch_tags_containing(
            repo=repo,
            release_tags=release_tags,
            target_commits=all_commits,
        )

        changed_cache: dict[str, list[str]] = {}
        changed_files: dict[str, list[str]] = {}
        path_queries: set[tuple[str, str]] = set()
        for cve, rec in records:
            try:
                files = _changed_files_for_commits(repo, _commits(rec), changed_cache)
            except Exception as exc:  # pragma: no cover - diagnostic path
                failures.append({"repo": repo_name, "cve": cve, "stage": "changed_files", "error": str(exc)})
                files = []
            changed_files[cve] = files
            for tags in release_lines.values():
                endpoints = tags[:1] + tags[-1:] if tags else []
                for tag in endpoints:
                    for path in files:
                        path_queries.add((tag, path))
        path_exists = _batch_path_exists(repo, path_queries)

        for cve, rec in records:
            fix_containing_tags: set[str] = set()
            for commit in _commits(rec):
                result = contains.get(commit, {"ok": False, "tags": []})
                if result.get("ok"):
                    fix_containing_tags.update(result.get("tags", []))
            file_endpoint_lines = _build_file_endpoint_lines(
                release_lines=release_lines,
                files=changed_files.get(cve, []),
                path_exists=path_exists,
            )
            for config in configs:
                rows.append(
                    _simulate_config(
                        repo_name=repo_name,
                        cve_id=cve,
                        rec=rec,
                        release_tags=release_tags,
                        release_lines=release_lines,
                        ordered_by_family=ordered_by_family,
                        fix_containing_tags=fix_containing_tags,
                        file_endpoint_lines=file_endpoint_lines,
                        config=config,
                    )
                )

    per_strategy: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        per_strategy[row["strategy"]].append(row)
    summary = {strategy: _summarize(rs) for strategy, rs in sorted(per_strategy.items())}
    fn_cases = [
        row for row in rows
        if row["has_fn"] or row["has_fp"] or row["skipped_affected_line_count"] > 0
    ]

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    with (out_dir / "per_cve.jsonl").open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    (out_dir / "fn_cases.json").write_text(
        json.dumps(fn_cases, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (out_dir / "failures.json").write_text(
        json.dumps(failures, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    lines = [
        "# Global-State Line Scheduler Simulator",
        "",
        "GT is used only as selected-probe oracle and final evaluator.",
        "",
        "| strategy | avg probes | p50 | p95 | exact | FN CVEs | FP CVEs | avg active lines | avg deferred lines | avg irrelevant active lines | irrelevant active % | version FN | P | R | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for strategy, s in summary.items():
        v = s["version"]
        lines.append(
            f"| {strategy} | {s['avg_probes']:.2f} | {s['p50_probes']} | {s['p95_probes']} | "
            f"{s['exact_cves']}/{s['cves']} | {s['fn_cves']} | {s['fp_cves']} | "
            f"{s['avg_visited_lines']:.2f} | {s['avg_deferred_lines']:.2f} | {s['avg_irrelevant_active_lines']:.2f} | "
            f"{100 * s['irrelevant_active_line_ratio']:.2f}% | {v['FN']} | "
            f"{v['precision']:.6f} | {v['recall']:.6f} | {v['f1']:.6f} |"
        )
    (out_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()
    summary = run(args.dataset, args.repo_root, args.out, args.limit)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
