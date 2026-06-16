"""VET-priority line relevance simulator for Step3.

This experiment tests whether cheap root-cause-style VET evidence can reduce
irrelevant `scout_stride` and `positive_neighbor` activations.  It intentionally
does not create CERT_ABSENT/CERT_FIXED predictions and does not hard-delete
release tags.  Lines rejected by a VET gate are deferred/unresolved; if they are
GT-affected, they appear as FN in the simulator metrics.

GT is used only as the simulated selected-probe oracle and final evaluator.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
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
from vulnversion.stage3_verify.line_scheduler import _no_fix_lines, _static_neighbors, _stride_lines

from simulate_global_state_line_scheduler import (
    LineRuntime,
    SchedulerConfig,
    _all_fix_file_scout_lines,
    _build_file_endpoint_lines,
    _commits,
    _initial_lines,
    _line_neighbors,
    _line_to_family,
    _load_dataset,
    _repo_name,
    _run_line,
)
from simulate_module_backed_step3 import (
    _batch_path_exists,
    _changed_files_for_commits,
    _release_context,
)
from simulate_step3_low_cost_schedulers import (
    PatchProfile,
    _batch_file_text,
    _extract_patch_profile,
    _sample_tags_for_line,
    _token_evidence_lines,
)


DEFAULT_DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
DEFAULT_REPO_ROOT = ROOT / "repo"
DEFAULT_OUT_DIR = ROOT / "tests" / "vet_line_relevance_scheduler"


@dataclass(frozen=True)
class VetPriorityConfig:
    name: str
    scout_threshold: float | None = None
    neighbor_threshold: float | None = None
    fallback_threshold: float | None = None
    rank_scout: bool = False
    keep_base_quota: bool = False
    allow_file_endpoint: bool = True
    allow_transition: bool = True


@dataclass
class LineEvidence:
    line: str
    score: float
    file_endpoint: bool = False
    critical_hit: bool = False
    vuln_hit: bool = False
    fix_guard_hit: bool = False
    function_hit: bool = False
    transition_line: bool = False
    no_fix: bool = False
    all_fix: bool = False


def _affected_set(rec: dict[str, Any], release_tags: list[str]) -> set[str]:
    mapped, _unmapped = map_gt_tags_to_repo_tags(
        sorted(str(t) for t in (rec.get("affected_version") or [])),
        release_tags,
        mode="loose",
    )
    return set(mapped)


def _line_score(
    *,
    file_endpoint: bool,
    critical_hit: bool,
    vuln_hit: bool,
    fix_guard_hit: bool,
    function_hit: bool,
    transition_line: bool,
    no_fix: bool,
    all_fix: bool,
) -> float:
    score = 0.0
    if file_endpoint:
        score += 0.35
    if critical_hit:
        score += 0.20
    if vuln_hit:
        score += 0.18
    if function_hit:
        score += 0.12
    if transition_line:
        score += 0.10
    if no_fix:
        score += 0.04
    if all_fix and file_endpoint:
        score += 0.06
    if fix_guard_hit and not vuln_hit:
        score -= 0.05
    return max(0.0, min(score, 1.0))


def _build_line_evidence(
    *,
    release_lines: dict[str, list[str]],
    fix_containing_tags: set[str],
    file_endpoint_lines: set[str],
    semantic_lines: dict[str, set[str]],
) -> dict[str, LineEvidence]:
    out: dict[str, LineEvidence] = {}
    for line, tags in release_lines.items():
        no_fix = bool(tags) and all(tag not in fix_containing_tags for tag in tags)
        all_fix = bool(tags) and all(tag in fix_containing_tags for tag in tags)
        transition_line = bool(tags) and any(tag in fix_containing_tags for tag in tags) and any(
            tag not in fix_containing_tags for tag in tags
        )
        evidence = LineEvidence(
            line=line,
            score=0.0,
            file_endpoint=line in file_endpoint_lines,
            critical_hit=line in semantic_lines.get("critical", set()),
            vuln_hit=line in semantic_lines.get("vulnerable", set()),
            fix_guard_hit=line in semantic_lines.get("fix_guard", set()),
            function_hit=line in semantic_lines.get("function", set()),
            transition_line=transition_line,
            no_fix=no_fix,
            all_fix=all_fix,
        )
        evidence.score = _line_score(
            file_endpoint=evidence.file_endpoint,
            critical_hit=evidence.critical_hit,
            vuln_hit=evidence.vuln_hit,
            fix_guard_hit=evidence.fix_guard_hit,
            function_hit=evidence.function_hit,
            transition_line=evidence.transition_line,
            no_fix=evidence.no_fix,
            all_fix=evidence.all_fix,
        )
        out[line] = evidence
    return out


def _passes_gate(
    evidence: LineEvidence,
    threshold: float | None,
    config: VetPriorityConfig,
) -> bool:
    if threshold is None:
        return True
    if evidence.score >= threshold:
        return True
    if config.allow_file_endpoint and evidence.file_endpoint:
        return True
    if config.allow_transition and evidence.transition_line:
        return True
    return False


def _ranked_stride_lines(
    *,
    ordered_by_family: dict[str, list[str]],
    candidates: set[str],
    evidence: dict[str, LineEvidence],
    stride: int,
) -> set[str]:
    if stride <= 0 or not candidates:
        return set()
    selected: set[str] = set()
    for lines in ordered_by_family.values():
        family_candidates = [line for line in lines if line in candidates]
        if not family_candidates:
            continue
        quota = max(1, (len(family_candidates) + stride - 1) // stride)
        ranked = sorted(
            family_candidates,
            key=lambda line: (-evidence[line].score, lines.index(line)),
        )
        selected.update(ranked[:quota])
    return selected


def _scout_candidates(
    *,
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    fix_containing_tags: set[str],
    visited_full: set[str],
    evidence: dict[str, LineEvidence],
    vet_config: VetPriorityConfig,
    stride: int,
) -> set[str]:
    candidates = _no_fix_lines(release_lines, fix_containing_tags) - visited_full
    if vet_config.rank_scout:
        selected = _ranked_stride_lines(
            ordered_by_family=ordered_by_family,
            candidates=candidates,
            evidence=evidence,
            stride=stride,
        )
    else:
        selected = _stride_lines(ordered_by_family, stride, lines_subset=candidates)
    return {
        line
        for line in selected
        if _passes_gate(evidence[line], vet_config.scout_threshold, vet_config)
    }


def _simulate(
    *,
    repo_name: str,
    cve_id: str,
    rec: dict[str, Any],
    release_tags: list[str],
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    fix_containing_tags: set[str],
    file_endpoint_lines: set[str],
    evidence: dict[str, LineEvidence],
    vet_config: VetPriorityConfig,
) -> dict[str, Any]:
    base_config = SchedulerConfig(
        name=vet_config.name,
        initial="transition",
        scout_stride=4,
        scout_scope="all_unvisited",
        scout_nn_sentinel=0,
        nohit_fallback="nofix",
        positive_expand_radius=2,
        all_fix_file_scout_stride=4,
    )
    affected_set = _affected_set(rec, release_tags)
    release_set = set(release_tags)
    affected_lines = {line for line, tags in release_lines.items() if set(tags) & affected_set}
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
    gate_reject_counts: Counter[str] = Counter()

    seeds, reasons = _initial_lines(
        config=base_config,
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
                config=base_config,
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
                    base_config.positive_expand_radius,
                ):
                    if neighbor in visited_full:
                        continue
                    if _passes_gate(evidence[neighbor], vet_config.neighbor_threshold, vet_config):
                        runtime[neighbor].activate("positive_neighbor")
                        queue.append((neighbor, "full", "positive_neighbor"))
                    else:
                        gate_reject_counts["positive_neighbor"] += 1

    process_queue()

    scouts = _scout_candidates(
        release_lines=release_lines,
        ordered_by_family=ordered_by_family,
        fix_containing_tags=fix_containing_tags,
        visited_full=visited_full,
        evidence=evidence,
        vet_config=vet_config,
        stride=base_config.scout_stride,
    )
    for line in sorted(scouts):
        if line not in visited_full:
            runtime[line].activate("scout_stride")
            queue.append((line, "scout", "scout_stride"))
    process_queue()

    all_fix_scouts = _all_fix_file_scout_lines(
        config=base_config,
        release_lines=release_lines,
        ordered_by_family=ordered_by_family,
        fix_containing_tags=fix_containing_tags,
        file_endpoint_lines=file_endpoint_lines,
        visited_full=visited_full,
    )
    if vet_config.rank_scout:
        all_fix_scouts = _ranked_stride_lines(
            ordered_by_family=ordered_by_family,
            candidates=all_fix_scouts,
            evidence=evidence,
            stride=base_config.all_fix_file_scout_stride,
        )
    all_fix_scouts = {
        line for line in all_fix_scouts
        if _passes_gate(evidence[line], vet_config.scout_threshold, vet_config)
    }
    for line in sorted(all_fix_scouts):
        if line not in visited_full:
            runtime[line].activate("all_fix_file_scout")
            queue.append((line, "scout", "all_fix_file_scout"))
    process_queue()

    if not positive_lines:
        fallback = _no_fix_lines(release_lines, fix_containing_tags)
        for line in sorted(fallback):
            if line in visited_full:
                continue
            if _passes_gate(evidence[line], vet_config.fallback_threshold, vet_config):
                runtime[line].activate("nohit_fallback")
                queue.append((line, "full", "nohit_fallback"))
            else:
                gate_reject_counts["nohit_fallback"] += 1
        process_queue()

    visited_lines = {line for line, state in runtime.items() if state.modes}
    full_lines = {line for line, state in runtime.items() if "full" in state.modes}
    scout_lines = {line for line, state in runtime.items() if "scout" in state.modes}
    skipped_affected_lines = affected_lines - visited_lines
    irrelevant_active_lines = visited_lines - affected_lines
    tp = len(predicted & affected_set)
    fp = len(predicted - affected_set)
    fn = len(affected_set - predicted)
    tn = len(release_set - affected_set - predicted)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "strategy": vet_config.name,
        "repo": repo_name,
        "cve": cve_id,
        "probe_count": len(probes),
        "visited_line_count": len(visited_lines),
        "full_line_count": len(full_lines),
        "scout_line_count": len(scout_lines),
        "affected_line_count": len(affected_lines),
        "irrelevant_active_line_count": len(irrelevant_active_lines),
        "skipped_affected_line_count": len(skipped_affected_lines),
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
        "gate_reject_counts": dict(gate_reject_counts),
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
    gate_rejects = Counter()
    for row in rows:
        cm.update({"TP": row["tp"], "FP": row["fp"], "FN": row["fn"], "TN": row["tn"]})
        repos[row["repo"]].append(row)
        gate_rejects.update(row.get("gate_reject_counts", {}))
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
        "avg_visited_lines": avg("visited_line_count"),
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
        "gate_reject_counts": dict(gate_rejects),
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
                "cves": len(repo_rows),
                "avg_probes": statistics.mean(float(r["probe_count"]) for r in repo_rows),
                "exact_cves": sum(1 for r in repo_rows if r["exact_match"]),
                "fn_cves": sum(1 for r in repo_rows if r["has_fn"]),
                "fp_cves": sum(1 for r in repo_rows if r["has_fp"]),
            }
            for repo, repo_rows in sorted(repos.items())
        },
    }


def _configs() -> list[VetPriorityConfig]:
    return [
        VetPriorityConfig("base_allfixfile_s4"),
        VetPriorityConfig("vet_ranked_scout_only", rank_scout=True, keep_base_quota=True),
        VetPriorityConfig("vet_neighbor_t0.20", neighbor_threshold=0.20),
        VetPriorityConfig("vet_neighbor_t0.30", neighbor_threshold=0.30),
        VetPriorityConfig("vet_scout_t0.20_neighbor_t0.20", scout_threshold=0.20, neighbor_threshold=0.20),
        VetPriorityConfig("vet_scout_t0.30_neighbor_t0.30", scout_threshold=0.30, neighbor_threshold=0.30),
        VetPriorityConfig(
            "vet_ranked_scout_neighbor_t0.20",
            rank_scout=True,
            keep_base_quota=True,
            neighbor_threshold=0.20,
        ),
        VetPriorityConfig(
            "vet_ranked_scout_neighbor_t0.30",
            rank_scout=True,
            keep_base_quota=True,
            neighbor_threshold=0.30,
        ),
        VetPriorityConfig(
            "vet_ranked_scout_all_gates_t0.20",
            rank_scout=True,
            keep_base_quota=True,
            scout_threshold=0.20,
            neighbor_threshold=0.20,
            fallback_threshold=0.20,
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
    line_evidence_rows: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    configs = _configs()
    for repo_name, records in sorted(by_repo.items()):
        context = _release_context(repo_name, repo_root / repo_name)
        repo = context["repo"]
        release_tags = context["release_tags"]
        release_lines = context["release_lines"]
        ordered_by_family = context["ordered_by_family"]
        all_commits = {commit for _cve, rec in records for commit in _commits(rec)}
        contains = batch_tags_containing(repo=repo, release_tags=release_tags, target_commits=all_commits)

        changed_cache: dict[str, list[str]] = {}
        changed_by_cve: dict[str, list[str]] = {}
        profile_by_cve: dict[str, PatchProfile] = {}
        path_queries: set[tuple[str, str]] = set()
        text_queries: set[tuple[str, str]] = set()
        sample_tags = {tag for tags in release_lines.values() for tag in _sample_tags_for_line(tags)}
        for cve, rec in records:
            try:
                commits = _commits(rec)
                changed = _changed_files_for_commits(repo, commits, changed_cache)
                profile = _extract_patch_profile(repo, commits, changed)
            except Exception as exc:
                failures.append({"repo": repo_name, "cve": cve, "stage": "profile", "error": str(exc)})
                changed = []
                profile = PatchProfile([], [], [], [], [], [])
            changed_by_cve[cve] = changed
            profile_by_cve[cve] = profile
            for tag in sample_tags:
                for path in profile.files:
                    path_queries.add((tag, path))
                    text_queries.add((tag, path))
        path_exists = _batch_path_exists(repo, path_queries)
        text_cache = _batch_file_text(repo, text_queries)

        for cve, rec in records:
            fix_containing_tags: set[str] = set()
            for commit in _commits(rec):
                result = contains.get(commit, {"ok": False, "tags": []})
                if result.get("ok"):
                    fix_containing_tags.update(result.get("tags", []))
            profile = profile_by_cve[cve]
            file_endpoint_lines = _build_file_endpoint_lines(
                release_lines=release_lines,
                files=changed_by_cve.get(cve, []),
                path_exists=path_exists,
            )
            semantic_lines = _token_evidence_lines(
                release_lines=release_lines,
                profile=profile,
                text_cache=text_cache,
            )
            evidence = _build_line_evidence(
                release_lines=release_lines,
                fix_containing_tags=fix_containing_tags,
                file_endpoint_lines=file_endpoint_lines,
                semantic_lines=semantic_lines,
            )
            affected_set = _affected_set(rec, release_tags)
            for line, ev in evidence.items():
                line_evidence_rows.append({
                    "repo": repo_name,
                    "cve": cve,
                    "line": line,
                    "score": ev.score,
                    "affected_tags": len(set(release_lines.get(line, [])) & affected_set),
                    "file_endpoint": ev.file_endpoint,
                    "critical_hit": ev.critical_hit,
                    "vuln_hit": ev.vuln_hit,
                    "fix_guard_hit": ev.fix_guard_hit,
                    "function_hit": ev.function_hit,
                    "transition_line": ev.transition_line,
                    "no_fix": ev.no_fix,
                    "all_fix": ev.all_fix,
                })
            for config in configs:
                rows.append(
                    _simulate(
                        repo_name=repo_name,
                        cve_id=cve,
                        rec=rec,
                        release_tags=release_tags,
                        release_lines=release_lines,
                        ordered_by_family=ordered_by_family,
                        fix_containing_tags=fix_containing_tags,
                        file_endpoint_lines=file_endpoint_lines,
                        evidence=evidence,
                        vet_config=config,
                    )
                )

    per_strategy: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        per_strategy[row["strategy"]].append(row)
    summary = {strategy: _summarize(rs) for strategy, rs in sorted(per_strategy.items())}
    fn_cases = [row for row in rows if row["has_fn"] or row["has_fp"]]
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    with (out_dir / "per_cve.jsonl").open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    (out_dir / "fn_cases.json").write_text(json.dumps(fn_cases, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    (out_dir / "failures.json").write_text(json.dumps(failures, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    with (out_dir / "line_evidence.jsonl").open("w", encoding="utf-8") as fh:
        for row in line_evidence_rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    lines = [
        "# VET Line Relevance Scheduler Simulator",
        "",
        "Dataset: `DataSet/BaseDataOrder.json`.",
        "",
        "VET evidence changes only activation priority/gates. It does not emit CERT_ABSENT/CERT_FIXED verdicts.",
        "",
        "| strategy | avg probes | p50 | p95 | exact | FN CVEs | FP CVEs | avg active lines | irrelevant active % | version FN | P | R | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for strategy, s in summary.items():
        v = s["version"]
        lines.append(
            f"| `{strategy}` | {s['avg_probes']:.2f} | {s['p50_probes']} | {s['p95_probes']} | "
            f"{s['exact_cves']}/{s['cves']} | {s['fn_cves']} | {s['fp_cves']} | "
            f"{s['avg_visited_lines']:.2f} | {100 * s['irrelevant_active_line_ratio']:.2f}% | "
            f"{v['FN']} | {v['precision']:.6f} | {v['recall']:.6f} | {v['f1']:.6f} |"
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
