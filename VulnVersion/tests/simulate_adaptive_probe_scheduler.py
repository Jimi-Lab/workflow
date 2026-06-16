"""Adaptive probe scheduler simulator for Step3.

This experiment targets the current main cost source: too many active lines are
fully probed even when they end up as N...N.  The candidate policy keeps the
same release-line graph and fix-reachability evidence, but runs a cheaper
triage probe on low-risk seed lines.  If a line or same-family neighbor shows
affected evidence, the line is escalated to full ASBS.

GT is used only as the selected probe oracle and final evaluator.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = ROOT / "tests"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from vulnversion.stage3_verify.git_reachability import batch_tags_containing
from vulnversion.stage3_verify.line_scheduler import (
    _line_to_family,
    _no_fix_lines,
    _static_neighbors,
    compute_seed_lines,
)
from vulnversion.git_ops.repo import map_gt_tags_to_repo_tags

from simulate_module_backed_step3 import (
    _batch_path_exists,
    _changed_files_for_commits,
    _flatten_fixing_commits,
    _release_context,
    _run_git_guided_line_module,
)


DEFAULT_OUT = ROOT / "tests" / "adaptive_probe_scheduler_simulator"


@dataclass(frozen=True)
class AdaptiveConfig:
    name: str
    triage_nn_sentinel: int
    high_neighbor_radius: int
    positive_expand_radius: int
    fallback_mode: str = "nohit_nofix"
    transition_high: bool = True
    fix_file_endpoint_high: bool = True
    family_edge_high: bool = False


def _load_dataset(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _repo_name(rec: dict[str, Any]) -> str:
    return str(rec.get("repo") or "").strip()


def _commits(rec: dict[str, Any]) -> list[str]:
    return _flatten_fixing_commits(rec.get("fixing_commits") or rec.get("fixing_commit") or rec.get("fix_commit"))


def _affected_set(rec: dict[str, Any], release_tags: list[str]) -> set[str]:
    mapped, _unmapped = map_gt_tags_to_repo_tags(
        sorted(str(t) for t in (rec.get("affected_version") or [])),
        release_tags,
        mode="loose",
    )
    return set(mapped)


def _line_neighbors(ordered_by_family: dict[str, list[str]], line: str, radius: int) -> set[str]:
    if radius <= 0:
        return set()
    for lines in ordered_by_family.values():
        if line in lines:
            return _static_neighbors(lines, {line}, radius) - {line}
    return set()


def _transition_lines(release_lines: dict[str, list[str]], fix_containing_tags: set[str]) -> set[str]:
    out = set()
    for line, tags in release_lines.items():
        has_fix = any(tag in fix_containing_tags for tag in tags)
        has_no_fix = any(tag not in fix_containing_tags for tag in tags)
        if has_fix and has_no_fix:
            out.add(line)
    return out


def _family_edge_lines(ordered_by_family: dict[str, list[str]]) -> set[str]:
    out = set()
    for lines in ordered_by_family.values():
        if lines:
            out.add(lines[0])
            out.add(lines[-1])
    return out


def _build_file_endpoint_lines(
    *,
    release_lines: dict[str, list[str]],
    files: list[str],
    path_exists: dict[tuple[str, str], bool],
) -> set[str]:
    out = set()
    for line, tags in release_lines.items():
        endpoints = {tags[0], tags[-1]} if tags else set()
        if any(path_exists.get((tag, path), False) for tag in endpoints for path in files):
            out.add(line)
    return out


def _run_line(
    *,
    line: str,
    tags: list[str],
    affected_set: set[str],
    fix_containing_tags: set[str],
    nn_sentinel: int,
) -> Any:
    return _run_git_guided_line_module(
        line=line,
        tags=tags,
        affected_set=affected_set,
        fix_containing_tags=fix_containing_tags,
        nn_sentinel_count=nn_sentinel,
        aa_sentinel_count=1,
        fixed_segment_sentinel=1,
    )


def _simulate_adaptive(
    *,
    repo_name: str,
    cve_id: str,
    rec: dict[str, Any],
    release_tags: list[str],
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    fix_containing_tags: set[str],
    file_endpoint_lines: set[str],
    config: AdaptiveConfig,
) -> dict[str, Any]:
    affected_set = _affected_set(rec, release_tags)
    release_set = set(release_tags)
    seed_lines = compute_seed_lines(
        repo_name=repo_name,
        release_lines=release_lines,
        ordered_by_family=ordered_by_family,
        fix_containing_tags=fix_containing_tags,
        file_endpoint_lines=file_endpoint_lines,
        stride=3,
        file_neighbor_radius=1,
    )
    transition = _transition_lines(release_lines, fix_containing_tags)
    high_lines: set[str] = set()
    if config.fix_file_endpoint_high:
        high_lines.update(file_endpoint_lines)
    if config.transition_high:
        high_lines.update(transition)
    if config.family_edge_high:
        high_lines.update(_family_edge_lines(ordered_by_family))
    if config.high_neighbor_radius > 0:
        expanded = set(high_lines)
        for lines in ordered_by_family.values():
            expanded.update(_static_neighbors(lines, set(lines) & high_lines, config.high_neighbor_radius))
        high_lines = expanded

    visited_mode: dict[str, str] = {}
    line_results: dict[tuple[str, str], Any] = {}
    predicted: set[str] = set()
    probes: set[str] = set()
    positive_lines: set[str] = set()
    status_counts: Counter[str] = Counter()
    queue: deque[tuple[str, str]] = deque()

    ordered_seed_lines = sorted(seed_lines, key=lambda line: (line not in high_lines, line))
    for line in ordered_seed_lines:
        queue.append((line, "full" if line in high_lines else "triage"))

    def process(line: str, mode: str) -> None:
        prev = visited_mode.get(line)
        if prev == "full" or (prev == "triage" and mode == "triage"):
            return
        tags = release_lines.get(line, [])
        nn = 3 if mode == "full" else config.triage_nn_sentinel
        result = _run_line(
            line=line,
            tags=tags,
            affected_set=affected_set,
            fix_containing_tags=fix_containing_tags,
            nn_sentinel=nn,
        )
        visited_mode[line] = mode
        line_results[(line, mode)] = result
        predicted.update(result.predicted_affected)
        probes.update(result.probe_tags)
        status_counts.update(result.statuses)
        if result.is_positive:
            positive_lines.add(line)
            for neighbor in _line_neighbors(ordered_by_family, line, config.positive_expand_radius):
                queue.append((neighbor, "full"))

    while queue:
        line, mode = queue.popleft()
        process(line, mode)

    if not positive_lines and config.fallback_mode in {"nohit_nofix", "nohit_all"}:
        if config.fallback_mode == "nohit_nofix":
            fallback = _no_fix_lines(release_lines, fix_containing_tags)
        else:
            fallback = set(release_lines)
        for line in sorted(fallback):
            queue.append((line, "full"))
        while queue:
            line, mode = queue.popleft()
            process(line, mode)

    affected_lines = {line for line, tags in release_lines.items() if set(tags) & affected_set}
    visited_lines = set(visited_mode)
    tp = len(predicted & affected_set)
    fp = len(predicted - affected_set)
    fn = len(affected_set - predicted)
    tn = len(release_set - predicted - affected_set)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "strategy": config.name,
        "repo": repo_name,
        "cve": cve_id,
        "release_tag_count": len(release_tags),
        "line_count": len(release_lines),
        "seed_line_count": len(seed_lines),
        "high_line_count": len(high_lines),
        "visited_line_count": len(visited_lines),
        "full_line_count": sum(1 for mode in visited_mode.values() if mode == "full"),
        "triage_line_count": sum(1 for mode in visited_mode.values() if mode == "triage"),
        "positive_line_count": len(positive_lines),
        "affected_line_count": len(affected_lines),
        "skipped_affected_lines": len(affected_lines - visited_lines),
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
        "status_counts": dict(status_counts),
    }


def _simulate_control(
    *,
    repo_name: str,
    cve_id: str,
    rec: dict[str, Any],
    release_tags: list[str],
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    fix_containing_tags: set[str],
    file_endpoint_lines: set[str],
) -> dict[str, Any]:
    return _simulate_adaptive(
        repo_name=repo_name,
        cve_id=cve_id,
        rec=rec,
        release_tags=release_tags,
        release_lines=release_lines,
        ordered_by_family=ordered_by_family,
        fix_containing_tags=fix_containing_tags,
        file_endpoint_lines=file_endpoint_lines,
        config=AdaptiveConfig(
            name="control_current",
            triage_nn_sentinel=3,
            high_neighbor_radius=999,
            positive_expand_radius=1,
            fallback_mode="nohit_nofix",
            transition_high=True,
            fix_file_endpoint_high=True,
            family_edge_high=True,
        ),
    )


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    probes = [row["probe_count"] for row in rows]
    cm = Counter()
    repos: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        cm.update({"TP": row["tp"], "FP": row["fp"], "FN": row["fn"], "TN": row["tn"]})
        repos[row["repo"]].append(row)
    precision = cm["TP"] / (cm["TP"] + cm["FP"]) if cm["TP"] + cm["FP"] else 1.0
    recall = cm["TP"] / (cm["TP"] + cm["FN"]) if cm["TP"] + cm["FN"] else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    def pct(p: float) -> int:
        if not probes:
            return 0
        xs = sorted(probes)
        idx = max(0, min(len(xs) - 1, int(len(xs) * p + 0.999999) - 1))
        return xs[idx]

    return {
        "cves": len(rows),
        "avg_probes": sum(probes) / len(probes) if probes else 0.0,
        "p50_probes": pct(0.50),
        "p95_probes": pct(0.95),
        "exact_cves": sum(1 for row in rows if row["exact_match"]),
        "fn_cves": sum(1 for row in rows if row["has_fn"]),
        "fp_cves": sum(1 for row in rows if row["has_fp"]),
        "skipped_affected_cves": sum(1 for row in rows if row["skipped_affected_lines"] > 0),
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
                "avg_probes": sum(r["probe_count"] for r in rs) / len(rs),
                "exact_cves": sum(1 for r in rs if r["exact_match"]),
                "fn_cves": sum(1 for r in rs if r["has_fn"]),
                "fp_cves": sum(1 for r in rs if r["has_fp"]),
            }
            for repo, rs in sorted(repos.items())
        },
    }


def _configs() -> list[AdaptiveConfig]:
    return [
        AdaptiveConfig("adaptive_t0_high0_expand1", 0, 0, 1),
        AdaptiveConfig("adaptive_t1_high0_expand1", 1, 0, 1),
        AdaptiveConfig("adaptive_t0_high1_expand1", 0, 1, 1),
        AdaptiveConfig("adaptive_t1_high1_expand1", 1, 1, 1),
        AdaptiveConfig("adaptive_t0_high1_expand2", 0, 1, 2),
        AdaptiveConfig("adaptive_t1_high1_expand2", 1, 1, 2),
        AdaptiveConfig("adaptive_t0_high2_expand2", 0, 2, 2),
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
    for repo_name, records in sorted(by_repo.items()):
        context = _release_context(repo_name, repo_root / repo_name)
        repo = context["repo"]
        release_tags = context["release_tags"]
        release_lines = context["release_lines"]
        ordered_by_family = context["ordered_by_family"]
        all_commits = {commit for _cve, rec in records for commit in _commits(rec)}
        contains = batch_tags_containing(repo=repo, release_tags=release_tags, target_commits=all_commits)
        changed_cache: dict[str, list[str]] = {}
        changed_files: dict[str, list[str]] = {}
        path_queries: set[tuple[str, str]] = set()
        for cve, rec in records:
            try:
                files = _changed_files_for_commits(repo, _commits(rec), changed_cache)
            except Exception as exc:  # pragma: no cover - diagnostic output
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
            fix_tags: set[str] = set()
            for commit in _commits(rec):
                result = contains.get(commit, {"ok": False, "tags": []})
                if result.get("ok"):
                    fix_tags.update(result.get("tags", []))
            file_endpoint_lines = _build_file_endpoint_lines(
                release_lines=release_lines,
                files=changed_files.get(cve, []),
                path_exists=path_exists,
            )
            rows.append(
                _simulate_control(
                    repo_name=repo_name,
                    cve_id=cve,
                    rec=rec,
                    release_tags=release_tags,
                    release_lines=release_lines,
                    ordered_by_family=ordered_by_family,
                    fix_containing_tags=fix_tags,
                    file_endpoint_lines=file_endpoint_lines,
                )
            )
            rows[-1]["strategy"] = "control_current"
            for cfg in _configs():
                rows.append(
                    _simulate_adaptive(
                        repo_name=repo_name,
                        cve_id=cve,
                        rec=rec,
                        release_tags=release_tags,
                        release_lines=release_lines,
                        ordered_by_family=ordered_by_family,
                        fix_containing_tags=fix_tags,
                        file_endpoint_lines=file_endpoint_lines,
                        config=cfg,
                    )
                )

    per_strategy: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        per_strategy[row["strategy"]].append(row)
    summary = {strategy: _summarize(rs) for strategy, rs in sorted(per_strategy.items())}
    fn_cases = [row for row in rows if row["has_fn"] or row["has_fp"]]

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    with (out_dir / "per_cve.jsonl").open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    (out_dir / "fn_cases.json").write_text(json.dumps(fn_cases, indent=2, sort_keys=True), encoding="utf-8")
    (out_dir / "failures.json").write_text(json.dumps(failures, indent=2, sort_keys=True), encoding="utf-8")
    lines = [
        "# Adaptive Probe Scheduler Simulator",
        "",
        "| strategy | avg probes | p50 | p95 | exact | FN CVEs | FP CVEs | version FN | P | R | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for strategy, s in summary.items():
        v = s["version"]
        lines.append(
            f"| {strategy} | {s['avg_probes']:.2f} | {s['p50_probes']} | {s['p95_probes']} | "
            f"{s['exact_cves']}/{s['cves']} | {s['fn_cves']} | {s['fp_cves']} | {v['FN']} | "
            f"{v['precision']:.6f} | {v['recall']:.6f} | {v['f1']:.6f} |"
        )
    (out_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=ROOT / "DataSet" / "BaseDataOrder.json")
    parser.add_argument("--repo-root", type=Path, default=ROOT / "repo")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()
    print(json.dumps(run(args.dataset, args.repo_root, args.out, args.limit), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
