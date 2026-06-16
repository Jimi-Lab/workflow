"""Build a failure/waste corpus for the current Step3 scheduler candidate.

The corpus fixes the strategy to ``transition_scout_s4_expand2_allfixfile_s4``.
GT is used only as the probe oracle and final evaluator.  It is never a
planning input.
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


DEFAULT_DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
DEFAULT_REPO_ROOT = ROOT / "repo"
DEFAULT_OUT_DIR = ROOT / "tests" / "scheduler_failure_corpus"
TARGET_STRATEGY = "transition_scout_s4_expand2_allfixfile_s4"


@dataclass
class LineRuntimeRecord:
    line: str
    tags: list[str]
    family: str
    activation_reasons: list[str] = field(default_factory=list)
    modes: list[str] = field(default_factory=list)
    probe_tags: set[str] = field(default_factory=set)
    predicted_affected: set[str] = field(default_factory=set)
    gt_affected: set[str] = field(default_factory=set)
    status_counts: Counter[str] = field(default_factory=Counter)

    def activate(self, reason: str) -> None:
        if reason not in self.activation_reasons:
            self.activation_reasons.append(reason)

    def update(self, *, mode: str, result: Any) -> None:
        if mode not in self.modes:
            self.modes.append(mode)
        self.probe_tags.update(result.probe_tags)
        self.predicted_affected.update(result.predicted_affected)
        self.status_counts.update(result.statuses)

    @property
    def visited(self) -> bool:
        return bool(self.modes)

    @property
    def primary_reason(self) -> str:
        return _primary_reason(self.activation_reasons)

    def to_dict(self) -> dict[str, Any]:
        gt = sorted(self.gt_affected)
        pred = sorted(self.predicted_affected)
        missed = sorted(set(gt) - set(pred))
        fp = sorted(set(pred) - set(gt))
        return {
            "line": self.line,
            "family": self.family,
            "tag_count": len(self.tags),
            "tags": self.tags,
            "visited": self.visited,
            "activation_reasons": list(self.activation_reasons),
            "primary_reason": self.primary_reason,
            "modes": list(self.modes),
            "probe_tags": sorted(self.probe_tags),
            "predicted_affected": pred,
            "gt_affected": gt,
            "missed_affected_tags": missed,
            "fp_tags": fp,
            "status_counts": dict(self.status_counts),
        }


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def _append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _primary_reason(reasons: list[str]) -> str:
    return reasons[0] if reasons else "unknown"


def _classify_fn_sources(lines: dict[str, dict[str, Any]]) -> dict[str, Any]:
    skipped_tags: list[str] = []
    active_missed_tags: list[str] = []
    skipped_lines: list[str] = []
    active_missed_lines: list[str] = []
    for line, row in lines.items():
        gt = set(row.get("gt_affected") or [])
        predicted = set(row.get("predicted_affected") or [])
        missed = sorted(gt - predicted)
        if not missed:
            continue
        if not row.get("visited"):
            skipped_tags.extend(missed)
            skipped_lines.append(line)
        else:
            active_missed_tags.extend(missed)
            active_missed_lines.append(line)
    return {
        "skipped_affected_line_tags": sorted(skipped_tags),
        "active_line_missed_tags": sorted(active_missed_tags),
        "skipped_affected_lines": sorted(skipped_lines),
        "active_line_missed_lines": sorted(active_missed_lines),
        "source_counts": {
            "skipped_affected_line": len(skipped_tags),
            "active_line_missed_asbs_or_sparse": len(active_missed_tags),
        },
    }


def _pct(values: list[int], pct: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    idx = round((len(ordered) - 1) * pct)
    return int(ordered[idx])


def _affected_set(rec: dict[str, Any], release_tags: list[str]) -> set[str]:
    mapped, _ = map_gt_tags_to_repo_tags(
        sorted(str(t) for t in (rec.get("affected_version") or [])),
        release_tags,
        mode="loose",
    )
    return set(mapped)


def _target_config() -> SchedulerConfig:
    return SchedulerConfig(
        name=TARGET_STRATEGY,
        initial="transition",
        scout_stride=4,
        scout_scope="all_unvisited",
        scout_nn_sentinel=0,
        nohit_fallback="nofix",
        positive_expand_radius=2,
        all_fix_file_scout_stride=4,
    )


def _simulate_one(
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
    affected = _affected_set(rec, release_tags)
    release_set = set(release_tags)
    line_to_family = _line_to_family(ordered_by_family)
    runtime = {
        line: LineRuntimeRecord(
            line=line,
            tags=list(tags),
            family=line_to_family.get(line, "unknown"),
            gt_affected=set(tags) & affected,
        )
        for line, tags in release_lines.items()
    }
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
                affected_set=affected,
                fix_containing_tags=fix_containing_tags,
                config=config,
            )
            runtime[line].update(mode=mode, result=result)
            reason_counts[reason] += 1
            mode_counts[mode] += 1
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

    scouts = _stride_lines(
        ordered_by_family,
        config.scout_stride,
        lines_subset=_no_fix_lines(release_lines, fix_containing_tags) - visited_full,
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

    if not positive_lines and config.nohit_fallback == "nofix":
        for line in sorted(_no_fix_lines(release_lines, fix_containing_tags)):
            if line not in visited_full:
                runtime[line].activate("nohit_fallback")
                queue.append((line, "full", "nohit_fallback"))
        process_queue()

    line_rows = {line: rt.to_dict() for line, rt in runtime.items()}
    visited_lines = {line for line, row in line_rows.items() if row["visited"]}
    affected_lines = {line for line, row in line_rows.items() if row["gt_affected"]}
    irrelevant_active = visited_lines - affected_lines
    fn_sources = _classify_fn_sources(line_rows)

    tp = len(predicted & affected)
    fp = len(predicted - affected)
    fn = len(affected - predicted)
    tn = len(release_set - affected - predicted)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    irrelevant_by_primary = Counter(line_rows[line]["primary_reason"] for line in irrelevant_active)
    irrelevant_by_any = Counter()
    for line in irrelevant_active:
        for reason in line_rows[line]["activation_reasons"] or ["unknown"]:
            irrelevant_by_any[reason] += 1

    return {
        "strategy": config.name,
        "repo": repo_name,
        "cve": cve_id,
        "release_tag_count": len(release_tags),
        "line_count": len(release_lines),
        "affected_line_count": len(affected_lines),
        "visited_line_count": len(visited_lines),
        "irrelevant_active_line_count": len(irrelevant_active),
        "skipped_affected_line_count": len(set(fn_sources["skipped_affected_lines"])),
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
        "fn_tags": sorted(affected - predicted),
        "fp_tags": sorted(predicted - affected),
        "fn_sources": fn_sources,
        "activation_reason_counts": dict(reason_counts),
        "mode_counts": dict(mode_counts),
        "status_counts": dict(status_counts),
        "irrelevant_activation_by_primary_reason": dict(irrelevant_by_primary),
        "irrelevant_activation_by_any_reason": dict(irrelevant_by_any),
        "lines": line_rows,
    }


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    cm = Counter()
    probes = [int(row["probe_count"]) for row in rows]
    by_repo: dict[str, list[dict[str, Any]]] = defaultdict(list)
    fn_sources = Counter()
    primary_irrelevant = Counter()
    any_irrelevant = Counter()
    activation_counts = Counter()
    status_counts = Counter()
    for row in rows:
        cm.update({"TP": row["tp"], "FP": row["fp"], "FN": row["fn"], "TN": row["tn"]})
        by_repo[row["repo"]].append(row)
        fn_sources.update(row["fn_sources"]["source_counts"])
        primary_irrelevant.update(row["irrelevant_activation_by_primary_reason"])
        any_irrelevant.update(row["irrelevant_activation_by_any_reason"])
        activation_counts.update(row["activation_reason_counts"])
        status_counts.update(row["status_counts"])
    precision = cm["TP"] / (cm["TP"] + cm["FP"]) if cm["TP"] + cm["FP"] else 1.0
    recall = cm["TP"] / (cm["TP"] + cm["FN"]) if cm["TP"] + cm["FN"] else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    def avg(key: str, rs: list[dict[str, Any]] = rows) -> float:
        return statistics.mean(float(row[key]) for row in rs) if rs else 0.0

    repo_summary = {}
    for repo, rs in sorted(by_repo.items()):
        repo_irrelevant = Counter()
        repo_fn_sources = Counter()
        for row in rs:
            repo_irrelevant.update(row["irrelevant_activation_by_primary_reason"])
            repo_fn_sources.update(row["fn_sources"]["source_counts"])
        repo_summary[repo] = {
            "cves": len(rs),
            "avg_probes": avg("probe_count", rs),
            "p95_probes": _pct([int(row["probe_count"]) for row in rs], 0.95),
            "exact_cves": sum(1 for row in rs if row["exact_match"]),
            "fn_cves": sum(1 for row in rs if row["has_fn"]),
            "fp_cves": sum(1 for row in rs if row["has_fp"]),
            "avg_visited_lines": avg("visited_line_count", rs),
            "avg_irrelevant_active_lines": avg("irrelevant_active_line_count", rs),
            "irrelevant_primary_reason_counts": dict(repo_irrelevant),
            "fn_source_counts": dict(repo_fn_sources),
        }

    return {
        "strategy": TARGET_STRATEGY,
        "cves": len(rows),
        "avg_probes": avg("probe_count"),
        "p50_probes": _pct(probes, 0.50),
        "p95_probes": _pct(probes, 0.95),
        "exact_cves": sum(1 for row in rows if row["exact_match"]),
        "fn_cves": sum(1 for row in rows if row["has_fn"]),
        "fp_cves": sum(1 for row in rows if row["has_fp"]),
        "avg_affected_lines": avg("affected_line_count"),
        "avg_visited_lines": avg("visited_line_count"),
        "avg_irrelevant_active_lines": avg("irrelevant_active_line_count"),
        "irrelevant_active_line_ratio": (
            sum(row["irrelevant_active_line_count"] for row in rows)
            / sum(row["visited_line_count"] for row in rows)
            if sum(row["visited_line_count"] for row in rows)
            else 0.0
        ),
        "fn_source_counts": dict(fn_sources),
        "irrelevant_primary_reason_counts": dict(primary_irrelevant),
        "irrelevant_any_reason_counts": dict(any_irrelevant),
        "activation_reason_counts": dict(activation_counts),
        "status_counts": dict(status_counts),
        "version": {
            "TP": cm["TP"],
            "FP": cm["FP"],
            "FN": cm["FN"],
            "TN": cm["TN"],
            "precision": precision,
            "recall": recall,
            "f1": f1,
        },
        "by_repo": repo_summary,
    }


def run(dataset: Path, repo_root: Path, out_dir: Path, limit: int | None = None) -> dict[str, Any]:
    data = _load_dataset(dataset)
    records: list[tuple[str, dict[str, Any]]] = list(data.items())
    if limit is not None:
        records = records[:limit]
    by_repo: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for cve, rec in records:
        by_repo[_repo_name(rec)].append((cve, rec))

    out_dir.mkdir(parents=True, exist_ok=True)
    line_runtime_path = out_dir / "per_cve_line_runtime.jsonl"
    if line_runtime_path.exists():
        line_runtime_path.unlink()

    config = _target_config()
    rows: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for repo_name, repo_records in sorted(by_repo.items()):
        context = _release_context(repo_name, repo_root / repo_name)
        repo = context["repo"]
        release_tags = context["release_tags"]
        release_lines = context["release_lines"]
        ordered_by_family = context["ordered_by_family"]
        all_commits = {commit for _cve, rec in repo_records for commit in _commits(rec)}
        contains = batch_tags_containing(
            repo=repo,
            release_tags=release_tags,
            target_commits=all_commits,
        )
        changed_cache: dict[str, list[str]] = {}
        files_by_cve = {
            cve: _changed_files_for_commits(repo, _commits(rec), changed_cache)[:3]
            for cve, rec in repo_records
        }
        endpoint_queries = {
            (tag, path)
            for files in files_by_cve.values()
            for tags in release_lines.values()
            for tag in (tags[:1] + tags[-1:] if tags else [])
            for path in files
        }
        path_exists = _batch_path_exists(repo, endpoint_queries)

        for cve, rec in repo_records:
            try:
                fix_containing: set[str] = set()
                for commit in _commits(rec):
                    info = contains.get(commit, {"ok": False, "tags": []})
                    if info.get("ok"):
                        fix_containing.update(info.get("tags") or [])
                file_endpoint_lines = _build_file_endpoint_lines(
                    release_lines=release_lines,
                    files=files_by_cve.get(cve, []),
                    path_exists=path_exists,
                )
                row = _simulate_one(
                    repo_name=repo_name,
                    cve_id=cve,
                    rec=rec,
                    release_tags=release_tags,
                    release_lines=release_lines,
                    ordered_by_family=ordered_by_family,
                    fix_containing_tags=fix_containing,
                    file_endpoint_lines=file_endpoint_lines,
                    config=config,
                )
                rows.append({k: v for k, v in row.items() if k != "lines"})
                _append_jsonl(line_runtime_path, row)
            except Exception as exc:
                failures.append({
                    "repo": repo_name,
                    "cve": cve,
                    "error": f"{type(exc).__name__}: {exc}",
                })

    summary = _summarize(rows)
    _write_json(out_dir / "summary.json", summary)
    _write_json(out_dir / "failures.json", failures)
    _write_json(
        out_dir / "irrelevant_activation_by_reason.json",
        {
            "strategy": TARGET_STRATEGY,
            "primary_reason_counts": summary["irrelevant_primary_reason_counts"],
            "any_reason_counts": summary["irrelevant_any_reason_counts"],
            "by_repo": {
                repo: vals["irrelevant_primary_reason_counts"]
                for repo, vals in summary["by_repo"].items()
            },
            "note": "Primary reason is the first reason that activated the irrelevant line; any_reason counts all recorded activation reasons.",
        },
    )
    fn_cases = [row for row in rows if row["has_fn"]]
    fp_cases = [row for row in rows if row["has_fp"]]
    skipped = [
        {
            "repo": row["repo"],
            "cve": row["cve"],
            "skipped_affected_lines": row["fn_sources"]["skipped_affected_lines"],
            "skipped_affected_line_tags": row["fn_sources"]["skipped_affected_line_tags"],
        }
        for row in rows
        if row["fn_sources"]["skipped_affected_lines"]
    ]
    _write_json(out_dir / "fn_cases.json", fn_cases)
    _write_json(out_dir / "fp_cases.json", fp_cases)
    _write_json(out_dir / "skipped_affected_lines.json", skipped)

    report = [
        "# Scheduler Failure Corpus",
        "",
        f"Dataset: `{dataset}`",
        f"Strategy: `{TARGET_STRATEGY}`",
        "",
        "| metric | value |",
        "| --- | ---: |",
        f"| CVEs | {summary['cves']} |",
        f"| avg probes | {summary['avg_probes']:.2f} |",
        f"| p50 probes | {summary['p50_probes']} |",
        f"| p95 probes | {summary['p95_probes']} |",
        f"| exact CVEs | {summary['exact_cves']}/{summary['cves']} |",
        f"| FN CVEs | {summary['fn_cves']} |",
        f"| FP CVEs | {summary['fp_cves']} |",
        f"| avg active lines | {summary['avg_visited_lines']:.2f} |",
        f"| avg irrelevant active lines | {summary['avg_irrelevant_active_lines']:.2f} |",
        f"| irrelevant active % | {100 * summary['irrelevant_active_line_ratio']:.2f}% |",
        f"| version FN | {summary['version']['FN']} |",
        f"| version FP | {summary['version']['FP']} |",
        f"| precision | {summary['version']['precision']:.6f} |",
        f"| recall | {summary['version']['recall']:.6f} |",
        f"| F1 | {summary['version']['f1']:.6f} |",
        "",
        "## FN Source Counts",
        "",
        json.dumps(summary["fn_source_counts"], ensure_ascii=False, indent=2, sort_keys=True),
        "",
        "## Irrelevant Active Lines by Primary Reason",
        "",
        json.dumps(summary["irrelevant_primary_reason_counts"], ensure_ascii=False, indent=2, sort_keys=True),
    ]
    (out_dir / "report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
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

