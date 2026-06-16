"""Diagnose transition_scout_s4_all_expand2 failure modes.

This script is intentionally diagnostic.  It explains why the aggressive
global-state scheduler saves probes but adds FNs:

  - which affected lines are skipped;
  - which irrelevant lines are activated and by which reason;
  - whether transition-only misses are concentrated in multi-commit CVEs;
  - what happens in a concrete case such as CVE-2023-5178.

GT is used only for diagnosis and final classification.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict, deque
from dataclasses import asdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = ROOT / "tests"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from simulate_global_state_line_scheduler import (
    LineRuntime,
    SchedulerConfig,
    _affected_set,
    _build_file_endpoint_lines,
    _commits,
    _initial_lines,
    _line_neighbors,
    _line_to_family,
    _load_dataset,
    _repo_name,
    _run_line,
    _scout_lines,
    _transition_lines,
)
from simulate_module_backed_step3 import (
    _batch_path_exists,
    _changed_files_for_commits,
    _release_context,
)
from vulnversion.stage3_verify.git_reachability import batch_tags_containing


DEFAULT_DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
DEFAULT_REPO_ROOT = ROOT / "repo"
DEFAULT_OUT_DIR = ROOT / "tests" / "transition_scout_failure_analysis"


AGGRESSIVE = SchedulerConfig(
    name="transition_scout_s4_all_expand2",
    initial="transition",
    scout_stride=4,
    scout_scope="all_unvisited",
    scout_nn_sentinel=0,
    nohit_fallback="nofix",
    positive_expand_radius=2,
)

TRANSITION_ONLY = SchedulerConfig(
    name="transition_first_no_fallback",
    initial="transition",
    nohit_fallback="none",
)


def _line_index(ordered_by_family: dict[str, list[str]]) -> dict[str, tuple[str, int, int]]:
    out: dict[str, tuple[str, int, int]] = {}
    for family, lines in ordered_by_family.items():
        for idx, line in enumerate(lines):
            out[line] = (family, idx, len(lines))
    return out


def _simulate_with_line_details(
    *,
    repo_name: str,
    cve: str,
    rec: dict[str, Any],
    release_tags: list[str],
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    fix_containing_tags: set[str],
    file_endpoint_lines: set[str],
    config: SchedulerConfig,
) -> dict[str, Any]:
    affected_set = _affected_set(rec, release_tags)
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

    if not positive_lines and config.nohit_fallback in {"nofix", "all"}:
        from simulate_global_state_line_scheduler import _no_fix_lines

        fallback = _no_fix_lines(release_lines, fix_containing_tags)
        if config.nohit_fallback == "all":
            fallback = set(release_lines)
        for line in sorted(fallback):
            if line not in visited_full:
                runtime[line].activate("nohit_fallback")
                queue.append((line, "full", "nohit_fallback"))
        process_queue()

    visited_lines = {line for line, state in runtime.items() if state.modes}
    line_meta = _line_index(ordered_by_family)
    line_details: dict[str, dict[str, Any]] = {}
    for line, tags in release_lines.items():
        state = runtime[line]
        family, family_index, family_size = line_meta.get(line, ("", -1, 0))
        affected_tags = sorted(set(tags) & affected_set)
        line_details[line] = {
            "line": line,
            "family": family,
            "family_index": family_index,
            "family_size": family_size,
            "tag_count": len(tags),
            "affected_tag_count": len(affected_tags),
            "affected_tags": affected_tags,
            "visited": line in visited_lines,
            "modes": list(state.modes),
            "activation_reasons": list(state.activation_reasons),
            "is_positive": state.is_positive,
            "probe_count": len(state.probe_tags),
            "predicted_count": len(state.predicted_affected),
            "status_counts": dict(state.status_counts),
            "has_fix_containing_tag": any(tag in fix_containing_tags for tag in tags),
            "all_fix_containing": bool(tags) and all(tag in fix_containing_tags for tag in tags),
            "is_transition_line": line in _transition_lines(release_lines, fix_containing_tags),
            "is_file_endpoint_line": line in file_endpoint_lines,
        }

    fn_tags = sorted(affected_set - predicted)
    fp_tags = sorted(predicted - affected_set)
    skipped_affected_lines = sorted(affected_lines - visited_lines)
    active_irrelevant_lines = sorted(visited_lines - affected_lines)
    return {
        "repo": repo_name,
        "cve": cve,
        "commit_count": len(_commits(rec)),
        "affected_tag_count": len(affected_set),
        "affected_line_count": len(affected_lines),
        "visited_line_count": len(visited_lines),
        "positive_line_count": len(positive_lines),
        "probe_count": len(probes),
        "fn": len(fn_tags),
        "fp": len(fp_tags),
        "fn_tags": fn_tags,
        "fp_tags": fp_tags,
        "skipped_affected_lines": skipped_affected_lines,
        "active_irrelevant_lines": active_irrelevant_lines,
        "line_details": line_details,
    }


def run(dataset: Path, repo_root: Path, out_dir: Path) -> dict[str, Any]:
    data = _load_dataset(dataset)
    by_repo: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for cve, rec in sorted(data.items()):
        repo_name = _repo_name(rec)
        if repo_name:
            by_repo[repo_name].append((cve, rec))

    aggressive_rows: list[dict[str, Any]] = []
    transition_only_rows: list[dict[str, Any]] = []
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
            except Exception as exc:
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
            kwargs = dict(
                repo_name=repo_name,
                cve=cve,
                rec=rec,
                release_tags=release_tags,
                release_lines=release_lines,
                ordered_by_family=ordered_by_family,
                fix_containing_tags=fix_containing_tags,
                file_endpoint_lines=file_endpoint_lines,
            )
            aggressive_rows.append(_simulate_with_line_details(config=AGGRESSIVE, **kwargs))
            transition_only_rows.append(_simulate_with_line_details(config=TRANSITION_ONLY, **kwargs))

    def summarize_transition_only() -> dict[str, Any]:
        fn_rows = [r for r in transition_only_rows if r["fn"] > 0]
        multi = [r for r in fn_rows if r["commit_count"] > 1]
        single = [r for r in fn_rows if r["commit_count"] <= 1]
        by_repo_counts = Counter(r["repo"] for r in fn_rows)
        return {
            "fn_cves": len(fn_rows),
            "fn_tags": sum(r["fn"] for r in fn_rows),
            "multi_commit_fn_cves": len(multi),
            "single_commit_fn_cves": len(single),
            "multi_commit_fn_tags": sum(r["fn"] for r in multi),
            "single_commit_fn_tags": sum(r["fn"] for r in single),
            "by_repo_fn_cves": dict(sorted(by_repo_counts.items())),
        }

    skipped_rows = [r for r in aggressive_rows if r["skipped_affected_lines"]]
    active_fn_rows = [r for r in aggressive_rows if r["fn"] > 0 and not r["skipped_affected_lines"]]
    active_irrelevant_reason_counts: Counter[str] = Counter()
    active_irrelevant_repo_counts: Counter[str] = Counter()
    for row in aggressive_rows:
        for line in row["active_irrelevant_lines"]:
            detail = row["line_details"][line]
            active_irrelevant_repo_counts[row["repo"]] += 1
            for reason in detail["activation_reasons"] or ["unknown"]:
                active_irrelevant_reason_counts[reason] += 1

    skipped_line_records: list[dict[str, Any]] = []
    for row in skipped_rows:
        for line in row["skipped_affected_lines"]:
            detail = row["line_details"][line]
            skipped_line_records.append({
                "repo": row["repo"],
                "cve": row["cve"],
                "line": line,
                "affected_tags": detail["affected_tags"],
                "tag_count": detail["tag_count"],
                "family": detail["family"],
                "family_index": detail["family_index"],
                "family_size": detail["family_size"],
                "has_fix_containing_tag": detail["has_fix_containing_tag"],
                "is_transition_line": detail["is_transition_line"],
                "is_file_endpoint_line": detail["is_file_endpoint_line"],
            })

    cve_2023_5178 = next((r for r in aggressive_rows if r["cve"] == "CVE-2023-5178"), None)
    cve_2023_5178_summary = None
    if cve_2023_5178:
        cve_2023_5178_summary = {
            k: v for k, v in cve_2023_5178.items()
            if k != "line_details"
        }
        cve_2023_5178_summary["skipped_line_details"] = [
            cve_2023_5178["line_details"][line]
            for line in cve_2023_5178["skipped_affected_lines"]
        ]
        cve_2023_5178_summary["visited_positive_lines"] = [
            detail for detail in cve_2023_5178["line_details"].values()
            if detail["visited"] and detail["is_positive"]
        ]

    summary = {
        "transition_only": summarize_transition_only(),
        "aggressive_transition_scout_s4_expand2": {
            "fn_cves": sum(1 for r in aggressive_rows if r["fn"] > 0),
            "fn_tags": sum(r["fn"] for r in aggressive_rows),
            "skipped_affected_line_cves": len(skipped_rows),
            "skipped_affected_line_fn_tags_upper": sum(r["fn"] for r in skipped_rows),
            "active_line_asbs_fn_cves": len(active_fn_rows),
            "active_line_asbs_fn_tags": sum(r["fn"] for r in active_fn_rows),
            "active_irrelevant_reason_counts": dict(active_irrelevant_reason_counts.most_common()),
            "active_irrelevant_repo_counts": dict(sorted(active_irrelevant_repo_counts.items())),
        },
        "cve_2023_5178": cve_2023_5178_summary,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    (out_dir / "skipped_affected_lines.json").write_text(json.dumps(skipped_line_records, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    (out_dir / "active_fn_cases.json").write_text(json.dumps(active_fn_rows, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    (out_dir / "transition_only_fn_cases.json").write_text(json.dumps([r for r in transition_only_rows if r["fn"] > 0], ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    (out_dir / "failures.json").write_text(json.dumps(failures, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT_DIR)
    args = parser.parse_args()
    summary = run(args.dataset, args.repo_root, args.out)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
