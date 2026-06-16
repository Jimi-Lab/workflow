"""Module-backed Step3 GT simulator.

This script verifies that the formal Step3 modules reproduce the validated
GT-oracle staged scheduler behavior without reusing the simulator-local ASBS,
line scheduler, or reachability implementations.

Used modules:
  - vulnversion.stage3_verify.git_reachability
  - vulnversion.stage3_verify.asbs_line
  - vulnversion.stage3_verify.line_scheduler

The simulator still uses ground truth affected_version as an oracle verdict
function. It measures deterministic scheduling/inference behavior, not real
agent accuracy.
"""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.asbs_line import (
    AA_SENTINEL_COUNT,
    FIXED_SEG_SENTINEL,
    NN_SENTINEL_COUNT,
    ASBSResult,
    run_asbs_segment,
    run_fixed_segment_sentinel,
)
from vulnversion.stage3_verify.git_reachability import batch_tags_containing
from vulnversion.stage3_verify.line_scheduler import (
    LineRunResult,
    _ordered_by_family,
    compute_seed_lines,
    run_staged_scheduler,
)
from vulnversion.stage3_verify.version_registry import (
    filter_release_tags,
    line_key,
    sort_tags_for_line,
)


DEFAULT_DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
DEFAULT_REPO_ROOT = ROOT / "repo"
DEFAULT_OUT_DIR = ROOT / "tests" / "module_backed_step3_simulator"
REFERENCE_PER_CVE = ROOT / "tests" / "staged_expansion_simulator_order_v2" / "per_cve.jsonl"


def _load_dataset(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _flatten_fixing_commits(value: Any) -> list[str]:
    commits: list[str] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, list):
                commits.extend(str(x) for x in item if x)
            elif item:
                commits.append(str(item))
    elif value:
        commits.append(str(value))
    seen: set[str] = set()
    out: list[str] = []
    for commit in commits:
        if commit in seen:
            continue
        seen.add(commit)
        out.append(commit)
    return out


def _git_base_cmd(repo_path: Path) -> list[str]:
    repo_str = str(repo_path.resolve())
    return ["git", "-c", f"safe.directory={repo_str}", "-C", repo_str]


def _release_context(repo_name: str, repo_path: Path) -> dict[str, Any]:
    repo = GitRepo.open(repo_path)
    release_tags_raw = filter_release_tags(repo_name, repo.list_tags(max_tags=None))
    release_lines: dict[str, list[str]] = defaultdict(list)
    for tag in release_tags_raw:
        release_lines[line_key(repo_name, tag)].append(tag)
    release_lines = {
        line: sort_tags_for_line(repo_name, tags, reverse=False)
        for line, tags in release_lines.items()
    }
    ordered_by_family = _ordered_by_family(repo_name, release_lines)
    release_tags = [tag for tags in release_lines.values() for tag in tags]
    return {
        "repo": repo,
        "release_tags": release_tags,
        "release_lines": release_lines,
        "ordered_by_family": ordered_by_family,
    }


def _changed_files_for_commits(repo: GitRepo, commits: list[str], cache: dict[str, list[str]]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for commit in commits:
        if commit not in cache:
            try:
                cache[commit] = repo.changed_files(commit)
            except Exception:
                cache[commit] = []
        for path in cache[commit]:
            if path and path not in seen:
                seen.add(path)
                out.append(path)
    return out


def _batch_path_exists(repo: GitRepo, queries: set[tuple[str, str]]) -> dict[tuple[str, str], bool]:
    if not queries:
        return {}
    ordered = sorted(queries)
    payload = "".join(f"{tag}:{path}\n" for tag, path in ordered)
    proc = subprocess.Popen(
        [*_git_base_cmd(repo.repo_path), "cat-file", "--batch-check"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    stdout, _ = proc.communicate(payload)
    out: dict[tuple[str, str], bool] = {}
    for query, raw_line in zip(ordered, stdout.splitlines()):
        out[query] = not raw_line.strip().endswith(" missing")
    for query in ordered[len(out):]:
        out[query] = False
    return out


def _runs_by_value(tags: list[str], fixed_tags: set[str]) -> list[dict[str, Any]]:
    if not tags:
        return []
    runs: list[dict[str, Any]] = []
    start = 0
    current = tags[0] in fixed_tags
    for idx, tag in enumerate(tags[1:], start=1):
        value = tag in fixed_tags
        if value == current:
            continue
        runs.append({"is_fix_containing": current, "tags": tags[start:idx]})
        start = idx
        current = value
    runs.append({"is_fix_containing": current, "tags": tags[start:]})
    return runs


def _merge_result(
    *,
    result: ASBSResult,
    predicted: set[str],
    probes: set[str],
    verdict_sources: dict[str, str],
) -> None:
    predicted.update(result.predicted_affected)
    probes.update(result.probe_tags)
    verdict_sources.update(result.verdict_sources)


def _run_git_guided_line_module(
    *,
    line: str,
    tags: list[str],
    affected_set: set[str],
    fix_containing_tags: set[str],
    nn_sentinel_count: int,
    aa_sentinel_count: int,
    fixed_segment_sentinel: int,
) -> LineRunResult:
    predicted: set[str] = set()
    probes: set[str] = set()
    verdict_sources: dict[str, str] = {}
    statuses: Counter[str] = Counter()

    def verdict_fn(tag: str) -> str:
        return "AFFECTED" if tag in affected_set else "NOT_AFFECTED"

    for segment in _runs_by_value(tags, fix_containing_tags):
        seg_tags = segment["tags"]
        if not segment["is_fix_containing"]:
            res = run_asbs_segment(
                seg_tags,
                verdict_fn,
                nn_sentinel_count=nn_sentinel_count,
                aa_sentinel_count=aa_sentinel_count,
            )
            _merge_result(result=res, predicted=predicted, probes=probes, verdict_sources=verdict_sources)
            statuses[res.status] += 1
            continue

        sentinel = run_fixed_segment_sentinel(
            seg_tags,
            verdict_fn,
            fixed_seg_sentinel=fixed_segment_sentinel,
        )
        _merge_result(result=sentinel, predicted=predicted, probes=probes, verdict_sources=verdict_sources)
        statuses[sentinel.status] += 1
        if sentinel.status == "fixed_segment_probe_hit":
            res = run_asbs_segment(
                seg_tags,
                verdict_fn,
                nn_sentinel_count=nn_sentinel_count,
                aa_sentinel_count=aa_sentinel_count,
            )
            _merge_result(result=res, predicted=predicted, probes=probes, verdict_sources=verdict_sources)
            statuses[f"fallback_{res.status}"] += 1

    is_positive = bool(predicted) or bool(probes & affected_set)
    return LineRunResult(
        line=line,
        is_positive=is_positive,
        predicted_affected=sorted(predicted),
        probe_tags=sorted(probes),
        verdict_sources=verdict_sources,
        statuses=dict(statuses),
        fix_containing_count=sum(1 for tag in tags if tag in fix_containing_tags),
    )


def _simulate_cve_module(
    *,
    cve_id: str,
    repo_name: str,
    affected_versions: list[str],
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    release_tags: list[str],
    fix_containing_tags: set[str],
    file_endpoint_lines: set[str],
    policy: str,
    nn_sentinel_count: int,
    aa_sentinel_count: int,
    fixed_segment_sentinel: int,
    expansion_radius: int,
) -> dict[str, Any]:
    mapped_gt, unmapped_gt = map_gt_tags_to_repo_tags(
        sorted(str(t) for t in affected_versions),
        release_tags,
        mode="loose",
    )
    affected_set = set(mapped_gt)
    release_set = set(release_tags)
    affected_lines = {
        line for line, tags in release_lines.items()
        if any(tag in affected_set for tag in tags)
    }

    if policy == "all_lines_soft":
        seed_lines = set(release_lines)
    elif policy == "staged_nofix_stride3_file":
        seed_lines = compute_seed_lines(
            repo_name=repo_name,
            release_lines=release_lines,
            ordered_by_family=ordered_by_family,
            fix_containing_tags=fix_containing_tags,
            file_endpoint_lines=file_endpoint_lines,
            stride=3,
            file_neighbor_radius=1,
        )
    else:
        raise ValueError(f"unsupported module-backed policy: {policy}")

    def run_line(line: str, tags: list[str]) -> LineRunResult:
        return _run_git_guided_line_module(
            line=line,
            tags=tags,
            affected_set=affected_set,
            fix_containing_tags=fix_containing_tags,
            nn_sentinel_count=nn_sentinel_count,
            aa_sentinel_count=aa_sentinel_count,
            fixed_segment_sentinel=fixed_segment_sentinel,
        )

    state = run_staged_scheduler(
        seed_lines=seed_lines,
        release_lines=release_lines,
        ordered_by_family=ordered_by_family,
        fix_containing_tags=fix_containing_tags,
        run_line_fn=run_line,
        expansion_radius=expansion_radius,
        fallback_mode="none",
    )

    predicted_set = set(state.predicted_affected)
    probe_tags = set(state.all_probe_tags)
    visited = set(state.visited)
    tp = len(predicted_set & affected_set)
    fp = len(predicted_set - affected_set)
    fn = len(affected_set - predicted_set)
    tn = len(release_set - predicted_set - affected_set)
    precision = tp / (tp + fp) if (tp + fp) else (1.0 if not affected_set else 0.0)
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "cve_id": cve_id,
        "repo": repo_name,
        "policy": policy,
        "release_tag_count": len(release_tags),
        "line_count": len(release_lines),
        "seed_line_count": len(seed_lines),
        "active_line_count": len(visited),
        "positive_line_count": len(state.positive_lines),
        "affected_line_count": len(affected_lines),
        "skipped_affected_lines": len(affected_lines - visited),
        "file_endpoint_line_count": len(file_endpoint_lines),
        "fix_containing_tag_count": len(fix_containing_tags),
        "mapped_gt_count": len(mapped_gt),
        "unmapped_gt_count": len(unmapped_gt),
        "probe_count": len(probe_tags),
        "predicted_count": len(predicted_set),
        "fallback_used": False,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "exact_match": fp == 0 and fn == 0 and len(unmapped_gt) == 0,
        "full_mapped_recall": fn == 0,
        "has_fp": fp > 0,
        "has_fn": fn > 0,
        "status_counts": dict(state.status_counts),
    }


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    idx = round((len(sorted_values) - 1) * pct)
    return float(sorted_values[idx])


def _summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {}
    probe_values = [float(row["probe_count"]) for row in rows]
    active_line_values = [float(row["active_line_count"]) for row in rows]
    seed_line_values = [float(row.get("seed_line_count", row["active_line_count"])) for row in rows]
    skipped_affected_values = [float(row["skipped_affected_lines"]) for row in rows]
    tp = sum(int(row["tp"]) for row in rows)
    fp = sum(int(row["fp"]) for row in rows)
    fn = sum(int(row["fn"]) for row in rows)
    tn = sum(int(row["tn"]) for row in rows)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "cves": len(rows),
        "probe_avg": round(statistics.mean(probe_values), 2),
        "probe_median": round(statistics.median(probe_values), 2),
        "probe_p90": round(_percentile(probe_values, 0.90), 2),
        "probe_p95": round(_percentile(probe_values, 0.95), 2),
        "probe_max": int(max(probe_values)),
        "seed_line_avg": round(statistics.mean(seed_line_values), 2),
        "active_line_avg": round(statistics.mean(active_line_values), 2),
        "skipped_affected_line_avg": round(statistics.mean(skipped_affected_values), 2),
        "exact_match_cves": sum(1 for row in rows if row["exact_match"]),
        "full_mapped_recall_cves": sum(1 for row in rows if row["full_mapped_recall"]),
        "has_fp_cves": sum(1 for row in rows if row["has_fp"]),
        "has_fn_cves": sum(1 for row in rows if row["has_fn"]),
        "unmapped_cves": sum(1 for row in rows if row["unmapped_gt_count"] > 0),
        "skipped_affected_line_cves": sum(1 for row in rows if row["skipped_affected_lines"] > 0),
        "fallback_used_cves": sum(1 for row in rows if row.get("fallback_used")),
        "micro_tp": tp,
        "micro_fp": fp,
        "micro_fn": fn,
        "micro_tn": tn,
        "micro_precision": round(precision, 6),
        "micro_recall": round(recall, 6),
        "micro_f1": round(f1, 6),
        "macro_precision": round(statistics.mean(float(row["precision"]) for row in rows), 6),
        "macro_recall": round(statistics.mean(float(row["recall"]) for row in rows), 6),
        "macro_f1": round(statistics.mean(float(row["f1"]) for row in rows), 6),
    }


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["policy"]].append(row)
    overall = {key: _summarize_rows(vals) for key, vals in sorted(grouped.items())}
    by_repo: dict[str, dict[str, Any]] = {}
    for key, vals in sorted(grouped.items()):
        repo_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in vals:
            repo_groups[row["repo"]].append(row)
        by_repo[key] = {repo: _summarize_rows(repo_rows) for repo, repo_rows in sorted(repo_groups.items())}
    return {"overall": overall, "by_repo": by_repo}


def _load_reference_rows(path: Path, policies: set[str]) -> dict[tuple[str, str, str], dict[str, Any]]:
    if not path.exists():
        return {}
    out: dict[tuple[str, str, str], dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as fp:
        for line in fp:
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("policy") in policies:
                out[(row["policy"], row["repo"], row["cve_id"])] = row
    return out


def _diff_reference(rows: list[dict[str, Any]], reference_path: Path) -> list[dict[str, Any]]:
    policies = {row["policy"] for row in rows}
    ref = _load_reference_rows(reference_path, policies)
    mismatches: list[dict[str, Any]] = []
    for row in rows:
        key = (row["policy"], row["repo"], row["cve_id"])
        expected = ref.get(key)
        if expected is None:
            mismatches.append({"policy": row["policy"], "repo": row["repo"], "cve_id": row["cve_id"], "error": "missing_reference"})
            continue
        fields = ["probe_count", "tp", "fp", "fn", "tn", "exact_match", "active_line_count", "seed_line_count"]
        diffs = {
            field: {"module": row.get(field), "reference": expected.get(field)}
            for field in fields
            if row.get(field) != expected.get(field)
        }
        if diffs:
            mismatches.append({
                "policy": row["policy"],
                "repo": row["repo"],
                "cve_id": row["cve_id"],
                "diffs": diffs,
            })
    return mismatches


def _write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as fp:
        for row in rows:
            fp.write(json.dumps(row, ensure_ascii=False) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run module-backed Step3 GT scheduler simulation.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--policies", default="all_lines_soft,staged_nofix_stride3_file")
    parser.add_argument("--nn-sentinel-count", type=int, default=NN_SENTINEL_COUNT)
    parser.add_argument("--aa-sentinel-count", type=int, default=AA_SENTINEL_COUNT)
    parser.add_argument("--fixed-segment-sentinel", type=int, default=FIXED_SEG_SENTINEL)
    parser.add_argument("--expansion-radius", type=int, default=1)
    parser.add_argument("--reference-per-cve", type=Path, default=REFERENCE_PER_CVE)
    parser.add_argument(
        "--strict-reference-parity",
        action="store_true",
        help=(
            "Exit non-zero when module output differs from reference_per_cve. "
            "Default is report-only because cost-aware profiles can intentionally "
            "differ from the high-precision v2 reference."
        ),
    )
    args = parser.parse_args(argv)

    dataset = _load_dataset(args.dataset)
    policies = [part.strip() for part in args.policies.split(",") if part.strip()]

    by_repo_records: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for cve_id, rec in sorted(dataset.items()):
        repo_name = str(rec.get("repo") or "").strip()
        if repo_name:
            by_repo_records[repo_name].append((cve_id, rec))

    contexts: dict[str, dict[str, Any]] = {}
    commit_contains_by_repo: dict[str, dict[str, dict[str, Any]]] = {}
    changed_files_by_cve: dict[str, list[str]] = {}
    endpoint_queries_by_repo: dict[str, set[tuple[str, str]]] = defaultdict(set)

    for repo_name, records in sorted(by_repo_records.items()):
        context = _release_context(repo_name, args.repo_root / repo_name)
        contexts[repo_name] = context
        repo: GitRepo = context["repo"]
        target_commits: set[str] = set()
        changed_cache: dict[str, list[str]] = {}
        endpoint_tags = {
            tag
            for tags in context["release_lines"].values()
            for tag in ([tags[0], tags[-1]] if tags else [])
        }
        for cve_id, rec in records:
            commits = _flatten_fixing_commits(rec.get("fixing_commits") or rec.get("fixing_commit"))
            target_commits.update(commits)
            files = _changed_files_for_commits(repo, commits, changed_cache)
            changed_files_by_cve[cve_id] = files
            for tag in endpoint_tags:
                for path in files:
                    endpoint_queries_by_repo[repo_name].add((tag, path))
        commit_contains_by_repo[repo_name] = batch_tags_containing(
            repo=repo,
            release_tags=context["release_tags"],
            target_commits=target_commits,
        )

    path_exists_by_repo: dict[str, dict[tuple[str, str], bool]] = {}
    for repo_name, queries in sorted(endpoint_queries_by_repo.items()):
        path_exists_by_repo[repo_name] = _batch_path_exists(contexts[repo_name]["repo"], queries)

    rows: list[dict[str, Any]] = []
    for repo_name, records in sorted(by_repo_records.items()):
        context = contexts[repo_name]
        release_lines: dict[str, list[str]] = context["release_lines"]
        for cve_id, rec in records:
            commits = _flatten_fixing_commits(rec.get("fixing_commits") or rec.get("fixing_commit"))
            fix_containing_tags: set[str] = set()
            for commit in commits:
                result = commit_contains_by_repo[repo_name].get(commit, {"ok": False, "tags": []})
                if result.get("ok"):
                    fix_containing_tags.update(result.get("tags", []))
            files = changed_files_by_cve.get(cve_id, [])
            path_exists = path_exists_by_repo.get(repo_name, {})
            file_endpoint_lines: set[str] = set()
            for line, tags in release_lines.items():
                if not tags:
                    continue
                endpoints = {tags[0], tags[-1]}
                if any(path_exists.get((tag, path), False) for tag in endpoints for path in files):
                    file_endpoint_lines.add(line)

            for policy in policies:
                rows.append(_simulate_cve_module(
                    cve_id=cve_id,
                    repo_name=repo_name,
                    affected_versions=list(rec.get("affected_version") or []),
                    release_lines=release_lines,
                    ordered_by_family=context["ordered_by_family"],
                    release_tags=context["release_tags"],
                    fix_containing_tags=fix_containing_tags,
                    file_endpoint_lines=file_endpoint_lines,
                    policy=policy,
                    nn_sentinel_count=args.nn_sentinel_count,
                    aa_sentinel_count=args.aa_sentinel_count,
                    fixed_segment_sentinel=args.fixed_segment_sentinel,
                    expansion_radius=args.expansion_radius,
                ))

    args.out_dir.mkdir(parents=True, exist_ok=True)
    summary = _summarize(rows)
    mismatches = _diff_reference(rows, args.reference_per_cve)
    metadata = {
        "dataset": str(args.dataset),
        "repo_root": str(args.repo_root),
        "policies": policies,
        "nn_sentinel_count": args.nn_sentinel_count,
        "aa_sentinel_count": args.aa_sentinel_count,
        "fixed_segment_sentinel": args.fixed_segment_sentinel,
        "expansion_radius": args.expansion_radius,
        "total_simulation_rows": len(rows),
        "reference_per_cve": str(args.reference_per_cve),
        "mismatch_count": len(mismatches),
        "strict_reference_parity": bool(args.strict_reference_parity),
        "oracle_note": "Module-backed GT-oracle simulator: affected_version supplies ideal probe verdicts.",
    }
    _write_json(args.out_dir / "summary.json", {"metadata": metadata, **summary})
    _write_jsonl(args.out_dir / "per_cve.jsonl", rows)
    _write_json(args.out_dir / "mismatch_cases.json", mismatches)
    print(json.dumps({"metadata": metadata, "overall": summary["overall"]}, ensure_ascii=False, indent=2))
    return 2 if args.strict_reference_parity and mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
