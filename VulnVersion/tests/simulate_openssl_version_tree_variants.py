"""OpenSSL-only release-line builder variants for Step3.

The global TDSC-style experiment showed that OpenSSL is the only repository
where a generic major.minor tree reduces probes without changing GT-oracle
metrics. This script isolates OpenSSL and tests whether that benefit comes
from a safe line merge or from semantically risky family mixing.

GT is used only for simulated probe verdicts and final metrics.
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = ROOT / "tests"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

import simulate_module_backed_step3 as module_sim
import simulate_step3_low_cost_schedulers as low_cost
import simulate_tdsc_version_tree_builder as builder_sim

from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.asbs_line import AA_SENTINEL_COUNT, FIXED_SEG_SENTINEL, NN_SENTINEL_COUNT
from vulnversion.stage3_verify.git_reachability import batch_tags_containing
from vulnversion.stage3_verify.line_scheduler import compute_seed_lines, run_staged_scheduler
from vulnversion.stage3_verify.version_registry import filter_release_tags, line_key, sort_tags_for_line


DEFAULT_DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
DEFAULT_REPO_ROOT = ROOT / "repo"
DEFAULT_OUT_DIR = ROOT / "tests" / "openssl_version_tree_variant_simulator"
REPO = "openssl"


@dataclass
class Variant:
    name: str
    line_fn: Callable[[str], str]
    family_fn: Callable[[str], str]
    note: str


def _numbers(tag: str) -> list[int]:
    return [int(x) for x in re.findall(r"\d+", tag)]


def _origin(tag: str) -> str:
    if tag.startswith("OpenSSL-fips-") or tag.startswith("OpenSSL_FIPS_"):
        return "fips"
    if tag.startswith("OpenSSL-engine-"):
        return "engine"
    return "mainline"


def _letter_series(tag: str) -> str:
    nums = _numbers(tag)
    if len(nums) >= 3:
        return f"{nums[0]}.{nums[1]}.{nums[2]}"
    if len(nums) >= 2:
        return f"{nums[0]}.{nums[1]}"
    return "main"


def _major_minor(tag: str) -> str:
    nums = _numbers(tag)
    if len(nums) >= 2:
        return f"{nums[0]}.{nums[1]}"
    if nums:
        return str(nums[0])
    return "main"


def _current_line(tag: str) -> str:
    return line_key(REPO, tag)


def _current_family(line: str) -> str:
    if line.startswith("fips-"):
        return "openssl-fips"
    if line.startswith("engine-"):
        return "openssl-engine"
    return "openssl-mainline"


def _generic_line(tag: str) -> str:
    return _major_minor(tag)


def _single_family(_: str) -> str:
    return "openssl-all"


def _prefixed_major_minor_line(tag: str) -> str:
    origin = _origin(tag)
    if origin == "fips":
        return f"fips-{_major_minor(tag)}"
    if origin == "engine":
        return f"engine-{_major_minor(tag)}"
    return _major_minor(tag)


def _prefixed_major_minor_family(line: str) -> str:
    if line.startswith("fips-"):
        return "openssl-fips"
    if line.startswith("engine-"):
        return "openssl-engine"
    return "openssl-mainline"


def _hybrid_safe_line(tag: str) -> str:
    origin = _origin(tag)
    if origin == "fips":
        return f"fips-{_major_minor(tag)}"
    if origin == "engine":
        nums = _numbers(tag)
        return f"engine-{'.'.join(map(str, nums[:3]))}" if len(nums) >= 3 else "engine-main"
    nums = _numbers(tag)
    if len(nums) >= 3 and nums[0] == 1:
        return f"{nums[0]}.{nums[1]}.{nums[2]}"
    if len(nums) >= 2:
        return f"{nums[0]}.{nums[1]}"
    return "main"


def _patch_series_family(line: str) -> str:
    return _prefixed_major_minor_family(line)


def _current_plus_merge_09_line(tag: str) -> str:
    origin = _origin(tag)
    if origin == "mainline":
        nums = _numbers(tag)
        if len(nums) >= 2 and nums[0] == 0 and nums[1] == 9:
            return "0.9"
    return _current_line(tag)


def _variant_defs() -> list[Variant]:
    return [
        Variant(
            "current",
            _current_line,
            _current_family,
            "Current version_registry line model.",
        ),
        Variant(
            "generic_major_minor_single_family",
            _generic_line,
            _single_family,
            "Generic TDSC major.minor; intentionally allows mainline/fips/engine mixing.",
        ),
        Variant(
            "major_minor_family_partition",
            _prefixed_major_minor_line,
            _prefixed_major_minor_family,
            "Major.minor lines but keep mainline/fips/engine in separate families.",
        ),
        Variant(
            "hybrid_patch_series_family_partition",
            _hybrid_safe_line,
            _patch_series_family,
            "Merge legacy 0.9.x and 3.x by major.minor; keep 1.0.2/1.1.1 letter series and fips/engine families.",
        ),
        Variant(
            "current_plus_merge_mainline_09",
            _current_plus_merge_09_line,
            _current_family,
            "Current model with only mainline 0.9.x collapsed.",
        ),
    ]


def _line_sort_key(line: str) -> tuple[Any, ...]:
    raw = line
    prefix = 0
    if line.startswith("fips-"):
        prefix = 1
        raw = line[5:]
    elif line.startswith("engine-"):
        prefix = 2
        raw = line[7:]
    nums = [int(x) for x in re.findall(r"\d+", raw)]
    padded = tuple((nums + [-1] * 8)[:8])
    return (prefix, *padded, raw)


def _build_variant_context(repo: GitRepo, variant: Variant) -> dict[str, Any]:
    tags = filter_release_tags(REPO, repo.list_tags(max_tags=None))
    release_lines: dict[str, list[str]] = defaultdict(list)
    line_origins: dict[str, set[str]] = defaultdict(set)
    line_series: dict[str, set[str]] = defaultdict(set)
    for tag in tags:
        line = variant.line_fn(tag)
        release_lines[line].append(tag)
        line_origins[line].add(_origin(tag))
        line_series[line].add(_letter_series(tag))
    release_lines = {
        line: sort_tags_for_line(REPO, vals, reverse=False)
        for line, vals in release_lines.items()
    }
    grouped: dict[str, list[str]] = defaultdict(list)
    for line in release_lines:
        grouped[variant.family_fn(line)].append(line)
    ordered_by_family = {
        family: sorted(lines, key=_line_sort_key, reverse=True)
        for family, lines in sorted(grouped.items())
    }
    release_tags = [tag for vals in release_lines.values() for tag in vals]
    mixed_lines = {
        line: {
            "origins": sorted(line_origins[line]),
            "series": sorted(line_series[line]),
            "tag_count": len(release_lines[line]),
            "sample_tags": release_lines[line][:5],
        }
        for line in release_lines
        if len(line_origins[line]) > 1
    }
    multi_series_lines = {
        line: {
            "origins": sorted(line_origins[line]),
            "series": sorted(line_series[line]),
            "tag_count": len(release_lines[line]),
            "sample_tags": release_lines[line][:5],
        }
        for line in release_lines
        if len(line_series[line]) > 1
    }
    return {
        "release_lines": release_lines,
        "ordered_by_family": ordered_by_family,
        "release_tags": release_tags,
        "mixed_origin_lines": mixed_lines,
        "multi_series_lines": multi_series_lines,
        "line_origins": line_origins,
        "line_series": line_series,
    }


def _pct(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    vals = sorted(values)
    idx = round((len(vals) - 1) * pct)
    return float(vals[idx])


def _mean(values: list[float]) -> float:
    return float(statistics.mean(values)) if values else 0.0


def _simulate_cve(
    *,
    cve_id: str,
    affected_versions: list[str],
    context: dict[str, Any],
    fix_containing_tags: set[str],
    file_endpoint_lines: set[str],
    nn_sentinel_count: int,
    aa_sentinel_count: int,
    fixed_segment_sentinel: int,
) -> dict[str, Any]:
    release_lines = context["release_lines"]
    ordered_by_family = context["ordered_by_family"]
    release_tags = context["release_tags"]
    mapped_gt, unmapped_gt = map_gt_tags_to_repo_tags(
        sorted(str(t) for t in affected_versions),
        release_tags,
        mode="loose",
    )
    affected_set = set(mapped_gt)
    seed_lines = compute_seed_lines(
        repo_name=REPO,
        release_lines=release_lines,
        ordered_by_family=ordered_by_family,
        fix_containing_tags=fix_containing_tags,
        file_endpoint_lines=file_endpoint_lines,
        stride=3,
        file_neighbor_radius=1,
    )

    def run_line(line: str, tags: list[str]) -> Any:
        return module_sim._run_git_guided_line_module(
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
        expansion_radius=1,
        fallback_mode="none",
    )
    predicted = set(state.predicted_affected)
    release_set = set(release_tags)
    tp = len(predicted & affected_set)
    fp = len(predicted - affected_set)
    fn = len(affected_set - predicted)
    tn = len(release_set - predicted - affected_set)
    precision = tp / (tp + fp) if (tp + fp) else (1.0 if not affected_set else 0.0)
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    affected_lines = {
        line for line, tags in release_lines.items()
        if any(tag in affected_set for tag in tags)
    }
    visited = set(state.visited)
    mixed_affected_lines = sorted(set(context["mixed_origin_lines"]) & affected_lines)
    multi_series_affected_lines = sorted(set(context["multi_series_lines"]) & affected_lines)
    return {
        "cve_id": cve_id,
        "release_tag_count": len(release_tags),
        "line_count": len(release_lines),
        "seed_line_count": len(seed_lines),
        "active_line_count": len(visited),
        "affected_line_count": len(affected_lines),
        "skipped_affected_line_count": len(affected_lines - visited),
        "skipped_affected_lines": sorted(affected_lines - visited),
        "mixed_origin_affected_lines": mixed_affected_lines,
        "multi_series_affected_lines": multi_series_affected_lines,
        "probe_count": len(state.all_probe_tags),
        "predicted_count": len(predicted),
        "mapped_gt_count": len(mapped_gt),
        "unmapped_gt_count": len(unmapped_gt),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "exact_match": fp == 0 and fn == 0 and len(unmapped_gt) == 0,
        "has_fn": fn > 0,
        "has_fp": fp > 0,
        "status_counts": dict(state.status_counts),
    }


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    probes = [float(r["probe_count"]) for r in rows]
    active = [float(r["active_line_count"]) for r in rows]
    tp = sum(int(r["tp"]) for r in rows)
    fp = sum(int(r["fp"]) for r in rows)
    fn = sum(int(r["fn"]) for r in rows)
    tn = sum(int(r["tn"]) for r in rows)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "cves": len(rows),
        "avg_probes": round(_mean(probes), 2),
        "p50_probes": round(_pct(probes, 0.50), 2),
        "p95_probes": round(_pct(probes, 0.95), 2),
        "max_probes": int(max(probes)) if probes else 0,
        "avg_active_lines": round(_mean(active), 2),
        "exact_cves": sum(1 for r in rows if r["exact_match"]),
        "fn_cves": sum(1 for r in rows if r["has_fn"]),
        "fp_cves": sum(1 for r in rows if r["has_fp"]),
        "skipped_affected_line_cves": sum(1 for r in rows if r["skipped_affected_line_count"] > 0),
        "mixed_origin_affected_cves": sum(1 for r in rows if r["mixed_origin_affected_lines"]),
        "multi_series_affected_cves": sum(1 for r in rows if r["multi_series_affected_lines"]),
        "version_tp": tp,
        "version_fp": fp,
        "version_fn": fn,
        "version_tn": tn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
    }


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _write_report(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# OpenSSL VersionTree Variant Simulator",
        "",
        f"Dataset: `{summary['metadata']['dataset']}`.",
        "",
        "GT is used only for oracle probe verdicts and final metrics.",
        "",
        "| variant | lines | mixed-origin lines | multi-series lines | avg probes | p95 | exact CVEs | FN CVEs | version FN | recall | F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, metrics in summary["overall"].items():
        topo = summary["topology"][name]
        lines.append(
            "| {name} | {lines_n} | {mixed} | {multi} | {avg:.2f} | {p95:.2f} | {exact}/{total} | {fnc} | {vfn} | {recall:.6f} | {f1:.6f} |".format(
                name=name,
                lines_n=topo["line_count"],
                mixed=topo["mixed_origin_line_count"],
                multi=topo["multi_series_line_count"],
                avg=metrics["avg_probes"],
                p95=metrics["p95_probes"],
                exact=metrics["exact_cves"],
                total=metrics["cves"],
                fnc=metrics["fn_cves"],
                vfn=metrics["version_fn"],
                recall=metrics["recall"],
                f1=metrics["f1"],
            )
        )
    lines.extend([
        "",
        "Interpretation:",
        "",
        "- Mixed-origin lines combine mainline/fips/engine tags and are semantically risky even if GT metrics do not drop.",
        "- Multi-series lines combine multiple maintenance series such as 1.0.0/1.0.1/1.0.2 and require case review.",
        "- A variant is eligible only if it reduces probes without introducing semantic mixing that affects CVE cases.",
        "",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OpenSSL-only line builder variant simulator.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--nn-sentinel-count", type=int, default=NN_SENTINEL_COUNT)
    parser.add_argument("--aa-sentinel-count", type=int, default=AA_SENTINEL_COUNT)
    parser.add_argument("--fixed-segment-sentinel", type=int, default=FIXED_SEG_SENTINEL)
    args = parser.parse_args(argv)

    dataset = json.loads(args.dataset.read_text(encoding="utf-8"))
    records = [
        (cve_id, rec) for cve_id, rec in sorted(dataset.items())
        if str(rec.get("repo") or "") == REPO
    ]
    repo = GitRepo.open(args.repo_root / REPO)
    variants = _variant_defs()
    contexts = {variant.name: _build_variant_context(repo, variant) for variant in variants}

    commits_all: set[str] = set()
    changed_cache: dict[str, list[str]] = {}
    changed_files_by_cve: dict[str, list[str]] = {}
    endpoint_queries: set[tuple[str, str]] = set()
    for cve_id, rec in records:
        commits = low_cost._flatten_fixing_commits(rec.get("fixing_commits") or rec.get("fixing_commit"))
        commits_all.update(commits)
        files = module_sim._changed_files_for_commits(repo, commits, changed_cache)
        changed_files_by_cve[cve_id] = files
        for context in contexts.values():
            sample_tags = {
                tag
                for tags in context["release_lines"].values()
                for tag in low_cost._sample_tags_for_line(tags)
            }
            for tag in sample_tags:
                for path in files[:3]:
                    endpoint_queries.add((tag, path))

    commit_contains = batch_tags_containing(
        repo=repo,
        release_tags=contexts[variants[0].name]["release_tags"],
        target_commits=commits_all,
    )
    path_exists = module_sim._batch_path_exists(repo, endpoint_queries)

    rows_by_variant: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for variant in variants:
        context = contexts[variant.name]
        for cve_id, rec in records:
            commits = low_cost._flatten_fixing_commits(rec.get("fixing_commits") or rec.get("fixing_commit"))
            fix_containing_tags: set[str] = set()
            for commit in commits:
                result = commit_contains.get(commit, {"ok": False, "tags": []})
                if result.get("ok"):
                    fix_containing_tags.update(result.get("tags", []))
            file_endpoint_lines: set[str] = set()
            for line, tags in context["release_lines"].items():
                for tag in low_cost._sample_tags_for_line(tags):
                    if any(path_exists.get((tag, path), False) for path in changed_files_by_cve.get(cve_id, [])[:3]):
                        file_endpoint_lines.add(line)
                        break
            row = _simulate_cve(
                cve_id=cve_id,
                affected_versions=list(rec.get("affected_version") or []),
                context=context,
                fix_containing_tags=fix_containing_tags,
                file_endpoint_lines=file_endpoint_lines,
                nn_sentinel_count=args.nn_sentinel_count,
                aa_sentinel_count=args.aa_sentinel_count,
                fixed_segment_sentinel=args.fixed_segment_sentinel,
            )
            row["variant"] = variant.name
            rows_by_variant[variant.name].append(row)

    topology: dict[str, Any] = {}
    for variant in variants:
        context = contexts[variant.name]
        sizes = [len(tags) for tags in context["release_lines"].values()]
        topology[variant.name] = {
            "note": variant.note,
            "release_tag_count": len(context["release_tags"]),
            "line_count": len(context["release_lines"]),
            "family_count": len(context["ordered_by_family"]),
            "singleton_line_count": sum(1 for size in sizes if size == 1),
            "avg_tags_per_line": round(_mean([float(s) for s in sizes]), 2),
            "max_tags_per_line": max(sizes) if sizes else 0,
            "mixed_origin_line_count": len(context["mixed_origin_lines"]),
            "multi_series_line_count": len(context["multi_series_lines"]),
            "mixed_origin_lines": context["mixed_origin_lines"],
            "multi_series_lines": context["multi_series_lines"],
        }

    overall = {name: _summarize(rows) for name, rows in rows_by_variant.items()}
    all_rows = [row for rows in rows_by_variant.values() for row in rows]
    fn_cases = [
        row for row in all_rows
        if row["has_fn"] or row["skipped_affected_line_count"] > 0
    ]
    fn_cases.sort(key=lambda r: (-int(r["fn"]), -int(r["skipped_affected_line_count"]), r["variant"], r["cve_id"]))
    semantic_risk_cases = [
        row for row in all_rows
        if row["mixed_origin_affected_lines"] or row["multi_series_affected_lines"]
    ]
    semantic_risk_cases.sort(key=lambda r: (r["variant"], r["cve_id"]))

    summary = {
        "metadata": {
            "dataset": str(args.dataset),
            "repo_root": str(args.repo_root),
            "repo": REPO,
            "cves": len(records),
            "nn_sentinel_count": args.nn_sentinel_count,
            "aa_sentinel_count": args.aa_sentinel_count,
            "fixed_segment_sentinel": args.fixed_segment_sentinel,
            "oracle_note": "GT is used only for simulated probe verdicts and final metrics.",
        },
        "topology": topology,
        "overall": overall,
    }

    args.out_dir.mkdir(parents=True, exist_ok=True)
    _write_json(args.out_dir / "summary.json", summary)
    _write_json(args.out_dir / "topology.json", topology)
    _write_json(args.out_dir / "fn_cases.json", fn_cases)
    _write_json(args.out_dir / "semantic_risk_cases.json", semantic_risk_cases)
    _write_jsonl(args.out_dir / "per_cve.jsonl", all_rows)
    _write_report(args.out_dir / "report.md", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
