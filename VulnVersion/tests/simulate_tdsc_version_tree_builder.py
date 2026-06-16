"""Compare release-line / version-tree builders for Step3.

This simulator changes only the release-line construction layer and keeps the
rest of Step3's module-backed GT oracle pipeline fixed:

  release tags -> line/tree builder -> current staged_nofix_stride3_file
  -> ASBS oracle probes -> interval inference -> metrics

Builders compared:
  - current_version_registry: current version_registry.line_key()
  - tdsc_version_tree: generic TDSC-style major.minor version tree
  - tdsc_hybrid_repo_aware: repo-aware TDSC-style tree for the 9 target repos

GT is used only for simulated probe verdicts and final metrics, never for
building lines or selecting probes.
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from collections import Counter, defaultdict
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

from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.asbs_line import (
    AA_SENTINEL_COUNT,
    FIXED_SEG_SENTINEL,
    NN_SENTINEL_COUNT,
)
from vulnversion.stage3_verify.git_reachability import batch_tags_containing
from vulnversion.stage3_verify.line_scheduler import compute_seed_lines, run_staged_scheduler
from vulnversion.stage3_verify.version_registry import (
    filter_release_tags,
    line_family_key,
    line_key,
    parse_version,
    sort_tags_for_line,
)


DEFAULT_DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
DEFAULT_REPO_ROOT = ROOT / "repo"
DEFAULT_OUT_DIR = ROOT / "tests" / "tdsc_version_tree_builder_simulator"
BUILDERS = ("current_version_registry", "tdsc_version_tree", "tdsc_hybrid_repo_aware")


@dataclass
class BuilderContext:
    """Release graph built by one line/tree builder."""

    builder: str
    repo_name: str
    repo: GitRepo
    release_tags: list[str]
    release_lines: dict[str, list[str]]
    ordered_by_family: dict[str, list[str]]


def _load_dataset(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _numbers(tag: str) -> list[int]:
    return [int(x) for x in re.findall(r"\d+", tag)]


def _line_sort_key(line: str) -> tuple[Any, ...]:
    prefix_rank = 0
    raw = line
    if line.startswith("fips-"):
        prefix_rank = 1
        raw = line[len("fips-"):]
    elif line.startswith("engine-"):
        prefix_rank = 2
        raw = line[len("engine-"):]
    nums = [int(x) for x in re.findall(r"\d+", raw)]
    padded = tuple((nums + [-1] * 8)[:8])
    return (prefix_rank, *padded, raw)


def _tdsc_line_key(repo: str, tag: str) -> str:
    """Generic TDSC-style branch key: first two numeric components."""
    nums = _numbers(tag)
    if len(nums) >= 2:
        return f"{nums[0]}.{nums[1]}"
    if nums:
        return str(nums[0])
    return "main"


def _tdsc_hybrid_line_key(repo: str, tag: str) -> str:
    """Repo-aware TDSC-style branch key for the 9 target repos.

    This is intentionally a hypothesis to be tested, not a production rule.
    """
    nums = _numbers(tag)
    if repo == "curl":
        # The current single-line curl model is cheap and must be tested
        # against generic major.minor splitting before replacement.
        return "main"

    if repo == "ImageMagick":
        if len(nums) >= 3:
            return f"{nums[0]}.{nums[1]}.{nums[2]}"
        if len(nums) >= 2:
            return f"{nums[0]}.{nums[1]}"
        return "main"

    if repo == "openssl":
        if tag.startswith("OpenSSL-fips-") or tag.startswith("OpenSSL_FIPS_"):
            return f"fips-{nums[0]}.{nums[1]}" if len(nums) >= 2 else "fips-main"
        if tag.startswith("OpenSSL-engine-"):
            return f"engine-{nums[0]}.{nums[1]}.{nums[2]}" if len(nums) >= 3 else "engine-main"
        if len(nums) >= 3 and nums[0] == 1:
            # Keep letter-patch maintenance lines such as 1.0.2 and 1.1.1.
            return f"{nums[0]}.{nums[1]}.{nums[2]}"
        if len(nums) >= 2:
            # OpenSSL 3.0.x / 3.1.x behave like major.minor stable lines.
            return f"{nums[0]}.{nums[1]}"
        return "main"

    if len(nums) >= 2:
        return f"{nums[0]}.{nums[1]}"
    if nums:
        return str(nums[0])
    return "main"


def _current_family(repo: str, line: str) -> str:
    return line_family_key(repo, line)


def _tdsc_family(repo: str, line: str) -> str:
    return f"{repo}-mainline"


def _tdsc_hybrid_family(repo: str, line: str) -> str:
    if repo == "openssl":
        if line.startswith("fips-"):
            return "openssl-fips"
        if line.startswith("engine-"):
            return "openssl-engine"
        return "openssl-mainline"
    return f"{repo}-mainline"


def _builder_funcs(builder: str) -> tuple[Callable[[str, str], str], Callable[[str, str], str]]:
    if builder == "current_version_registry":
        return line_key, _current_family
    if builder == "tdsc_version_tree":
        return _tdsc_line_key, _tdsc_family
    if builder == "tdsc_hybrid_repo_aware":
        return _tdsc_hybrid_line_key, _tdsc_hybrid_family
    raise ValueError(f"unsupported builder: {builder}")


def _build_context(repo_name: str, repo_path: Path, builder: str) -> BuilderContext:
    repo = GitRepo.open(repo_path)
    release_tags_raw = filter_release_tags(repo_name, repo.list_tags(max_tags=None))
    line_fn, family_fn = _builder_funcs(builder)
    release_lines: dict[str, list[str]] = defaultdict(list)
    for tag in release_tags_raw:
        release_lines[line_fn(repo_name, tag)].append(tag)
    release_lines = {
        line: sort_tags_for_line(repo_name, tags, reverse=False)
        for line, tags in release_lines.items()
    }
    grouped: dict[str, list[str]] = defaultdict(list)
    for line in release_lines:
        grouped[family_fn(repo_name, line)].append(line)
    ordered_by_family = {
        family: sorted(lines, key=_line_sort_key, reverse=True)
        for family, lines in sorted(grouped.items())
    }
    release_tags = [tag for tags in release_lines.values() for tag in tags]
    return BuilderContext(
        builder=builder,
        repo_name=repo_name,
        repo=repo,
        release_tags=release_tags,
        release_lines=dict(release_lines),
        ordered_by_family=ordered_by_family,
    )


def _pct(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    vals = sorted(values)
    idx = round((len(vals) - 1) * pct)
    return float(vals[idx])


def _mean(values: list[float]) -> float:
    return float(statistics.mean(values)) if values else 0.0


def _line_quality_for_cve(
    *,
    cve_id: str,
    repo_name: str,
    builder: str,
    release_lines: dict[str, list[str]],
    release_tags: list[str],
    affected_versions: list[str],
) -> dict[str, Any]:
    mapped_gt, unmapped_gt = map_gt_tags_to_repo_tags(
        sorted(str(t) for t in affected_versions),
        release_tags,
        mode="loose",
    )
    affected = set(mapped_gt)
    affected_line_count = 0
    contiguous_line_count = 0
    noncontiguous_lines: list[str] = []
    monotone_line_count = 0
    for line, tags in release_lines.items():
        idxs = [idx for idx, tag in enumerate(tags) if tag in affected]
        if not idxs:
            continue
        affected_line_count += 1
        is_contig = idxs == list(range(min(idxs), max(idxs) + 1))
        if is_contig:
            contiguous_line_count += 1
        else:
            noncontiguous_lines.append(line)
        if idxs == sorted(idxs):
            monotone_line_count += 1
    return {
        "cve_id": cve_id,
        "repo": repo_name,
        "builder": builder,
        "line_count": len(release_lines),
        "affected_line_count": affected_line_count,
        "contiguous_affected_line_count": contiguous_line_count,
        "noncontiguous_affected_line_count": len(noncontiguous_lines),
        "noncontiguous_lines": noncontiguous_lines,
        "monotone_affected_line_count": monotone_line_count,
        "mapped_gt_count": len(mapped_gt),
        "unmapped_gt_count": len(unmapped_gt),
    }


def _simulate_cve(
    *,
    cve_id: str,
    repo_name: str,
    builder: str,
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    release_tags: list[str],
    affected_versions: list[str],
    fix_containing_tags: set[str],
    file_endpoint_lines: set[str],
    nn_sentinel_count: int,
    aa_sentinel_count: int,
    fixed_segment_sentinel: int,
) -> dict[str, Any]:
    mapped_gt, unmapped_gt = map_gt_tags_to_repo_tags(
        sorted(str(t) for t in affected_versions),
        release_tags,
        mode="loose",
    )
    affected_set = set(mapped_gt)
    seed_lines = compute_seed_lines(
        repo_name=repo_name,
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
    predicted_set = set(state.predicted_affected)
    release_set = set(release_tags)
    tp = len(predicted_set & affected_set)
    fp = len(predicted_set - affected_set)
    fn = len(affected_set - predicted_set)
    tn = len(release_set - predicted_set - affected_set)
    precision = tp / (tp + fp) if (tp + fp) else (1.0 if not affected_set else 0.0)
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    affected_lines = {
        line for line, tags in release_lines.items()
        if any(tag in affected_set for tag in tags)
    }
    skipped_affected_lines = affected_lines - set(state.visited)
    return {
        "cve_id": cve_id,
        "repo": repo_name,
        "builder": builder,
        "release_tag_count": len(release_tags),
        "line_count": len(release_lines),
        "singleton_line_count": sum(1 for tags in release_lines.values() if len(tags) == 1),
        "seed_line_count": len(seed_lines),
        "active_line_count": len(state.visited),
        "positive_line_count": len(state.positive_lines),
        "affected_line_count": len(affected_lines),
        "skipped_affected_line_count": len(skipped_affected_lines),
        "skipped_affected_lines": sorted(skipped_affected_lines),
        "probe_count": len(state.all_probe_tags),
        "predicted_count": len(predicted_set),
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
        "has_fp": fp > 0,
        "has_fn": fn > 0,
        "status_counts": dict(state.status_counts),
    }


def _summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {}
    probes = [float(row["probe_count"]) for row in rows]
    line_counts = [float(row["line_count"]) for row in rows]
    singletons = [float(row["singleton_line_count"]) for row in rows]
    active = [float(row["active_line_count"]) for row in rows]
    skipped = [float(row["skipped_affected_line_count"]) for row in rows]
    tp = sum(int(row["tp"]) for row in rows)
    fp = sum(int(row["fp"]) for row in rows)
    fn = sum(int(row["fn"]) for row in rows)
    tn = sum(int(row["tn"]) for row in rows)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    singleton_ratio = sum(singletons) / sum(line_counts) if sum(line_counts) else 0.0
    return {
        "cves": len(rows),
        "avg_lines": round(_mean(line_counts), 2),
        "avg_singleton_lines": round(_mean(singletons), 2),
        "singleton_line_ratio": round(singleton_ratio, 6),
        "avg_active_lines": round(_mean(active), 2),
        "avg_skipped_affected_lines": round(_mean(skipped), 4),
        "avg_probes": round(_mean(probes), 2),
        "p50_probes": round(_pct(probes, 0.50), 2),
        "p95_probes": round(_pct(probes, 0.95), 2),
        "max_probes": int(max(probes)) if probes else 0,
        "exact_cves": sum(1 for row in rows if row["exact_match"]),
        "fn_cves": sum(1 for row in rows if row["has_fn"]),
        "fp_cves": sum(1 for row in rows if row["has_fp"]),
        "skipped_affected_line_cves": sum(1 for row in rows if row["skipped_affected_line_count"] > 0),
        "unmapped_cves": sum(1 for row in rows if row["unmapped_gt_count"] > 0),
        "version_tp": tp,
        "version_fp": fp,
        "version_fn": fn,
        "version_tn": tn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
    }


def _summarize_quality(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {}
    affected_lines = sum(int(r["affected_line_count"]) for r in rows)
    contiguous = sum(int(r["contiguous_affected_line_count"]) for r in rows)
    noncontig = sum(int(r["noncontiguous_affected_line_count"]) for r in rows)
    return {
        "cves": len(rows),
        "affected_lines": affected_lines,
        "contiguous_affected_lines": contiguous,
        "noncontiguous_affected_lines": noncontig,
        "affected_line_continuity": round(contiguous / affected_lines, 6) if affected_lines else 1.0,
        "noncontiguous_line_cves": sum(1 for r in rows if r["noncontiguous_affected_line_count"] > 0),
        "unmapped_cves": sum(1 for r in rows if r["unmapped_gt_count"] > 0),
    }


def _group_summary(rows: list[dict[str, Any]], key: str, summarizer: Callable[[list[dict[str, Any]]], dict[str, Any]]) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[str(row[key])].append(row)
    return {name: summarizer(vals) for name, vals in sorted(groups.items())}


def _write_report(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# TDSC-style VersionTree Builder Simulator",
        "",
        f"Dataset: `{summary['metadata']['dataset']}`.",
        "",
        "GT is used only for oracle probe verdicts and final metrics.",
        "",
        "## Overall Metrics",
        "",
        "| builder | avg lines | singleton ratio | avg probes | p95 | exact CVEs | FN CVEs | version FN | precision | recall | F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for builder, metrics in summary["overall"].items():
        lines.append(
            "| {b} | {lines_avg:.2f} | {single:.4f} | {avg:.2f} | {p95:.2f} | {exact}/1128 | {fnc} | {vfn} | {p:.6f} | {r:.6f} | {f1:.6f} |".format(
                b=builder,
                lines_avg=metrics["avg_lines"],
                single=metrics["singleton_line_ratio"],
                avg=metrics["avg_probes"],
                p95=metrics["p95_probes"],
                exact=metrics["exact_cves"],
                fnc=metrics["fn_cves"],
                vfn=metrics["version_fn"],
                p=metrics["precision"],
                r=metrics["recall"],
                f1=metrics["f1"],
            )
        )
    lines.extend([
        "",
        "## Affected-line Continuity",
        "",
        "| builder | affected lines | non-contiguous lines | non-contiguous CVEs | continuity |",
        "| --- | ---: | ---: | ---: | ---: |",
    ])
    for builder, metrics in summary["line_quality"].items():
        lines.append(
            "| {b} | {aff} | {non} | {cves} | {cont:.6f} |".format(
                b=builder,
                aff=metrics["affected_lines"],
                non=metrics["noncontiguous_affected_lines"],
                cves=metrics["noncontiguous_line_cves"],
                cont=metrics["affected_line_continuity"],
            )
        )
    lines.extend([
        "",
        "## Interpretation",
        "",
        "- A builder is not better just because its version tree is more fine-grained.",
        "- It must reduce probes without increasing version FN or reducing exact CVEs.",
        "- `tdsc_version_tree` is the generic major.minor rule; `tdsc_hybrid_repo_aware` is the repo-aware hypothesis.",
        "",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare Step3 line/tree builders on BaseDataOrder.json.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--builders", default=",".join(BUILDERS))
    parser.add_argument("--limit-cves", type=int, default=0)
    parser.add_argument("--nn-sentinel-count", type=int, default=NN_SENTINEL_COUNT)
    parser.add_argument("--aa-sentinel-count", type=int, default=AA_SENTINEL_COUNT)
    parser.add_argument("--fixed-segment-sentinel", type=int, default=FIXED_SEG_SENTINEL)
    args = parser.parse_args(argv)

    builders = [b.strip() for b in args.builders.split(",") if b.strip()]
    dataset = _load_dataset(args.dataset)
    by_repo: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for cve_id, rec in sorted(dataset.items()):
        repo_name = str(rec.get("repo") or "").strip()
        if repo_name:
            by_repo[repo_name].append((cve_id, rec))
    if args.limit_cves > 0:
        remaining = args.limit_cves
        trimmed: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        for repo_name, records in sorted(by_repo.items()):
            take = min(remaining, len(records))
            if take:
                trimmed[repo_name] = records[:take]
                remaining -= take
            if remaining <= 0:
                break
        by_repo = defaultdict(list, trimmed)

    contexts: dict[tuple[str, str], BuilderContext] = {}
    commit_contains_by_repo: dict[str, dict[str, dict[str, Any]]] = {}
    changed_files_by_cve: dict[str, list[str]] = {}
    endpoint_queries_by_repo: dict[str, set[tuple[str, str]]] = defaultdict(set)

    for repo_name, records in sorted(by_repo.items()):
        current_repo = GitRepo.open(args.repo_root / repo_name)
        target_commits: set[str] = set()
        changed_cache: dict[str, list[str]] = {}
        for builder in builders:
            context = _build_context(repo_name, args.repo_root / repo_name, builder)
            contexts[(repo_name, builder)] = context
        for cve_id, rec in records:
            commits = low_cost._flatten_fixing_commits(rec.get("fixing_commits") or rec.get("fixing_commit"))
            target_commits.update(commits)
            files = module_sim._changed_files_for_commits(current_repo, commits, changed_cache)
            changed_files_by_cve[cve_id] = files
            for builder in builders:
                context = contexts[(repo_name, builder)]
                sample_tags = {
                    tag
                    for tags in context.release_lines.values()
                    for tag in low_cost._sample_tags_for_line(tags)
                }
                for tag in sample_tags:
                    for path in files[:3]:
                        endpoint_queries_by_repo[repo_name].add((tag, path))
        release_tags_for_reachability = contexts[(repo_name, builders[0])].release_tags
        commit_contains_by_repo[repo_name] = batch_tags_containing(
            repo=current_repo,
            release_tags=release_tags_for_reachability,
            target_commits=target_commits,
        )

    path_exists_by_repo: dict[str, dict[tuple[str, str], bool]] = {}
    for repo_name in sorted(by_repo):
        path_exists_by_repo[repo_name] = module_sim._batch_path_exists(
            contexts[(repo_name, builders[0])].repo,
            endpoint_queries_by_repo.get(repo_name, set()),
        )

    sim_rows: list[dict[str, Any]] = []
    quality_rows: list[dict[str, Any]] = []
    topology_rows: list[dict[str, Any]] = []
    for repo_name, records in sorted(by_repo.items()):
        for builder in builders:
            context = contexts[(repo_name, builder)]
            line_sizes = [len(tags) for tags in context.release_lines.values()]
            topology_rows.append({
                "repo": repo_name,
                "builder": builder,
                "release_tag_count": len(context.release_tags),
                "line_count": len(context.release_lines),
                "family_count": len(context.ordered_by_family),
                "singleton_line_count": sum(1 for size in line_sizes if size == 1),
                "singleton_line_ratio": (
                    sum(1 for size in line_sizes if size == 1) / len(line_sizes)
                    if line_sizes else 0.0
                ),
                "avg_tags_per_line": round(_mean([float(x) for x in line_sizes]), 2),
                "max_tags_per_line": max(line_sizes) if line_sizes else 0,
            })
            for cve_id, rec in records:
                commits = low_cost._flatten_fixing_commits(rec.get("fixing_commits") or rec.get("fixing_commit"))
                fix_containing_tags: set[str] = set()
                for commit in commits:
                    result = commit_contains_by_repo[repo_name].get(commit, {"ok": False, "tags": []})
                    if result.get("ok"):
                        fix_containing_tags.update(result.get("tags", []))
                path_exists = path_exists_by_repo.get(repo_name, {})
                file_endpoint_lines: set[str] = set()
                for line, tags in context.release_lines.items():
                    for tag in low_cost._sample_tags_for_line(tags):
                        if any(path_exists.get((tag, path), False) for path in changed_files_by_cve.get(cve_id, [])[:3]):
                            file_endpoint_lines.add(line)
                            break
                quality_rows.append(_line_quality_for_cve(
                    cve_id=cve_id,
                    repo_name=repo_name,
                    builder=builder,
                    release_lines=context.release_lines,
                    release_tags=context.release_tags,
                    affected_versions=list(rec.get("affected_version") or []),
                ))
                sim_rows.append(_simulate_cve(
                    cve_id=cve_id,
                    repo_name=repo_name,
                    builder=builder,
                    release_lines=context.release_lines,
                    ordered_by_family=context.ordered_by_family,
                    release_tags=context.release_tags,
                    affected_versions=list(rec.get("affected_version") or []),
                    fix_containing_tags=fix_containing_tags,
                    file_endpoint_lines=file_endpoint_lines,
                    nn_sentinel_count=args.nn_sentinel_count,
                    aa_sentinel_count=args.aa_sentinel_count,
                    fixed_segment_sentinel=args.fixed_segment_sentinel,
                ))

    overall = _group_summary(sim_rows, "builder", _summarize_rows)
    line_quality = _group_summary(quality_rows, "builder", _summarize_quality)
    by_repo: dict[str, dict[str, Any]] = {}
    for builder in builders:
        builder_rows = [row for row in sim_rows if row["builder"] == builder]
        by_repo[builder] = _group_summary(builder_rows, "repo", _summarize_rows)

    topology_by_repo: dict[str, dict[str, Any]] = defaultdict(dict)
    for row in topology_rows:
        topology_by_repo[row["repo"]][row["builder"]] = row

    fn_cases = [
        row for row in sim_rows
        if row["has_fn"] or row["skipped_affected_line_count"] > 0
    ]
    fn_cases.sort(key=lambda r: (-int(r["fn"]), -int(r["skipped_affected_line_count"]), r["builder"], r["repo"], r["cve_id"]))
    noncontiguous_cases = [
        row for row in quality_rows
        if row["noncontiguous_affected_line_count"] > 0
    ]
    noncontiguous_cases.sort(key=lambda r: (-int(r["noncontiguous_affected_line_count"]), r["builder"], r["repo"], r["cve_id"]))

    metadata = {
        "dataset": str(args.dataset),
        "repo_root": str(args.repo_root),
        "builders": builders,
        "total_cves": sum(len(v) for v in by_repo.values()) if isinstance(by_repo, defaultdict) else len({r["cve_id"] for r in sim_rows}),
        "nn_sentinel_count": args.nn_sentinel_count,
        "aa_sentinel_count": args.aa_sentinel_count,
        "fixed_segment_sentinel": args.fixed_segment_sentinel,
        "oracle_note": "GT is used only for simulated probe verdicts and final metrics.",
    }
    summary = {
        "metadata": metadata,
        "overall": overall,
        "by_repo": by_repo,
        "line_quality": line_quality,
        "topology_by_repo": dict(topology_by_repo),
    }

    args.out_dir.mkdir(parents=True, exist_ok=True)
    _write_json(args.out_dir / "summary.json", summary)
    _write_json(args.out_dir / "topology_by_repo.json", dict(topology_by_repo))
    _write_json(args.out_dir / "line_quality.json", {
        "summary": line_quality,
        "noncontiguous_cases": noncontiguous_cases,
    })
    _write_json(args.out_dir / "fn_cases.json", fn_cases[:1000])
    _write_jsonl(args.out_dir / "per_cve.jsonl", sim_rows)
    _write_jsonl(args.out_dir / "line_quality_per_cve.jsonl", quality_rows)
    _write_report(args.out_dir / "report.md", summary)
    print(json.dumps({
        "metadata": metadata,
        "overall": overall,
        "line_quality": line_quality,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
