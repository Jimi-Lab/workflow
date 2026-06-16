"""Risk-scored Step3 graph scheduler simulator.

This experiment evaluates the proposed two-layer Step3 graph before touching
the production verifier:

Layer 1: TDSC-style release-version graph
  release tags -> line/family graph -> family-local neighbors -> branch ends

Layer 2: Beyond-Blame-style cheap evidence graph
  fix reachability, touched files, hunk/function tokens, vulnerable/fix tokens

The simulator uses BaseDataOrder.json ground truth only as an oracle for the
selected probe verdicts and final metrics. GT is never used to build scores,
select seed lines, or choose probes.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


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
from vulnversion.stage3_verify.line_scheduler import (
    LineRunResult,
    _no_fix_lines,
    _static_neighbors,
    _stride_lines,
    run_staged_scheduler,
)


DEFAULT_DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
DEFAULT_REPO_ROOT = ROOT / "repo"
DEFAULT_OUT_DIR = ROOT / "tests" / "step3_risk_scored_scheduler_simulator"


@dataclass(frozen=True)
class ThresholdConfig:
    """Deterministic scheduler threshold configuration."""

    config_id: str
    high: float
    mid: float
    no_fix_stride: int
    expansion_radius: int = 1
    fallback_mode: str = "nohit_nofix"


@dataclass
class LineEvidence:
    """One line node in the experimental Vuln graph."""

    line: str
    family: str
    family_index: int
    tag_count: int
    no_fix: bool
    mixed_fix: bool
    all_fix: bool
    family_edge: bool
    fix_transition: bool
    file_endpoint: bool
    critical_token: bool
    vulnerable_pattern: bool
    function_hint: bool
    fix_guard: bool
    conflict: bool
    score: float
    components: dict[str, float]


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


def _pct(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    vals = sorted(values)
    idx = round((len(vals) - 1) * pct)
    return float(vals[idx])


def _mean(values: list[float]) -> float:
    return float(statistics.mean(values)) if values else 0.0


def _threshold_configs(grid: str) -> list[ThresholdConfig]:
    """Return a compact or full threshold grid.

    The grid is intentionally small enough to run repeatedly on all 1128 CVEs.
    """
    if grid == "smoke":
        highs = [0.30, 0.40]
        mids = [0.10, 0.20]
        strides = [6, 4]
    elif grid == "full":
        highs = [0.20, 0.30, 0.40, 0.50, 0.60]
        mids = [0.05, 0.10, 0.15, 0.20, 0.30]
        strides = [0, 8, 6, 5, 4, 3]
    else:
        highs = [0.20, 0.30, 0.40, 0.50]
        mids = [0.05, 0.10, 0.20]
        strides = [0, 6, 4, 3]
    configs: list[ThresholdConfig] = []
    for high in highs:
        for mid in mids:
            if mid > high:
                continue
            for stride in strides:
                configs.append(ThresholdConfig(
                    config_id=f"risk_h{high:.2f}_m{mid:.2f}_s{stride}",
                    high=high,
                    mid=mid,
                    no_fix_stride=stride,
                ))
    return configs


def _line_to_family(ordered_by_family: dict[str, list[str]]) -> dict[str, tuple[str, int]]:
    return {
        line: (family, idx)
        for family, lines in ordered_by_family.items()
        for idx, line in enumerate(lines)
    }


def _family_edge_lines(ordered_by_family: dict[str, list[str]]) -> set[str]:
    return low_cost._family_edge_lines(ordered_by_family)


def _build_line_evidence(
    *,
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    fix_containing_tags: set[str],
    file_endpoint_lines: set[str],
    semantic_lines: dict[str, set[str]],
) -> dict[str, LineEvidence]:
    """Build the experimental line-level Vuln graph evidence."""
    line_family = _line_to_family(ordered_by_family)
    no_fix_lines = _no_fix_lines(release_lines, fix_containing_tags)
    transition_lines = low_cost._fix_transition_lines(release_lines, ordered_by_family, fix_containing_tags)
    edge_lines = _family_edge_lines(ordered_by_family)

    critical = semantic_lines.get("critical_token_lines", set())
    vuln = semantic_lines.get("vuln_pattern_lines", set())
    func = semantic_lines.get("function_hint_lines", set())
    fix_guard = semantic_lines.get("fix_guard_lines", set())

    out: dict[str, LineEvidence] = {}
    for line, tags in release_lines.items():
        fix_hits = sum(1 for tag in tags if tag in fix_containing_tags)
        no_fix = line in no_fix_lines
        all_fix = bool(tags) and fix_hits == len(tags)
        mixed_fix = fix_hits > 0 and fix_hits < len(tags)
        has_file = line in file_endpoint_lines
        has_critical = line in critical
        has_vuln = line in vuln
        has_func = line in func
        has_fix_guard = line in fix_guard
        conflict = has_fix_guard and (has_vuln or has_critical or no_fix)

        components: dict[str, float] = {}
        if has_file:
            components["file_endpoint"] = 0.24
        if has_vuln:
            components["vulnerable_pattern"] = 0.22
        if has_critical:
            components["critical_token"] = 0.16
        if has_func:
            components["function_hint"] = 0.12
        if no_fix:
            components["no_fix"] = 0.10
        if line in transition_lines:
            components["fix_transition"] = 0.10
        if mixed_fix:
            components["mixed_fix"] = 0.08
        if line in edge_lines:
            components["family_edge"] = 0.04
        if conflict:
            components["conflict"] = 0.08
        if has_fix_guard and not conflict and all_fix:
            components["strong_fixed_evidence"] = -0.08

        score = max(0.0, min(1.0, sum(components.values())))
        family, idx = line_family.get(line, ("unknown", -1))
        out[line] = LineEvidence(
            line=line,
            family=family,
            family_index=idx,
            tag_count=len(tags),
            no_fix=no_fix,
            mixed_fix=mixed_fix,
            all_fix=all_fix,
            family_edge=line in edge_lines,
            fix_transition=line in transition_lines,
            file_endpoint=has_file,
            critical_token=has_critical,
            vulnerable_pattern=has_vuln,
            function_hint=has_func,
            fix_guard=has_fix_guard,
            conflict=conflict,
            score=round(score, 6),
            components=components,
        )
    return out


def _risk_seed_lines(
    *,
    config: ThresholdConfig,
    line_graph: dict[str, LineEvidence],
    ordered_by_family: dict[str, list[str]],
) -> set[str]:
    high_lines = {line for line, ev in line_graph.items() if ev.score >= config.high}
    mid_lines = {line for line, ev in line_graph.items() if config.mid <= ev.score < config.high}
    seeds: set[str] = set(mid_lines)
    for _, lines in ordered_by_family.items():
        seeds.update(_static_neighbors(lines, set(lines) & high_lines, 1))
    if config.no_fix_stride > 0:
        no_fix = {line for line, ev in line_graph.items() if ev.no_fix}
        seeds.update(_stride_lines(ordered_by_family, config.no_fix_stride, lines_subset=no_fix))
    return seeds


def _run_cached_line(
    *,
    cache: dict[str, LineRunResult],
    line: str,
    tags: list[str],
    affected_set: set[str],
    fix_containing_tags: set[str],
    nn_sentinel_count: int,
    aa_sentinel_count: int,
    fixed_segment_sentinel: int,
) -> LineRunResult:
    if line not in cache:
        cache[line] = module_sim._run_git_guided_line_module(
            line=line,
            tags=tags,
            affected_set=affected_set,
            fix_containing_tags=fix_containing_tags,
            nn_sentinel_count=nn_sentinel_count,
            aa_sentinel_count=aa_sentinel_count,
            fixed_segment_sentinel=fixed_segment_sentinel,
        )
    return cache[line]


def _simulate_with_seeds(
    *,
    cve_id: str,
    repo_name: str,
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    release_tags: list[str],
    affected_set: set[str],
    unmapped_gt: list[str],
    fix_containing_tags: set[str],
    seed_lines: set[str],
    config_id: str,
    fallback_mode: str,
    expansion_radius: int,
    line_cache: dict[str, LineRunResult],
    nn_sentinel_count: int,
    aa_sentinel_count: int,
    fixed_segment_sentinel: int,
) -> dict[str, Any]:
    affected_lines = {
        line for line, tags in release_lines.items()
        if any(tag in affected_set for tag in tags)
    }

    def run_line(line: str, tags: list[str]) -> LineRunResult:
        return _run_cached_line(
            cache=line_cache,
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
        fallback_mode=fallback_mode,
    )
    predicted = set(state.predicted_affected)
    probes = set(state.all_probe_tags)
    release_set = set(release_tags)
    tp = len(predicted & affected_set)
    fp = len(predicted - affected_set)
    fn = len(affected_set - predicted)
    tn = len(release_set - predicted - affected_set)
    precision = tp / (tp + fp) if (tp + fp) else (1.0 if not affected_set else 0.0)
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    skipped_affected_lines = affected_lines - set(state.visited)
    return {
        "cve_id": cve_id,
        "repo": repo_name,
        "config_id": config_id,
        "release_tag_count": len(release_tags),
        "line_count": len(release_lines),
        "seed_line_count": len(seed_lines),
        "active_line_count": len(state.visited),
        "positive_line_count": len(state.positive_lines),
        "affected_line_count": len(affected_lines),
        "skipped_affected_line_count": len(skipped_affected_lines),
        "skipped_affected_lines": sorted(skipped_affected_lines),
        "probe_count": len(probes),
        "predicted_count": len(predicted),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "unmapped_gt_count": len(unmapped_gt),
        "exact_match": fp == 0 and fn == 0 and len(unmapped_gt) == 0,
        "has_fp": fp > 0,
        "has_fn": fn > 0,
        "status_counts": dict(state.status_counts),
    }


def _summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {}
    probes = [float(row["probe_count"]) for row in rows]
    seeds = [float(row["seed_line_count"]) for row in rows]
    active = [float(row["active_line_count"]) for row in rows]
    skipped = [float(row["skipped_affected_line_count"]) for row in rows]
    tp = sum(int(row["tp"]) for row in rows)
    fp = sum(int(row["fp"]) for row in rows)
    fn = sum(int(row["fn"]) for row in rows)
    tn = sum(int(row["tn"]) for row in rows)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "cves": len(rows),
        "avg_probes": round(_mean(probes), 2),
        "p50_probes": round(_pct(probes, 0.50), 2),
        "p95_probes": round(_pct(probes, 0.95), 2),
        "max_probes": int(max(probes)) if probes else 0,
        "avg_seed_lines": round(_mean(seeds), 2),
        "avg_active_lines": round(_mean(active), 2),
        "avg_skipped_affected_lines": round(_mean(skipped), 4),
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


def _summarize_by_config(rows: list[dict[str, Any]]) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[row["config_id"]].append(row)
    return {config_id: _summarize_rows(vals) for config_id, vals in sorted(groups.items())}


def _score_curve_rows(
    *,
    repo_name: str,
    cve_id: str,
    line_graph: dict[str, LineEvidence],
    affected_lines: set[str],
    thresholds: list[float],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    all_lines = set(line_graph)
    for threshold in thresholds:
        selected = {line for line, ev in line_graph.items() if ev.score >= threshold}
        affected_selected = selected & affected_lines
        rows.append({
            "repo": repo_name,
            "cve_id": cve_id,
            "threshold": threshold,
            "selected_line_count": len(selected),
            "affected_line_count": len(affected_lines),
            "affected_line_covered": len(affected_selected),
            "affected_line_recall": (
                len(affected_selected) / len(affected_lines)
                if affected_lines else 1.0
            ),
            "unaffected_line_selected": len(selected - affected_lines),
            "line_count": len(all_lines),
        })
    return rows


def _line_score_distribution(line_rows: list[dict[str, Any]]) -> dict[str, Any]:
    affected = [float(r["score"]) for r in line_rows if r["is_affected_line"]]
    unaffected = [float(r["score"]) for r in line_rows if not r["is_affected_line"]]
    return {
        "affected_line_count": len(affected),
        "unaffected_line_count": len(unaffected),
        "affected_score_avg": round(_mean(affected), 4),
        "unaffected_score_avg": round(_mean(unaffected), 4),
        "affected_score_p50": round(_pct(affected, 0.50), 4),
        "unaffected_score_p50": round(_pct(unaffected, 0.50), 4),
        "affected_score_p10": round(_pct(affected, 0.10), 4),
        "unaffected_score_p90": round(_pct(unaffected, 0.90), 4),
    }


def _write_report(
    path: Path,
    *,
    metadata: dict[str, Any],
    config_summary: dict[str, Any],
    graph_summary: dict[str, Any],
    best_configs: list[dict[str, Any]],
) -> None:
    lines = [
        "# Step3 Risk-Scored Vuln Graph Simulator",
        "",
        f"Dataset: `{metadata['dataset']}`.",
        "",
        "This is a GT-oracle experiment. GT is used only for simulated probe verdicts and final metrics.",
        "",
        "## Graph Model",
        "",
        "- Layer 1: TDSC-style release-version graph: release tags, line/family groups, family-local neighbors, branch edges.",
        "- Layer 2: Beyond-Blame-style evidence graph: fix reachability, touched files, patch tokens, hunk functions, fix/vulnerable token hits.",
        "- Agent is not used in this simulator; selected probes are answered by GT oracle.",
        "",
        "## Score Separability",
        "",
        f"- affected line avg score: `{graph_summary['score_distribution']['affected_score_avg']}`",
        f"- unaffected line avg score: `{graph_summary['score_distribution']['unaffected_score_avg']}`",
        f"- affected line p10 score: `{graph_summary['score_distribution']['affected_score_p10']}`",
        f"- unaffected line p90 score: `{graph_summary['score_distribution']['unaffected_score_p90']}`",
        "",
        "## Best Configs By Recall-Constrained Cost",
        "",
        "| config | avg probes | p95 | exact CVEs | FN CVEs | version FN | recall | F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in best_configs:
        metrics = row["metrics"]
        lines.append(
            "| {config} | {avg:.2f} | {p95:.2f} | {exact}/1128 | {fnc} | {vfn} | {recall:.6f} | {f1:.6f} |".format(
                config=row["config_id"],
                avg=metrics["avg_probes"],
                p95=metrics["p95_probes"],
                exact=metrics["exact_cves"],
                fnc=metrics["fn_cves"],
                vfn=metrics["version_fn"],
                recall=metrics["recall"],
                f1=metrics["f1"],
            )
        )
    lines.extend([
        "",
        "## Current Control",
        "",
    ])
    control = config_summary.get("control_current_staged_nofix_stride3_file", {})
    if control:
        lines.append(
            "- control avg probes: `{avg}`, exact CVEs: `{exact}/1128`, recall: `{recall}`, F1: `{f1}`.".format(
                avg=control.get("avg_probes"),
                exact=control.get("exact_cves"),
                recall=control.get("recall"),
                f1=control.get("f1"),
            )
        )
    lines.extend([
        "",
        "## Interpretation Rule",
        "",
        "- A lower-probe config is not eligible if it introduces unacceptable affected-line skips.",
        "- Low-score lines are treated as deferred in planning experiments, not as proven NOT_AFFECTED.",
        "- A config can enter production only after case-level FN review and small real-agent validation.",
        "",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Simulate risk-scored Step3 Vuln graph schedulers.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--grid", choices=["smoke", "compact", "full"], default="compact")
    parser.add_argument("--limit-cves", type=int, default=0, help="Debug only: limit CVEs after sorting.")
    parser.add_argument("--nn-sentinel-count", type=int, default=NN_SENTINEL_COUNT)
    parser.add_argument("--aa-sentinel-count", type=int, default=AA_SENTINEL_COUNT)
    parser.add_argument("--fixed-segment-sentinel", type=int, default=FIXED_SEG_SENTINEL)
    args = parser.parse_args(argv)

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

    configs = _threshold_configs(args.grid)
    contexts: dict[str, dict[str, Any]] = {}
    commit_contains_by_repo: dict[str, dict[str, dict[str, Any]]] = {}
    profile_by_cve: dict[str, low_cost.PatchProfile] = {}
    endpoint_queries_by_repo: dict[str, set[tuple[str, str]]] = defaultdict(set)
    text_queries_by_repo: dict[str, set[tuple[str, str]]] = defaultdict(set)

    for repo_name, records in sorted(by_repo.items()):
        context = module_sim._release_context(repo_name, args.repo_root / repo_name)
        contexts[repo_name] = context
        repo: GitRepo = context["repo"]
        target_commits: set[str] = set()
        changed_cache: dict[str, list[str]] = {}
        sample_tags = {
            tag
            for tags in context["release_lines"].values()
            for tag in low_cost._sample_tags_for_line(tags)
        }
        for cve_id, rec in records:
            commits = low_cost._flatten_fixing_commits(rec.get("fixing_commits") or rec.get("fixing_commit"))
            target_commits.update(commits)
            files = module_sim._changed_files_for_commits(repo, commits, changed_cache)
            profile = low_cost._extract_patch_profile(repo, commits, files)
            profile_by_cve[cve_id] = profile
            for tag in sample_tags:
                for path in profile.files:
                    endpoint_queries_by_repo[repo_name].add((tag, path))
                    text_queries_by_repo[repo_name].add((tag, path))
        commit_contains_by_repo[repo_name] = batch_tags_containing(
            repo=repo,
            release_tags=context["release_tags"],
            target_commits=target_commits,
        )

    path_exists_by_repo: dict[str, dict[tuple[str, str], bool]] = {}
    text_by_repo: dict[str, dict[tuple[str, str], str | None]] = {}
    for repo_name in sorted(by_repo):
        path_exists = module_sim._batch_path_exists(
            contexts[repo_name]["repo"],
            endpoint_queries_by_repo.get(repo_name, set()),
        )
        path_exists_by_repo[repo_name] = path_exists
        existing_text_queries = {
            q for q in text_queries_by_repo.get(repo_name, set())
            if path_exists.get(q, False)
        }
        text_by_repo[repo_name] = low_cost._batch_file_text(contexts[repo_name]["repo"], existing_text_queries)

    per_config_rows: list[dict[str, Any]] = []
    line_rows: list[dict[str, Any]] = []
    score_curve_rows: list[dict[str, Any]] = []
    graph_case_summaries: list[dict[str, Any]] = []

    for repo_name, records in sorted(by_repo.items()):
        context = contexts[repo_name]
        release_lines: dict[str, list[str]] = context["release_lines"]
        ordered_by_family: dict[str, list[str]] = context["ordered_by_family"]
        release_tags: list[str] = context["release_tags"]
        for cve_id, rec in records:
            commits = low_cost._flatten_fixing_commits(rec.get("fixing_commits") or rec.get("fixing_commit"))
            fix_containing_tags: set[str] = set()
            for commit in commits:
                result = commit_contains_by_repo[repo_name].get(commit, {"ok": False, "tags": []})
                if result.get("ok"):
                    fix_containing_tags.update(result.get("tags", []))

            profile = profile_by_cve[cve_id]
            file_endpoint_lines: set[str] = set()
            path_exists = path_exists_by_repo.get(repo_name, {})
            for line, tags in release_lines.items():
                for tag in low_cost._sample_tags_for_line(tags):
                    if any(path_exists.get((tag, path), False) for path in profile.files):
                        file_endpoint_lines.add(line)
                        break
            semantic_lines = low_cost._token_evidence_lines(
                release_lines=release_lines,
                profile=profile,
                text_cache=text_by_repo.get(repo_name, {}),
            )
            line_graph = _build_line_evidence(
                release_lines=release_lines,
                ordered_by_family=ordered_by_family,
                fix_containing_tags=fix_containing_tags,
                file_endpoint_lines=file_endpoint_lines,
                semantic_lines=semantic_lines,
            )
            mapped_gt, unmapped_gt = map_gt_tags_to_repo_tags(
                sorted(str(t) for t in (rec.get("affected_version") or [])),
                release_tags,
                mode="loose",
            )
            affected_set = set(mapped_gt)
            affected_lines = {
                line for line, tags in release_lines.items()
                if any(tag in affected_set for tag in tags)
            }
            for ev in line_graph.values():
                row = asdict(ev)
                row.update({
                    "repo": repo_name,
                    "cve_id": cve_id,
                    "is_affected_line": ev.line in affected_lines,
                })
                line_rows.append(row)
            score_curve_rows.extend(_score_curve_rows(
                repo_name=repo_name,
                cve_id=cve_id,
                line_graph=line_graph,
                affected_lines=affected_lines,
                thresholds=[0.0, 0.05, 0.10, 0.15, 0.20, 0.30, 0.40, 0.50, 0.60],
            ))
            graph_case_summaries.append({
                "repo": repo_name,
                "cve_id": cve_id,
                "line_count": len(release_lines),
                "family_count": len(ordered_by_family),
                "affected_line_count": len(affected_lines),
                "no_fix_line_count": sum(1 for ev in line_graph.values() if ev.no_fix),
                "file_endpoint_line_count": sum(1 for ev in line_graph.values() if ev.file_endpoint),
                "semantic_hit_line_count": sum(
                    1 for ev in line_graph.values()
                    if ev.critical_token or ev.vulnerable_pattern or ev.function_hint or ev.fix_guard
                ),
                "max_line_score": max((ev.score for ev in line_graph.values()), default=0.0),
                "avg_line_score": round(_mean([ev.score for ev in line_graph.values()]), 4),
                "affected_avg_line_score": round(_mean([
                    ev.score for ev in line_graph.values()
                    if ev.line in affected_lines
                ]), 4),
            })

            line_cache: dict[str, LineRunResult] = {}
            control_seeds = low_cost.compute_seed_lines(
                repo_name=repo_name,
                release_lines=release_lines,
                ordered_by_family=ordered_by_family,
                fix_containing_tags=fix_containing_tags,
                file_endpoint_lines=file_endpoint_lines,
                stride=3,
                file_neighbor_radius=1,
            )
            per_config_rows.append(_simulate_with_seeds(
                cve_id=cve_id,
                repo_name=repo_name,
                release_lines=release_lines,
                ordered_by_family=ordered_by_family,
                release_tags=release_tags,
                affected_set=affected_set,
                unmapped_gt=unmapped_gt,
                fix_containing_tags=fix_containing_tags,
                seed_lines=control_seeds,
                config_id="control_current_staged_nofix_stride3_file",
                fallback_mode="none",
                expansion_radius=1,
                line_cache=line_cache,
                nn_sentinel_count=args.nn_sentinel_count,
                aa_sentinel_count=args.aa_sentinel_count,
                fixed_segment_sentinel=args.fixed_segment_sentinel,
            ))
            for config in configs:
                seeds = _risk_seed_lines(
                    config=config,
                    line_graph=line_graph,
                    ordered_by_family=ordered_by_family,
                )
                per_config_rows.append(_simulate_with_seeds(
                    cve_id=cve_id,
                    repo_name=repo_name,
                    release_lines=release_lines,
                    ordered_by_family=ordered_by_family,
                    release_tags=release_tags,
                    affected_set=affected_set,
                    unmapped_gt=unmapped_gt,
                    fix_containing_tags=fix_containing_tags,
                    seed_lines=seeds,
                    config_id=config.config_id,
                    fallback_mode=config.fallback_mode,
                    expansion_radius=config.expansion_radius,
                    line_cache=line_cache,
                    nn_sentinel_count=args.nn_sentinel_count,
                    aa_sentinel_count=args.aa_sentinel_count,
                    fixed_segment_sentinel=args.fixed_segment_sentinel,
                ))

    config_summary = _summarize_by_config(per_config_rows)
    curve_summary: dict[str, Any] = {}
    curve_groups: dict[float, list[dict[str, Any]]] = defaultdict(list)
    for row in score_curve_rows:
        curve_groups[float(row["threshold"])].append(row)
    for threshold, rows in sorted(curve_groups.items()):
        affected_total = sum(int(r["affected_line_count"]) for r in rows)
        affected_covered = sum(int(r["affected_line_covered"]) for r in rows)
        selected_total = sum(int(r["selected_line_count"]) for r in rows)
        line_total = sum(int(r["line_count"]) for r in rows)
        curve_summary[f"{threshold:.2f}"] = {
            "line_selection_rate": round(selected_total / line_total, 6) if line_total else 0.0,
            "affected_line_recall": round(affected_covered / affected_total, 6) if affected_total else 1.0,
            "avg_selected_lines_per_cve": round(selected_total / len(rows), 2) if rows else 0.0,
        }

    control = config_summary.get("control_current_staged_nofix_stride3_file", {})
    baseline_recall = float(control.get("recall", 0.0))
    best_candidates: list[dict[str, Any]] = []
    for config_id, metrics in config_summary.items():
        if config_id == "control_current_staged_nofix_stride3_file":
            continue
        if float(metrics.get("recall", 0.0)) >= baseline_recall - 0.001:
            best_candidates.append({"config_id": config_id, "metrics": metrics})
    best_candidates.sort(key=lambda r: (float(r["metrics"]["avg_probes"]), -float(r["metrics"]["f1"])))
    best_candidates = best_candidates[:10]

    graph_summary = {
        "case_count": len(graph_case_summaries),
        "avg_lines_per_cve": round(_mean([float(r["line_count"]) for r in graph_case_summaries]), 2),
        "avg_families_per_cve": round(_mean([float(r["family_count"]) for r in graph_case_summaries]), 2),
        "avg_affected_lines_per_cve": round(_mean([float(r["affected_line_count"]) for r in graph_case_summaries]), 2),
        "avg_no_fix_lines_per_cve": round(_mean([float(r["no_fix_line_count"]) for r in graph_case_summaries]), 2),
        "avg_semantic_hit_lines_per_cve": round(_mean([float(r["semantic_hit_line_count"]) for r in graph_case_summaries]), 2),
        "score_distribution": _line_score_distribution(line_rows),
        "score_threshold_curve": curve_summary,
    }

    metadata = {
        "dataset": str(args.dataset),
        "repo_root": str(args.repo_root),
        "grid": args.grid,
        "threshold_config_count": len(configs),
        "total_cves": sum(len(v) for v in by_repo.values()),
        "nn_sentinel_count": args.nn_sentinel_count,
        "aa_sentinel_count": args.aa_sentinel_count,
        "fixed_segment_sentinel": args.fixed_segment_sentinel,
        "oracle_note": "GT is used only for simulated probe verdicts and final metrics, never for score construction.",
    }

    args.out_dir.mkdir(parents=True, exist_ok=True)
    _write_json(args.out_dir / "summary.json", {
        "metadata": metadata,
        "control": control,
        "best_recall_constrained_configs": best_candidates,
        "overall": config_summary,
        "graph_summary": graph_summary,
    })
    _write_json(args.out_dir / "threshold_curve.json", curve_summary)
    _write_json(args.out_dir / "graph_model_stats.json", {
        "metadata": metadata,
        "graph_summary": graph_summary,
        "case_summaries": graph_case_summaries,
    })
    _write_jsonl(args.out_dir / "per_config_cve.jsonl", per_config_rows)
    _write_jsonl(args.out_dir / "line_scores.jsonl", line_rows)
    fn_cases = [
        row for row in per_config_rows
        if row["has_fn"] or row["skipped_affected_line_count"] > 0
    ]
    fn_cases.sort(key=lambda r: (-int(r["fn"]), -int(r["skipped_affected_line_count"]), r["config_id"], r["repo"], r["cve_id"]))
    _write_json(args.out_dir / "fn_cases.json", fn_cases[:1000])
    _write_report(
        args.out_dir / "report.md",
        metadata=metadata,
        config_summary=config_summary,
        graph_summary=graph_summary,
        best_configs=best_candidates,
    )
    print(json.dumps({
        "metadata": metadata,
        "control": control,
        "best_recall_constrained_configs": best_candidates[:5],
        "score_distribution": graph_summary["score_distribution"],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
