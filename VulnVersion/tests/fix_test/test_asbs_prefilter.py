"""
Test: ASBS Static Pre-filter Efficiency on All 1128 CVEs

Measures:
1. Tag plan statistics: raw tags → release tags → scan candidates
2. Frontier detection reduction rate
3. Static pre-filter (token existence check) additional reduction
4. GT coverage after all filtering
5. Per-repo and per-topology breakdown

Run:
    cd E:/AI/Agent/workflow/VulnVersion
    python -m tests.fix_test.test_asbs_prefilter
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.version_registry import (
    filter_release_tags,
    infer_repo_name,
)
from vulnversion.stage3_verify.plan_tags import build_tag_plan


REPO_DIR = PROJECT_ROOT / "repo"
DATASET_PATH = PROJECT_ROOT / "DataSet" / "BaseDataOrder.json"
OUTPUT_DIR = Path(__file__).parent / "asbs_results"


def _static_prefilter_tag(
    repo: GitRepo,
    tag: str,
    rci_anchor: dict[str, Any],
) -> str:
    """Quick Python-native check: does the anchor exist at this tag?

    Returns:
      "exists"      — anchor file or function found → needs LLM
      "not_found"   — anchor completely absent → can skip (NOT_AFFECTED)
      "error"       — git error → needs LLM (conservative)
    """
    file_paths = rci_anchor.get("file_paths", [])[:3]
    function_names = rci_anchor.get("function_names", [])[:3]

    # Check if any anchor file exists
    for fp in file_paths:
        try:
            repo.show(tag, fp)
            return "exists"
        except Exception:
            continue

    # File not found — try function name grep
    for fn in function_names:
        if not fn.strip():
            continue
        try:
            matches = repo.grep(tag, fn)
            if matches:
                return "exists"
        except Exception:
            continue

    # Nothing found at all
    if file_paths or function_names:
        return "not_found"
    return "error"  # no anchor to check


def analyze_cve(
    cve_id: str,
    record: dict[str, Any],
    gt_tags: list[str],
    *,
    do_prefilter: bool = False,
) -> dict[str, Any]:
    """Analyze a single CVE's tag_plan and optionally run static pre-filter."""
    repo_name = record.get("repo", "")
    repo_path = str(REPO_DIR / repo_name)
    fixing_commits = record.get("fixing_commits", [])

    if not Path(repo_path).exists():
        return {"cve_id": cve_id, "status": "repo_missing", "repo": repo_name}

    try:
        tag_plan = build_tag_plan(
            repo_path=repo_path,
            cve_id=cve_id,
            fixing_commits=fixing_commits,
            mode="eval",
        )
    except Exception as e:
        return {
            "cve_id": cve_id,
            "status": "plan_error",
            "repo": repo_name,
            "error": str(e)[:200],
        }

    verification_order = tag_plan.get("verification_order", [])
    raw_tags_count = tag_plan.get("raw_tags_count", 0)
    release_tags_count = tag_plan.get("release_tags_count", 0)

    # Frontier status counts
    frontiers = tag_plan.get("frontiers", {})
    status_counts: dict[str, int] = {}
    for line, frontier in frontiers.items():
        st = frontier.get("status", "unknown")
        status_counts[st] = status_counts.get(st, 0) + 1

    # GT coverage
    if gt_tags:
        mapped, unmapped = map_gt_tags_to_repo_tags(
            gt_tags, verification_order, mode="loose"
        )
        gt_coverage = len(mapped) / len(gt_tags)
    else:
        mapped, unmapped = [], []
        gt_coverage = 1.0

    result: dict[str, Any] = {
        "cve_id": cve_id,
        "status": "ok",
        "repo": repo_name,
        "raw_tags": raw_tags_count,
        "release_tags": release_tags_count,
        "scan_candidates": len(verification_order),
        "gt_tags": len(gt_tags),
        "gt_mapped": len(mapped),
        "gt_unmapped": len(unmapped),
        "gt_coverage": round(gt_coverage, 4),
        "frontier_statuses": status_counts,
        "reduction_rate": round(
            1 - len(verification_order) / max(1, release_tags_count), 4
        ),
    }

    # Optional: run static pre-filter on scan candidates
    if do_prefilter and verification_order:
        repo = GitRepo.open(repo_path)
        # Simulate a minimal RCI anchor from fix commit
        # In real pipeline, RCI provides this. Here we derive from patch.
        fix_commits_flat = []
        for fc in fixing_commits or []:
            if isinstance(fc, str):
                fix_commits_flat.append(fc)
            elif isinstance(fc, list):
                fix_commits_flat.extend(fc)

        # Get changed files from fix commit as pseudo-anchor
        anchor: dict[str, Any] = {"file_paths": [], "function_names": []}
        if fix_commits_flat:
            try:
                patch = repo.show_patch(fix_commits_flat[0])
                import re
                files = re.findall(r"^\+\+\+ b/(.+)$", patch, re.MULTILINE)
                funcs = re.findall(r"^@@.*@@\s+(\w+)", patch, re.MULTILINE)
                anchor["file_paths"] = list(dict.fromkeys(files))[:4]
                anchor["function_names"] = list(dict.fromkeys(funcs))[:4]
            except Exception:
                pass

        if anchor["file_paths"] or anchor["function_names"]:
            # Sample: check up to 20 tags for efficiency
            sample_tags = verification_order[:20]
            pf_results = {"exists": 0, "not_found": 0, "error": 0}
            for tag in sample_tags:
                pf_status = _static_prefilter_tag(repo, tag, anchor)
                pf_results[pf_status] = pf_results.get(pf_status, 0) + 1

            # Extrapolate
            total_sampled = len(sample_tags)
            skip_rate = pf_results["not_found"] / total_sampled if total_sampled > 0 else 0
            result["prefilter_sample_size"] = total_sampled
            result["prefilter_exists"] = pf_results["exists"]
            result["prefilter_not_found"] = pf_results["not_found"]
            result["prefilter_error"] = pf_results["error"]
            result["prefilter_skip_rate"] = round(skip_rate, 4)
            result["estimated_llm_tags"] = round(
                len(verification_order) * (1 - skip_rate)
            )

    return result


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    def _p(*args, **kwargs):
        kwargs.setdefault("flush", True)
        print(*args, **kwargs)

    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    _p(f"Loaded {len(dataset)} CVEs from BaseDataOrder.json")
    _p()

    # Phase 1: Tag plan statistics (frontier detection on all CVEs)
    _p("=" * 70)
    _p("Phase 1: Tag Plan Statistics (all CVEs)")
    _p("=" * 70)

    results: list[dict[str, Any]] = []
    repo_agg: dict[str, dict[str, Any]] = {}
    errors = 0
    t0 = time.time()

    for i, (cve_id, record) in enumerate(dataset.items()):
        gt_tags = record.get("affected_version", [])
        repo_name = record.get("repo", "")

        result = analyze_cve(cve_id, record, gt_tags, do_prefilter=False)
        results.append(result)

        if result["status"] != "ok":
            errors += 1
            if (i + 1) % 50 == 0:
                _p(f"  [{i+1}/{len(dataset)}] {errors} errors so far...")
            continue

        agg = repo_agg.setdefault(repo_name, {
            "count": 0,
            "raw_tags_total": 0,
            "release_tags_total": 0,
            "scan_candidates_total": 0,
            "gt_tags_total": 0,
            "gt_mapped_total": 0,
            "full_coverage_count": 0,
        })
        agg["count"] += 1
        agg["raw_tags_total"] += result["raw_tags"]
        agg["release_tags_total"] += result["release_tags"]
        agg["scan_candidates_total"] += result["scan_candidates"]
        agg["gt_tags_total"] += result["gt_tags"]
        agg["gt_mapped_total"] += result["gt_mapped"]
        if result["gt_coverage"] >= 0.99:
            agg["full_coverage_count"] += 1

        if (i + 1) % 50 == 0:
            elapsed = time.time() - t0
            _p(f"  [{i+1}/{len(dataset)}] {elapsed:.1f}s elapsed, {errors} errors")

    elapsed = time.time() - t0
    _p(f"\nPhase 1 complete: {elapsed:.1f}s, {errors} errors")

    # Summary
    _p()
    _p("=" * 70)
    _p("Per-Repo Tag Plan Summary")
    _p("=" * 70)
    _p(f"{'Repo':15s} {'CVEs':>5s} {'AvgRaw':>8s} {'AvgRel':>8s} {'AvgScan':>8s} "
       f"{'Reduction':>10s} {'AvgGT':>6s} {'Cover%':>7s}")
    _p("-" * 70)

    total_cves = 0
    total_raw = 0
    total_release = 0
    total_scan = 0
    total_gt = 0
    total_gt_mapped = 0
    total_full_cov = 0

    for repo, agg in sorted(repo_agg.items()):
        n = agg["count"]
        avg_raw = agg["raw_tags_total"] / n
        avg_rel = agg["release_tags_total"] / n
        avg_scan = agg["scan_candidates_total"] / n
        reduction = 1 - avg_scan / max(1, avg_rel)
        avg_gt = agg["gt_tags_total"] / n
        cov_pct = agg["full_coverage_count"] / n * 100

        _p(f"{repo:15s} {n:5d} {avg_raw:8.0f} {avg_rel:8.0f} {avg_scan:8.0f} "
           f"{reduction:10.1%} {avg_gt:6.0f} {cov_pct:6.1f}%")

        total_cves += n
        total_raw += agg["raw_tags_total"]
        total_release += agg["release_tags_total"]
        total_scan += agg["scan_candidates_total"]
        total_gt += agg["gt_tags_total"]
        total_gt_mapped += agg["gt_mapped_total"]
        total_full_cov += agg["full_coverage_count"]

    _p("-" * 70)
    if total_cves > 0:
        _p(f"{'TOTAL':15s} {total_cves:5d} {total_raw/total_cves:8.0f} "
           f"{total_release/total_cves:8.0f} {total_scan/total_cves:8.0f} "
           f"{1 - total_scan/max(1, total_release):10.1%} "
           f"{total_gt/total_cves:6.0f} {total_full_cov/total_cves*100:6.1f}%")

    # Save detailed results
    with open(OUTPUT_DIR / "tag_plan_all_cves.json", "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    summary = {
        "total_cves": len(dataset),
        "processed_ok": total_cves,
        "errors": errors,
        "total_raw_tags": total_raw,
        "total_release_tags": total_release,
        "total_scan_candidates": total_scan,
        "avg_scan_per_cve": total_scan / max(1, total_cves),
        "overall_reduction": 1 - total_scan / max(1, total_release),
        "total_gt_tags": total_gt,
        "total_gt_mapped": total_gt_mapped,
        "full_coverage_count": total_full_cov,
        "full_coverage_rate": total_full_cov / max(1, total_cves),
        "per_repo": repo_agg,
    }
    with open(OUTPUT_DIR / "summary.json", "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    _p(f"\nResults saved to {OUTPUT_DIR}")

    # Phase 2: Static pre-filter sample test (on a subset)
    _p()
    _p("=" * 70)
    _p("Phase 2: Static Pre-filter Sampling (10 CVEs per repo)")
    _p("=" * 70)

    pf_results: list[dict[str, Any]] = []
    repo_tested: dict[str, int] = {}
    MAX_PER_REPO = 10

    for cve_id, record in dataset.items():
        repo_name = record.get("repo", "")
        gt_tags = record.get("affected_version", [])
        if not gt_tags:
            continue
        if repo_tested.get(repo_name, 0) >= MAX_PER_REPO:
            continue
        repo_tested[repo_name] = repo_tested.get(repo_name, 0) + 1

        result = analyze_cve(cve_id, record, gt_tags, do_prefilter=True)
        pf_results.append(result)

        if result["status"] == "ok" and "prefilter_skip_rate" in result:
            _p(f"  {cve_id:20s} [{repo_name:12s}] "
               f"scan={result['scan_candidates']:4d} "
               f"pf_skip={result['prefilter_skip_rate']:.0%} "
               f"est_llm={result.get('estimated_llm_tags', '?'):>4} "
               f"gt_cov={result['gt_coverage']:.2%}")
        elif result["status"] == "ok":
            _p(f"  {cve_id:20s} [{repo_name:12s}] "
               f"scan={result['scan_candidates']:4d} (no anchor for prefilter)")

    with open(OUTPUT_DIR / "prefilter_sample.json", "w") as f:
        json.dump(pf_results, f, indent=2, ensure_ascii=False)

    # Pre-filter summary
    pf_repos: dict[str, dict[str, float]] = {}
    for r in pf_results:
        if r["status"] != "ok" or "prefilter_skip_rate" not in r:
            continue
        repo = r["repo"]
        pf_repos.setdefault(repo, {"count": 0, "total_skip": 0.0, "total_scan": 0, "total_est_llm": 0})
        pf_repos[repo]["count"] += 1
        pf_repos[repo]["total_skip"] += r["prefilter_skip_rate"]
        pf_repos[repo]["total_scan"] += r["scan_candidates"]
        pf_repos[repo]["total_est_llm"] += r.get("estimated_llm_tags", r["scan_candidates"])

    _p()
    _p("Pre-filter Summary:")
    for repo, stats in sorted(pf_repos.items()):
        n = stats["count"]
        _p(f"  {repo:15s}: avg_skip={stats['total_skip']/n:.0%} "
           f"avg_scan={stats['total_scan']/n:.0f} "
           f"avg_est_llm={stats['total_est_llm']/n:.0f}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
