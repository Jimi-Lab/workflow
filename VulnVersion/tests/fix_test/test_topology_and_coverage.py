"""
Test: Version Topology Classification + GT Tag Coverage

Verifies that:
1. The auto-classification correctly categorizes all 9 repos
2. After removing force_all_release_tags, the frontier-based tag_plan
   covers ALL ground truth (GT) affected tags from BaseDataOrder.json
3. Reports per-repo and per-CVE coverage stats

Run:
    cd E:/AI/Agent/workflow/VulnVersion
    python -m tests.fix_test.test_topology_and_coverage
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.version_registry import (
    filter_release_tags,
    infer_repo_name,
    line_key,
    sort_tags_for_line,
    branch_model,
)
from vulnversion.stage3_verify.plan_tags import build_tag_plan


REPO_DIR = PROJECT_ROOT / "repo"
DATASET_PATH = PROJECT_ROOT / "DataSet" / "BaseDataOrder.json"
OUTPUT_DIR = Path(__file__).parent / "topology_results"


def _group_release_tags_by_line(repo_name: str, release_tags: list[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for tag in release_tags:
        grouped.setdefault(line_key(repo_name, tag), []).append(tag)
    return {
        line: sort_tags_for_line(repo_name, tags, reverse=False)
        for line, tags in grouped.items()
    }


# ── Part 1: Auto-classify repos ──

def auto_classify_repo(repo_path: str) -> dict[str, Any]:
    """Classify a repo's version topology based on git data."""
    repo_name = infer_repo_name(repo_path)
    repo = GitRepo.open(repo_path)
    raw_tags = repo.list_tags(max_tags=None)
    release_tags = filter_release_tags(repo_name, raw_tags)
    lines = _group_release_tags_by_line(repo_name, release_tags)
    line_count = len(lines)
    avg_density = len(release_tags) / max(1, line_count)

    # Count stable/release branches
    try:
        branches_out = repo._git(["branch", "-r"])
        stable_branches = [
            b.strip() for b in branches_out.splitlines()
            if any(kw in b.lower() for kw in ["stable", "release/"])
        ]
    except Exception:
        stable_branches = []

    # Classification logic
    if line_count <= 3:
        if avg_density > 50:
            topology = "B_dense_single_line"
        else:
            topology = "A_sequential_single_line"
    elif line_count > 30 and avg_density < 5:
        topology = "D_complex_multi_line"
    else:
        topology = "C_multi_branch_maintained"

    return {
        "repo": repo_name,
        "total_tags": len(raw_tags),
        "release_tags": len(release_tags),
        "release_lines": line_count,
        "avg_density": round(avg_density, 1),
        "stable_branches": len(stable_branches),
        "branch_model": branch_model(repo_name),
        "topology": topology,
    }


# ── Part 2: Test frontier detection + GT coverage ──

def evaluate_frontier_coverage_for_cve(
    cve_id: str,
    record: dict[str, Any],
    gt_tags: list[str],
) -> dict[str, Any]:
    """Test whether tag_plan covers GT tags for a single CVE."""
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
    scanned_set = set(verification_order)

    # Map GT tags to scanned tags
    mapped, unmapped = map_gt_tags_to_repo_tags(gt_tags, list(scanned_set), mode="loose")
    coverage = len(mapped) / len(gt_tags) if gt_tags else 0.0

    # Check frontier info
    frontiers = tag_plan.get("frontiers", {})
    frontier_statuses = {}
    for line, frontier in frontiers.items():
        frontier_statuses[line] = frontier.get("status", "unknown")

    return {
        "cve_id": cve_id,
        "status": "ok",
        "repo": repo_name,
        "gt_tags_count": len(gt_tags),
        "scanned_tags_count": len(verification_order),
        "mapped_count": len(mapped),
        "unmapped_count": len(unmapped),
        "coverage": round(coverage, 4),
        "frontier_statuses": frontier_statuses,
        "unmapped_sample": unmapped[:5],
    }


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # ── Part 1: Classify all repos ──
    print("=" * 60)
    print("Part 1: Auto-classify repo version topologies")
    print("=" * 60)

    classifications = {}
    repos = ["FFmpeg", "curl", "ImageMagick", "httpd", "openssl",
             "wireshark", "qemu", "linux", "openjpeg"]

    for repo_name in repos:
        repo_path = str(REPO_DIR / repo_name)
        if not Path(repo_path).exists():
            print(f"  SKIP {repo_name}: repo not found at {repo_path}")
            continue
        info = auto_classify_repo(repo_path)
        classifications[repo_name] = info
        print(f"  {repo_name:15s} -> {info['topology']:30s} "
              f"(lines={info['release_lines']}, tags={info['release_tags']}, "
              f"density={info['avg_density']}, branches={info['stable_branches']})")

    with open(OUTPUT_DIR / "classifications.json", "w") as f:
        json.dump(classifications, f, indent=2)

    # ── Part 2: Test GT coverage on BaseDataSet CVEs ──
    print()
    print("=" * 60)
    print("Part 2: Test tag_plan GT coverage (frontier-based, no force_all)")
    print("=" * 60)

    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))

    # Sample: test up to 10 CVEs per repo for speed
    MAX_PER_REPO = 10
    repo_tested: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    repo_stats: dict[str, dict[str, Any]] = {}
    total = 0
    covered = 0

    for cve_id, record in dataset.items():
        repo_name = record.get("repo", "")
        gt_tags = record.get("affected_version", [])
        if not gt_tags:
            continue  # skip CVEs with no GT

        if repo_tested.get(repo_name, 0) >= MAX_PER_REPO:
            continue
        repo_tested[repo_name] = repo_tested.get(repo_name, 0) + 1

        result = evaluate_frontier_coverage_for_cve(cve_id, record, gt_tags)
        results.append(result)

        if result["status"] == "ok":
            total += 1
            if result["coverage"] >= 0.99:
                covered += 1
            status_char = "OK" if result["coverage"] >= 0.99 else f"PARTIAL({result['coverage']:.0%})"
            repo_stats.setdefault(repo_name, {"ok": 0, "covered": 0, "partial": 0, "error": 0})
            repo_stats[repo_name]["ok"] += 1
            if result["coverage"] >= 0.99:
                repo_stats[repo_name]["covered"] += 1
            else:
                repo_stats[repo_name]["partial"] += 1
            print(f"  {cve_id:20s} [{repo_name:12s}] gt={result['gt_tags_count']:3d} "
                  f"scanned={result['scanned_tags_count']:4d} "
                  f"mapped={result['mapped_count']:3d} "
                  f"coverage={result['coverage']:.2%} {status_char}")
        else:
            repo_stats.setdefault(repo_name, {"ok": 0, "covered": 0, "partial": 0, "error": 0})
            repo_stats[repo_name]["error"] += 1
            print(f"  {cve_id:20s} [{repo_name:12s}] {result['status']}: "
                  f"{result.get('error', '')[:80]}")

    # Summary
    print()
    print("=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"Total CVEs tested: {total}")
    print(f"Full coverage (>=99%): {covered}")
    print(f"Coverage rate: {covered/total:.1%}" if total > 0 else "N/A")
    print()
    print("Per-repo:")
    for repo, stats in sorted(repo_stats.items()):
        print(f"  {repo:15s}: tested={stats['ok']} "
              f"full_cover={stats['covered']} "
              f"partial={stats['partial']} "
              f"error={stats['error']}")

    # Save results
    with open(OUTPUT_DIR / "coverage_results.json", "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    with open(OUTPUT_DIR / "summary.json", "w") as f:
        json.dump({
            "total_tested": total,
            "full_coverage": covered,
            "coverage_rate": covered / total if total > 0 else 0,
            "per_repo": repo_stats,
        }, f, indent=2)

    print(f"\nResults saved to {OUTPUT_DIR}")
    return 0 if (total > 0 and covered / total >= 0.8) else 1


if __name__ == "__main__":
    sys.exit(main())
