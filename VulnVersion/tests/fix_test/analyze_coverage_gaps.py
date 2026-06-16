"""Identify and categorize the 48 CVEs with <100% GT coverage.

Outputs a per-CVE breakdown showing which tags are unmapped, how many are
missed, and the frontier status distribution for that CVE.  This is the
first step in the 6.1 Coverage Gap Investigation.
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.plan_tags import build_tag_plan
from vulnversion.stage3_verify.version_registry import filter_release_tags


REPO_DIR = PROJECT_ROOT / "repo"
DATASET_PATH = PROJECT_ROOT / "DataSet" / "BaseDataOrder.json"
TAG_PLAN_RESULTS = Path(__file__).parent / "asbs_results" / "tag_plan_all_cves.json"
OUT_PATH = Path(__file__).parent / "coverage_gap_analysis.json"


def classify_gap(cve_id: str, record: dict, gap_row: dict) -> dict:
    """Classify a single coverage-gap CVE to determine root cause."""
    repo_name = record.get("repo", "")
    repo_path = REPO_DIR / repo_name
    if not repo_path.exists():
        return {"cve_id": cve_id, "classification": "repo_missing"}

    repo = GitRepo.open(str(repo_path))
    all_tags = repo.list_tags()
    release_tags = filter_release_tags(repo_name, all_tags)

    gt_tags = record.get("affected_version", [])
    # Which GT tags are in the overall release tag universe?
    gt_mapped_all, gt_unmapped_all = map_gt_tags_to_repo_tags(
        gt_tags, release_tags, mode="loose"
    )

    # Build the actual tag plan (matching what test_asbs_prefilter did)
    fixing_commits = record.get("fixing_commits", [])
    try:
        tag_plan = build_tag_plan(
            repo_path=str(repo_path),
            cve_id=cve_id,
            fixing_commits=fixing_commits,
            mode="eval",
        )
    except Exception as e:
        return {
            "cve_id": cve_id,
            "repo": repo_name,
            "classification": "plan_error",
            "error": str(e)[:200],
        }

    verification_order = tag_plan.get("verification_order", [])
    mapped_scan, unmapped_scan = map_gt_tags_to_repo_tags(
        gt_tags, verification_order, mode="loose"
    )

    # Category A: GT tags not in release-tag universe at all (true GT noise)
    # Category B: GT tags in release-tag universe but not in verification_order (planner pruned too aggressively)
    unmapped_at_universe = set(gt_unmapped_all)
    unmapped_at_plan = set(unmapped_scan)
    unmapped_by_planner = unmapped_at_plan - unmapped_at_universe

    # Find which lines the "planner pruned" GT tags belong to
    frontiers = tag_plan.get("frontiers", {})
    line_plans = tag_plan.get("line_plans", {})

    # Build a map of tag -> line (from line_plans)
    tag_to_line: dict[str, str] = {}
    for line_name, lp in line_plans.items():
        for t in lp.get("candidate_tags", []):
            tag_to_line[t] = line_name

    # For each unmapped_by_planner GT tag, find its corresponding repo tag(s)
    # and identify which line they would have belonged to
    from vulnversion.git_ops.repo import _strip_dev_suffix
    core_to_all: dict[str, list[str]] = {}
    for t in all_tags:
        core = _strip_dev_suffix(t).lower()
        core_to_all.setdefault(core, []).append(t)

    pruned_line_counter: Counter = Counter()
    missing_tags_categorized: list[dict] = []

    for unmapped_core in unmapped_by_planner:
        # Find the actual repo tag for this unmapped core
        core = _strip_dev_suffix(unmapped_core).lower()
        repo_matches = core_to_all.get(core, [])
        if not repo_matches:
            missing_tags_categorized.append({
                "gt_tag": unmapped_core,
                "reason": "no_repo_tag_match",
            })
            continue
        # What frontier did this tag's line get?
        repo_tag = repo_matches[0]
        # Try to determine which release line this belongs to
        from vulnversion.stage3_verify.version_registry import line_key
        lk = line_key(repo_name, repo_tag)
        frontier = frontiers.get(lk, {})
        frontier_status = frontier.get("status", "unknown")
        pruned_line_counter[frontier_status] += 1
        missing_tags_categorized.append({
            "gt_tag": unmapped_core,
            "repo_tag": repo_tag,
            "line_key": lk,
            "frontier_status": frontier_status,
        })

    return {
        "cve_id": cve_id,
        "repo": repo_name,
        "gt_total": len(gt_tags),
        "gt_in_release_universe": len(gt_mapped_all),
        "gt_in_plan": len(mapped_scan),
        "unmapped_gt_noise": sorted(unmapped_at_universe),  # Category A
        "unmapped_by_planner": sorted(unmapped_by_planner),  # Category B
        "pruned_line_frontier_counts": dict(pruned_line_counter),
        "missing_tags_categorized": missing_tags_categorized[:20],  # sample
        "missing_tags_total": len(missing_tags_categorized),
        "planner_prune_rate": (
            len(unmapped_by_planner) / len(gt_tags) if gt_tags else 0.0
        ),
        "gt_noise_rate": (
            len(unmapped_at_universe) / len(gt_tags) if gt_tags else 0.0
        ),
        "classification": _classify(
            len(unmapped_at_universe), len(unmapped_by_planner), len(gt_tags)
        ),
    }


def _classify(gt_noise: int, planner_pruned: int, gt_total: int) -> str:
    if gt_total == 0:
        return "no_gt"
    if gt_noise >= planner_pruned * 2:
        return "gt_data_issue_dominant"
    if planner_pruned >= gt_noise * 2:
        return "planner_bug_dominant"
    return "mixed"


def main() -> int:
    if not TAG_PLAN_RESULTS.exists():
        print(f"ERROR: {TAG_PLAN_RESULTS} not found. Run test_asbs_prefilter first.")
        return 1

    tag_plan_rows = json.loads(TAG_PLAN_RESULTS.read_text(encoding="utf-8"))
    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))

    # Find all CVEs with coverage < 0.99
    gap_rows = [
        r for r in tag_plan_rows
        if r.get("status") == "ok" and r.get("gt_coverage", 0) < 0.99
    ]
    print(f"Found {len(gap_rows)} CVEs with coverage < 99%")
    print()

    # Per-repo breakdown
    by_repo: dict[str, list] = defaultdict(list)
    for r in gap_rows:
        by_repo[r["repo"]].append(r)

    for repo, rows in sorted(by_repo.items()):
        print(f"  {repo:15s}: {len(rows):3d} CVEs")

    print()
    print("Analyzing each gap CVE (this may take a minute)...")
    print()

    results = []
    classification_counter: Counter = Counter()

    for i, gap_row in enumerate(gap_rows):
        cve_id = gap_row["cve_id"]
        record = dataset.get(cve_id, {})
        if not record:
            continue

        try:
            result = classify_gap(cve_id, record, gap_row)
        except Exception as e:
            result = {
                "cve_id": cve_id,
                "repo": gap_row["repo"],
                "classification": "analysis_error",
                "error": str(e)[:200],
            }
        results.append(result)
        classification_counter[result.get("classification", "unknown")] += 1

        if (i + 1) % 10 == 0:
            print(f"  [{i+1}/{len(gap_rows)}] done")

    print()
    print("=" * 70)
    print("Classification Summary")
    print("=" * 70)
    for cls, count in classification_counter.most_common():
        print(f"  {cls:30s}: {count:4d}")

    print()
    print("Per-repo classification:")
    repo_cls: dict[str, Counter] = defaultdict(Counter)
    for r in results:
        repo_cls[r.get("repo", "?")][r.get("classification", "unknown")] += 1
    for repo in sorted(repo_cls):
        total = sum(repo_cls[repo].values())
        breakdown = ", ".join(
            f"{k}={v}" for k, v in repo_cls[repo].most_common()
        )
        print(f"  {repo:15s} (n={total}): {breakdown}")

    # Output top planner_bug_dominant cases — these are the most actionable
    print()
    print("=" * 70)
    print("Top 'planner_bug_dominant' cases (most actionable)")
    print("=" * 70)
    planner_bugs = [
        r for r in results if r.get("classification") == "planner_bug_dominant"
    ]
    planner_bugs.sort(key=lambda r: r.get("planner_prune_rate", 0), reverse=True)
    for r in planner_bugs[:15]:
        front = r.get("pruned_line_frontier_counts", {})
        print(
            f"  {r['repo']:12s} {r['cve_id']:20s} "
            f"prune_rate={r.get('planner_prune_rate', 0):.2%} "
            f"({r.get('missing_tags_total', 0)} tags) "
            f"frontiers={front}"
        )

    # Save full results
    OUT_PATH.write_text(
        json.dumps(
            {
                "classification_summary": dict(classification_counter),
                "per_repo_classification": {
                    k: dict(v) for k, v in repo_cls.items()
                },
                "total_gap_cves": len(results),
                "details": results,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    print()
    print(f"Full analysis saved to: {OUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
