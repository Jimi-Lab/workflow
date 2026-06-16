"""Refine the 'planner_bug_dominant' classification by checking whether the
fix commit is a git-ancestor of the GT-affected tag.

If fix_commit IS an ancestor of the GT tag, then the tag genuinely contains
the fix (it's git-correct to label it NOT_AFFECTED) — the NVD GT is misaligned
with git semantics (NVD semantic mismatch). If fix_commit is NOT an ancestor,
then it's a real planner pruning bug.
"""
from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPO_DIR = PROJECT_ROOT / "repo"
DATASET_PATH = PROJECT_ROOT / "DataSet" / "BaseDataOrder.json"
GAP_ANALYSIS = Path(__file__).parent / "coverage_gap_analysis.json"
OUT_PATH = Path(__file__).parent / "coverage_gap_refined.json"


def is_ancestor(repo_path: Path, commit: str, tag: str) -> bool | None:
    """Return True if commit is ancestor of tag; None on error."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "merge-base", "--is-ancestor", commit, tag],
            capture_output=True,
            timeout=15,
        )
        if result.returncode == 0:
            return True
        if result.returncode == 1:
            return False
        return None
    except (subprocess.TimeoutExpired, Exception):
        return None


def tag_exists(repo_path: Path, tag: str) -> bool:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "--verify", f"refs/tags/{tag}"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def refine_cve(detail: dict, dataset: dict) -> dict:
    """For a planner_bug_dominant case, check whether each missing GT tag's
    fix commit is an ancestor of the tag."""
    cve_id = detail["cve_id"]
    repo_name = detail["repo"]
    repo_path = REPO_DIR / repo_name
    record = dataset.get(cve_id, {})
    fixing_commits = record.get("fixing_commits", [])
    # fixing_commits is nested: [['hash']] or [['hash1', 'hash2'], ['hash3']]
    fix_commits: list[str] = []
    for fc in fixing_commits:
        if isinstance(fc, list):
            fix_commits.extend(str(x) for x in fc if x)
        elif isinstance(fc, str):
            fix_commits.append(fc)
    fix_commit = fix_commits[0] if fix_commits else None

    missing_tags = detail.get("missing_tags_categorized", [])
    ancestor_count = 0
    non_ancestor_count = 0
    tag_not_found_count = 0
    per_tag_results = []

    for mt in missing_tags:
        repo_tag = mt.get("repo_tag")
        if not repo_tag or not fix_commits:
            continue
        if not tag_exists(repo_path, repo_tag):
            tag_not_found_count += 1
            per_tag_results.append({
                "gt_tag": mt.get("gt_tag"),
                "repo_tag": repo_tag,
                "is_ancestor": "tag_not_found",
            })
            continue
        # Any fix_commit being an ancestor of the tag ⇒ tag contains the fix
        anc = False
        any_error = False
        for fc in fix_commits:
            r = is_ancestor(repo_path, fc, repo_tag)
            if r is True:
                anc = True
                break
            if r is None:
                any_error = True
        if not anc and any_error and not any(
            is_ancestor(repo_path, fc, repo_tag) is False for fc in fix_commits
        ):
            anc = None
        if anc is True:
            ancestor_count += 1
            per_tag_results.append({
                "gt_tag": mt.get("gt_tag"),
                "repo_tag": repo_tag,
                "is_ancestor": True,
            })
        elif anc is False:
            non_ancestor_count += 1
            per_tag_results.append({
                "gt_tag": mt.get("gt_tag"),
                "repo_tag": repo_tag,
                "is_ancestor": False,
            })
        else:
            per_tag_results.append({
                "gt_tag": mt.get("gt_tag"),
                "repo_tag": repo_tag,
                "is_ancestor": "error",
            })

    total_checked = ancestor_count + non_ancestor_count
    if total_checked == 0:
        refined_class = "insufficient_data"
    elif ancestor_count >= non_ancestor_count * 2:
        refined_class = "nvd_semantic_mismatch"
    elif non_ancestor_count >= ancestor_count * 2:
        refined_class = "real_planner_bug"
    else:
        refined_class = "mixed"

    return {
        "cve_id": cve_id,
        "repo": repo_name,
        "fix_commit": fix_commit,
        "all_fix_commits": fix_commits,
        "ancestor_count": ancestor_count,
        "non_ancestor_count": non_ancestor_count,
        "tag_not_found_count": tag_not_found_count,
        "refined_classification": refined_class,
        "per_tag": per_tag_results,
    }


def main() -> int:
    if not GAP_ANALYSIS.exists():
        print(f"ERROR: {GAP_ANALYSIS} not found")
        return 1

    gap_data = json.loads(GAP_ANALYSIS.read_text(encoding="utf-8"))
    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))

    details = gap_data.get("details", [])
    planner_bugs = [
        d for d in details
        if d.get("classification") == "planner_bug_dominant"
    ]
    print(f"Refining {len(planner_bugs)} planner_bug_dominant cases...")
    print()

    refined = []
    counter: Counter = Counter()
    repo_counter: dict[str, Counter] = defaultdict(Counter)
    for i, detail in enumerate(planner_bugs):
        r = refine_cve(detail, dataset)
        refined.append(r)
        counter[r["refined_classification"]] += 1
        repo_counter[r["repo"]][r["refined_classification"]] += 1
        if (i + 1) % 5 == 0:
            print(f"  [{i+1}/{len(planner_bugs)}] done")

    print()
    print("=" * 70)
    print("Refined Classification (planner_bug_dominant cases)")
    print("=" * 70)
    for cls, cnt in counter.most_common():
        print(f"  {cls:30s}: {cnt:4d}")

    print()
    print("Per-repo refined classification:")
    for repo in sorted(repo_counter):
        total = sum(repo_counter[repo].values())
        breakdown = ", ".join(
            f"{k}={v}" for k, v in repo_counter[repo].most_common()
        )
        print(f"  {repo:12s} (n={total}): {breakdown}")

    print()
    print("Real planner bugs (non-ancestor dominant):")
    print("=" * 70)
    real_bugs = [r for r in refined if r["refined_classification"] == "real_planner_bug"]
    for r in real_bugs:
        print(
            f"  {r['repo']:12s} {r['cve_id']:20s} "
            f"ancestor={r['ancestor_count']} non_ancestor={r['non_ancestor_count']}"
        )

    print()
    print("Mixed / insufficient_data cases:")
    print("=" * 70)
    for r in refined:
        if r["refined_classification"] in ("mixed", "insufficient_data"):
            print(
                f"  {r['repo']:12s} {r['cve_id']:20s} "
                f"class={r['refined_classification']} "
                f"ancestor={r['ancestor_count']} non_ancestor={r['non_ancestor_count']}"
            )

    OUT_PATH.write_text(
        json.dumps(
            {
                "refined_counts": dict(counter),
                "per_repo_refined": {k: dict(v) for k, v in repo_counter.items()},
                "details": refined,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    print()
    print(f"Saved: {OUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
