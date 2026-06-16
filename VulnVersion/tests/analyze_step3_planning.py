from __future__ import annotations

import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path
import sys
from functools import lru_cache
import argparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vulnversion.git_ops.repo import map_gt_tags_to_repo_tags
from vulnversion.git_ops.repo import GitRepo
from vulnversion.stage3_verify.plan_tags import build_tag_plan


DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
REPO_ROOT = ROOT / "repo"
OUT_BASE = ROOT / "tests" / "step3_planning_report"


def pct(num: int, den: int) -> float:
    return (num / den * 100.0) if den else 0.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=str(DATASET))
    ap.add_argument("--out-dir", default=str(OUT_BASE))
    ap.add_argument("--repo", default=None)
    args = ap.parse_args()

    dataset_path = Path(args.dataset)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    data = json.loads(dataset_path.read_text(encoding="utf-8"))
    if args.repo:
        data = {k: v for k, v in data.items() if v.get("repo") == args.repo}

    # Testing-only speedups/caching: do not touch source code, only monkeypatch
    # methods inside this analysis process.
    orig_list_tags = GitRepo.list_tags
    orig_list_tags_containing = GitRepo.list_tags_containing

    @lru_cache(maxsize=None)
    def _cached_list_tags(repo_path: str, tags_glob: str | None, max_tags: int | None):
        repo = GitRepo.open(repo_path)
        return tuple(orig_list_tags(repo, tags_glob=tags_glob, max_tags=max_tags))

    @lru_cache(maxsize=None)
    def _cached_list_tags_containing(repo_path: str, commit: str, tags_glob: str | None):
        repo = GitRepo.open(repo_path)
        return tuple(orig_list_tags_containing(repo, commit, tags_glob=tags_glob))

    def _list_tags(self, tags_glob=None, max_tags=None):
        return list(_cached_list_tags(str(self.repo_path), tags_glob, max_tags))

    def _list_tags_containing(self, commit, *, tags_glob=None):
        return list(_cached_list_tags_containing(str(self.repo_path), commit, tags_glob))

    GitRepo.list_tags = _list_tags  # type: ignore[method-assign]
    GitRepo.list_tags_containing = _list_tags_containing  # type: ignore[method-assign]
    GitRepo.patch_id = lambda self, commit: ""  # type: ignore[method-assign]
    GitRepo.list_remote_branches_containing = lambda self, commit: []  # type: ignore[method-assign]

    repo_rows: dict[str, list[dict]] = defaultdict(list)
    all_rows: list[dict] = []

    for cve_id, rec in data.items():
        repo_name = rec["repo"]
        repo_path = REPO_ROOT / repo_name
        if not repo_path.exists():
            continue

        plan = build_tag_plan(
            repo_path=str(repo_path),
            cve_id=cve_id,
            fixing_commits=rec.get("fixing_commits"),
            mode="eval",
        )

        verification_order = list(plan.get("verification_order") or [])
        gt_tags = list(rec.get("affected_version") or [])
        mapped_gt, unmapped_gt = map_gt_tags_to_repo_tags(gt_tags, verification_order, mode="strict")

        frontier_counts = Counter((line_plan.get("frontier_status") or "unknown") for line_plan in (plan.get("line_plans") or {}).values())
        nonempty_lines = {line: len(line_plan.get("verification_order") or []) for line, line_plan in (plan.get("line_plans") or {}).items() if line_plan.get("verification_order")}

        row = {
            "repo": repo_name,
            "cve_id": cve_id,
            "fix_family_count": len(rec.get("fixing_commits") or []),
            "fix_commit_count": sum(len(x) for x in (rec.get("fixing_commits") or [])),
            "gt_count": len(gt_tags),
            "candidate_count": len(verification_order),
            "candidate_gt_coverage_count": len(mapped_gt),
            "candidate_gt_coverage_rate": len(mapped_gt) / len(gt_tags) if gt_tags else 0.0,
            "unmapped_gt": unmapped_gt,
            "release_line_count": len(plan.get("release_lines") or {}),
            "frontier_status_counts": dict(frontier_counts),
            "nonempty_lines": nonempty_lines,
            "verification_order": verification_order,
        }
        repo_rows[repo_name].append(row)
        all_rows.append(row)

    summary = {"repos": {}, "overall": {}}
    for repo_name, rows in sorted(repo_rows.items()):
        cand_counts = [r["candidate_count"] for r in rows]
        cov_rates = [r["candidate_gt_coverage_rate"] for r in rows]
        exact_cover = sum(1 for r in rows if r["candidate_gt_coverage_count"] == r["gt_count"])
        missing_cover = [r for r in rows if r["candidate_gt_coverage_count"] < r["gt_count"]]
        frontier_counter = Counter()
        for r in rows:
            frontier_counter.update(r["frontier_status_counts"])
        summary["repos"][repo_name] = {
            "cve_count": len(rows),
            "candidate_count": {
                "avg": round(statistics.mean(cand_counts), 2) if cand_counts else 0.0,
                "median": statistics.median(cand_counts) if cand_counts else 0.0,
                "max": max(cand_counts) if cand_counts else 0,
                "min": min(cand_counts) if cand_counts else 0,
            },
            "coverage": {
                "avg_rate": round(statistics.mean(cov_rates), 4) if cov_rates else 0.0,
                "full_coverage_cves": exact_cover,
                "full_coverage_rate": round(exact_cover / len(rows), 4) if rows else 0.0,
            },
            "frontier_status_counts": dict(frontier_counter),
            "worst_candidate_cves": sorted(rows, key=lambda r: (-r["candidate_count"], r["cve_id"]))[:10],
            "coverage_miss_cves": sorted(missing_cover, key=lambda r: (r["candidate_gt_coverage_rate"], -r["gt_count"], r["cve_id"]))[:20],
        }

    overall_candidate_counts = [r["candidate_count"] for r in all_rows]
    overall_cov = [r["candidate_gt_coverage_rate"] for r in all_rows]
    overall_exact = sum(1 for r in all_rows if r["candidate_gt_coverage_count"] == r["gt_count"])
    overall_miss = [r for r in all_rows if r["candidate_gt_coverage_count"] < r["gt_count"]]
    overall_frontiers = Counter()
    for r in all_rows:
        overall_frontiers.update(r["frontier_status_counts"])
    summary["overall"] = {
        "cve_count": len(all_rows),
        "candidate_count": {
            "avg": round(statistics.mean(overall_candidate_counts), 2) if overall_candidate_counts else 0.0,
            "median": statistics.median(overall_candidate_counts) if overall_candidate_counts else 0.0,
            "max": max(overall_candidate_counts) if overall_candidate_counts else 0,
            "min": min(overall_candidate_counts) if overall_candidate_counts else 0,
        },
        "coverage": {
            "avg_rate": round(statistics.mean(overall_cov), 4) if overall_cov else 0.0,
            "full_coverage_cves": overall_exact,
            "full_coverage_rate": round(overall_exact / len(all_rows), 4) if all_rows else 0.0,
            "coverage_miss_cves": len(overall_miss),
        },
        "frontier_status_counts": dict(overall_frontiers),
        "top_expensive_cves": sorted(all_rows, key=lambda r: (-r["candidate_count"], r["cve_id"]))[:30],
        "top_coverage_miss_cves": sorted(overall_miss, key=lambda r: (r["candidate_gt_coverage_rate"], -r["gt_count"], r["cve_id"]))[:50],
    }

    (out_dir / "step3_planning_rows.json").write_text(json.dumps(all_rows, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "step3_planning_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = []
    lines.append("# Step3 Planning Evaluation")
    lines.append("")
    lines.append(f"- dataset: `{dataset_path}`")
    lines.append(f"- repos tested: `{len(summary['repos'])}`")
    lines.append(f"- CVEs tested: `{summary['overall']['cve_count']}`")
    lines.append("")
    ov = summary["overall"]
    lines.append("## Overall")
    lines.append("")
    lines.append(f"- avg candidate tags/CVE: `{ov['candidate_count']['avg']}`")
    lines.append(f"- median candidate tags/CVE: `{ov['candidate_count']['median']}`")
    lines.append(f"- max candidate tags/CVE: `{ov['candidate_count']['max']}`")
    lines.append(f"- avg GT coverage rate: `{ov['coverage']['avg_rate']}`")
    lines.append(f"- full GT coverage CVEs: `{ov['coverage']['full_coverage_cves']}/{ov['cve_count']}`")
    lines.append(f"- coverage miss CVEs: `{ov['coverage']['coverage_miss_cves']}`")
    lines.append(f"- frontier statuses: `{ov['frontier_status_counts']}`")
    lines.append("")
    lines.append("## Per Repo")
    lines.append("")
    for repo_name, repo_summary in summary["repos"].items():
        lines.append(f"### {repo_name}")
        lines.append(f"- CVEs: `{repo_summary['cve_count']}`")
        lines.append(f"- avg/median/max candidates: `{repo_summary['candidate_count']['avg']}` / `{repo_summary['candidate_count']['median']}` / `{repo_summary['candidate_count']['max']}`")
        lines.append(f"- avg GT coverage: `{repo_summary['coverage']['avg_rate']}`")
        lines.append(f"- full coverage CVEs: `{repo_summary['coverage']['full_coverage_cves']}/{repo_summary['cve_count']}`")
        lines.append(f"- frontier statuses: `{repo_summary['frontier_status_counts']}`")
        worst = repo_summary["worst_candidate_cves"][:5]
        if worst:
            lines.append("- most expensive CVEs:")
            for row in worst:
                lines.append(f"  - `{row['cve_id']}`: candidates=`{row['candidate_count']}`, gt=`{row['gt_count']}`, coverage=`{row['candidate_gt_coverage_rate']:.3f}`")
        miss = repo_summary["coverage_miss_cves"][:5]
        if miss:
            lines.append("- worst coverage misses:")
            for row in miss:
                lines.append(f"  - `{row['cve_id']}`: covered=`{row['candidate_gt_coverage_count']}/{row['gt_count']}`, candidates=`{row['candidate_count']}`, unmapped=`{row['unmapped_gt'][:5]}`")
        lines.append("")

    lines.append("## Top Expensive CVEs")
    lines.append("")
    for row in ov["top_expensive_cves"][:20]:
        lines.append(f"- `{row['repo']}/{row['cve_id']}`: candidates=`{row['candidate_count']}`, gt=`{row['gt_count']}`, coverage=`{row['candidate_gt_coverage_rate']:.3f}`, lines={list(row['nonempty_lines'].keys())}")
    lines.append("")
    lines.append("## Worst Coverage Misses")
    lines.append("")
    for row in ov["top_coverage_miss_cves"][:20]:
        lines.append(f"- `{row['repo']}/{row['cve_id']}`: covered=`{row['candidate_gt_coverage_count']}/{row['gt_count']}`, candidates=`{row['candidate_count']}`, unmapped=`{row['unmapped_gt'][:8]}`")
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- This evaluates Step3 planning only; it does not call the backend model.")
    lines.append("- Source code under `vulnversion/` is not modified by this script.")
    lines.append("- Candidate count is based on `tag_plan.verification_order`.")
    lines.append("- GT coverage is strict-match coverage of dataset `affected_version` by planned candidate tags.")

    (out_dir / "step3_planning_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote: {out_dir / 'step3_planning_summary.json'}")
    print(f"Wrote: {out_dir / 'step3_planning_rows.json'}")
    print(f"Wrote: {out_dir / 'step3_planning_report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
