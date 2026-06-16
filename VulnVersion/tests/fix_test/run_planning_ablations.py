"""VulnTree planning report for Step3.

This script replaces the removed legacy planning ablations that depended on
``DEFAULT_POLICY`` / ``REPO_POLICY`` / cross-line early-stop heuristics.
It evaluates the current deterministic VulnTree planner without invoking the
LLM verifier and reports candidate/probe coverage statistics.
"""
from __future__ import annotations

import json
import statistics
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from vulnversion.git_ops.repo import map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.plan_tags import build_tag_plan

REPO_DIR = PROJECT_ROOT / "repo"
DATASET_PATH = PROJECT_ROOT / "DataSet" / "BaseDataOrder.json"
OUTPUT_DIR = Path(__file__).parent / "ablation_results"


def _candidate_count(plan: dict[str, Any]) -> int:
    return len(plan.get("verification_order") or [])


def _probe_task_count(plan: dict[str, Any]) -> int:
    tasks = plan.get("verification_tasks") or []
    return sum(len(task.get("probe_tags") or []) for task in tasks)


def _run_planning_report(dataset: dict[str, Any]) -> dict[str, Any]:
    t0 = time.time()
    per_repo: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "count": 0,
            "raw_tags": 0,
            "release_tags": 0,
            "candidate_tags": 0,
            "probe_tasks": 0,
            "full_candidate_coverage": 0,
            "full_probe_coverage": 0,
            "gt_total": 0,
            "gt_candidate_hits": 0,
            "gt_probe_hits": 0,
            "frontier_status_counts": Counter(),
        }
    )
    errors = 0
    for index, (cve_id, record) in enumerate(dataset.items(), start=1):
        repo_name = record.get("repo", "")
        repo_path = REPO_DIR / repo_name
        if not repo_path.exists():
            errors += 1
            continue
        try:
            plan = build_tag_plan(
                repo_path=str(repo_path),
                cve_id=cve_id,
                fixing_commits=record.get("fixing_commits", []),
                mode="eval",
            )
        except Exception:
            errors += 1
            continue

        candidate_tags = list(plan.get("verification_order") or [])
        probe_tags: list[str] = []
        for task in (plan.get("verification_tasks") or []):
            for tag in task.get("probe_tags") or []:
                if tag not in probe_tags:
                    probe_tags.append(tag)
        gt_tags = record.get("affected_version", []) or []
        mapped_candidate, _ = map_gt_tags_to_repo_tags(gt_tags, candidate_tags, mode="loose")
        mapped_probe, _ = map_gt_tags_to_repo_tags(gt_tags, probe_tags, mode="loose")

        agg = per_repo[repo_name]
        agg["count"] += 1
        agg["raw_tags"] += int(plan.get("raw_tags_count", 0) or 0)
        agg["release_tags"] += int(plan.get("release_tags_count", 0) or 0)
        agg["candidate_tags"] += _candidate_count(plan)
        agg["probe_tasks"] += _probe_task_count(plan)
        agg["gt_total"] += len(gt_tags)
        agg["gt_candidate_hits"] += len(mapped_candidate)
        agg["gt_probe_hits"] += len(mapped_probe)
        if len(mapped_candidate) == len(gt_tags):
            agg["full_candidate_coverage"] += 1
        if len(mapped_probe) == len(gt_tags):
            agg["full_probe_coverage"] += 1
        for boundary in (plan.get("line_boundaries") or {}).values():
            status = str(boundary.get("status") or "unknown")
            agg["frontier_status_counts"][status] += 1

        if index % 50 == 0:
            print(f"  [planning-report] [{index}/{len(dataset)}] {time.time() - t0:.0f}s", flush=True)

    total = sum(v["count"] for v in per_repo.values())
    summary = {
        "variant": "vuln_tree_baseline",
        "elapsed_s": time.time() - t0,
        "processed": total,
        "errors": errors,
        "per_repo": {},
    }
    repo_rows = []
    for repo_name, agg in sorted(per_repo.items()):
        repo_row = {
            "repo": repo_name,
            "count": agg["count"],
            "avg_candidate_tags": round(agg["candidate_tags"] / max(1, agg["count"]), 2),
            "avg_probe_tags": round(agg["probe_tasks"] / max(1, agg["count"]), 2),
            "avg_release_tags": round(agg["release_tags"] / max(1, agg["count"]), 2),
            "candidate_gt_coverage": round(agg["gt_candidate_hits"] / max(1, agg["gt_total"]), 4),
            "probe_gt_coverage": round(agg["gt_probe_hits"] / max(1, agg["gt_total"]), 4),
            "full_candidate_coverage_rate": round(agg["full_candidate_coverage"] / max(1, agg["count"]), 4),
            "full_probe_coverage_rate": round(agg["full_probe_coverage"] / max(1, agg["count"]), 4),
            "frontier_status_counts": dict(agg["frontier_status_counts"]),
        }
        summary["per_repo"][repo_name] = repo_row
        repo_rows.append(repo_row)

    candidate_avgs = [row["avg_candidate_tags"] for row in repo_rows]
    probe_avgs = [row["avg_probe_tags"] for row in repo_rows]
    summary["overall"] = {
        "repo_count": len(repo_rows),
        "avg_candidate_tags_per_repo": round(statistics.mean(candidate_avgs), 2) if candidate_avgs else 0.0,
        "avg_probe_tags_per_repo": round(statistics.mean(probe_avgs), 2) if probe_avgs else 0.0,
        "notes": [
            "Legacy plan-policy ablations were removed with the old Step3 tag-plan algorithm.",
            "This report measures the current VulnTree planner only.",
        ],
    }
    return summary


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    print(f"Loaded {len(dataset)} CVEs from BaseDataOrder.json")
    result = _run_planning_report(dataset)
    out_path = OUTPUT_DIR / "vuln_tree_planning_report.json"
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result["overall"], ensure_ascii=False, indent=2))
    print(f"Saved planning report to {out_path}")


if __name__ == "__main__":
    main()
