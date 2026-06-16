"""Offline verification: run build_vuln_tree_plan against every CVE in
BaseDataSet_30.json + BaseDataSet_10.json and assert that runtime state is
populated for every LineNode / TagNode / LineBoundary across all 9 repos.

This is the >=95% correctness gate before merging P0-1 into the main pipeline.
No LLM, no OpenCode — purely deterministic planner.

Usage:
  python tests/verify_runtime_state_coverage.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
import traceback
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vulnversion.stage3_verify.plan_tags import build_tag_plan
from vulnversion.stage3_verify.vuln_tree import write_vuln_tree_artifacts


REQUIRED_LINE_FIELDS = (
    "plan_status",
    "search_mode",
    "boundary_status",
    "certificate_id",
)
REQUIRED_BOUNDARY_FIELDS = (
    "plan_status",
    "boundary_status",
    "search_mode",
    "certificate_id",
)


def _load_cve_records(dataset_paths: list[Path]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for p in dataset_paths:
        if not p.exists():
            continue
        d = json.loads(p.read_text(encoding="utf-8"))
        for cve_id, rec in d.items():
            if isinstance(rec, dict):
                out[cve_id] = rec
    return out


def _check_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Return per-CVE failures map. Empty dict ⇒ all passed."""
    fails: dict[str, list[str]] = {
        "lines_unplanned": [],
        "lines_missing_field": [],
        "boundaries_missing_field": [],
        "tag_runtime_missing": [],
        "tag_role_invalid": [],
    }
    lines = plan.get("lines") or {}
    boundaries = plan.get("line_boundaries") or {}

    for line, line_dict in lines.items():
        rt = line_dict.get("runtime") or {}
        if rt.get("plan_status") in (None, "unplanned"):
            fails["lines_unplanned"].append(line)
        for field in REQUIRED_LINE_FIELDS:
            if rt.get(field) in (None, ""):
                fails["lines_missing_field"].append(f"{line}/{field}")
        for tn in line_dict.get("tag_nodes") or []:
            tag = tn.get("tag")
            tag_rt = tn.get("runtime") or {}
            if not tag_rt:
                fails["tag_runtime_missing"].append(f"{line}/{tag}")
                continue
            if tag_rt.get("plan_status") not in ("in_candidate", "outside_candidate"):
                fails["tag_role_invalid"].append(f"{line}/{tag}/{tag_rt.get('plan_status')}")

    for line, boundary_dict in boundaries.items():
        rt = boundary_dict.get("runtime") or {}
        for field in REQUIRED_BOUNDARY_FIELDS:
            if rt.get(field) in (None, ""):
                fails["boundaries_missing_field"].append(f"{line}/{field}")

    return {k: v for k, v in fails.items() if v}


def _run_one(cve_id: str, rec: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    repo_name = str(rec.get("repo") or "").strip()
    repo_path = repo_root / repo_name
    if not repo_path.exists():
        return {"status": "skipped", "reason": f"repo missing: {repo_path}"}
    fixing_commits = rec.get("fixing_commits") or []
    started = time.monotonic()
    try:
        plan = build_tag_plan(
            repo_path=str(repo_path),
            cve_id=cve_id,
            fixing_commits=fixing_commits,
        )
    except Exception as e:
        return {
            "status": "error",
            "error": f"{type(e).__name__}: {e}",
            "trace": traceback.format_exc(limit=3),
            "elapsed_s": time.monotonic() - started,
        }
    fails = _check_plan(plan)
    n_lines = len(plan.get("lines") or {})
    n_tags = sum(len((ld.get("tag_nodes") or [])) for ld in (plan.get("lines") or {}).values())
    # Verify artifact write does not raise and produces vuln_tree_runtime.json
    artifact_ok = False
    artifact_error: str | None = None
    try:
        with tempfile.TemporaryDirectory() as tmp:
            write_vuln_tree_artifacts(tmp, plan)
            artifact_ok = (Path(tmp) / "vuln_tree_runtime.json").exists()
    except Exception as e:
        artifact_error = f"{type(e).__name__}: {e}"

    return {
        "status": "ok" if not fails and artifact_ok else "fail",
        "n_lines": n_lines,
        "n_tags": n_tags,
        "fails": fails,
        "artifact_ok": artifact_ok,
        "artifact_error": artifact_error,
        "elapsed_s": round(time.monotonic() - started, 2),
        "repo": repo_name,
    }


def main() -> int:
    repo_root = ROOT / "repo"
    datasets = [
        ROOT / "DataSet" / "BaseDataSet_10.json",
        ROOT / "DataSet" / "BaseDataSet_30.json",
    ]
    cves = _load_cve_records(datasets)
    print(f"[verify] loaded {len(cves)} unique CVEs from {len(datasets)} datasets")

    by_status: dict[str, int] = {"ok": 0, "fail": 0, "error": 0, "skipped": 0}
    by_repo: dict[str, dict[str, int]] = {}
    failures: list[dict[str, Any]] = []
    n_lines_total = 0
    n_tags_total = 0

    for cve_id, rec in cves.items():
        result = _run_one(cve_id, rec, repo_root)
        status = result.get("status", "error")
        by_status[status] = by_status.get(status, 0) + 1
        repo = result.get("repo") or rec.get("repo") or "?"
        rb = by_repo.setdefault(repo, {"ok": 0, "fail": 0, "error": 0, "skipped": 0})
        rb[status] = rb.get(status, 0) + 1
        n_lines_total += result.get("n_lines", 0) or 0
        n_tags_total += result.get("n_tags", 0) or 0
        if status != "ok":
            failures.append({"cve_id": cve_id, **result})

    total = sum(by_status.values())
    runnable = total - by_status["skipped"]
    pass_count = by_status["ok"]
    pass_rate = (pass_count / runnable * 100.0) if runnable else 0.0

    print()
    print("==== summary ====")
    print(f"total_cves       : {total}")
    print(f"runnable         : {runnable}")
    print(f"ok               : {pass_count}")
    print(f"fail             : {by_status['fail']}")
    print(f"error            : {by_status['error']}")
    print(f"skipped (no repo): {by_status['skipped']}")
    print(f"line_nodes_total : {n_lines_total}")
    print(f"tag_nodes_total  : {n_tags_total}")
    print(f"pass_rate        : {pass_rate:.2f}%  (gate >= 95%)")
    print()
    print("==== by repo ====")
    for repo, counts in sorted(by_repo.items()):
        print(f"  {repo:14s} ok={counts.get('ok',0)} fail={counts.get('fail',0)} error={counts.get('error',0)} skipped={counts.get('skipped',0)}")

    if failures:
        print()
        print("==== first 5 failures ====")
        for f in failures[:5]:
            print(json.dumps(f, ensure_ascii=False, indent=2)[:1500])

    return 0 if pass_rate >= 95.0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
