"""P0-3 verification gate: no-FIC subtype classification correctness on
real planner runs across all 9 target repos.

Gate A — invariant compliance (>=95%):
  For every line in every CVE plan:
    * line WITH fix-cluster hit  → no_fic_reason MUST be None
    * line WITHOUT fix-cluster hit → no_fic_reason MUST be in
      {never_fixed_on_this_line, duplicate_expansion_missed}
      (the third subtype "line_not_vulnerable_in_released_tags" can only
      be set by the verifier post-ASBS, not the planner)
    * placeholder "no_fic_pending_search" MUST never appear

Gate B — topological consistency (>=95%):
  Each duplicate_expansion_missed line must have at least one ancestor
  on its newer_line chain whose contains_fix_clusters is non-empty.
  Each never_fixed_on_this_line line must have NO such ancestor.

Reports per-repo subtype distribution so we know where BAPEE will pay off.
"""

from __future__ import annotations

import json
import sys
import time
import traceback
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vulnversion.stage3_verify.plan_tags import build_tag_plan


CANONICAL_PLANNER_SUBTYPES = {
    "never_fixed_on_this_line",
    "duplicate_expansion_missed",
}


def _load_cves(datasets: list[Path]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for p in datasets:
        if not p.exists():
            continue
        d = json.loads(p.read_text(encoding="utf-8"))
        for cve_id, rec in d.items():
            if isinstance(rec, dict):
                out[cve_id] = rec
    return out


def _check_one(plan: dict[str, Any]) -> dict[str, Any]:
    """Return invariant violations + topology violations + subtype counts."""
    lines = plan.get("lines") or {}
    line_to_runtime = {line: (ld.get("runtime") or {}) for line, ld in lines.items()}
    line_to_newer = {line: ld.get("newer_line") for line, ld in lines.items()}

    invariant_viol: list[str] = []
    topology_viol: list[str] = []
    subtype_counts = {
        "with_fic_reason_None": 0,
        "with_fic_reason_NOT_None_BUG": 0,
        "no_fic_never_fixed": 0,
        "no_fic_duplicate_missed": 0,
        "no_fic_other_BUG": 0,
        "placeholder_BUG": 0,
    }

    for line, rt in line_to_runtime.items():
        has_fic = bool(rt.get("contains_fix_clusters"))
        reason = rt.get("no_fic_reason")
        # Gate A — invariant
        if reason == "no_fic_pending_search":
            invariant_viol.append(f"{line}: placeholder still present")
            subtype_counts["placeholder_BUG"] += 1
            continue
        if has_fic:
            if reason is not None:
                invariant_viol.append(f"{line}: has FIC but reason={reason!r}")
                subtype_counts["with_fic_reason_NOT_None_BUG"] += 1
            else:
                subtype_counts["with_fic_reason_None"] += 1
        else:
            if reason not in CANONICAL_PLANNER_SUBTYPES:
                invariant_viol.append(f"{line}: no FIC but reason={reason!r} not in canonical set")
                subtype_counts["no_fic_other_BUG"] += 1
                continue
            if reason == "never_fixed_on_this_line":
                subtype_counts["no_fic_never_fixed"] += 1
                # Gate B — chain must NOT reach any FIC ancestor
                cur = line_to_newer.get(line)
                while cur is not None:
                    if line_to_runtime.get(cur, {}).get("contains_fix_clusters"):
                        topology_viol.append(
                            f"{line} classified never_fixed but ancestor {cur} has FIC"
                        )
                        break
                    cur = line_to_newer.get(cur)
            else:  # duplicate_expansion_missed
                subtype_counts["no_fic_duplicate_missed"] += 1
                cur = line_to_newer.get(line)
                upstream_has_fix = False
                while cur is not None:
                    if line_to_runtime.get(cur, {}).get("contains_fix_clusters"):
                        upstream_has_fix = True
                        break
                    cur = line_to_newer.get(cur)
                if not upstream_has_fix:
                    topology_viol.append(
                        f"{line} classified duplicate_missed but newer chain has no FIC"
                    )

    return {
        "invariant_viol": invariant_viol,
        "topology_viol": topology_viol,
        "subtype_counts": subtype_counts,
        "n_lines": len(lines),
    }


def main() -> int:
    repo_root = ROOT / "repo"
    datasets = [
        ROOT / "DataSet" / "BaseDataSet_10.json",
        ROOT / "DataSet" / "BaseDataSet_30.json",
    ]
    cves = _load_cves(datasets)
    print(f"[verify] {len(cves)} CVEs loaded across 9 repos")

    by_repo_status: dict[str, dict[str, int]] = {}
    by_repo_subtype: dict[str, dict[str, int]] = {}
    failures: list[dict[str, Any]] = []
    n_lines_total = 0
    n_invariant_pass = 0
    n_topology_pass = 0
    n_checked = 0

    started = time.monotonic()
    for cve_id, rec in cves.items():
        repo = str(rec.get("repo") or "")
        repo_path = repo_root / repo
        if not repo_path.exists() or not (rec.get("fixing_commits")):
            continue
        try:
            plan = build_tag_plan(
                repo_path=str(repo_path),
                cve_id=cve_id,
                fixing_commits=rec.get("fixing_commits"),
            )
        except Exception as e:
            failures.append({
                "cve_id": cve_id, "repo": repo, "stage": "plan",
                "error": f"{type(e).__name__}: {e}",
            })
            continue

        result = _check_one(plan)
        n_checked += 1
        n_lines_total += result["n_lines"]
        rs = by_repo_status.setdefault(repo, {"ok_inv": 0, "ok_topo": 0, "n": 0})
        rs["n"] += 1
        if not result["invariant_viol"]:
            rs["ok_inv"] += 1
            n_invariant_pass += 1
        if not result["topology_viol"]:
            rs["ok_topo"] += 1
            n_topology_pass += 1
        if result["invariant_viol"] or result["topology_viol"]:
            if len(failures) < 8:
                failures.append({
                    "cve_id": cve_id, "repo": repo,
                    "invariant_viol": result["invariant_viol"][:5],
                    "topology_viol": result["topology_viol"][:5],
                })
        agg = by_repo_subtype.setdefault(repo, {})
        for k, v in result["subtype_counts"].items():
            agg[k] = agg.get(k, 0) + v

    elapsed = time.monotonic() - started

    inv_rate = n_invariant_pass / n_checked * 100.0 if n_checked else 0.0
    topo_rate = n_topology_pass / n_checked * 100.0 if n_checked else 0.0

    print()
    print("==== invariant + topology compliance (per CVE) ====")
    print(f"  cves_checked={n_checked} lines_total={n_lines_total} time={elapsed:.1f}s")
    print(f"  invariant pass_rate={inv_rate:.2f}%   (gate >=95%)")
    print(f"  topology  pass_rate={topo_rate:.2f}%   (gate >=95%)")
    print()
    print("==== per-repo compliance ====")
    for repo, c in sorted(by_repo_status.items()):
        n = c["n"]
        i = c["ok_inv"]; t = c["ok_topo"]
        print(f"  {repo:14s} cves={n:>3d}  ok_inv={i:>3d}/{n}  ok_topo={t:>3d}/{n}")

    print()
    print("==== per-repo subtype distribution (line-level) ====")
    print(f"  {'repo':14s} {'with_fic':>10s} {'never_fixed':>13s} {'dup_missed':>12s} {'placeholder':>12s} {'other_BUG':>10s}")
    for repo, agg in sorted(by_repo_subtype.items()):
        print(
            f"  {repo:14s} "
            f"{agg.get('with_fic_reason_None', 0):>10d} "
            f"{agg.get('no_fic_never_fixed', 0):>13d} "
            f"{agg.get('no_fic_duplicate_missed', 0):>12d} "
            f"{agg.get('placeholder_BUG', 0):>12d} "
            f"{agg.get('no_fic_other_BUG', 0) + agg.get('with_fic_reason_NOT_None_BUG', 0):>10d}"
        )

    if failures:
        print()
        print("==== first violations ====")
        for f in failures[:5]:
            print(json.dumps(f, ensure_ascii=False, indent=2)[:1500])

    overall_pass = inv_rate >= 95.0 and topo_rate >= 95.0
    print()
    print(f"==== overall: {'PASS' if overall_pass else 'FAIL'} (gate >=95%) ====")
    return 0 if overall_pass else 2


if __name__ == "__main__":
    raise SystemExit(main())
