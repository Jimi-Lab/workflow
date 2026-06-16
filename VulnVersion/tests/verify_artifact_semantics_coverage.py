"""P0-2 verification gate: ensure verdict_source bucketing applies cleanly
to (a) all real existing per_tag_verdict.jsonl artifacts under Result/,
and (b) freshly-built vuln_tree plans on real repos with a synthetic
deterministic agent across all 9 target repos.

Two correctness gates (both must hit >=95%):
  Gate A — replay coverage:
    For every CVE under Result/<repo>/<cve>/ that has per_tag_verdict.jsonl,
    feeding it into main._eval_against_gt() must produce a 4-way bucket
    such that:
      * every scanned tag falls into exactly one bucket (totality)
      * confusion-matrix cells (TP+FP+FN+TN) == resolved tags count
      * the bucket fields exist in the returned dict
  Gate B — fresh-run inferred-row coverage:
    For every CVE in BaseDataSet_30.json/BaseDataSet_10.json, run the
    deterministic planner against the real repo, then drive ASBS with a
    synthetic agent (oldest tag => NOT_AFFECTED, all others => AFFECTED).
    For each line that has any candidate tags, the resulting
    per_tag_verdict.jsonl must contain at least the asbs probe rows AND
    at least one inferred_interval row whenever ASBS produces an
    affected_interval whose tag count > #probed_anchors.

Usage:
  python tests/verify_artifact_semantics_coverage.py
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

from main import _eval_against_gt
from vulnversion.stage3_verify.verify_tags import verify_tags


# ────────────────────────────────────────────────────────────────────
# Gate A — replay existing Result/ jsonl through new _eval_against_gt
# ────────────────────────────────────────────────────────────────────


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def _gate_a_replay(result_root: Path) -> dict[str, Any]:
    counts = {"checked": 0, "ok": 0, "fail": 0, "skipped": 0}
    by_repo: dict[str, dict[str, int]] = {}
    failures: list[dict[str, Any]] = []
    for repo_dir in sorted(result_root.iterdir()):
        if not repo_dir.is_dir():
            continue
        repo = repo_dir.name
        for cve_dir in sorted(repo_dir.iterdir()):
            if not cve_dir.is_dir():
                continue
            jsonl_path = cve_dir / "per_tag_verdict.jsonl"
            ds_path = cve_dir / "dataset_record.json"
            if not jsonl_path.exists():
                counts["skipped"] += 1
                continue
            rows = _read_jsonl(jsonl_path)
            if not rows:
                counts["skipped"] += 1
                continue
            scanned = [str(r.get("tag") or "") for r in rows if r.get("tag")]
            scanned = list(dict.fromkeys(scanned))
            gt: list[str] = []
            if ds_path.exists():
                try:
                    rec = json.loads(ds_path.read_text(encoding="utf-8"))
                    gt = [str(t) for t in (rec.get("affected_version") or [])]
                except Exception:
                    pass
            ev = _eval_against_gt(
                gt_tags=gt,
                scanned_tags=scanned,
                results=rows,
                mode="strict",
            )
            cm = ev.get("confusion_matrix") or {}
            probed = set(ev.get("probed_tags") or [])
            prefiltered = set(ev.get("prefiltered_tags") or [])
            inferred = set(ev.get("inferred_tags") or [])
            errored = set(ev.get("agent_error_tags") or [])
            buckets_union = probed | prefiltered | inferred | errored
            buckets_count = len(probed) + len(prefiltered) + len(inferred) + len(errored)
            tp_fp_fn_tn = int(cm.get("TP", 0)) + int(cm.get("FP", 0)) + int(cm.get("FN", 0)) + int(cm.get("TN", 0))
            resolved = len(probed) + len(prefiltered) + len(inferred)

            problems: list[str] = []
            if set(scanned) != buckets_union:
                missing = set(scanned) - buckets_union
                extra = buckets_union - set(scanned)
                problems.append(
                    f"bucket-totality mismatch: missing={list(missing)[:5]} extra={list(extra)[:5]}"
                )
            if buckets_count != len(scanned):
                problems.append(
                    f"bucket disjoint check: sum={buckets_count} != scanned={len(scanned)}"
                )
            if tp_fp_fn_tn != resolved:
                problems.append(
                    f"CM cells={tp_fp_fn_tn} != resolved={resolved}"
                )
            for required in ("probed_tags", "prefiltered_tags", "inferred_tags",
                             "unmapped_gt_tags", "agent_error_tags", "metrics_resolved_only"):
                if required not in ev:
                    problems.append(f"missing eval field: {required}")

            counts["checked"] += 1
            rb = by_repo.setdefault(repo, {"ok": 0, "fail": 0})
            if problems:
                counts["fail"] += 1
                rb["fail"] += 1
                if len(failures) < 8:
                    failures.append({
                        "repo": repo,
                        "cve": cve_dir.name,
                        "problems": problems,
                    })
            else:
                counts["ok"] += 1
                rb["ok"] += 1

    pass_rate = (counts["ok"] / counts["checked"] * 100.0) if counts["checked"] else 0.0
    return {"counts": counts, "by_repo": by_repo, "failures": failures, "pass_rate": pass_rate}


# ────────────────────────────────────────────────────────────────────
# Gate B — fresh planner run with synthetic agent on each BaseDataSet CVE
# ────────────────────────────────────────────────────────────────────


class _SyntheticAgent:
    """Always returns NOT_AFFECTED for the oldest tag of any line, AFFECTED otherwise.

    With this verdict pattern, ASBS will reliably produce affected_interval > 0
    for every multi-candidate line, which lets us validate the inferred-row
    emission across all 9 repos without LLM cost.
    """

    def __init__(self, oldest_per_line: dict[str, str]):
        self._oldest = oldest_per_line

    def run_json(self, *, session_id: str, prompt: str, system=None, tools=None, timeout_s=None):
        tag = ""
        line = ""
        for prompt_line in prompt.splitlines():
            if prompt_line.startswith("# Task: Verify whether tag `"):
                tag = prompt_line.split("`")[1]
            if prompt_line.startswith("Release line: `"):
                line = prompt_line.split("`")[1]
        if self._oldest.get(line) == tag:
            verdict = "NOT_AFFECTED"
        else:
            verdict = "AFFECTED"
        return {
            "tag": tag, "line": line, "verdict": verdict, "run_status": "OK",
            "confidence": 0.7, "reasoning_summary": "synthetic",
            "matched_predicates": [], "failed_predicates": [], "triggered_guards": [],
            "evidence_snippets": [],
        }


def _write_minimal_rci(p: Path) -> None:
    p.write_text(json.dumps({
        "anchor": {"file_paths": [], "function_names": [], "stable_tokens": []},
        "vuln_predicates": [], "fix_predicates": [], "guards": [],
    }, ensure_ascii=False, indent=2), encoding="utf-8")


def _gate_b_fresh(repo_root: Path, datasets: list[Path]) -> dict[str, Any]:
    cves: dict[str, dict[str, Any]] = {}
    for p in datasets:
        if not p.exists():
            continue
        d = json.loads(p.read_text(encoding="utf-8"))
        for cve_id, rec in d.items():
            if isinstance(rec, dict):
                cves[cve_id] = rec

    counts = {"checked": 0, "ok": 0, "fail": 0, "skipped": 0, "error": 0}
    by_repo: dict[str, dict[str, int]] = {}
    failures: list[dict[str, Any]] = []

    from vulnversion.stage3_verify.plan_tags import build_tag_plan

    for cve_id, rec in cves.items():
        repo = str(rec.get("repo") or "")
        repo_path = repo_root / repo
        if not repo_path.exists():
            counts["skipped"] += 1
            continue
        fixing_commits = rec.get("fixing_commits") or []
        if not fixing_commits:
            counts["skipped"] += 1
            continue
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            rci = Path(tmp) / "rci.json"
            _write_minimal_rci(rci)
            try:
                plan = build_tag_plan(
                    repo_path=str(repo_path),
                    cve_id=cve_id,
                    fixing_commits=fixing_commits,
                )
            except Exception as e:
                counts["error"] += 1
                rb = by_repo.setdefault(repo, {"ok": 0, "fail": 0, "error": 0})
                rb["error"] = rb.get("error", 0) + 1
                if len(failures) < 5:
                    failures.append({
                        "cve": cve_id, "repo": repo,
                        "stage": "plan", "error": f"{type(e).__name__}: {e}",
                    })
                continue
            release_lines = plan.get("release_lines") or {}
            oldest_per_line = {
                line: (entry.get("tags") or [None])[0]
                for line, entry in release_lines.items()
                if entry.get("tags")
            }
            agent = _SyntheticAgent(oldest_per_line)
            try:
                verify_tags(
                    repo_path=str(repo_path),
                    cve_id=cve_id,
                    rci_path=str(rci),
                    out_dir=str(out_dir),
                    fixing_commits=fixing_commits,
                    resume=False,
                    agent=agent,
                    session_id="s",
                    per_tag_session=False,
                    log_progress=False,
                    tag_timeout_s=60.0,
                )
            except Exception as e:
                counts["error"] += 1
                rb = by_repo.setdefault(repo, {"ok": 0, "fail": 0, "error": 0})
                rb["error"] = rb.get("error", 0) + 1
                if len(failures) < 5:
                    failures.append({
                        "cve": cve_id, "repo": repo,
                        "stage": "verify",
                        "error": f"{type(e).__name__}: {e}",
                        "trace": traceback.format_exc(limit=2),
                    })
                continue
            rows = _read_jsonl(out_dir / "per_tag_verdict.jsonl")
            line_boundaries_path = out_dir / "line_boundaries.json"
            try:
                line_boundaries = json.loads(line_boundaries_path.read_text(encoding="utf-8"))
            except Exception:
                line_boundaries = {}
            problems: list[str] = []

            # Every row must have verdict_source set (P0-2 invariant).
            missing_src = [r.get("tag") for r in rows if not r.get("verdict_source")]
            if missing_src:
                problems.append(f"{len(missing_src)} rows missing verdict_source (sample={missing_src[:3]})")

            # Every line with affected_interval whose tags > probed_anchors must
            # produce inferred_interval rows. Count expected vs actual.
            inferred_rows_by_line: dict[str, set[str]] = {}
            for r in rows:
                if r.get("verdict_source") == "inferred_interval":
                    inferred_rows_by_line.setdefault(str(r.get("line") or ""), set()).add(str(r.get("tag")))

            expected_inferred_total = 0
            actual_inferred_total = 0
            for line, boundary in (line_boundaries or {}).items():
                interval = (boundary or {}).get("affected_interval") or {}
                interval_tags = list(interval.get("tags") or [])
                if not interval_tags:
                    continue
                probed_in_interval = sum(
                    1 for r in rows
                    if str(r.get("line")) == str(line) and r.get("verdict_source") in ("agent", "prefilter")
                    and r.get("tag") in interval_tags
                )
                expected = max(0, len(interval_tags) - probed_in_interval)
                expected_inferred_total += expected
                actual_inferred_total += len(inferred_rows_by_line.get(str(line), set()))

            if expected_inferred_total > 0 and actual_inferred_total < expected_inferred_total:
                problems.append(
                    f"inferred row deficit: expected>={expected_inferred_total} got={actual_inferred_total}"
                )

            counts["checked"] += 1
            rb = by_repo.setdefault(repo, {"ok": 0, "fail": 0, "error": 0})
            if problems:
                counts["fail"] += 1
                rb["fail"] = rb.get("fail", 0) + 1
                if len(failures) < 8:
                    failures.append({
                        "cve": cve_id, "repo": repo, "stage": "verify",
                        "problems": problems,
                    })
            else:
                counts["ok"] += 1
                rb["ok"] = rb.get("ok", 0) + 1

    runnable = counts["checked"] + counts["error"]
    pass_rate = (counts["ok"] / runnable * 100.0) if runnable else 0.0
    return {"counts": counts, "by_repo": by_repo, "failures": failures, "pass_rate": pass_rate}


# ────────────────────────────────────────────────────────────────────
# main
# ────────────────────────────────────────────────────────────────────


def main() -> int:
    result_root = ROOT / "Result"
    repo_root = ROOT / "repo"
    datasets = [
        ROOT / "DataSet" / "BaseDataSet_10.json",
        ROOT / "DataSet" / "BaseDataSet_30.json",
    ]

    print("==== Gate A: replay existing Result/ jsonl through main._eval_against_gt ====")
    started = time.monotonic()
    a = _gate_a_replay(result_root)
    elapsed_a = time.monotonic() - started
    counts = a["counts"]
    print(
        f"  checked={counts['checked']} ok={counts['ok']} fail={counts['fail']} "
        f"skipped={counts['skipped']} pass_rate={a['pass_rate']:.2f}% time={elapsed_a:.1f}s"
    )
    for repo, c in sorted(a["by_repo"].items()):
        print(f"    {repo:14s} ok={c['ok']} fail={c['fail']}")
    if a["failures"]:
        print("  first failures:")
        for f in a["failures"][:5]:
            print(f"    {f}")

    print()
    print("==== Gate B: fresh planner run with synthetic agent (BaseDataSet_30+10) ====")
    started = time.monotonic()
    b = _gate_b_fresh(repo_root, datasets)
    elapsed_b = time.monotonic() - started
    counts = b["counts"]
    print(
        f"  checked={counts['checked']} ok={counts['ok']} fail={counts['fail']} "
        f"error={counts['error']} skipped={counts['skipped']} "
        f"pass_rate={b['pass_rate']:.2f}% time={elapsed_b:.1f}s"
    )
    for repo, c in sorted(b["by_repo"].items()):
        print(f"    {repo:14s} ok={c.get('ok',0)} fail={c.get('fail',0)} error={c.get('error',0)}")
    if b["failures"]:
        print("  first failures:")
        for f in b["failures"][:5]:
            print(f"    {f}")

    overall_ok = (a["pass_rate"] >= 95.0) and (b["pass_rate"] >= 95.0)
    print()
    print(f"==== overall: {'PASS' if overall_ok else 'FAIL'} (gate >= 95%) ====")
    return 0 if overall_ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
