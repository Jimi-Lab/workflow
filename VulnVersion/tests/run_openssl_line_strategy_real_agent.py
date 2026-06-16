"""Small-sample real-agent validation for OpenSSL line strategy candidates.

This script is deliberately not part of the Step3 production path.  It uses
GT only to choose/evaluate a balanced validation sample.  The OpenCode agent
prompt never receives GT and only judges one tag at a time.

The goal is to validate whether real tag verdicts on selected probes are
stable enough before any OpenSSL line strategy is promoted from simulator to
main code.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = ROOT / "tests"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

import simulate_module_backed_step3 as module_sim
import simulate_openssl_version_tree_variants as openssl_variants
import simulate_step3_low_cost_schedulers as low_cost

from vulnversion.agent_harness.runtimes.opencode_runtime import OpenCodeRuntime
from vulnversion.config import Config, resolve_model_config
from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.asbs_line import AA_SENTINEL_COUNT, FIXED_SEG_SENTINEL, NN_SENTINEL_COUNT
from vulnversion.stage3_verify.git_reachability import batch_tags_containing
from vulnversion.stage3_verify.line_scheduler import compute_seed_lines, run_staged_scheduler


DEFAULT_DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
DEFAULT_REPO_ROOT = ROOT / "repo"
DEFAULT_OUT_DIR = ROOT / "tests" / "openssl_line_strategy_real_agent"
REPO = "openssl"
VARIANT_A = "major_minor_family_partition"
VARIANT_B = "current_plus_merge_mainline_09"
DEFAULT_CVES = [
    "CVE-2020-1971",
    "CVE-2022-1343",
    "CVE-2023-0464",
]


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _flatten_commits(rec: dict[str, Any]) -> list[str]:
    return low_cost._flatten_fixing_commits(rec.get("fixing_commits") or rec.get("fixing_commit"))


def _patch_excerpt(repo: GitRepo, commits: list[str], max_chars: int = 7000) -> str:
    chunks: list[str] = []
    used = 0
    for commit in commits:
        try:
            raw = repo.show_patch(commit)
        except Exception as exc:
            raw = f"[patch unavailable for {commit}: {type(exc).__name__}: {exc}]"
        if used + len(raw) > max_chars:
            raw = raw[: max(0, max_chars - used)] + "\n[TRUNCATED]"
        chunks.append(f"commit {commit}\n{raw}")
        used += len(raw)
        if used >= max_chars:
            break
    return "\n\n".join(chunks)


def _planned_state(
    *,
    cve_id: str,
    rec: dict[str, Any],
    context: dict[str, Any],
    fix_containing_tags: set[str],
    file_endpoint_lines: set[str],
) -> tuple[Any, set[str], set[str]]:
    release_lines = context["release_lines"]
    ordered_by_family = context["ordered_by_family"]
    release_tags = context["release_tags"]
    mapped_gt, _ = map_gt_tags_to_repo_tags(
        sorted(str(t) for t in (rec.get("affected_version") or [])),
        release_tags,
        mode="loose",
    )
    affected_set = set(mapped_gt)
    seed_lines = compute_seed_lines(
        repo_name=REPO,
        release_lines=release_lines,
        ordered_by_family=ordered_by_family,
        fix_containing_tags=fix_containing_tags,
        file_endpoint_lines=file_endpoint_lines,
        stride=3,
        file_neighbor_radius=1,
    )

    def run_line(line: str, tags: list[str]) -> Any:
        return module_sim._run_git_guided_line_module(
            line=line,
            tags=tags,
            affected_set=affected_set,
            fix_containing_tags=fix_containing_tags,
            nn_sentinel_count=NN_SENTINEL_COUNT,
            aa_sentinel_count=AA_SENTINEL_COUNT,
            fixed_segment_sentinel=FIXED_SEG_SENTINEL,
        )

    state = run_staged_scheduler(
        seed_lines=seed_lines,
        release_lines=release_lines,
        ordered_by_family=ordered_by_family,
        fix_containing_tags=fix_containing_tags,
        run_line_fn=run_line,
        expansion_radius=1,
        fallback_mode="none",
    )
    return state, affected_set, set(release_tags)


def _line_for_tag(context: dict[str, Any], tag: str) -> str:
    for line, tags in context["release_lines"].items():
        if tag in tags:
            return line
    return "unknown"


def _select_probe_rows(
    *,
    cve_id: str,
    state_a: Any,
    state_b: Any,
    affected_set: set[str],
    context_a: dict[str, Any],
    context_b: dict[str, Any],
    per_cve_limit: int,
) -> list[dict[str, Any]]:
    probes_a = set(state_a.all_probe_tags)
    probes_b = set(state_b.all_probe_tags)
    categories = [
        ("major_only", probes_a - probes_b, context_a),
        ("current_plus_only", probes_b - probes_a, context_b),
        ("common", probes_a & probes_b, context_b),
    ]
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    # Pick both oracle classes when possible.  This uses GT only for validation
    # sample stratification, never for the agent prompt.
    for category, tags, context in categories:
        for desired in ("AFFECTED", "NOT_AFFECTED"):
            for tag in sorted(tags):
                if tag in seen:
                    continue
                oracle = "AFFECTED" if tag in affected_set else "NOT_AFFECTED"
                if oracle != desired:
                    continue
                selected.append({
                    "cve_id": cve_id,
                    "tag": tag,
                    "category": category,
                    "line": _line_for_tag(context, tag),
                    "oracle_verdict": oracle,
                    "selected_by": [v for v, probes in [(VARIANT_A, probes_a), (VARIANT_B, probes_b)] if tag in probes],
                })
                seen.add(tag)
                break
        if len(selected) >= per_cve_limit:
            break
    # Fill remaining deterministically if class-balanced picks were sparse.
    if len(selected) < per_cve_limit:
        for category, tags, context in categories:
            for tag in sorted(tags):
                if tag in seen:
                    continue
                oracle = "AFFECTED" if tag in affected_set else "NOT_AFFECTED"
                selected.append({
                    "cve_id": cve_id,
                    "tag": tag,
                    "category": category,
                    "line": _line_for_tag(context, tag),
                    "oracle_verdict": oracle,
                    "selected_by": [v for v, probes in [(VARIANT_A, probes_a), (VARIANT_B, probes_b)] if tag in probes],
                })
                seen.add(tag)
                if len(selected) >= per_cve_limit:
                    break
            if len(selected) >= per_cve_limit:
                break
    return selected[:per_cve_limit]


def _build_prompt(*, repo_path: Path, cve_id: str, tag: str, line: str, rec: dict[str, Any], commits: list[str], files: list[str], patch_excerpt: str) -> str:
    return f"""# Task: OpenSSL tag-level vulnerability verdict

Repository path: `{repo_path}`
CVE: `{cve_id}`
Target tag: `{tag}`
Release line: `{line}`
CWE: `{rec.get('CWE')}`
Fix commits: `{commits}`
Fix-touched files (search hints only): `{files[:8]}`

You must judge only this target tag. Do not use GT affected versions, neighboring
tag verdicts, advisory ranges, release dates, or scheduler decisions.

Use read-only git commands with the explicit repository path, for example:

```bash
git -C "{repo_path}" show {tag}:<filepath>
git -C "{repo_path}" grep -n "<symbol-or-token>" {tag}
git -C "{repo_path}" grep -n -C 3 "<symbol-or-token>" {tag}
git -C "{repo_path}" ls-tree -r --name-only {tag}
```

Fix patch excerpt for vulnerability semantics and search hints:

```diff
{patch_excerpt}
```

Return exactly one JSON object:

{{
  "tag": "{tag}",
  "line": "{line}",
  "verdict": "AFFECTED | NOT_AFFECTED",
  "run_status": "OK",
  "confidence": 0.0,
  "matched_predicates": [],
  "failed_predicates": [],
  "triggered_guards": [],
  "evidence_snippets": [{{"ref": "{tag}:<file>:<line>", "source": "git_show|git_grep", "snippet": "<actual code>"}}],
  "reasoning_summary": "Brief code-grounded explanation"
}}
"""


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    completed = [r for r in rows if r.get("agent_verdict") in {"AFFECTED", "NOT_AFFECTED"}]
    correct = [r for r in completed if r.get("agent_verdict") == r.get("oracle_verdict")]
    latencies = [float(r.get("latency_s") or 0.0) for r in completed]
    by_category: dict[str, dict[str, Any]] = {}
    for row in rows:
        cat = str(row.get("category"))
        d = by_category.setdefault(cat, {"total": 0, "completed": 0, "correct": 0})
        d["total"] += 1
        if row.get("agent_verdict") in {"AFFECTED", "NOT_AFFECTED"}:
            d["completed"] += 1
            if row.get("agent_verdict") == row.get("oracle_verdict"):
                d["correct"] += 1
    return {
        "total_rows": len(rows),
        "completed": len(completed),
        "correct": len(correct),
        "accuracy_completed": round(len(correct) / len(completed), 6) if completed else 0.0,
        "errors": len(rows) - len(completed),
        "avg_latency_s": round(statistics.mean(latencies), 2) if latencies else 0.0,
        "p50_latency_s": round(statistics.median(latencies), 2) if latencies else 0.0,
        "max_latency_s": round(max(latencies), 2) if latencies else 0.0,
        "by_category": by_category,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run small-sample real OpenCode agent validation for OpenSSL line candidates.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--cves", default=",".join(DEFAULT_CVES))
    parser.add_argument("--per-cve-limit", type=int, default=4)
    parser.add_argument("--max-probes-total", type=int, default=8)
    parser.add_argument("--tag-timeout-s", type=float, default=240.0)
    parser.add_argument("--model", default=None)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)

    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    verdict_path = out_dir / "real_agent_verdicts.jsonl"
    selected_path = out_dir / "selected_probes.json"
    summary_path = out_dir / "summary.json"

    dataset = json.loads(args.dataset.read_text(encoding="utf-8"))
    cve_ids = [x.strip() for x in args.cves.split(",") if x.strip()]
    records = {cve: dataset[cve] for cve in cve_ids if cve in dataset and dataset[cve].get("repo") == REPO}
    repo_path = args.repo_root / REPO
    repo = GitRepo.open(repo_path)

    variants = {variant.name: variant for variant in openssl_variants._variant_defs()}
    contexts = {
        name: openssl_variants._build_variant_context(repo, variants[name])
        for name in (VARIANT_A, VARIANT_B)
    }
    all_release_tags = contexts[VARIANT_B]["release_tags"]

    changed_cache: dict[str, list[str]] = {}
    commits_all: set[str] = set()
    changed_files: dict[str, list[str]] = {}
    endpoint_queries: set[tuple[str, str]] = set()
    for cve, rec in records.items():
        commits = _flatten_commits(rec)
        commits_all.update(commits)
        files = module_sim._changed_files_for_commits(repo, commits, changed_cache)
        changed_files[cve] = files
        for context in contexts.values():
            for tags in context["release_lines"].values():
                for tag in low_cost._sample_tags_for_line(tags):
                    for path in files[:3]:
                        endpoint_queries.add((tag, path))
    commit_contains = batch_tags_containing(repo=repo, release_tags=all_release_tags, target_commits=commits_all)
    path_exists = module_sim._batch_path_exists(repo, endpoint_queries)

    selected: list[dict[str, Any]] = []
    planning_rows: list[dict[str, Any]] = []
    for cve, rec in records.items():
        commits = _flatten_commits(rec)
        fix_containing_tags: set[str] = set()
        for commit in commits:
            result = commit_contains.get(commit, {"ok": False, "tags": []})
            if result.get("ok"):
                fix_containing_tags.update(result.get("tags", []))
        states: dict[str, Any] = {}
        affected_set: set[str] | None = None
        for name, context in contexts.items():
            file_lines: set[str] = set()
            for line, tags in context["release_lines"].items():
                for tag in low_cost._sample_tags_for_line(tags):
                    if any(path_exists.get((tag, path), False) for path in changed_files.get(cve, [])[:3]):
                        file_lines.add(line)
                        break
            state, aff, _release = _planned_state(
                cve_id=cve,
                rec=rec,
                context=context,
                fix_containing_tags=fix_containing_tags,
                file_endpoint_lines=file_lines,
            )
            states[name] = state
            affected_set = aff
            planning_rows.append({
                "cve_id": cve,
                "variant": name,
                "planned_probe_count": len(state.all_probe_tags),
                "planned_predicted_count": len(state.predicted_affected),
                "visited_line_count": len(state.visited),
            })
        assert affected_set is not None
        selected.extend(_select_probe_rows(
            cve_id=cve,
            state_a=states[VARIANT_A],
            state_b=states[VARIANT_B],
            affected_set=affected_set,
            context_a=contexts[VARIANT_A],
            context_b=contexts[VARIANT_B],
            per_cve_limit=max(0, args.per_cve_limit),
        ))
    selected = selected[: max(0, args.max_probes_total)]
    _write_json(selected_path, {
        "metadata": {
            "dataset": str(args.dataset),
            "repo": REPO,
            "variants": [VARIANT_A, VARIANT_B],
            "selection_note": "GT is used only for validation sample stratification and oracle evaluation. GT is not sent to the agent.",
            "tag_timeout_s": args.tag_timeout_s,
        },
        "planning": planning_rows,
        "selected_probes": selected,
    })

    existing = {(r.get("cve_id"), r.get("tag")): r for r in _read_jsonl(verdict_path)} if args.resume else {}
    cfg = Config()
    if args.model:
        cfg.model_profile = args.model
    provider_id, model_id, profile_timeout = resolve_model_config(cfg)
    if provider_id:
        cfg.opencode_provider_id = provider_id
    if model_id:
        cfg.opencode_model_id = model_id
    timeout_s = float(args.tag_timeout_s or profile_timeout)
    agent = OpenCodeRuntime.from_config(cfg, timeout_s=timeout_s, health_check=True, project_root=ROOT)

    for item in selected:
        key = (item["cve_id"], item["tag"])
        if key in existing:
            continue
        rec = records[item["cve_id"]]
        commits = _flatten_commits(rec)
        prompt = _build_prompt(
            repo_path=repo_path.resolve(),
            cve_id=item["cve_id"],
            tag=item["tag"],
            line=item["line"],
            rec=rec,
            commits=commits,
            files=changed_files.get(item["cve_id"], []),
            patch_excerpt=_patch_excerpt(repo, commits),
        )
        row = dict(item)
        row.update({
            "provider_id": cfg.opencode_provider_id,
            "model_id": cfg.opencode_model_id,
        })
        start = time.monotonic()
        try:
            session_id = agent.create_readonly_session(title=f"vv-openssl-real-{item['cve_id']}-{item['tag']}")
            raw = agent.run_json(
                session_id=session_id,
                prompt=prompt,
                system=(
                    "You are a read-only security researcher. Return one JSON object only. "
                    "The verdict must be exactly AFFECTED or NOT_AFFECTED."
                ),
                timeout_s=timeout_s,
            )
            verdict = str(raw.get("verdict") or "").strip().upper()
            if verdict not in {"AFFECTED", "NOT_AFFECTED"}:
                verdict = None  # type: ignore[assignment]
            row.update({
                "agent_verdict": verdict,
                "run_status": str(raw.get("run_status") or ("OK" if verdict else "PARSE_ERROR")),
                "confidence": raw.get("confidence"),
                "correct": verdict == item["oracle_verdict"],
                "latency_s": round(time.monotonic() - start, 2),
                "raw": raw,
            })
        except Exception as exc:
            row.update({
                "agent_verdict": None,
                "run_status": "AGENT_ERROR",
                "correct": False,
                "latency_s": round(time.monotonic() - start, 2),
                "error": f"{type(exc).__name__}: {exc}",
            })
        _append_jsonl(verdict_path, row)
        # Keep a current summary on disk after every probe.
        rows_now = _read_jsonl(verdict_path)
        _write_json(summary_path, {
            "metadata": {
                "dataset": str(args.dataset),
                "repo": REPO,
                "variants": [VARIANT_A, VARIANT_B],
                "cves": list(records),
                "selected_probe_count": len(selected),
                "completed_rows": len(rows_now),
                "tag_timeout_s": timeout_s,
                "provider_id": cfg.opencode_provider_id,
                "model_id": cfg.opencode_model_id,
                "gt_note": "GT is used only for sample selection and final evaluation, not in prompts.",
            },
            "summary": _summarize(rows_now),
        })
        print(json.dumps(row, ensure_ascii=False), flush=True)

    rows = _read_jsonl(verdict_path)
    final = {
        "metadata": {
            "dataset": str(args.dataset),
            "repo": REPO,
            "variants": [VARIANT_A, VARIANT_B],
            "cves": list(records),
            "selected_probe_count": len(selected),
            "completed_rows": len(rows),
            "tag_timeout_s": timeout_s,
            "provider_id": cfg.opencode_provider_id,
            "model_id": cfg.opencode_model_id,
            "gt_note": "GT is used only for sample selection and final evaluation, not in prompts.",
        },
        "summary": _summarize(rows),
    }
    _write_json(summary_path, final)
    print(json.dumps(final, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
