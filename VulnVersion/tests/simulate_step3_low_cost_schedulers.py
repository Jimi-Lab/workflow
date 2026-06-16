"""Low-cost Step3 scheduler simulator.

This script evaluates candidate tag-plan schedulers on the official
BaseDataOrder.json dataset without changing the production verifier path.

Important boundaries:
  - GT affected_version is used only as an oracle for simulated probe verdicts.
  - Planning inputs are release tags, version_registry/VulnTree line parsing,
    fix reachability, changed-file existence, and cheap patch-derived tokens.
  - No BAPEE, no line-local FIC recovery, no hard deletion by fix reachability.

Output directory:
  tests/step3_low_cost_scheduler_simulator/
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = ROOT / "tests"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

import simulate_module_backed_step3 as module_sim

from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.asbs_line import (
    AA_SENTINEL_COUNT,
    FIXED_SEG_SENTINEL,
    NN_SENTINEL_COUNT,
)
from vulnversion.stage3_verify.git_reachability import batch_tags_containing
from vulnversion.stage3_verify.line_scheduler import (
    LineRunResult,
    _no_fix_lines,
    _ordered_by_family,
    _static_neighbors,
    _stride_lines,
    compute_seed_lines,
    run_staged_scheduler,
)


DEFAULT_DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
DEFAULT_REPO_ROOT = ROOT / "repo"
DEFAULT_OUT_DIR = ROOT / "tests" / "step3_low_cost_scheduler_simulator"


STOPWORDS = {
    "auto", "bool", "break", "case", "char", "const", "continue", "default",
    "define", "double", "else", "enum", "extern", "false", "float", "for",
    "goto", "ifdef", "ifndef", "include", "inline", "int", "long", "null",
    "NULL", "return", "short", "signed", "sizeof", "static", "struct",
    "switch", "true", "typedef", "uint", "unsigned", "void", "while",
    "this", "that", "with", "from", "into", "then", "have", "will",
}


@dataclass
class PatchProfile:
    """Cheap, deterministic profile extracted from fix commits."""

    files: list[str]
    added_tokens: list[str]
    deleted_tokens: list[str]
    critical_tokens: list[str]
    hunk_functions: list[str]
    message_tokens: list[str]


def _flatten_fixing_commits(value: Any) -> list[str]:
    return module_sim._flatten_fixing_commits(value)


def _git_base_cmd(repo_path: Path) -> list[str]:
    repo_str = str(repo_path.resolve())
    return ["git", "-c", f"safe.directory={repo_str}", "-C", repo_str]


def _rank_tokens(tokens: list[str], *, limit: int) -> list[str]:
    counts = Counter(t for t in tokens if len(t) >= 4 and t not in STOPWORDS)
    ranked = sorted(counts, key=lambda t: (-counts[t], -len(t), t))
    return ranked[:limit]


def _tokens_from_text(text: str) -> list[str]:
    return re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", text or "")


def _extract_patch_profile(
    repo: GitRepo,
    commits: list[str],
    changed_files: list[str],
    *,
    max_files: int = 3,
    max_tokens: int = 10,
) -> PatchProfile:
    """Extract short greppable evidence from fix diffs and messages.

    This is intentionally conservative and deterministic. It is not a verdict;
    it only supplies scheduler risk signals.
    """
    added: list[str] = []
    deleted: list[str] = []
    hunk_functions: list[str] = []
    message_tokens: list[str] = []
    for commit in commits:
        try:
            patch = repo.show_patch(commit)
        except Exception:
            patch = ""
        for raw in patch.splitlines():
            line = raw.rstrip("\n")
            if line.startswith("@@"):
                parts = line.split("@@", 2)
                if len(parts) >= 3:
                    suffix = parts[-1].strip()
                    hunk_functions.extend(_tokens_from_text(suffix))
                continue
            if line.startswith("+++") or line.startswith("---"):
                continue
            if line.startswith("+"):
                added.extend(_tokens_from_text(line[1:]))
            elif line.startswith("-"):
                deleted.extend(_tokens_from_text(line[1:]))
        try:
            message = repo.commit_message(commit)
        except Exception:
            message = ""
        message_tokens.extend(_tokens_from_text(message))

    added_tokens = _rank_tokens(added, limit=max_tokens)
    deleted_tokens = _rank_tokens(deleted, limit=max_tokens)
    functions = _rank_tokens(hunk_functions, limit=max_tokens)
    msg_tokens = _rank_tokens(message_tokens, limit=max_tokens)
    critical = _rank_tokens(deleted_tokens + added_tokens + functions + msg_tokens, limit=max_tokens)
    return PatchProfile(
        files=list(dict.fromkeys(changed_files[:max_files])),
        added_tokens=added_tokens,
        deleted_tokens=deleted_tokens,
        critical_tokens=critical,
        hunk_functions=functions,
        message_tokens=msg_tokens,
    )


def _batch_file_text(
    repo: GitRepo,
    queries: set[tuple[str, str]],
    *,
    max_blob_bytes: int = 750_000,
) -> dict[tuple[str, str], str | None]:
    """Read many tag:path blobs with one git cat-file --batch process."""
    if not queries:
        return {}
    ordered = sorted(queries)
    payload = "".join(f"{tag}:{path}\n" for tag, path in ordered).encode("utf-8", "replace")
    proc = subprocess.Popen(
        [*_git_base_cmd(repo.repo_path), "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, _ = proc.communicate(payload)
    out: dict[tuple[str, str], str | None] = {}
    pos = 0
    for query in ordered:
        if pos >= len(stdout):
            out[query] = None
            continue
        nl = stdout.find(b"\n", pos)
        if nl < 0:
            out[query] = None
            break
        header = stdout[pos:nl].decode("utf-8", "replace")
        pos = nl + 1
        parts = header.split()
        if len(parts) >= 2 and parts[-1] == "missing":
            out[query] = None
            continue
        if len(parts) < 3:
            out[query] = None
            continue
        obj_type = parts[1]
        try:
            size = int(parts[2])
        except ValueError:
            out[query] = None
            continue
        content = stdout[pos:pos + size]
        pos += size
        if pos < len(stdout) and stdout[pos:pos + 1] == b"\n":
            pos += 1
        if obj_type != "blob":
            out[query] = None
            continue
        if len(content) > max_blob_bytes:
            content = content[:max_blob_bytes]
        out[query] = content.decode("utf-8", "ignore")
    for query in ordered:
        out.setdefault(query, None)
    return out


def _sample_tags_for_line(tags: list[str]) -> list[str]:
    """Cheap semantic sample positions for one release line."""
    if not tags:
        return []
    idxs = {0, len(tags) - 1}
    if len(tags) >= 3:
        idxs.add((len(tags) - 1) // 2)
    return [tags[i] for i in sorted(idxs)]


def _line_has_text_hit(
    *,
    tags: list[str],
    files: list[str],
    tokens: list[str],
    text_cache: dict[tuple[str, str], str | None],
) -> bool:
    if not tags or not files or not tokens:
        return False
    lowered_tokens = [t.lower() for t in tokens if t]
    for tag in _sample_tags_for_line(tags):
        for path in files:
            text = text_cache.get((tag, path))
            if not text:
                continue
            lowered = text.lower()
            if any(tok in lowered for tok in lowered_tokens):
                return True
    return False


def _token_evidence_lines(
    *,
    release_lines: dict[str, list[str]],
    profile: PatchProfile,
    text_cache: dict[tuple[str, str], str | None],
) -> dict[str, set[str]]:
    """Compute line-level cheap semantic evidence from sampled snapshots."""
    critical: set[str] = set()
    fix_guard: set[str] = set()
    vuln_pattern: set[str] = set()
    function_hint: set[str] = set()
    for line, tags in release_lines.items():
        if _line_has_text_hit(tags=tags, files=profile.files, tokens=profile.critical_tokens, text_cache=text_cache):
            critical.add(line)
        if _line_has_text_hit(tags=tags, files=profile.files, tokens=profile.added_tokens, text_cache=text_cache):
            fix_guard.add(line)
        if _line_has_text_hit(tags=tags, files=profile.files, tokens=profile.deleted_tokens, text_cache=text_cache):
            vuln_pattern.add(line)
        if _line_has_text_hit(tags=tags, files=profile.files, tokens=profile.hunk_functions, text_cache=text_cache):
            function_hint.add(line)
    return {
        "critical_token_lines": critical,
        "fix_guard_lines": fix_guard,
        "vuln_pattern_lines": vuln_pattern,
        "function_hint_lines": function_hint,
    }


def _fix_transition_lines(
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    fix_containing_tags: set[str],
) -> set[str]:
    """Lines near a fix-containing/no-fix transition.

    This approximates TDSC-style boundary-first scheduling without using GT.
    """
    line_has_fix = {
        line: any(tag in fix_containing_tags for tag in tags)
        for line, tags in release_lines.items()
    }
    mixed = {
        line
        for line, tags in release_lines.items()
        if any(tag in fix_containing_tags for tag in tags)
        and any(tag not in fix_containing_tags for tag in tags)
    }
    out = set(mixed)
    for _, lines in ordered_by_family.items():
        for idx, line in enumerate(lines):
            if idx + 1 >= len(lines):
                continue
            nxt = lines[idx + 1]
            if line_has_fix.get(line, False) != line_has_fix.get(nxt, False):
                out.add(line)
                out.add(nxt)
    return out


def _family_edge_lines(ordered_by_family: dict[str, list[str]]) -> set[str]:
    out: set[str] = set()
    for _, lines in ordered_by_family.items():
        if not lines:
            continue
        out.add(lines[0])
        out.add(lines[-1])
    return out


def _expand_static(
    ordered_by_family: dict[str, list[str]],
    seeds: set[str],
    radius: int,
) -> set[str]:
    out: set[str] = set()
    for _, lines in ordered_by_family.items():
        out.update(_static_neighbors(lines, set(lines) & seeds, radius))
    return out


def _strategy_seed_lines(
    *,
    strategy: str,
    repo_name: str,
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    fix_containing_tags: set[str],
    file_endpoint_lines: set[str],
    semantic_lines: dict[str, set[str]],
) -> tuple[set[str], str, dict[str, Any]]:
    """Return seed lines, fallback mode, and evidence summary for a strategy."""
    no_fix = _no_fix_lines(release_lines, fix_containing_tags)
    transition = _fix_transition_lines(release_lines, ordered_by_family, fix_containing_tags)
    token_union = set().union(*semantic_lines.values()) if semantic_lines else set()
    evidence: dict[str, Any] = {
        "no_fix_line_count": len(no_fix),
        "file_endpoint_line_count": len(file_endpoint_lines),
        "fix_transition_line_count": len(transition),
        "token_union_line_count": len(token_union),
        **{f"{k}_count": len(v) for k, v in semantic_lines.items()},
    }

    if strategy == "current_staged_nofix_stride3_file":
        seeds = compute_seed_lines(
            repo_name=repo_name,
            release_lines=release_lines,
            ordered_by_family=ordered_by_family,
            fix_containing_tags=fix_containing_tags,
            file_endpoint_lines=file_endpoint_lines,
            stride=3,
            file_neighbor_radius=1,
        )
        return seeds, "none", {**evidence, "seed_rule": "file_neighbor1 + no_fix_stride3"}

    if strategy == "patch_semantics_cheap":
        semantic_seed = _expand_static(
            ordered_by_family,
            file_endpoint_lines | token_union | semantic_lines.get("vuln_pattern_lines", set()),
            1,
        )
        seeds = semantic_seed | _stride_lines(ordered_by_family, 5, lines_subset=no_fix)
        return seeds, "nohit_nofix", {**evidence, "seed_rule": "semantic/file_neighbor1 + no_fix_stride5"}

    if strategy == "tdsc_boundary_first":
        boundary_seed = _expand_static(ordered_by_family, transition | _family_edge_lines(ordered_by_family), 1)
        seeds = boundary_seed | _stride_lines(ordered_by_family, 6, lines_subset=no_fix)
        return seeds, "nohit_nofix", {**evidence, "seed_rule": "fix_transition_boundary + family_edges + no_fix_stride6"}

    if strategy == "agentszz_greppable":
        grep_seed = _expand_static(
            ordered_by_family,
            token_union | semantic_lines.get("function_hint_lines", set()),
            1,
        )
        if not grep_seed:
            grep_seed = _expand_static(ordered_by_family, file_endpoint_lines, 1)
        seeds = grep_seed | _stride_lines(ordered_by_family, 5, lines_subset=no_fix)
        return seeds, "nohit_nofix", {**evidence, "seed_rule": "greppable_token_neighbor1 + no_fix_stride5"}

    if strategy == "hybrid_low_cost":
        hybrid_seed = _expand_static(
            ordered_by_family,
            token_union | transition | file_endpoint_lines,
            1,
        )
        seeds = hybrid_seed | _stride_lines(ordered_by_family, 4, lines_subset=no_fix)
        return seeds, "nohit_nofix", {**evidence, "seed_rule": "token_or_transition_or_file_neighbor1 + no_fix_stride4"}

    raise ValueError(f"unsupported strategy: {strategy}")


def _simulate_cve(
    *,
    cve_id: str,
    repo_name: str,
    affected_versions: list[str],
    release_lines: dict[str, list[str]],
    ordered_by_family: dict[str, list[str]],
    release_tags: list[str],
    fix_containing_tags: set[str],
    file_endpoint_lines: set[str],
    semantic_lines: dict[str, set[str]],
    strategy: str,
    nn_sentinel_count: int,
    aa_sentinel_count: int,
    fixed_segment_sentinel: int,
    expansion_radius: int,
) -> dict[str, Any]:
    mapped_gt, unmapped_gt = map_gt_tags_to_repo_tags(
        sorted(str(t) for t in affected_versions),
        release_tags,
        mode="loose",
    )
    affected_set = set(mapped_gt)
    affected_lines = {
        line for line, tags in release_lines.items()
        if any(tag in affected_set for tag in tags)
    }
    seed_lines, fallback_mode, evidence = _strategy_seed_lines(
        strategy=strategy,
        repo_name=repo_name,
        release_lines=release_lines,
        ordered_by_family=ordered_by_family,
        fix_containing_tags=fix_containing_tags,
        file_endpoint_lines=file_endpoint_lines,
        semantic_lines=semantic_lines,
    )

    def run_line(line: str, tags: list[str]) -> LineRunResult:
        return module_sim._run_git_guided_line_module(
            line=line,
            tags=tags,
            affected_set=affected_set,
            fix_containing_tags=fix_containing_tags,
            nn_sentinel_count=nn_sentinel_count,
            aa_sentinel_count=aa_sentinel_count,
            fixed_segment_sentinel=fixed_segment_sentinel,
        )

    state = run_staged_scheduler(
        seed_lines=seed_lines,
        release_lines=release_lines,
        ordered_by_family=ordered_by_family,
        fix_containing_tags=fix_containing_tags,
        run_line_fn=run_line,
        expansion_radius=expansion_radius,
        fallback_mode=fallback_mode,
    )
    predicted_set = set(state.predicted_affected)
    probe_tags = set(state.all_probe_tags)
    visited = set(state.visited)
    release_set = set(release_tags)
    tp = len(predicted_set & affected_set)
    fp = len(predicted_set - affected_set)
    fn = len(affected_set - predicted_set)
    tn = len(release_set - predicted_set - affected_set)
    precision = tp / (tp + fp) if (tp + fp) else (1.0 if not affected_set else 0.0)
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    skipped_affected_lines = affected_lines - visited
    return {
        "cve_id": cve_id,
        "repo": repo_name,
        "strategy": strategy,
        "release_tag_count": len(release_tags),
        "line_count": len(release_lines),
        "seed_line_count": len(seed_lines),
        "active_line_count": len(visited),
        "positive_line_count": len(state.positive_lines),
        "affected_line_count": len(affected_lines),
        "skipped_affected_line_count": len(skipped_affected_lines),
        "skipped_affected_lines": sorted(skipped_affected_lines),
        "fix_containing_tag_count": len(fix_containing_tags),
        "mapped_gt_count": len(mapped_gt),
        "unmapped_gt_count": len(unmapped_gt),
        "probe_count": len(probe_tags),
        "predicted_count": len(predicted_set),
        "fallback_mode": fallback_mode,
        "fallback_used": fallback_mode != "none" and not seed_lines <= visited,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "exact_match": fp == 0 and fn == 0 and len(unmapped_gt) == 0,
        "full_mapped_recall": fn == 0,
        "has_fp": fp > 0,
        "has_fn": fn > 0,
        "status_counts": dict(state.status_counts),
        "evidence": evidence,
    }


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    idx = round((len(sorted_values) - 1) * pct)
    return float(sorted_values[idx])


def _summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {}
    probes = [float(r["probe_count"]) for r in rows]
    active_lines = [float(r["active_line_count"]) for r in rows]
    seeds = [float(r["seed_line_count"]) for r in rows]
    skipped = [float(r["skipped_affected_line_count"]) for r in rows]
    tp = sum(int(r["tp"]) for r in rows)
    fp = sum(int(r["fp"]) for r in rows)
    fn = sum(int(r["fn"]) for r in rows)
    tn = sum(int(r["tn"]) for r in rows)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "cves": len(rows),
        "avg_probes": round(statistics.mean(probes), 2),
        "p50_probes": round(statistics.median(probes), 2),
        "p95_probes": round(_percentile(probes, 0.95), 2),
        "max_probes": int(max(probes)),
        "avg_seed_lines": round(statistics.mean(seeds), 2),
        "avg_active_lines": round(statistics.mean(active_lines), 2),
        "avg_skipped_affected_lines": round(statistics.mean(skipped), 4),
        "exact_cves": sum(1 for r in rows if r["exact_match"]),
        "fn_cves": sum(1 for r in rows if r["has_fn"]),
        "fp_cves": sum(1 for r in rows if r["has_fp"]),
        "skipped_affected_line_cves": sum(1 for r in rows if r["skipped_affected_line_count"] > 0),
        "unmapped_cves": sum(1 for r in rows if r["unmapped_gt_count"] > 0),
        "version_tp": tp,
        "version_fp": fp,
        "version_fn": fn,
        "version_tn": tn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
    }


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_strategy: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_strategy[row["strategy"]].append(row)
    overall = {k: _summarize_rows(v) for k, v in sorted(by_strategy.items())}
    by_repo: dict[str, dict[str, Any]] = {}
    for strategy, vals in sorted(by_strategy.items()):
        repo_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in vals:
            repo_groups[row["repo"]].append(row)
        by_repo[strategy] = {repo: _summarize_rows(repo_rows) for repo, repo_rows in sorted(repo_groups.items())}
    return {"overall": overall, "by_repo": by_repo}


def _write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as fp:
        for row in rows:
            fp.write(json.dumps(row, ensure_ascii=False) + "\n")


def _write_report(path: Path, summary: dict[str, Any], evidence_table: list[dict[str, str]]) -> None:
    lines: list[str] = [
        "# Step3 Low-Cost Scheduler Simulator Report",
        "",
        "Dataset: `DataSet/BaseDataOrder.json`.",
        "",
        "This is a GT-oracle simulator. GT is used only to emulate selected probe verdicts and compute metrics.",
        "",
        "## Evidence Table",
        "",
        "| Method | Transferable idea | Probe-reduction help | Risk | Validation needed |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in evidence_table:
        lines.append(
            f"| {row['method']} | {row['idea']} | {row['help']} | {row['risk']} | {row['validation']} |"
        )
    lines.extend([
        "",
        "## Strategy Summary",
        "",
        "| Strategy | avg probes | p50 | p95 | exact CVEs | FN CVEs | FP CVEs | Precision | Recall | F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ])
    for strategy, metrics in summary["overall"].items():
        lines.append(
            "| {s} | {avg:.2f} | {p50:.2f} | {p95:.2f} | {exact}/1128 | {fn} | {fp} | {p:.6f} | {r:.6f} | {f:.6f} |".format(
                s=strategy,
                avg=metrics["avg_probes"],
                p50=metrics["p50_probes"],
                p95=metrics["p95_probes"],
                exact=metrics["exact_cves"],
                fn=metrics["fn_cves"],
                fp=metrics["fp_cves"],
                p=metrics["precision"],
                r=metrics["recall"],
                f=metrics["f1"],
            )
        )
    lines.extend([
        "",
        "## Interpretation",
        "",
        "- A strategy is not eligible for the production path unless its FN/FP case dump is acceptable.",
        "- Lower avg probes alone is not sufficient; skipped affected lines are treated as first-class failures.",
        "- `current_staged_nofix_stride3_file` remains the control strategy.",
        "",
    ])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _evidence_table() -> list[dict[str, str]]:
    return [
        {
            "method": "How-far-are-we tracing-based / V-SZZ",
            "idea": "Git reachability, duplicate patch, temporal boundary",
            "help": "Use fix-containing tags as fixed-side evidence and segment boundaries",
            "risk": "Hard fix filtering misses affected tags; VIC recovery is unstable",
            "validation": "Already validated as soft evidence only; retested here in current baseline",
        },
        {
            "method": "How-far-are-we matching-based",
            "idea": "Tag snapshot vulnerability existence matching",
            "help": "Keep agent verdict only on selected probes instead of all tags",
            "risk": "Full matching scan is too expensive; exact signatures are brittle",
            "validation": "Simulate selected probes, not full scan",
        },
        {
            "method": "TDSC",
            "idea": "Version tree and boundary-first search",
            "help": "Prioritize family/line boundary and fix-transition lines",
            "risk": "Patch presence is not sufficient, so boundary evidence cannot hard skip",
            "validation": "Strategy C in this simulator",
        },
        {
            "method": "AgentSZZ / SZZ-Agent",
            "idea": "git grep, git log -S/-G, file/function history, scoped tools",
            "help": "Patch-derived greppable tokens rank active lines before agent",
            "risk": "Tokens can be generic, renamed, or absent in old tags",
            "validation": "Strategy D in this simulator",
        },
        {
            "method": "VicDiff / differential patching patterns",
            "idea": "Critical statement sequence instead of raw patch lines",
            "help": "Patch-semantic tokens and hunk functions become cheap risk signals",
            "risk": "Statement-level criticality is approximate without full semantic engine",
            "validation": "Strategy B in this simulator",
        },
        {
            "method": "CaVulner",
            "idea": "tags_containing(VIC cluster) - tags_containing(fix cluster)",
            "help": "Batch reachability and duplicate evidence inspire segmentation",
            "risk": "VulnVersion cannot assume reliable VIC seed on 1128 CVE",
            "validation": "Do not use VIC as planning input in this simulator",
        },
        {
            "method": "Beyond Blame",
            "idea": "Knowledge-graph candidate ranking over commit/file/function nodes",
            "help": "Use line/family graph plus evidence edges for staged expansion",
            "risk": "Graph priors can skip isolated affected lines if made hard",
            "validation": "Hybrid strategy and skipped-line dump",
        },
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Simulate low-cost Step3 schedulers on BaseDataOrder.json.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument(
        "--strategies",
        default=(
            "current_staged_nofix_stride3_file,"
            "patch_semantics_cheap,"
            "tdsc_boundary_first,"
            "agentszz_greppable,"
            "hybrid_low_cost"
        ),
    )
    parser.add_argument("--nn-sentinel-count", type=int, default=NN_SENTINEL_COUNT)
    parser.add_argument("--aa-sentinel-count", type=int, default=AA_SENTINEL_COUNT)
    parser.add_argument("--fixed-segment-sentinel", type=int, default=FIXED_SEG_SENTINEL)
    parser.add_argument("--expansion-radius", type=int, default=1)
    parser.add_argument("--limit-cves", type=int, default=0, help="Debug only: limit CVEs after sorting.")
    args = parser.parse_args(argv)

    dataset = module_sim._load_dataset(args.dataset)
    strategies = [s.strip() for s in args.strategies.split(",") if s.strip()]
    by_repo: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for cve_id, rec in sorted(dataset.items()):
        repo_name = str(rec.get("repo") or "").strip()
        if repo_name:
            by_repo[repo_name].append((cve_id, rec))
    if args.limit_cves > 0:
        remaining = args.limit_cves
        trimmed: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        for repo_name, records in sorted(by_repo.items()):
            take = min(remaining, len(records))
            if take:
                trimmed[repo_name] = records[:take]
                remaining -= take
            if remaining <= 0:
                break
        by_repo = defaultdict(list, trimmed)

    contexts: dict[str, dict[str, Any]] = {}
    commit_contains_by_repo: dict[str, dict[str, dict[str, Any]]] = {}
    changed_files_by_cve: dict[str, list[str]] = {}
    profile_by_cve: dict[str, PatchProfile] = {}
    endpoint_queries_by_repo: dict[str, set[tuple[str, str]]] = defaultdict(set)
    text_queries_by_repo: dict[str, set[tuple[str, str]]] = defaultdict(set)

    for repo_name, records in sorted(by_repo.items()):
        context = module_sim._release_context(repo_name, args.repo_root / repo_name)
        contexts[repo_name] = context
        repo: GitRepo = context["repo"]
        target_commits: set[str] = set()
        changed_cache: dict[str, list[str]] = {}
        endpoint_tags = {
            tag
            for tags in context["release_lines"].values()
            for tag in _sample_tags_for_line(tags)
        }
        for cve_id, rec in records:
            commits = _flatten_fixing_commits(rec.get("fixing_commits") or rec.get("fixing_commit"))
            target_commits.update(commits)
            files = module_sim._changed_files_for_commits(repo, commits, changed_cache)
            changed_files_by_cve[cve_id] = files
            profile = _extract_patch_profile(repo, commits, files)
            profile_by_cve[cve_id] = profile
            for tag in endpoint_tags:
                for path in profile.files:
                    endpoint_queries_by_repo[repo_name].add((tag, path))
                    text_queries_by_repo[repo_name].add((tag, path))
        commit_contains_by_repo[repo_name] = batch_tags_containing(
            repo=repo,
            release_tags=context["release_tags"],
            target_commits=target_commits,
        )

    path_exists_by_repo: dict[str, dict[tuple[str, str], bool]] = {}
    text_by_repo: dict[str, dict[tuple[str, str], str | None]] = {}
    for repo_name in sorted(by_repo):
        path_exists_by_repo[repo_name] = module_sim._batch_path_exists(
            contexts[repo_name]["repo"],
            endpoint_queries_by_repo.get(repo_name, set()),
        )
        existing_text_queries = {
            q for q in text_queries_by_repo.get(repo_name, set())
            if path_exists_by_repo[repo_name].get(q, False)
        }
        text_by_repo[repo_name] = _batch_file_text(contexts[repo_name]["repo"], existing_text_queries)

    rows: list[dict[str, Any]] = []
    for repo_name, records in sorted(by_repo.items()):
        context = contexts[repo_name]
        release_lines: dict[str, list[str]] = context["release_lines"]
        for cve_id, rec in records:
            commits = _flatten_fixing_commits(rec.get("fixing_commits") or rec.get("fixing_commit"))
            fix_containing_tags: set[str] = set()
            for commit in commits:
                result = commit_contains_by_repo[repo_name].get(commit, {"ok": False, "tags": []})
                if result.get("ok"):
                    fix_containing_tags.update(result.get("tags", []))

            profile = profile_by_cve[cve_id]
            path_exists = path_exists_by_repo.get(repo_name, {})
            file_endpoint_lines: set[str] = set()
            for line, tags in release_lines.items():
                for tag in _sample_tags_for_line(tags):
                    if any(path_exists.get((tag, path), False) for path in profile.files):
                        file_endpoint_lines.add(line)
                        break
            semantic_lines = _token_evidence_lines(
                release_lines=release_lines,
                profile=profile,
                text_cache=text_by_repo.get(repo_name, {}),
            )
            for strategy in strategies:
                rows.append(_simulate_cve(
                    cve_id=cve_id,
                    repo_name=repo_name,
                    affected_versions=list(rec.get("affected_version") or []),
                    release_lines=release_lines,
                    ordered_by_family=context["ordered_by_family"],
                    release_tags=context["release_tags"],
                    fix_containing_tags=fix_containing_tags,
                    file_endpoint_lines=file_endpoint_lines,
                    semantic_lines=semantic_lines,
                    strategy=strategy,
                    nn_sentinel_count=args.nn_sentinel_count,
                    aa_sentinel_count=args.aa_sentinel_count,
                    fixed_segment_sentinel=args.fixed_segment_sentinel,
                    expansion_radius=args.expansion_radius,
                ))

    args.out_dir.mkdir(parents=True, exist_ok=True)
    summary = _summarize(rows)
    metadata = {
        "dataset": str(args.dataset),
        "repo_root": str(args.repo_root),
        "strategies": strategies,
        "nn_sentinel_count": args.nn_sentinel_count,
        "aa_sentinel_count": args.aa_sentinel_count,
        "fixed_segment_sentinel": args.fixed_segment_sentinel,
        "expansion_radius": args.expansion_radius,
        "total_cves": sum(len(v) for v in by_repo.values()),
        "total_rows": len(rows),
        "oracle_note": "GT oracle is used only to emulate selected probe verdicts and compute final metrics.",
    }
    fn_cases = [
        row for row in rows
        if row["has_fn"] or row["skipped_affected_line_count"] > 0
    ]
    fn_cases = sorted(fn_cases, key=lambda r: (-int(r["fn"]), -int(r["skipped_affected_line_count"]), r["strategy"], r["repo"], r["cve_id"]))

    _write_json(args.out_dir / "summary.json", {"metadata": metadata, **summary})
    _write_json(args.out_dir / "per_strategy.json", summary)
    _write_jsonl(args.out_dir / "per_cve.jsonl", rows)
    _write_json(args.out_dir / "fn_cases.json", fn_cases)
    _write_report(args.out_dir / "report.md", summary, _evidence_table())
    print(json.dumps({"metadata": metadata, "overall": summary["overall"]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
