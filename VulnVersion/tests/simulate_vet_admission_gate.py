from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vulnversion.git_ops.repo import map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.version_registry import filter_release_tags


DEFAULT_REVIEW_DIR = ROOT / "tests" / "vet_taxonomy_case_review" / "expanded_27"


@dataclass
class CaseEvidence:
    repo: str
    cve_id: str
    cert_absent_allowed: bool
    cert_fixed_allowed: bool
    uncertainty: list[Any]
    negative_evidence: list[Any]
    source_refs: list[Any]
    hard_certificate_candidates: list[Any]
    admission_requirements: list[Any]
    forbidden_hard_certificates: list[Any]
    line_risk_signals: list[Any]
    scope_files: list[str]
    scope_functions: list[str]
    fix_tokens: list[str]
    vulnerable_tokens: list[str]
    quality_issues: set[str] = field(default_factory=set)


@dataclass
class TagChecks:
    file_exists: bool
    function_hit: bool
    vulnerable_token_hit: bool
    fix_token_hit: bool
    checked_paths: list[str]
    errors: list[str]


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _run_git(repo_path: Path, args: list[str]) -> tuple[int, str, str]:
    repo_path = repo_path.resolve()
    proc = subprocess.run(
        ["git", "-c", f"safe.directory={repo_path}", "-C", str(repo_path), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
        errors="replace",
    )
    return proc.returncode, proc.stdout, proc.stderr


def _git_tags(repo_path: Path) -> list[str]:
    code, out, err = _run_git(repo_path, ["tag", "-l", "--sort=version:refname"])
    if code != 0:
        raise RuntimeError(f"git tag failed for {repo_path}: {err.strip()}")
    return [line.strip() for line in out.splitlines() if line.strip()]


def _ls_tree_path(repo_path: Path, tag: str, path: str) -> bool:
    code, out, _ = _run_git(repo_path, ["ls-tree", "-r", "--name-only", tag, "--", path])
    return code == 0 and any(line.strip() == path for line in out.splitlines())


@lru_cache(maxsize=200_000)
def _show_file_cached(repo_path_str: str, tag: str, path: str) -> tuple[bool, str]:
    repo_path = Path(repo_path_str)
    code, out, _ = _run_git(repo_path, ["show", f"{tag}:{path}"])
    return code == 0, out if code == 0 else ""


def _token_hit(contents: list[str], tokens: list[str], *, min_len: int = 4) -> bool:
    clean = [tok for tok in tokens if len(tok) >= min_len]
    if not clean:
        return False
    return any(tok in content for content in contents for tok in clean)


def _dedupe(items: list[Any], *, max_items: int | None = None) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items or []:
        if isinstance(item, dict):
            text = str(item.get("value") or item.get("signal") or item.get("pattern") or "").strip()
        else:
            text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
        if max_items and len(out) >= max_items:
            break
    return out


def _usable_evidence(row: dict[str, Any]) -> dict[str, Any]:
    top = row.get("step3_usable_evidence")
    if isinstance(top, dict) and top:
        return top
    theta = row.get("theta") or {}
    nested = theta.get("step3_usable_evidence")
    if isinstance(nested, dict):
        return nested
    return {}


def _extract_case_evidence(row: dict[str, Any], issues: set[str]) -> CaseEvidence:
    theta = row.get("theta") or {}
    scope = theta.get("Scope") or {}
    cert = theta.get("CertificatePolicy") or {}
    vuln = theta.get("VulnerableCondition") or {}
    evidence = _usable_evidence(row)
    return CaseEvidence(
        repo=row.get("repo", ""),
        cve_id=row.get("cve_id", ""),
        cert_absent_allowed=bool(cert.get("cert_absent_allowed")),
        cert_fixed_allowed=bool(cert.get("cert_fixed_allowed")),
        uncertainty=list(row.get("uncertainty") or []),
        negative_evidence=list(vuln.get("negative_evidence") or []),
        source_refs=list(scope.get("source_refs") or []),
        hard_certificate_candidates=list(cert.get("hard_certificate_candidates") or []),
        admission_requirements=list(cert.get("admission_requirements") or []),
        forbidden_hard_certificates=list(cert.get("forbidden_hard_certificates") or []),
        line_risk_signals=list(evidence.get("line_risk_signals") or []),
        scope_files=_dedupe(list(scope.get("files") or []) + list(evidence.get("file_patterns") or []), max_items=8),
        scope_functions=_dedupe(list(scope.get("functions") or []) + list(evidence.get("function_patterns") or []), max_items=8),
        fix_tokens=_dedupe(list(evidence.get("fix_tokens") or []) + list((theta.get("FixEvidence") or {}).get("fix_code_patterns") or []), max_items=8),
        vulnerable_tokens=_dedupe(list(evidence.get("vulnerable_tokens") or []) + list(vuln.get("vulnerable_code_patterns") or []), max_items=8),
        quality_issues=set(issues),
    )


def _quality_issue_map(review_dir: Path) -> dict[tuple[str, str], set[str]]:
    report = _load_json(review_dir / "review_quality_report.json")
    issues: dict[tuple[str, str], set[str]] = defaultdict(set)
    for finding in report.get("findings", []):
        issues[(finding.get("repo", ""), finding.get("cve_id", ""))].add(finding.get("issue", ""))
    return issues


def _source_refs_are_structured(refs: list[Any]) -> bool:
    return bool(refs) and all(isinstance(ref, dict) and ref.get("source_ref") for ref in refs)


def _fixed_gate_reasons(ev: CaseEvidence) -> list[str]:
    reasons: list[str] = []
    if not ev.cert_fixed_allowed:
        reasons.append("agent_did_not_allow_cert_fixed")
    if ev.uncertainty:
        reasons.append("uncertainty_present")
    if "reviewed_with_uncertainty" in ev.quality_issues or "cert_fixed_with_uncertainty" in ev.quality_issues:
        reasons.append("quality_uncertainty")
    if not ev.negative_evidence or "empty_negative_evidence" in ev.quality_issues:
        reasons.append("negative_evidence_missing")
    if not _source_refs_are_structured(ev.source_refs):
        reasons.append("source_refs_not_structured")
    if not ev.hard_certificate_candidates:
        reasons.append("hard_certificate_candidates_missing")
    if not ev.admission_requirements:
        reasons.append("admission_requirements_missing")
    if not ev.forbidden_hard_certificates:
        reasons.append("forbidden_hard_certificates_missing")
    if not ev.fix_tokens:
        reasons.append("fix_tokens_missing")
    return reasons


def _absent_gate_reasons(ev: CaseEvidence) -> list[str]:
    reasons: list[str] = []
    if not ev.cert_absent_allowed:
        reasons.append("agent_did_not_allow_cert_absent")
    if ev.uncertainty:
        reasons.append("uncertainty_present")
    if "reviewed_with_uncertainty" in ev.quality_issues:
        reasons.append("quality_uncertainty")
    if not ev.negative_evidence or "empty_negative_evidence" in ev.quality_issues:
        reasons.append("negative_evidence_missing")
    if not _source_refs_are_structured(ev.source_refs):
        reasons.append("source_refs_not_structured")
    if not ev.line_risk_signals or "empty_line_risk_signals" in ev.quality_issues:
        reasons.append("line_risk_signals_missing")
    if not ev.scope_files:
        reasons.append("scope_files_missing")
    return reasons


def _tag_checks(repo_path: Path, tag: str, ev: CaseEvidence) -> TagChecks:
    paths = [p for p in ev.scope_files if p and not p.endswith("/")]
    errors: list[str] = []
    existing_paths: list[str] = []
    contents: list[str] = []
    for path in paths:
        try:
            ok, content = _show_file_cached(str(repo_path.resolve()), tag, path)
            if ok:
                existing_paths.append(path)
                contents.append(content)
        except Exception as exc:
            errors.append(f"show_file:{path}:{exc}")
    checked_paths = existing_paths or paths
    function_hit = _token_hit(contents, ev.scope_functions[:4], min_len=3)
    vulnerable_hit = _token_hit(contents, ev.vulnerable_tokens, min_len=4)
    fix_hit = _token_hit(contents, ev.fix_tokens, min_len=4)
    return TagChecks(
        file_exists=bool(existing_paths),
        function_hit=function_hit,
        vulnerable_token_hit=vulnerable_hit,
        fix_token_hit=fix_hit,
        checked_paths=checked_paths,
        errors=errors,
    )


def _clear_reasons(strategy: str, ev: CaseEvidence, checks: TagChecks, fixed_gate_ok: bool, absent_gate_ok: bool) -> list[str]:
    if strategy == "raw_agent_flags_any":
        reasons: list[str] = []
        if ev.cert_fixed_allowed and checks.fix_token_hit:
            reasons.append("raw_fixed_token_present")
        if ev.cert_absent_allowed and not checks.file_exists:
            reasons.append("raw_scope_file_absent")
        if ev.cert_absent_allowed and ev.vulnerable_tokens and not checks.vulnerable_token_hit:
            reasons.append("raw_vulnerable_token_absent")
        return reasons
    if strategy == "raw_fixed_token":
        return ["raw_fixed_token_present"] if ev.cert_fixed_allowed and checks.fix_token_hit else []
    if strategy == "raw_absent_scope_or_vuln":
        reasons = []
        if ev.cert_absent_allowed and not checks.file_exists:
            reasons.append("raw_scope_file_absent")
        if ev.cert_absent_allowed and ev.vulnerable_tokens and not checks.vulnerable_token_hit:
            reasons.append("raw_vulnerable_token_absent")
        return reasons
    if strategy == "strict_fixed_token":
        return ["strict_fixed_token_present"] if fixed_gate_ok and checks.fix_token_hit else []
    if strategy == "strict_fixed_token_and_vuln_absent":
        if fixed_gate_ok and checks.fix_token_hit and ev.vulnerable_tokens and not checks.vulnerable_token_hit:
            return ["strict_fixed_token_present", "strict_vulnerable_token_absent"]
        return []
    if strategy == "strict_absent_scope_only":
        return ["strict_scope_file_absent"] if absent_gate_ok and not checks.file_exists else []
    if strategy == "strict_gate_any":
        reasons = []
        if fixed_gate_ok and checks.fix_token_hit:
            reasons.append("strict_fixed_token_present")
        if absent_gate_ok and not checks.file_exists:
            reasons.append("strict_scope_file_absent")
        return reasons
    if strategy == "ultra_strict_gate_any":
        reasons = []
        if fixed_gate_ok and checks.fix_token_hit and ev.vulnerable_tokens and not checks.vulnerable_token_hit:
            reasons.extend(["strict_fixed_token_present", "strict_vulnerable_token_absent"])
        if absent_gate_ok and not checks.file_exists:
            reasons.append("strict_scope_file_absent")
        return reasons
    return []


def _pct(num: int, den: int) -> float:
    return round(num / den, 6) if den else 0.0


def _sample_unaffected(tags: list[str], gt_set: set[str], max_count: int) -> list[str]:
    candidates = [tag for tag in tags if tag not in gt_set]
    if max_count <= 0 or len(candidates) <= max_count:
        return candidates
    if max_count == 1:
        return [candidates[len(candidates) // 2]]
    positions = sorted({round(i * (len(candidates) - 1) / (max_count - 1)) for i in range(max_count)})
    return [candidates[i] for i in positions]


def simulate(
    review_dir: Path,
    dataset_path: Path,
    repo_root: Path,
    out_dir: Path,
    *,
    max_unaffected_per_case: int = 40,
) -> dict[str, Any]:
    review_dir = review_dir.resolve()
    dataset_path = dataset_path.resolve()
    repo_root = repo_root.resolve()
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    dataset = _load_json(dataset_path)
    rows = _jsonl(review_dir / "per_case_vet.jsonl")
    issue_map = _quality_issue_map(review_dir)
    strategies = [
        "raw_agent_flags_any",
        "raw_fixed_token",
        "raw_absent_scope_or_vuln",
        "strict_fixed_token",
        "strict_fixed_token_and_vuln_absent",
        "strict_absent_scope_only",
        "strict_gate_any",
        "ultra_strict_gate_any",
    ]
    metrics = {
        name: {
            "cleared_tags": 0,
            "wrong_cleared_affected_tags": 0,
            "true_cleared_unaffected_tags": 0,
            "cases_with_wrong_clear": set(),
            "cases_with_any_clear": set(),
        }
        for name in strategies
    }
    wrong_cases: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    per_case_lines: list[str] = []
    repo_cache: dict[str, list[str]] = {}

    for row in rows:
        key = (row.get("repo", ""), row.get("cve_id", ""))
        ev = _extract_case_evidence(row, issue_map.get(key, set()))
        repo_path = repo_root / ev.repo
        if ev.repo not in repo_cache:
            repo_cache[ev.repo] = filter_release_tags(ev.repo, _git_tags(repo_path))
        release_tags = repo_cache[ev.repo]
        record = dataset.get(ev.cve_id) or {}
        gt_mapped, gt_unmapped = map_gt_tags_to_repo_tags(
            sorted(str(t) for t in record.get("affected_version", [])),
            release_tags,
            mode="loose",
        )
        gt_set = set(gt_mapped)
        fixed_reasons = _fixed_gate_reasons(ev)
        absent_reasons = _absent_gate_reasons(ev)
        fixed_gate_ok = not fixed_reasons
        absent_gate_ok = not absent_reasons
        tag_checks: dict[str, TagChecks] = {}

        eval_tags = sorted(gt_set) + _sample_unaffected(release_tags, gt_set, max_unaffected_per_case)
        eval_tags = list(dict.fromkeys(eval_tags))

        per_case = {
            "repo": ev.repo,
            "cve_id": ev.cve_id,
            "release_tag_count": len(release_tags),
            "gt_affected_count": len(gt_set),
            "evaluated_tag_count": len(eval_tags),
            "evaluated_all_affected_tags": True,
            "max_unaffected_per_case": max_unaffected_per_case,
            "gt_unmapped": gt_unmapped,
            "cert_absent_allowed": ev.cert_absent_allowed,
            "cert_fixed_allowed": ev.cert_fixed_allowed,
            "fixed_gate_ok": fixed_gate_ok,
            "fixed_gate_blockers": fixed_reasons,
            "absent_gate_ok": absent_gate_ok,
            "absent_gate_blockers": absent_reasons,
            "quality_issues": sorted(ev.quality_issues),
            "source_ref_count": len(ev.source_refs),
            "negative_evidence_count": len(ev.negative_evidence),
            "line_risk_signal_count": len(ev.line_risk_signals),
            "fix_token_count": len(ev.fix_tokens),
            "vulnerable_token_count": len(ev.vulnerable_tokens),
            "strategy_clears": {},
        }

        for tag in eval_tags:
            checks = _tag_checks(repo_path, tag, ev)
            tag_checks[tag] = checks
            for strategy in strategies:
                reasons = _clear_reasons(strategy, ev, checks, fixed_gate_ok, absent_gate_ok)
                if not reasons:
                    continue
                metrics[strategy]["cleared_tags"] += 1
                metrics[strategy]["cases_with_any_clear"].add(f"{ev.repo}/{ev.cve_id}")
                per_case["strategy_clears"].setdefault(strategy, 0)
                per_case["strategy_clears"][strategy] += 1
                if tag in gt_set:
                    metrics[strategy]["wrong_cleared_affected_tags"] += 1
                    metrics[strategy]["cases_with_wrong_clear"].add(f"{ev.repo}/{ev.cve_id}")
                    wrong_cases.append({
                        "strategy": strategy,
                        "repo": ev.repo,
                        "cve_id": ev.cve_id,
                        "tag": tag,
                        "clear_reasons": reasons,
                        "fixed_gate_ok": fixed_gate_ok,
                        "fixed_gate_blockers": fixed_reasons,
                        "absent_gate_ok": absent_gate_ok,
                        "absent_gate_blockers": absent_reasons,
                        "checks": checks.__dict__,
                    })
                else:
                    metrics[strategy]["true_cleared_unaffected_tags"] += 1

        decisions.append(per_case)
        per_case_lines.append(json.dumps(per_case, ensure_ascii=False))

    summary_strategies: dict[str, Any] = {}
    for strategy, m in metrics.items():
        cleared = int(m["cleared_tags"])
        wrong = int(m["wrong_cleared_affected_tags"])
        true = int(m["true_cleared_unaffected_tags"])
        summary_strategies[strategy] = {
            "cleared_tags": cleared,
            "true_cleared_unaffected_tags": true,
            "wrong_cleared_affected_tags": wrong,
            "not_affected_clear_precision": _pct(true, true + wrong),
            "cases_with_any_clear": len(m["cases_with_any_clear"]),
            "cases_with_wrong_clear": len(m["cases_with_wrong_clear"]),
        }

    blocker_counts = Counter()
    for decision in decisions:
        blocker_counts.update(f"fixed:{b}" for b in decision["fixed_gate_blockers"])
        blocker_counts.update(f"absent:{b}" for b in decision["absent_gate_blockers"])

    summary = {
        "schema_version": "vet_admission_gate_summary.v1",
        "review_dir": str(review_dir),
        "dataset": str(dataset_path),
        "cases": len(rows),
        "tag_evaluation_policy": {
            "affected_tags": "all mapped GT affected tags",
            "unaffected_tags": f"deterministic sample, max {max_unaffected_per_case} per case",
            "wrong_cleared_affected_tags": "exact for mapped GT affected tags",
            "true_cleared_unaffected_tags": "sample-based estimate, not full release-tag coverage",
        },
        "strategies": summary_strategies,
        "blocker_counts": dict(blocker_counts),
        "conclusion": {
            "raw_agent_certificates_safe_for_hard_decision": summary_strategies["raw_agent_flags_any"]["wrong_cleared_affected_tags"] == 0,
            "strict_gate_safe_on_p1b": summary_strategies["strict_gate_any"]["wrong_cleared_affected_tags"] == 0,
            "strict_gate_has_coverage": summary_strategies["strict_gate_any"]["cleared_tags"] > 0,
        },
    }

    (out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "admission_decisions.json").write_text(json.dumps(decisions, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "wrong_certificate_cases.json").write_text(json.dumps(wrong_cases, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "per_case.jsonl").write_text("\n".join(per_case_lines) + "\n", encoding="utf-8")
    report = _render_report(summary)
    (out_dir / "report.md").write_text(report, encoding="utf-8")
    return summary


def _render_report(summary: dict[str, Any]) -> str:
    lines = [
        "# VET Admission Gate Simulator Report",
        "",
        f"cases: {summary['cases']}",
        "",
        "## Strategy Metrics",
        "",
        "| strategy | cleared tags | true clear | wrong affected clear | clear precision | wrong cases |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, data in summary["strategies"].items():
        lines.append(
            f"| `{name}` | {data['cleared_tags']} | {data['true_cleared_unaffected_tags']} | "
            f"{data['wrong_cleared_affected_tags']} | {data['not_affected_clear_precision']:.6f} | "
            f"{data['cases_with_wrong_clear']} |"
        )
    lines.extend([
        "",
        "## Gate Conclusion",
        "",
        f"- raw_agent_certificates_safe_for_hard_decision: {summary['conclusion']['raw_agent_certificates_safe_for_hard_decision']}",
        f"- strict_gate_safe_on_p1b: {summary['conclusion']['strict_gate_safe_on_p1b']}",
        f"- strict_gate_has_coverage: {summary['conclusion']['strict_gate_has_coverage']}",
        "",
        "## Dominant Blockers",
        "",
    ])
    for key, count in sorted(summary["blocker_counts"].items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"- `{key}`: {count}")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--review-dir", type=Path, default=DEFAULT_REVIEW_DIR)
    parser.add_argument("--dataset", type=Path, default=ROOT / "DataSet" / "BaseDataOrder.json")
    parser.add_argument("--repo-root", type=Path, default=ROOT / "repo")
    parser.add_argument("--out", type=Path, default=ROOT / "tests" / "vet_admission_gate_p1b")
    parser.add_argument("--max-unaffected-per-case", type=int, default=40)
    args = parser.parse_args()
    summary = simulate(
        args.review_dir,
        args.dataset,
        args.repo_root,
        args.out,
        max_unaffected_per_case=args.max_unaffected_per_case,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
