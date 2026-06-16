#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from vulnversion.stage3_verify.version_registry import (  # noqa: E402
    filter_release_tags,
    sort_tags_for_line,
)


_GIT_LINES_CACHE: dict[tuple[str, tuple[str, ...]], list[str]] = {}
_COMMIT_EXISTS_CACHE: dict[tuple[str, str], bool] = {}
_COMMIT_TIMESTAMP_CACHE: dict[tuple[str, str], int | None] = {}
_TAG_TIMESTAMPS_CACHE: dict[str, dict[str, int]] = {}


def run_git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    safe_path = repo.resolve().as_posix()
    return subprocess.run(
        ["git", "-c", f"safe.directory={safe_path}", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def git_lines(repo: Path, *args: str) -> list[str]:
    key = (str(repo.resolve()), tuple(args))
    if key in _GIT_LINES_CACHE:
        return list(_GIT_LINES_CACHE[key])
    result = run_git(repo, *args)
    if result.returncode != 0:
        return []
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    _GIT_LINES_CACHE[key] = lines
    return list(lines)


def commit_exists(repo: Path, commit: str) -> bool:
    if not commit:
        return False
    key = (str(repo.resolve()), commit)
    if key in _COMMIT_EXISTS_CACHE:
        return _COMMIT_EXISTS_CACHE[key]
    result = run_git(repo, "cat-file", "-e", f"{commit}^{{commit}}")
    exists = result.returncode == 0
    _COMMIT_EXISTS_CACHE[key] = exists
    return exists


def commit_timestamp(repo: Path, revision: str) -> int | None:
    key = (str(repo.resolve()), revision)
    if key in _COMMIT_TIMESTAMP_CACHE:
        return _COMMIT_TIMESTAMP_CACHE[key]
    result = run_git(repo, "show", "-s", "--format=%ct", f"{revision}^{{commit}}")
    try:
        value = int(result.stdout.strip()) if result.returncode == 0 else None
    except ValueError:
        value = None
    _COMMIT_TIMESTAMP_CACHE[key] = value
    return value


def tags_containing(repo: Path, commit: str) -> set[str]:
    return set(git_lines(repo, "tag", "--contains", commit))


def tag_timestamps(repo: Path) -> dict[str, int]:
    key = str(repo.resolve())
    if key in _TAG_TIMESTAMPS_CACHE:
        return dict(_TAG_TIMESTAMPS_CACHE[key])
    lines = git_lines(repo, "for-each-ref", "--format=%(refname:short)\t%(creatordate:unix)", "refs/tags")
    values: dict[str, int] = {}
    for line in lines:
        name, separator, raw_timestamp = line.partition("\t")
        if not separator:
            continue
        try:
            values[name] = int(raw_timestamp)
        except ValueError:
            continue
    _TAG_TIMESTAMPS_CACHE[key] = values
    return dict(values)


def collect_affected_tags(
    *,
    repo_path: Path,
    repo_name: str,
    predicted_bics: list[str],
    fixing_commits: list[str],
    time_bound: str = "latest_fic",
) -> dict[str, Any]:
    raw_tags = git_lines(repo_path, "tag", "-l")
    release_tags = filter_release_tags(repo_name, raw_tags)
    release_tags = sort_tags_for_line(repo_name, release_tags)
    release_set = set(release_tags)

    unique_bics = list(dict.fromkeys(value for value in predicted_bics if value))
    unique_fics = list(dict.fromkeys(value for value in fixing_commits if value))
    missing_bics = [value for value in unique_bics if not commit_exists(repo_path, value)]
    missing_fics = [value for value in unique_fics if not commit_exists(repo_path, value)]

    vulnerable_reachability: set[str] = set()
    for bic in unique_bics:
        if bic not in missing_bics:
            vulnerable_reachability.update(tags_containing(repo_path, bic))

    fixed_reachability: set[str] = set()
    for fic in unique_fics:
        if fic not in missing_fics:
            fixed_reachability.update(tags_containing(repo_path, fic))

    affected = release_set.intersection(vulnerable_reachability).difference(fixed_reachability)
    fic_timestamps = [
        value
        for fic in unique_fics
        if fic not in missing_fics
        for value in [commit_timestamp(repo_path, fic)]
        if value is not None
    ]
    cutoff_timestamp = max(fic_timestamps) if fic_timestamps and time_bound == "latest_fic" else None
    if time_bound not in {"latest_fic", "none"}:
        raise ValueError(f"unsupported time bound: {time_bound}")
    if cutoff_timestamp is not None:
        release_timestamps = tag_timestamps(repo_path)
        affected = {
            tag
            for tag in affected
            if release_timestamps.get(tag, cutoff_timestamp + 1) <= cutoff_timestamp
        }
    affected_tags = [tag for tag in release_tags if tag in affected]
    return {
        "raw_tag_count": len(raw_tags),
        "excluded_tag_count": len(raw_tags) - len(release_tags),
        "release_tags": release_tags,
        "affected_tags": affected_tags,
        "missing_bics": missing_bics,
        "missing_fics": missing_fics,
        "bic_reachable_release_count": len(release_set.intersection(vulnerable_reachability)),
        "fixed_reachable_release_count": len(release_set.intersection(fixed_reachability)),
        "fic_cutoff_timestamp": cutoff_timestamp,
        "time_bound": time_bound,
    }


def parse_agentic_results(path: Path) -> dict[tuple[str, str], dict[str, Any]]:
    values = json.loads(path.read_text(encoding="utf-8"))
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for item in values:
        repo = str(item.get("project") or item.get("repo") or "")
        fic = str(item.get("bfc") or "")
        predicted = str(item.get("predicted") or item.get("predicted_bic") or "")
        rows[(repo, fic)] = {
            "repo": repo,
            "fic": fic,
            "predicted_bics": [predicted] if predicted else [],
            "confidence": item.get("confidence"),
            "time_ms": item.get("time_ms", 0) or 0,
            "blame_time_ms": item.get("blame_time_ms", 0) or 0,
            "tkg_time_ms": item.get("tkg_time_ms", 0) or 0,
            "agent_time_ms": item.get("agent_time_ms", 0) or 0,
            "tokens_input": item.get("tokens_input", 0) or 0,
            "tokens_output": item.get("tokens_output", 0) or 0,
            "cost_usd": item.get("cost_usd", 0) or 0,
            "agent_steps": item.get("agent_steps", 0) or 0,
            "source": str(path),
        }
    return rows


def parse_mas_results(root: Path) -> dict[tuple[str, str], dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for path in sorted(root.rglob("result.json")):
        item = json.loads(path.read_text(encoding="utf-8"))
        repo = str(item.get("repo_name") or "")
        fics = [str(value) for value in item.get("fix_commit_hashes") or [] if value]
        if not fics:
            continue
        predicted = item.get("predicted_bic") or []
        if isinstance(predicted, str):
            predicted = [predicted] if predicted else []
        rows[(repo, fics[0])] = {
            "repo": repo,
            "fic": fics[0],
            "predicted_bics": list(dict.fromkeys(str(value) for value in predicted if value)),
            "cve": item.get("cveid"),
            "all_result_fics": fics,
            "bic_method": item.get("bic_method"),
            "llm_calls": item.get("llm_calls", 0) or 0,
            "llm_tokens": item.get("llm_tokens", 0) or 0,
            "used_fallback": bool(item.get("used_fallback")),
            "root_cause_passed_review": bool((item.get("root_cause") or {}).get("passed_review")),
            "vuln_statement_count": len(item.get("vuln_statements") or []),
            "error": item.get("error") or "",
            "source": str(path),
        }
    return rows


def flatten_fixing_commits(value: Any) -> list[str]:
    output: list[str] = []
    if isinstance(value, str):
        if value.strip():
            output.append(value.strip())
    elif isinstance(value, list):
        for item in value:
            output.extend(flatten_fixing_commits(item))
    return list(dict.fromkeys(output))


def _case_metrics(ground_truth: set[str], predicted: set[str]) -> dict[str, Any]:
    tp = len(ground_truth.intersection(predicted))
    fp = len(predicted.difference(ground_truth))
    fn = len(ground_truth.difference(predicted))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    union = ground_truth.union(predicted)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "jaccard": len(ground_truth.intersection(predicted)) / len(union) if union else 1.0,
        "exact_match": ground_truth == predicted,
    }


def compute_metrics(cases: list[dict[str, Any]]) -> dict[str, Any]:
    per_case = [
        _case_metrics(set(item.get("ground_truth") or []), set(item.get("predicted") or []))
        for item in cases
    ]
    tp = sum(item["tp"] for item in per_case)
    fp = sum(item["fp"] for item in per_case)
    fn = sum(item["fn"] for item in per_case)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    total = len(per_case)
    return {
        "case_count": total,
        "micro": {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1},
        "macro": {
            "precision": statistics.mean(item["precision"] for item in per_case) if total else 0.0,
            "recall": statistics.mean(item["recall"] for item in per_case) if total else 0.0,
            "f1": statistics.mean(item["f1"] for item in per_case) if total else 0.0,
            "jaccard": statistics.mean(item["jaccard"] for item in per_case) if total else 0.0,
        },
        "vulnerability_level_accuracy": (
            sum(item["exact_match"] for item in per_case) / total if total else 0.0
        ),
        "exact_match_count": sum(item["exact_match"] for item in per_case),
    }


def repo_history_state(repo: Path) -> dict[str, Any]:
    inside = run_git(repo, "rev-parse", "--is-inside-work-tree")
    shallow = run_git(repo, "rev-parse", "--is-shallow-repository")
    promisor = run_git(repo, "config", "--get", "remote.origin.promisor")
    return {
        "path": str(repo),
        "valid": inside.returncode == 0 and inside.stdout.strip() == "true",
        "shallow": shallow.stdout.strip() == "true",
        "partial_clone": promisor.stdout.strip().lower() == "true",
    }


def evaluate_method(
    *,
    method: str,
    dataset: dict[str, Any],
    rows: dict[tuple[str, str], dict[str, Any]],
    repo_root: Path,
    bic_policy: str,
    time_bound: str,
) -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    history: dict[str, dict[str, Any]] = {}
    for cve, record in dataset.items():
        repo_name = str(record.get("repo") or "")
        repo = repo_root / repo_name
        history.setdefault(repo_name, repo_history_state(repo))
        fics = flatten_fixing_commits(record.get("fixing_commits") or [])
        lookup_fic = fics[0] if fics else ""
        source = rows.get((repo_name, lookup_fic))
        predicted_bics = list((source or {}).get("predicted_bics") or [])
        if bic_policy == "top1":
            predicted_bics = predicted_bics[:1]
        elif bic_policy != "union":
            raise ValueError(f"unsupported BIC policy: {bic_policy}")

        conversion = collect_affected_tags(
            repo_path=repo,
            repo_name=repo_name,
            predicted_bics=predicted_bics,
            fixing_commits=fics,
            time_bound=time_bound,
        )
        ground_truth = [str(value) for value in record.get("affected_version") or []]
        predicted = conversion["affected_tags"]
        metrics = _case_metrics(set(ground_truth), set(predicted))
        missing_gt_tags = sorted(set(ground_truth).difference(conversion["release_tags"]))
        if source is None:
            status = "missing_result"
        elif not predicted_bics:
            status = "empty_bic"
        elif conversion["missing_bics"]:
            status = "missing_bic_commit"
        elif conversion["missing_fics"]:
            status = "missing_fic_commit"
        elif conversion["bic_reachable_release_count"] == 0:
            status = "bic_reaches_no_release"
        else:
            status = "converted"

        cases.append(
            {
                "cve": cve,
                "repo": repo_name,
                "fixing_commits": fics,
                "lookup_fic": lookup_fic,
                "predicted_bics": predicted_bics,
                "ground_truth": sorted(ground_truth),
                "predicted": predicted,
                "missing_gt_tags": missing_gt_tags,
                "status": status,
                "conversion": {key: value for key, value in conversion.items() if key != "release_tags"},
                "metrics": metrics,
                "source_result": source,
            }
        )

    metrics = compute_metrics(cases)
    status_counts: dict[str, int] = {}
    for item in cases:
        status_counts[item["status"]] = status_counts.get(item["status"], 0) + 1
    metrics["result_coverage"] = sum(item["status"] != "missing_result" for item in cases) / len(cases)
    metrics["bic_coverage"] = sum(bool(item["predicted_bics"]) for item in cases) / len(cases)
    metrics["gt_tag_coverage"] = (
        sum(len(item["ground_truth"]) - len(item["missing_gt_tags"]) for item in cases)
        / sum(len(item["ground_truth"]) for item in cases)
    )
    return {
        "method": method,
        "bic_policy": bic_policy,
        "time_bound": time_bound,
        "metrics": metrics,
        "status_counts": status_counts,
        "repository_history": history,
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert BIC predictions to affected release tags and evaluate them.")
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--agentic-results", type=Path, required=True)
    parser.add_argument("--mas-results", type=Path, required=True)
    parser.add_argument("--bic-policy", choices=("union", "top1"), default="union")
    parser.add_argument("--time-bound", choices=("latest_fic", "none"), default="latest_fic")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    dataset = json.loads(args.dataset.read_text(encoding="utf-8"))
    if not isinstance(dataset, dict):
        raise SystemExit("dataset must be an object keyed by CVE")

    agentic_rows = parse_agentic_results(args.agentic_results)
    mas_rows = parse_mas_results(args.mas_results)
    report = {
        "schema_version": 1,
        "dataset": str(args.dataset),
        "repo_root": str(args.repo_root),
        "method_reports": {
            "Agentic-SZZ": evaluate_method(
                method="Agentic-SZZ",
                dataset=dataset,
                rows=agentic_rows,
                repo_root=args.repo_root,
                bic_policy=args.bic_policy,
                time_bound=args.time_bound,
            ),
            "MAS-SZZ": evaluate_method(
                method="MAS-SZZ",
                dataset=dataset,
                rows=mas_rows,
                repo_root=args.repo_root,
                bic_policy=args.bic_policy,
                time_bound=args.time_bound,
            ),
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for name, method_report in report["method_reports"].items():
        metrics = method_report["metrics"]
        print(
            f"{name}: coverage={metrics['bic_coverage']:.3f}, "
            f"micro_f1={metrics['micro']['f1']:.3f}, "
            f"macro_f1={metrics['macro']['f1']:.3f}, "
            f"vuln_accuracy={metrics['vulnerability_level_accuracy']:.3f}"
        )
    print(f"report={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
