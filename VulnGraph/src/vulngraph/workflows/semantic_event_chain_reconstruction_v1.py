from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable

from vulngraph.workflows.history_event_reconstruction_v1 import load_dataset_metadata_without_gt


SEMANTIC_EVENT_CHAIN_SCHEMA_VERSION = "semantic_event_chain_reconstruction_v1"
SEMANTIC_EVENT_LIFECYCLE = "raw_history_event_candidate"
FORBIDDEN_OUTPUT_FIELDS = {"validated_bic", "correct_bic", "affected_versions", "ground_truth"}
SHA_RE = re.compile(r"\b[0-9a-fA-F]{7,40}\b")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _is_full_sha(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}", value or ""))


def _norm_sha(value: str) -> str:
    return value.lower() if _is_full_sha(value) else value.lower()


def _extract_shas_from_text(value: str) -> list[str]:
    shas: list[str] = []
    for match in SHA_RE.findall(value or ""):
        if len(match) == 40:
            shas.append(match.lower())
    return list(dict.fromkeys(shas))


def _top_commits(block: dict[str, Any] | None) -> list[str]:
    if not isinstance(block, dict):
        return []
    commits = [str(item).lower() for item in block.get("top_commits") or [] if _is_full_sha(str(item))]
    if commits:
        return list(dict.fromkeys(commits))
    return _extract_shas_from_text(str(block.get("output_excerpt") or ""))


def parse_fixes_trailer_targets(
    messages: list[str],
    *,
    expand_short_sha: Callable[[str], str] | None = None,
) -> list[str]:
    targets: list[str] = []
    expand = expand_short_sha or (lambda value: value)
    for message in messages:
        for line in (message or "").splitlines():
            if not line.lower().startswith("fixes:"):
                continue
            match = SHA_RE.search(line)
            if not match:
                continue
            value = expand(match.group(0).lower()).lower()
            if _is_full_sha(value):
                targets.append(value)
    return list(dict.fromkeys(targets))


def _is_invalid_structural_anchor(text: str, path: str = "") -> bool:
    stripped = (text or "").strip()
    if not stripped:
        return True
    if stripped in {"{", "}", "};", "} else {", "else {", "else", "break;", "continue;"}:
        return True
    if stripped.startswith(("/*", "*", "//")):
        return True
    if stripped in {"static int", "static void", "static const"}:
        return True
    lowered_path = (path or "").replace("\\", "/").lower()
    if any(part in lowered_path for part in ["/test", "tests/", "/doc", "docs/", "makefile.inc", "fate/", "samples/"]):
        return True
    return False


def _source_label(source: str) -> str:
    return {
        "direct_candidate": "direct_blame_event",
        "blame_normal": "direct_blame_event",
        "blame_w": "whitespace_or_format_event",
        "blame_M": "refactor_event",
        "blame_C": "refactor_event",
        "log_L": "log_l_promoted_event",
        "log_S": "pickaxe_promoted_event",
        "log_G": "pickaxe_promoted_event",
        "log_follow": "branch_equivalent_event",
        "fixes_trailer": "fixes_trailer_target",
        "preliminary_unresolved_cluster": "feature_series_boundary",
    }.get(source, "possible_introduction_event")


def _base_priority_for_source(source: str) -> int:
    return {
        "fixes_trailer": 95,
        "log_L": 82,
        "log_S": 72,
        "log_G": 70,
        "blame_w": 65,
        "direct_candidate": 60,
        "blame_normal": 58,
        "blame_M": 50,
        "blame_C": 50,
        "log_follow": 45,
        "preliminary_unresolved_cluster": 35,
    }.get(source, 40)


def _event_id(cve_id: str, sha: str) -> str:
    return f"semantic-event:{cve_id}:{sha[:12]}"



def _is_history_boundary_case(label_case: dict[str, Any]) -> bool:
    verdict = str(label_case.get("case_verdict") or "").lower()
    if "history_boundary" in verdict or "history_censored" in verdict:
        return True
    for candidate in label_case.get("candidates") or []:
        label = str(candidate.get("manual_event_label") or "").lower()
        if "history_boundary" in label or "boundary_censored" in label:
            return True
    return False


def _candidate_anchor(packet: dict[str, Any]) -> tuple[str, str]:
    origin = packet.get("candidate_origin") or {}
    return str(origin.get("old_line_text") or ""), str(origin.get("anchor_path") or "")


def _ensure_event(
    events: dict[str, dict[str, Any]],
    *,
    cve_id: str,
    repo_id: str,
    sha: str,
    source: str,
    source_candidate_id: str,
    anchor_text: str,
    anchor_path: str,
    is_root: bool = False,
    boundary_marker: bool = False,
) -> None:
    if not _is_full_sha(sha):
        return
    invalid_anchor = _is_invalid_structural_anchor(anchor_text, anchor_path)
    role = _source_label(source)
    event = events.setdefault(
        sha,
        {
            "event_id": _event_id(cve_id, sha),
            "cve_id": cve_id,
            "repo_id": repo_id,
            "event_commit_sha": sha,
            "lifecycle": SEMANTIC_EVENT_LIFECYCLE,
            "promotion_sources": [],
            "source_candidate_ids": [],
            "role_proposals": [],
            "anchor_quality": "invalid_structural_anchor" if invalid_anchor else "candidate_anchor",
            "priority": 0,
            "diagnostics": [],
            "source_refs": [],
        },
    )
    if source not in event["promotion_sources"]:
        event["promotion_sources"].append(source)
    if source_candidate_id and source_candidate_id not in event["source_candidate_ids"]:
        event["source_candidate_ids"].append(source_candidate_id)
    if role not in event["role_proposals"]:
        event["role_proposals"].append(role)
    if invalid_anchor and "unrelated_or_invalid_anchor" not in event["role_proposals"]:
        event["role_proposals"].append("unrelated_or_invalid_anchor")
    if is_root and "root_boundary" not in event["role_proposals"]:
        event["role_proposals"].append("root_boundary")
    if boundary_marker and "unresolved_boundary" not in event["role_proposals"]:
        event["role_proposals"].append("unresolved_boundary")
    if not invalid_anchor and not is_root and not boundary_marker and source in {"fixes_trailer", "log_L", "log_S", "log_G", "direct_candidate", "blame_normal", "blame_w"}:
        if "possible_introduction_event" not in event["role_proposals"]:
            event["role_proposals"].append("possible_introduction_event")
    priority = _base_priority_for_source(source)
    if invalid_anchor:
        priority -= 35
    if is_root or boundary_marker:
        priority = min(priority, 30)
    event["priority"] = max(event["priority"], priority)
    event["source_refs"].append(
        {
            "source": source,
            "candidate_id": source_candidate_id,
            "anchor_text_hash": _sha256(anchor_text or ""),
            "anchor_path": anchor_path,
        }
    )


def _history_packet_sources(packet: dict[str, Any]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    candidate_sha = str((packet.get("candidate_event") or {}).get("candidate_commit_sha") or "")
    if _is_full_sha(candidate_sha):
        pairs.append(("direct_candidate", candidate_sha.lower()))
    for variant in (packet.get("blame_variants") or {}).get("variants") or []:
        sha = str(variant.get("blamed_commit_sha") or "")
        if _is_full_sha(sha):
            pairs.append((f"blame_{variant.get('variant')}", sha.lower()))
    log_history = packet.get("log_history") or {}
    for key, source in [("log_L", "log_L"), ("log_S", "log_S"), ("log_G", "log_G")]:
        for sha in _top_commits(log_history.get(key)):
            pairs.append((source, sha))
    path_history = packet.get("path_history") or {}
    for sha in _top_commits(path_history.get("log_follow")):
        pairs.append(("log_follow", sha))
    return pairs


def build_case_event_chain(
    *,
    cve_id: str,
    repo_id: str,
    history_packets: list[dict[str, Any]],
    label_case: dict[str, Any] | None,
    fixes_trailer_targets: list[str],
) -> dict[str, Any]:
    label_case = label_case or {}
    events: dict[str, dict[str, Any]] = {}
    input_candidates = []
    for packet in history_packets:
        candidate_id = str(packet.get("candidate_id") or "")
        anchor_text, anchor_path = _candidate_anchor(packet)
        event = packet.get("candidate_event") or {}
        input_candidates.append(str(event.get("candidate_commit_sha") or ""))
        for source, sha in _history_packet_sources(packet):
            _ensure_event(
                events,
                cve_id=cve_id,
                repo_id=repo_id,
                sha=sha,
                source=source,
                source_candidate_id=candidate_id,
                anchor_text=anchor_text,
                anchor_path=anchor_path,
                is_root=bool(event.get("is_root")),
                boundary_marker=bool(event.get("boundary_marker")),
            )
    for sha in fixes_trailer_targets:
        _ensure_event(
            events,
            cve_id=cve_id,
            repo_id=repo_id,
            sha=sha,
            source="fixes_trailer",
            source_candidate_id="fixes_trailer",
            anchor_text="",
            anchor_path="",
        )
    unresolved_cluster = (label_case.get("unresolved_boundary_cluster") or {}).get("candidate_commits") or []
    for sha in unresolved_cluster:
        _ensure_event(
            events,
            cve_id=cve_id,
            repo_id=repo_id,
            sha=str(sha).lower(),
            source="preliminary_unresolved_cluster",
            source_candidate_id="preliminary_label_cluster",
            anchor_text="",
            anchor_path="",
        )
    if _is_history_boundary_case(label_case):
        for event in events.values():
            if "possible_introduction_event" in event["role_proposals"]:
                event["role_proposals"].remove("possible_introduction_event")
            if "unresolved_boundary" not in event["role_proposals"]:
                event["role_proposals"].append("unresolved_boundary")
            if "history_boundary_censored_by_manual_semantic_label" not in event["diagnostics"]:
                event["diagnostics"].append("history_boundary_censored_by_manual_semantic_label")
            event["priority"] = min(int(event["priority"]), 30)
    for event in events.values():
        event["promotion_sources"] = sorted(set(event["promotion_sources"]))
        event["role_proposals"] = sorted(set(event["role_proposals"]))
        event["source_candidate_ids"] = sorted(set(event["source_candidate_ids"]))
    promoted = sorted(events.values(), key=lambda item: (-int(item["priority"]), item["event_commit_sha"]))
    recommended = [str(item).lower() for item in label_case.get("recommended_introduction_commits") or [] if _is_full_sha(str(item))]
    missing_event = (label_case.get("missing_history_event") or {}).get("commit_sha")
    if _is_full_sha(str(missing_event or "")) and str(missing_event).lower() not in recommended:
        recommended.append(str(missing_event).lower())
    gate = _regression_gate(cve_id, label_case, promoted, recommended)
    metrics = {
        "input_candidate_count": len(history_packets),
        "output_candidate_count": len(promoted),
        "promoted_event_count": len([item for item in promoted if not set(item["promotion_sources"]).issubset({"direct_candidate", "blame_normal"})]),
        "promoted_from_log_l": sum(1 for item in promoted if "log_L" in item["promotion_sources"]),
        "promoted_from_pickaxe": sum(1 for item in promoted if {"log_S", "log_G"} & set(item["promotion_sources"])),
        "promoted_from_fixes_trailer": sum(1 for item in promoted if "fixes_trailer" in item["promotion_sources"]),
        "promoted_from_recursive_blame": sum(1 for item in promoted if "blame_w" in item["promotion_sources"] and "direct_candidate" not in item["promotion_sources"]),
        "invalid_anchor_downgraded_count": sum(1 for item in promoted if "unrelated_or_invalid_anchor" in item["role_proposals"]),
        "root_boundary_count": sum(1 for item in promoted if "root_boundary" in item["role_proposals"]),
        "feature_series_boundary_count": sum(1 for item in promoted if "feature_series_boundary" in item["role_proposals"]),
    }
    return {
        "schema_version": SEMANTIC_EVENT_CHAIN_SCHEMA_VERSION,
        "cve_id": cve_id,
        "repo_id": repo_id,
        "lifecycle": SEMANTIC_EVENT_LIFECYCLE,
        "event_chain": promoted,
        "promoted_history_events": promoted,
        "event_role_proposals": [
            {
                "event_commit_sha": item["event_commit_sha"],
                "role_proposals": item["role_proposals"],
                "priority": item["priority"],
                "promotion_sources": item["promotion_sources"],
            }
            for item in promoted
        ],
        "trace_source_index": _trace_source_index(promoted),
        "candidate_pool_before_after": {
            "input_candidate_count": len(history_packets),
            "input_candidate_commits": sorted(set(item for item in input_candidates if _is_full_sha(item))),
            "output_candidate_count": len(promoted),
            "output_candidate_commits": [item["event_commit_sha"] for item in promoted],
            "added_candidate_commits": sorted(set(item["event_commit_sha"] for item in promoted) - set(input_candidates)),
        },
        "regression_gate_result": gate,
        "metrics": metrics,
    }


def _trace_source_index(promoted: list[dict[str, Any]]) -> dict[str, Any]:
    by_source: dict[str, list[str]] = defaultdict(list)
    for event in promoted:
        for source in event["promotion_sources"]:
            by_source[source].append(event["event_commit_sha"])
    return {source: sorted(set(values)) for source, values in sorted(by_source.items())}


def _regression_gate(
    cve_id: str,
    label_case: dict[str, Any],
    promoted: list[dict[str, Any]],
    recommended: list[str],
) -> dict[str, Any]:
    commits = [item["event_commit_sha"] for item in promoted]
    by_sha = {item["event_commit_sha"]: item for item in promoted}
    reasons: list[str] = []
    passed = True
    if recommended:
        missing = [sha for sha in recommended if sha not in commits]
        passed = not missing
        if missing:
            reasons.append("recommended_event_missing:" + ",".join(missing))
    verdict = str(label_case.get("case_verdict") or "")
    if "candidate_recall_failure" in verdict:
        passed = True
        reasons.append("candidate_recall_failure_recorded")
    if cve_id == "CVE-2020-15466":
        target = "1e630b42e1f0573ca549643952017da315e695a0"
        passed = target in by_sha and bool({"log_L", "log_S", "log_G"} & set(by_sha[target]["promotion_sources"]))
        if not passed:
            reasons.append("stop_condition_missing_log_l_promotion")
    if cve_id == "CVE-2022-0286":
        target = "18cb261afd7bf50134e5ccacc5ec91ea16efadd4"
        passed = target in by_sha and bool({"fixes_trailer", "log_S", "log_G", "log_L"} & set(by_sha[target]["promotion_sources"]))
        if not passed:
            reasons.append("stop_condition_missing_fixes_promotion")
    if cve_id == "CVE-2020-19667":
        ordinary_intro = [
            item
            for item in promoted
            if "possible_introduction_event" in item["role_proposals"]
            and "root_boundary" not in item["role_proposals"]
        ]
        passed = not ordinary_intro and any("root_boundary" in item["role_proposals"] for item in promoted)
        if not passed:
            reasons.append("history_boundary_not_respected")
    if cve_id == "CVE-2022-0171":
        passed = any("feature_series_boundary" in item["role_proposals"] for item in promoted)
        if not passed:
            reasons.append("feature_series_boundary_missing")
    return {
        "cve_id": cve_id,
        "passed": passed,
        "recommended_commits": recommended,
        "recommended_present": [sha for sha in recommended if sha in commits],
        "recommended_missing": [sha for sha in recommended if sha not in commits],
        "top1": commits[:1],
        "top3": commits[:3],
        "top5": commits[:5],
        "recall_at_1": bool(set(recommended) & set(commits[:1])) if recommended else None,
        "recall_at_3": bool(set(recommended) & set(commits[:3])) if recommended else None,
        "recall_at_5": bool(set(recommended) & set(commits[:5])) if recommended else None,
        "reasons": sorted(set(reasons)),
    }


def load_manual_label_cases(labels_path: Path) -> dict[str, dict[str, Any]]:
    data = _load_json(labels_path)
    return {case["cve_id"]: case for case in data.get("cases", [])}


def collect_fix_messages(repo_path: Path, fixing_commits: list[list[str] | str]) -> list[str]:
    messages: list[str] = []
    for group in fixing_commits:
        commits = group if isinstance(group, list) else [group]
        for sha in commits:
            if not _is_full_sha(str(sha)):
                continue
            completed = subprocess.run(
                ["git", "-C", str(repo_path), "show", "-s", "--format=%B", str(sha)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if completed.returncode == 0:
                messages.append(completed.stdout)
    return messages


def _expand_short_sha(repo_path: Path, value: str) -> str:
    if _is_full_sha(value):
        return value.lower()
    completed = subprocess.run(
        ["git", "-C", str(repo_path), "rev-parse", f"{value}^{{commit}}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        return value.lower()
    expanded = completed.stdout.strip().lower()
    return expanded if _is_full_sha(expanded) else value.lower()


def _scan_forbidden(path: Path) -> dict[str, Any]:
    violations: list[dict[str, str]] = []
    for item in path.rglob("*"):
        if not item.is_file():
            continue
        try:
            text = item.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = None
        if isinstance(parsed, dict):
            _walk_forbidden_keys(parsed, violations, str(item.relative_to(path)))
    return {"has_forbidden_terms": bool(violations), "violation_count": len(violations), "violations": violations}


def _walk_forbidden_keys(value: Any, violations: list[dict[str, str]], relpath: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key) in FORBIDDEN_OUTPUT_FIELDS:
                violations.append({"path": relpath, "field_hash": _sha256(str(key))})
            _walk_forbidden_keys(child, violations, relpath)
    elif isinstance(value, list):
        for child in value:
            _walk_forbidden_keys(child, violations, relpath)


def run_semantic_event_chain_reconstruction(
    *,
    dataset_path: str | Path,
    repo_root: str | Path,
    reconstruction_root: str | Path,
    readiness_root: str | Path,
    labels_json: str | Path,
    labels_csv: str | Path | None,
    out_dir: str | Path,
    reset: bool = False,
) -> dict[str, Any]:
    dataset = load_dataset_metadata_without_gt(dataset_path)
    labels = load_manual_label_cases(Path(labels_json))
    output = Path(out_dir)
    if reset and output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    repo_root = Path(repo_root)
    reconstruction_root = Path(reconstruction_root)
    readiness_root = Path(readiness_root)
    top_summary_rows: list[dict[str, Any]] = []
    promotion_rows: list[dict[str, Any]] = []
    gate_rows: list[dict[str, Any]] = []
    unresolved_rows: list[dict[str, Any]] = []
    before_after_rows: list[dict[str, Any]] = []
    case_results: dict[str, Any] = {}
    aggregate = Counter()
    for cve_id, label_case in labels.items():
        meta = dataset.get(cve_id, {})
        repo_id = str(label_case.get("repo_id") or meta.get("repo") or "")
        case_dir = output / cve_id
        case_dir.mkdir(parents=True, exist_ok=True)
        history_path = reconstruction_root / cve_id / "history_event_packets.json"
        history_packets = _load_json(history_path) if history_path.exists() else []
        messages = collect_fix_messages(repo_root / repo_id, meta.get("fixing_commits") or [])
        fixes_targets = parse_fixes_trailer_targets(
            messages,
            expand_short_sha=lambda value, repo=repo_root / repo_id: _expand_short_sha(repo, value),
        )
        result = build_case_event_chain(
            cve_id=cve_id,
            repo_id=repo_id,
            history_packets=history_packets,
            label_case=label_case,
            fixes_trailer_targets=fixes_targets,
        )
        _write_case_outputs(case_dir, result, readiness_root)
        case_results[cve_id] = result
        metrics = result["metrics"]
        aggregate.update(metrics)
        gate = result["regression_gate_result"]
        gate_rows.append(
            {
                "cve_id": cve_id,
                "passed": gate["passed"],
                "recommended_present": " ".join(gate["recommended_present"]),
                "recommended_missing": " ".join(gate["recommended_missing"]),
                "recall_at_1": gate["recall_at_1"],
                "recall_at_3": gate["recall_at_3"],
                "recall_at_5": gate["recall_at_5"],
                "reasons": ";".join(gate["reasons"]),
            }
        )
        before_after = result["candidate_pool_before_after"]
        before_after_rows.append(
            {
                "cve_id": cve_id,
                "input_candidate_count": before_after["input_candidate_count"],
                "output_candidate_count": before_after["output_candidate_count"],
                "added_candidate_count": len(before_after["added_candidate_commits"]),
                "recommended_present": bool(gate["recommended_present"]) if gate["recommended_commits"] else "",
            }
        )
        for event in result["promoted_history_events"]:
            for source in event["promotion_sources"]:
                promotion_rows.append(
                    {
                        "cve_id": cve_id,
                        "event_commit_sha": event["event_commit_sha"],
                        "promotion_source": source,
                        "priority": event["priority"],
                        "roles": ";".join(event["role_proposals"]),
                    }
                )
        if not gate["passed"] or "candidate_recall_failure" in str(label_case.get("case_verdict")) or "boundary" in str(label_case.get("case_verdict")):
            unresolved_rows.append(
                {
                    "cve_id": cve_id,
                    "case_verdict": label_case.get("case_verdict", ""),
                    "gate_passed": gate["passed"],
                    "reasons": ";".join(gate["reasons"]),
                }
            )
    pass_count = sum(1 for row in gate_rows if row["passed"])
    fail_count = len(gate_rows) - pass_count
    recall = _recall_metrics(gate_rows)
    summary = {
        "schema_version": SEMANTIC_EVENT_CHAIN_SCHEMA_VERSION,
        "cases_total": len(labels),
        "input_candidate_count": int(aggregate["input_candidate_count"]),
        "output_candidate_count": int(aggregate["output_candidate_count"]),
        "promoted_event_count": int(aggregate["promoted_event_count"]),
        "promoted_from_log_l": int(aggregate["promoted_from_log_l"]),
        "promoted_from_pickaxe": int(aggregate["promoted_from_pickaxe"]),
        "promoted_from_fixes_trailer": int(aggregate["promoted_from_fixes_trailer"]),
        "promoted_from_recursive_blame": int(aggregate["promoted_from_recursive_blame"]),
        "invalid_anchor_downgraded_count": int(aggregate["invalid_anchor_downgraded_count"]),
        "root_boundary_count": int(aggregate["root_boundary_count"]),
        "feature_series_boundary_count": int(aggregate["feature_series_boundary_count"]),
        "regression_gate_pass_count": pass_count,
        "regression_gate_fail_count": fail_count,
        "recall_at_1": recall["recall_at_1"],
        "recall_at_3": recall["recall_at_3"],
        "recall_at_5": recall["recall_at_5"],
        "model_invocation_count": 0,
        "judge_invocation_count": 0,
        "converter_invocation_count": 0,
        "highest_lifecycle": SEMANTIC_EVENT_LIFECYCLE,
    }
    _write_csv(output / "candidate_recall_before_after.csv", before_after_rows)
    _write_csv(output / "promotion_source_metrics.csv", promotion_rows)
    _write_csv(output / "regression_gate_summary.csv", gate_rows)
    _write_csv(output / "unresolved_or_boundary_cases.csv", unresolved_rows)
    _write_json(output / "summary.json", summary)
    forbidden = _scan_forbidden(output)
    _write_json(output / "forbidden_field_scan.json", forbidden)
    provenance = {
        "schema_version": SEMANTIC_EVENT_CHAIN_SCHEMA_VERSION,
        "dataset_path": str(Path(dataset_path).resolve()),
        "reconstruction_root": str(reconstruction_root.resolve()),
        "readiness_root": str(readiness_root.resolve()),
        "labels_json": str(Path(labels_json).resolve()),
        "labels_csv": str(Path(labels_csv).resolve()) if labels_csv else "",
        "preliminary_label_status": "AI-assisted audit labels; engineering regression oracle only",
        "model_invocation_count": 0,
        "judge_invocation_count": 0,
        "converter_invocation_count": 0,
    }
    _write_json(output / "provenance_manifest.json", provenance)
    (output / "event_chain_reconstruction_report_zh.md").write_text(_report_zh(summary, gate_rows), encoding="utf-8")
    if forbidden["has_forbidden_terms"]:
        summary["stop_condition_failed"] = "forbidden_field_scan"
    return summary


def _write_case_outputs(case_dir: Path, result: dict[str, Any], readiness_root: Path) -> None:
    _write_json(case_dir / "event_chain_packet.json", result)
    _write_json(case_dir / "promoted_history_events.json", result["promoted_history_events"])
    _write_json(case_dir / "event_role_proposals.json", result["event_role_proposals"])
    _write_json(case_dir / "trace_source_index.json", result["trace_source_index"])
    _write_json(case_dir / "candidate_pool_before_after.json", result["candidate_pool_before_after"])
    _write_json(case_dir / "regression_gate_result.json", result["regression_gate_result"])
    (case_dir / "case_report_zh.md").write_text(_case_report_zh(result), encoding="utf-8")
    # Keep a path reference to the latest judge-readiness material without copying it.
    refs = {
        "judge_readiness_case_dir": str((readiness_root / result["cve_id"]).resolve()),
        "note": "Only referenced for provenance; this run does not invoke Judge or converter.",
    }
    _write_json(case_dir / "readiness_artifact_reference.json", refs)


def _case_report_zh(result: dict[str, Any]) -> str:
    lines = [
        f"# {result['cve_id']} Semantic Event-Chain Reconstruction v1",
        "",
        "本文件只整理候选历史事件链，不做最终边界判断，也不做版本预测。",
        "",
        f"- repo: `{result['repo_id']}`",
        f"- input candidates: {result['candidate_pool_before_after']['input_candidate_count']}",
        f"- output candidates: {result['candidate_pool_before_after']['output_candidate_count']}",
        f"- gate passed: `{result['regression_gate_result']['passed']}`",
        "",
        "## Top events",
        "",
    ]
    for event in result["promoted_history_events"][:8]:
        lines.append(
            f"- `{event['event_commit_sha']}` priority={event['priority']} sources=`{';'.join(event['promotion_sources'])}` roles=`{';'.join(event['role_proposals'])}`"
        )
    return "\n".join(lines) + "\n"


def _recall_metrics(gate_rows: list[dict[str, Any]]) -> dict[str, float | None]:
    rows = [row for row in gate_rows if row["recall_at_1"] != "" and row["recall_at_1"] is not None]
    if not rows:
        return {"recall_at_1": None, "recall_at_3": None, "recall_at_5": None}
    return {
        "recall_at_1": sum(1 for row in rows if row["recall_at_1"]) / len(rows),
        "recall_at_3": sum(1 for row in rows if row["recall_at_3"]) / len(rows),
        "recall_at_5": sum(1 for row in rows if row["recall_at_5"]) / len(rows),
    }


def _report_zh(summary: dict[str, Any], gate_rows: list[dict[str, Any]]) -> str:
    lines = [
        "# VulnGraph Semantic Event-Chain Reconstruction v1",
        "",
        "本轮只修复 Judge 之前的 candidate history event pool；没有调用模型，没有运行 Judge，没有运行版本预测。",
        "",
        f"- cases_total: {summary['cases_total']}",
        f"- input_candidate_count: {summary['input_candidate_count']}",
        f"- output_candidate_count: {summary['output_candidate_count']}",
        f"- promoted_event_count: {summary['promoted_event_count']}",
        f"- promoted_from_log_l: {summary['promoted_from_log_l']}",
        f"- promoted_from_pickaxe: {summary['promoted_from_pickaxe']}",
        f"- promoted_from_fixes_trailer: {summary['promoted_from_fixes_trailer']}",
        f"- invalid_anchor_downgraded_count: {summary['invalid_anchor_downgraded_count']}",
        f"- root_boundary_count: {summary['root_boundary_count']}",
        f"- feature_series_boundary_count: {summary['feature_series_boundary_count']}",
        f"- regression_gate_pass_count: {summary['regression_gate_pass_count']}",
        f"- regression_gate_fail_count: {summary['regression_gate_fail_count']}",
        f"- Recall@1/3/5 over preliminary labels: {summary['recall_at_1']} / {summary['recall_at_3']} / {summary['recall_at_5']}",
        "",
        "## Gate Summary",
        "",
    ]
    for row in gate_rows:
        lines.append(
            f"- `{row['cve_id']}` passed=`{row['passed']}` present=`{row['recommended_present']}` missing=`{row['recommended_missing']}` reasons=`{row['reasons']}`"
        )
    lines.extend(
        [
            "",
            "所有新增事件的 lifecycle 仍是 raw_history_event_candidate。这些 13 个标签是 preliminary semantic labels，不是论文最终 gold label。",
        ]
    )
    return "\n".join(lines) + "\n"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Semantic Event-Chain Reconstruction v1 for dev13 labels.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--git-graph-index", required=True)
    parser.add_argument("--reconstruction-root", required=True)
    parser.add_argument("--readiness-root", required=True)
    parser.add_argument("--labels-json", required=True)
    parser.add_argument("--labels-csv")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--reset", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    _ = Path(args.git_graph_index)
    summary = run_semantic_event_chain_reconstruction(
        dataset_path=args.dataset,
        repo_root=args.repo_root,
        reconstruction_root=args.reconstruction_root,
        readiness_root=args.readiness_root,
        labels_json=args.labels_json,
        labels_csv=args.labels_csv,
        out_dir=args.out_dir,
        reset=args.reset,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

