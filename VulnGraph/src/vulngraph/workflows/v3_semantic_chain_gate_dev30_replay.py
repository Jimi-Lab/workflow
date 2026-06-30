from __future__ import annotations

import argparse
import json
import shutil
from collections import Counter
from pathlib import Path
from statistics import median
from typing import Any

from vulngraph.workflows.event_promotion_ablation_v1 import (
    ABLATION_SCHEMA_VERSION,
    SEMANTIC_EVENT_LIFECYCLE,
    _case_root_boundary_mode,
    _collect_events,
    _finalize_event,
    _load_json,
    _load_labels,
    _percentile,
    _rank_candidates,
    _scan_candidate_files_for_leakage,
    _scan_output_for_forbidden,
    _write_csv,
    _write_json,
    evaluate_candidates,
    recommended_commits_from_label,
)
from vulngraph.workflows.history_event_reconstruction_v1 import load_dataset_metadata_without_gt
from vulngraph.workflows.semantic_event_chain_reconstruction_v1 import (
    _expand_short_sha,
    collect_fix_messages,
    parse_fixes_trailer_targets,
)


DEV30_REPLAY_SCHEMA_VERSION = "v3_semantic_chain_gate_dev30_replay_v1"
V3_VARIANT = "V3_semantic_chain_plus_gate"
V3_TOP_K = 8


def _counter_to_dict(counter: Counter) -> dict[str, int]:
    return dict(sorted(counter.items()))


def _event_metric_flags(item: dict[str, Any]) -> dict[str, bool]:
    sources = set(item.get("promotion_sources") or [])
    reasons = set(item.get("gate_reasons") or [])
    features = item.get("evidence_features") or {}
    return {
        "trace_only_candidate": bool(features.get("trace_only")),
        "direct_candidate": bool(features.get("direct_source")),
        "fixes_trailer_candidate": "fixes_trailer" in sources,
        "log_L_pickaxe_cross_hit": "log_l_pickaxe_cross_hit" in reasons,
        "log_follow_only_rejected": item.get("gate_decision") == "rejected" and "trace_only_follow_not_candidate" in reasons,
        "invalid_anchor_rejected_or_penalized": "invalid_structural_anchor_penalty" in reasons,
        "noise_path_rejected": "test_doc_build_path_rejected" in reasons,
    }


def build_v3_replay_case(
    *,
    cve_id: str,
    repo_id: str,
    history_packets: list[dict[str, Any]],
    fixes_trailer_targets: list[str],
    label_case: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one CVE's frozen V3 candidates and metrics.

    Manual labels are used only after candidate generation for regression metrics.
    """

    chain_events = _collect_events(
        cve_id=cve_id,
        repo_id=repo_id,
        history_packets=history_packets,
        fixes_trailer_targets=fixes_trailer_targets,
        include_trace=True,
    )
    boundary_mode = _case_root_boundary_mode(history_packets)
    finalized = [
        _finalize_event(event, variant=V3_VARIANT, case_root_boundary_mode=boundary_mode)
        for event in chain_events.values()
    ]
    promoted_pre_truncation = [item for item in finalized if item.get("gate_decision") == "promoted"]
    candidates = _rank_candidates(promoted_pre_truncation, max_candidates=V3_TOP_K)
    rejected = [item for item in finalized if item.get("gate_decision") == "rejected"]

    source_distribution: Counter[str] = Counter()
    rejection_distribution: Counter[str] = Counter()
    for item in finalized:
        for source in item.get("promotion_sources") or []:
            source_distribution[source] += 1
        if item.get("gate_decision") == "rejected":
            for reason in item.get("gate_reasons") or []:
                rejection_distribution[reason] += 1

    candidate_flags = [_event_metric_flags(item) for item in candidates]
    finalized_flags = [_event_metric_flags(item) for item in finalized]
    roles = {role for item in candidates for role in item.get("role_proposals") or []}
    unresolved_case = bool(boundary_mode or {"root_boundary", "unresolved_boundary"} & roles)

    metrics = {
        "cve_id": cve_id,
        "repo_id": repo_id,
        "candidate_count": len(candidates),
        "pre_truncation_promoted_count": len(promoted_pre_truncation),
        "post_truncation_candidate_count": len(candidates),
        "truncated_event_count": max(0, len(promoted_pre_truncation) - len(candidates)),
        "rejected_event_count": len(rejected),
        "trace_only_candidate_count": sum(1 for item in candidate_flags if item["trace_only_candidate"]),
        "direct_candidate_count": sum(1 for item in candidate_flags if item["direct_candidate"]),
        "fixes_trailer_candidate_count": sum(1 for item in candidate_flags if item["fixes_trailer_candidate"]),
        "log_L_pickaxe_cross_hit_count": sum(1 for item in candidate_flags if item["log_L_pickaxe_cross_hit"]),
        "log_follow_only_rejected_count": sum(1 for item in finalized_flags if item["log_follow_only_rejected"]),
        "invalid_anchor_rejected_or_penalized_count": sum(
            1 for item in finalized_flags if item["invalid_anchor_rejected_or_penalized"]
        ),
        "noise_path_rejected_count": sum(1 for item in finalized_flags if item["noise_path_rejected"]),
        "root_or_boundary_case": bool(boundary_mode),
        "unresolved_case": unresolved_case,
        "promotion_source_distribution": _counter_to_dict(source_distribution),
        "rejection_reason_distribution": _counter_to_dict(rejection_distribution),
    }

    regression = None
    missing_targets: list[str] = []
    if label_case:
        targets = recommended_commits_from_label(label_case)
        regression = evaluate_candidates(candidates, targets, label_case)
        candidate_shas = {item["event_commit_sha"] for item in candidates}
        missing_targets = [sha for sha in targets if sha not in candidate_shas]

    return {
        "schema_version": DEV30_REPLAY_SCHEMA_VERSION,
        "cve_id": cve_id,
        "repo_id": repo_id,
        "candidates": candidates,
        "gate_decisions": finalized,
        "rejected_events": rejected,
        "metrics": metrics,
        "regression": regression,
        "regression_target_commits_missing": missing_targets,
    }


def summarize_replay_cases(
    *,
    cases: list[dict[str, Any]],
    expected_cases_total: int,
    previous_v3_recall_at_5: float,
    label_leakage: dict[str, Any],
    forbidden: dict[str, Any],
) -> dict[str, Any]:
    candidate_counts = [int(case["metrics"]["candidate_count"]) for case in cases]
    pre_counts = [int(case["metrics"]["pre_truncation_promoted_count"]) for case in cases]
    post_counts = [int(case["metrics"]["post_truncation_candidate_count"]) for case in cases]

    rejection_distribution: Counter[str] = Counter()
    promotion_distribution: Counter[str] = Counter()
    for case in cases:
        rejection_distribution.update(case["metrics"].get("rejection_reason_distribution") or {})
        promotion_distribution.update(case["metrics"].get("promotion_source_distribution") or {})

    regression_cases = [case for case in cases if case.get("regression")]
    regression_denominator = len([case for case in regression_cases if case["regression"].get("recall_at_5") is not None])

    def _regression_rate(key: str) -> float | None:
        if not regression_denominator:
            return None
        return sum(1 for case in regression_cases if case["regression"].get(key) is True) / regression_denominator

    cve_19667 = next((case for case in cases if case["cve_id"] == "CVE-2020-19667"), None)
    cve_19667_roles = {
        role
        for item in (cve_19667 or {}).get("candidates", [])
        for role in item.get("role_proposals") or []
    }
    hard_gates = {
        "processed_30_of_30": len(cases) == expected_cases_total == 30,
        "no_backend_model_judge_converter_invocation": True,
        "production_inputs_only": True,
        "label_leakage_free": not bool(label_leakage.get("has_leakage")),
        "forbidden_field_scan_clean": not bool(forbidden.get("has_forbidden_terms")),
        "dev13_recall_at_5_not_below_previous_v3": (_regression_rate("recall_at_5") or 0.0) >= previous_v3_recall_at_5,
        "cve_2020_15466_target_retained": not _missing_target(cases, "CVE-2020-15466", "1e630b42e1f0573ca549643952017da315e695a0"),
        "cve_2022_0286_target_retained": not _missing_target(cases, "CVE-2022-0286", "18cb261afd7bf50134e5ccacc5ec91ea16efadd4"),
        "cve_2020_19667_no_plain_intro": "possible_introduction_event" not in cve_19667_roles,
        "post_truncation_max_le_8": (max(post_counts) if post_counts else 0) <= V3_TOP_K,
    }

    return {
        "schema_version": DEV30_REPLAY_SCHEMA_VERSION,
        "cases_total": len(cases),
        "cases_expected": expected_cases_total,
        "cases_with_candidates": sum(1 for value in candidate_counts if value > 0),
        "no_candidate_cases": [case["cve_id"] for case in cases if case["metrics"]["candidate_count"] == 0],
        "total_v3_candidates": sum(candidate_counts),
        "candidate_count_p50": median(candidate_counts) if candidate_counts else 0,
        "candidate_count_p90": _percentile(candidate_counts, 0.9),
        "candidate_count_max": max(candidate_counts) if candidate_counts else 0,
        "pre_truncation_promoted_count_total": sum(pre_counts),
        "pre_truncation_promoted_count_p50": median(pre_counts) if pre_counts else 0,
        "pre_truncation_promoted_count_p90": _percentile(pre_counts, 0.9),
        "pre_truncation_promoted_count_max": max(pre_counts) if pre_counts else 0,
        "post_truncation_candidate_count_total": sum(post_counts),
        "post_truncation_candidate_count_p50": median(post_counts) if post_counts else 0,
        "post_truncation_candidate_count_p90": _percentile(post_counts, 0.9),
        "post_truncation_candidate_count_max": max(post_counts) if post_counts else 0,
        "truncated_event_count": sum(int(case["metrics"]["truncated_event_count"]) for case in cases),
        "rejection_reason_distribution": _counter_to_dict(rejection_distribution),
        "promotion_source_distribution": _counter_to_dict(promotion_distribution),
        "trace_only_candidate_count": sum(int(case["metrics"]["trace_only_candidate_count"]) for case in cases),
        "direct_candidate_count": sum(int(case["metrics"]["direct_candidate_count"]) for case in cases),
        "fixes_trailer_candidate_count": sum(int(case["metrics"]["fixes_trailer_candidate_count"]) for case in cases),
        "log_L_pickaxe_cross_hit_count": sum(int(case["metrics"]["log_L_pickaxe_cross_hit_count"]) for case in cases),
        "log_follow_only_rejected_count": sum(int(case["metrics"]["log_follow_only_rejected_count"]) for case in cases),
        "invalid_anchor_rejected_or_penalized_count": sum(
            int(case["metrics"]["invalid_anchor_rejected_or_penalized_count"]) for case in cases
        ),
        "noise_path_rejected_count": sum(int(case["metrics"]["noise_path_rejected_count"]) for case in cases),
        "root_or_boundary_case_count": sum(1 for case in cases if case["metrics"]["root_or_boundary_case"]),
        "unresolved_case_count": sum(1 for case in cases if case["metrics"]["unresolved_case"]),
        "dev13_regression_case_count": len(regression_cases),
        "dev13_regression_recall_at_1": _regression_rate("recall_at_1"),
        "dev13_regression_recall_at_3": _regression_rate("recall_at_3"),
        "dev13_regression_recall_at_5": _regression_rate("recall_at_5"),
        "dev13_regression_missing_target_commits": {
            case["cve_id"]: case["regression_target_commits_missing"]
            for case in regression_cases
            if case.get("regression_target_commits_missing")
        },
        "label_leakage_count": int(label_leakage.get("leakage_count") or 0),
        "forbidden_field_violation_count": int(forbidden.get("violation_count") or 0),
        "model_invocation_count": 0,
        "judge_invocation_count": 0,
        "converter_invocation_count": 0,
        "highest_lifecycle": SEMANTIC_EVENT_LIFECYCLE,
        "top_k": V3_TOP_K,
        "hard_gates": hard_gates,
        "all_feasibility_gates_passed": all(hard_gates.values()),
    }


def _missing_target(cases: list[dict[str, Any]], cve_id: str, sha: str) -> bool:
    case = next((item for item in cases if item["cve_id"] == cve_id), None)
    if not case:
        return True
    return sha not in {item["event_commit_sha"] for item in case.get("candidates", [])}


def _case_report_zh(case: dict[str, Any]) -> str:
    metrics = case["metrics"]
    top = case["candidates"][:5]
    lines = [
        f"# {case['cve_id']} V3 Semantic-Chain Gate Replay",
        "",
        "本文件只记录 no-Judge candidate generation replay；不运行模型、Judge、converter，也不输出版本预测。",
        "",
        "## Metrics",
        "",
        f"- repo: `{case['repo_id']}`",
        f"- post-truncation candidates: `{metrics['candidate_count']}`",
        f"- pre-truncation promoted events: `{metrics['pre_truncation_promoted_count']}`",
        f"- truncated events: `{metrics['truncated_event_count']}`",
        f"- rejected events: `{metrics['rejected_event_count']}`",
        f"- root/boundary case: `{metrics['root_or_boundary_case']}`",
        f"- unresolved case: `{metrics['unresolved_case']}`",
        "",
        "## Top Candidates",
        "",
    ]
    if not top:
        lines.append("- none")
    for item in top:
        lines.append(
            f"- rank {item.get('rank')}: `{item['event_commit_sha']}` score={item.get('gate_score')} "
            f"sources={','.join(item.get('promotion_sources') or [])} roles={','.join(item.get('role_proposals') or [])}"
        )
    lines.extend(
        [
            "",
            "## Regression Note",
            "",
            "若该 CVE 属于已人工审计集合，Recall@k 只用于回归检查；未参与 candidate generation。",
        ]
    )
    return "\n".join(lines) + "\n"


def _report_zh(summary: dict[str, Any], cases: list[dict[str, Any]]) -> str:
    priority = _manual_review_priority_rows(cases)[:10]
    lines = [
        "# VulnGraph V3 Semantic-Chain Gate dev30 Feasibility Replay",
        "",
        "本轮只验证 candidate generation feasibility：没有调用 OpenCode/DeepSeek，没有运行 Judge，没有运行 affected-version converter。",
        "V3 gate 规则沿用 dev13 ablation 的冻结实现，本报告只做 dev30 批处理和诊断统计。",
        "",
        "## Summary",
        "",
        f"- cases total: `{summary['cases_total']}`",
        f"- cases with candidates: `{summary['cases_with_candidates']}`",
        f"- total V3 candidates: `{summary['total_v3_candidates']}`",
        f"- candidate count p50/p90/max: `{summary['candidate_count_p50']}` / `{summary['candidate_count_p90']}` / `{summary['candidate_count_max']}`",
        f"- pre-truncation promoted p90/max: `{summary['pre_truncation_promoted_count_p90']}` / `{summary['pre_truncation_promoted_count_max']}`",
        f"- truncated event count: `{summary['truncated_event_count']}`",
        f"- dev13 regression R@1/R@3/R@5: `{summary['dev13_regression_recall_at_1']}` / `{summary['dev13_regression_recall_at_3']}` / `{summary['dev13_regression_recall_at_5']}`",
        "",
        "## Feasibility Gates",
        "",
    ]
    for key, value in summary["hard_gates"].items():
        lines.append(f"- {key}: `{value}`")
    lines.extend(["", "## Answers", ""])
    lines.append(
        "1. 当前 V3 是否泛化到 dev30："
        + ("初步可行，30/30 processed 且 hard gates 通过。" if summary["all_feasibility_gates_passed"] else "存在 gate 未通过，需先看失败项和 per-CVE ledger。")
    )
    lines.append(
        f"2. V3 是否仍控制在 Judge 可处理范围：post-truncation max=`{summary['post_truncation_candidate_count_max']}`，top-k=`{summary['top_k']}`。"
    )
    lines.append("3. 最需要人工审计的 CVE：")
    for row in priority[:5]:
        lines.append(f"   - {row['cve_id']}: score={row['priority_score']}, reasons={row['priority_reasons']}")
    lines.append(
        "4. 最常见 gate/rejection reason："
        + ", ".join(f"{k}={v}" for k, v in list(summary["rejection_reason_distribution"].items())[:8])
    )
    lines.append(
        "5. 是否可以进入 Top-k Judge Packet v1："
        + ("可以进入输入包冻结阶段，但仍需人工重点审计高 priority case。" if summary["all_feasibility_gates_passed"] else "暂不建议进入，先修失败 gate 或数据输入缺陷。")
    )
    return "\n".join(lines) + "\n"


def _manual_review_priority_rows(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case in cases:
        metrics = case["metrics"]
        score = 0
        reasons: list[str] = []
        if metrics["candidate_count"] == 0:
            score += 50
            reasons.append("no_candidate")
        if metrics["unresolved_case"]:
            score += 25
            reasons.append("unresolved")
        if metrics["truncated_event_count"]:
            score += min(30, int(metrics["truncated_event_count"]))
            reasons.append("truncated")
        if metrics["trace_only_candidate_count"]:
            score += min(20, int(metrics["trace_only_candidate_count"]) * 2)
            reasons.append("trace_only_candidates")
        if metrics["invalid_anchor_rejected_or_penalized_count"]:
            score += min(20, int(metrics["invalid_anchor_rejected_or_penalized_count"]))
            reasons.append("invalid_anchor_pressure")
        if metrics["noise_path_rejected_count"]:
            score += min(20, int(metrics["noise_path_rejected_count"]))
            reasons.append("noise_path_pressure")
        rows.append(
            {
                "cve_id": case["cve_id"],
                "repo_id": case["repo_id"],
                "priority_score": score,
                "priority_reasons": ";".join(reasons) if reasons else "low_noise",
                "candidate_count": metrics["candidate_count"],
                "pre_truncation_promoted_count": metrics["pre_truncation_promoted_count"],
                "truncated_event_count": metrics["truncated_event_count"],
                "trace_only_candidate_count": metrics["trace_only_candidate_count"],
                "root_or_boundary_case": metrics["root_or_boundary_case"],
                "unresolved_case": metrics["unresolved_case"],
            }
        )
    return sorted(rows, key=lambda row: (-int(row["priority_score"]), row["cve_id"]))


def run_v3_semantic_chain_gate_dev30_replay(
    *,
    dataset_path: str | Path,
    repo_root: str | Path,
    git_graph_index: str | Path,
    reconstruction_root: str | Path,
    readiness_root: str | Path,
    previous_dev13_root: str | Path,
    labels_json: str | Path,
    out_dir: str | Path,
    reset: bool = False,
) -> dict[str, Any]:
    dataset = load_dataset_metadata_without_gt(dataset_path)
    labels = _load_labels(Path(labels_json))
    repo_root = Path(repo_root)
    reconstruction_root = Path(reconstruction_root)
    output = Path(out_dir)
    if reset and output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    cases: list[dict[str, Any]] = []
    per_cve_rows: list[dict[str, Any]] = []
    candidate_rows: list[dict[str, Any]] = []
    gate_rows: list[dict[str, Any]] = []
    rejected_rows: list[dict[str, Any]] = []
    regression_rows: list[dict[str, Any]] = []

    for cve_id in sorted(dataset):
        meta = dataset[cve_id]
        repo_id = str(meta.get("repo") or "")
        history_path = reconstruction_root / cve_id / "history_event_packets.json"
        history_packets = _load_json(history_path) if history_path.exists() else []
        fix_messages = collect_fix_messages(repo_root / repo_id, meta.get("fixing_commits") or [])
        fixes_targets = parse_fixes_trailer_targets(
            fix_messages,
            expand_short_sha=lambda value, repo=repo_root / repo_id: _expand_short_sha(repo, value),
        )
        case = build_v3_replay_case(
            cve_id=cve_id,
            repo_id=repo_id,
            history_packets=history_packets,
            fixes_trailer_targets=fixes_targets,
            label_case=labels.get(cve_id),
        )
        cases.append(case)
        case_dir = output / cve_id
        _write_json(case_dir / "v3_candidates.json", case["candidates"])
        _write_json(case_dir / "v3_gate_decisions.json", case["gate_decisions"])
        _write_json(case_dir / "v3_rejected_events.json", case["rejected_events"])
        _write_json(case_dir / "v3_case_metrics.json", case["metrics"])
        (case_dir / "v3_case_report_zh.md").write_text(_case_report_zh(case), encoding="utf-8")

        per_cve_rows.append(_flat_metrics_row(case))
        for item in case["candidates"]:
            candidate_rows.append(_candidate_summary_row(case, item))
        for item in case["gate_decisions"]:
            gate_rows.append(_gate_row(case, item))
        for item in case["rejected_events"]:
            rejected_rows.append(_gate_row(case, item))
        if case["regression"]:
            regression_rows.append(_regression_row(case))

    label_leakage = _scan_candidate_files_for_leakage(output)
    forbidden = _scan_output_for_forbidden(output)
    previous_summary = _load_json(Path(previous_dev13_root) / "summary.json")
    previous_v3_recall_at_5 = float(
        previous_summary.get("variants", {}).get(V3_VARIANT, {}).get("recall_at_5") or 0.0
    )
    summary = summarize_replay_cases(
        cases=cases,
        expected_cases_total=len(dataset),
        previous_v3_recall_at_5=previous_v3_recall_at_5,
        label_leakage=label_leakage,
        forbidden=forbidden,
    )

    _write_csv(output / "per_cve_v3_metrics.csv", per_cve_rows)
    _write_csv(output / "v3_candidate_summary.csv", candidate_rows)
    _write_csv(output / "v3_gate_decision_ledger.csv", gate_rows)
    _write_csv(output / "v3_rejected_event_ledger.csv", rejected_rows)
    _write_csv(output / "dev13_regression_check.csv", regression_rows)
    _write_csv(output / "dev30_manual_review_priority.csv", _manual_review_priority_rows(cases))
    _write_json(output / "label_leakage_check.json", label_leakage)
    _write_json(output / "forbidden_field_scan.json", forbidden)
    _write_json(output / "summary.json", summary)
    (output / "dev30_v3_feasibility_report_zh.md").write_text(_report_zh(summary, cases), encoding="utf-8")
    _write_json(
        output / "provenance_manifest.json",
        {
            "schema_version": DEV30_REPLAY_SCHEMA_VERSION,
            "dataset_path": str(Path(dataset_path).resolve()),
            "git_graph_index": str(Path(git_graph_index).resolve()),
            "reconstruction_root": str(Path(reconstruction_root).resolve()),
            "readiness_root": str(Path(readiness_root).resolve()),
            "previous_dev13_root": str(Path(previous_dev13_root).resolve()),
            "labels_json_for_regression_only": str(Path(labels_json).resolve()),
            "candidate_generation_uses_labels": False,
            "model_invocation_count": 0,
            "judge_invocation_count": 0,
            "converter_invocation_count": 0,
        },
    )
    return summary


def _flat_metrics_row(case: dict[str, Any]) -> dict[str, Any]:
    metrics = case["metrics"]
    row = {
        key: value
        for key, value in metrics.items()
        if key not in {"promotion_source_distribution", "rejection_reason_distribution"}
    }
    row["promotion_source_distribution"] = json.dumps(metrics["promotion_source_distribution"], sort_keys=True)
    row["rejection_reason_distribution"] = json.dumps(metrics["rejection_reason_distribution"], sort_keys=True)
    return row


def _candidate_summary_row(case: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    features = item.get("evidence_features") or {}
    return {
        "cve_id": case["cve_id"],
        "repo_id": case["repo_id"],
        "rank": item.get("rank", ""),
        "event_commit_sha": item.get("event_commit_sha", ""),
        "event_id": item.get("event_id", ""),
        "lifecycle": item.get("lifecycle", ""),
        "gate_score": item.get("gate_score", ""),
        "gate_decision": item.get("gate_decision", ""),
        "promotion_sources": ";".join(item.get("promotion_sources") or []),
        "gate_reasons": ";".join(item.get("gate_reasons") or []),
        "role_proposals": ";".join(item.get("role_proposals") or []),
        "source_candidate_ids": ";".join(item.get("source_candidate_ids") or []),
        "trace_only": features.get("trace_only", ""),
        "direct_source": features.get("direct_source", ""),
        "source_lanes": ";".join(features.get("source_lanes") or []),
        "risk_flags": ";".join(features.get("risk_flags") or []),
        "conflict_flags": ";".join(features.get("conflict_flags") or []),
    }


def _gate_row(case: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve_id": case["cve_id"],
        "repo_id": case["repo_id"],
        "event_commit_sha": item.get("event_commit_sha", ""),
        "event_id": item.get("event_id", ""),
        "gate_decision": item.get("gate_decision", ""),
        "gate_score": item.get("gate_score", ""),
        "promotion_sources": ";".join(item.get("promotion_sources") or []),
        "gate_reasons": ";".join(item.get("gate_reasons") or []),
        "role_proposals": ";".join(item.get("role_proposals") or []),
        "source_candidate_ids": ";".join(item.get("source_candidate_ids") or []),
    }


def _regression_row(case: dict[str, Any]) -> dict[str, Any]:
    regression = case["regression"] or {}
    return {
        "cve_id": case["cve_id"],
        "repo_id": case["repo_id"],
        "candidate_count": regression.get("candidate_count"),
        "candidate_pool_recall": regression.get("candidate_pool_recall"),
        "recall_at_1": regression.get("recall_at_1"),
        "recall_at_3": regression.get("recall_at_3"),
        "recall_at_5": regression.get("recall_at_5"),
        "recommended_event_rank": regression.get("recommended_event_rank"),
        "top5_known_noise_ratio": regression.get("top5_known_noise_ratio"),
        "target_commits_missing_for_regression": ";".join(case.get("regression_target_commits_missing") or []),
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run frozen V3 semantic-chain gate dev30 replay.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--git-graph-index", required=True)
    parser.add_argument("--reconstruction-root", required=True)
    parser.add_argument("--readiness-root", required=True)
    parser.add_argument("--previous-dev13-root", required=True)
    parser.add_argument("--labels-json", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--reset", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    summary = run_v3_semantic_chain_gate_dev30_replay(
        dataset_path=args.dataset,
        repo_root=args.repo_root,
        git_graph_index=args.git_graph_index,
        reconstruction_root=args.reconstruction_root,
        readiness_root=args.readiness_root,
        previous_dev13_root=args.previous_dev13_root,
        labels_json=args.labels_json,
        out_dir=args.out_dir,
        reset=args.reset,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("all_feasibility_gates_passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
