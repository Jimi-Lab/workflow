from __future__ import annotations

import argparse
import csv
import json
import shutil
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.build_selected_manual_history_event_review import (
    FORBIDDEN_KEYS,
    _candidate_row,
    _evidence_index,
    _load_json,
    _priority_score,
    _scan_forbidden_keys,
    _write_case_markdown,
    _write_csv,
    _write_json,
    _write_links,
)


EXCLUDED_REVIEWED_CVES = {"CVE-2020-8231", "CVE-2020-11647", "CVE-2020-13904"}

REQUIRED_COVERAGE_TYPES = [
    "strong_lane_ready",
    "fallback_only",
    "mixed_strong_fallback",
    "blame_variant_disagreement",
    "whitespace_sensitive",
    "move_copy_sensitive",
    "relocation_problem",
    "add_only_or_weak_old_side",
    "merge_equivalent_or_multi_fix",
    "multi_branch_or_release_line_complex",
    "clean_low_noise",
]

COVERAGE_TYPE_ZH = {
    "strong_lane_ready": "strong lane 候选可用样本",
    "fallback_only": "fallback-only 样本",
    "mixed_strong_fallback": "strong + fallback 混合样本",
    "blame_variant_disagreement": "blame variant 分歧样本",
    "whitespace_sensitive": "whitespace-sensitive 样本",
    "move_copy_sensitive": "move/copy-sensitive 样本",
    "relocation_problem": "relocation ambiguous / not_found / path_missing 样本",
    "add_only_or_weak_old_side": "add-only 或 weak old-side evidence 样本",
    "merge_equivalent_or_multi_fix": "merge / equivalent-fix / multi-fix 样本",
    "multi_branch_or_release_line_complex": "multi-branch / release-line complex 样本",
    "clean_low_noise": "clean low-noise sanity 样本",
}


@dataclass(frozen=True)
class SelectionFeature:
    cve_id: str
    repo_id: str
    candidate_count: int
    strong_count: int
    fallback_count: int
    fix_commit_count: int
    has_blame_disagreement: bool
    has_whitespace_sensitive: bool
    has_move_copy_sensitive: bool
    has_boundary_or_merge_candidate: bool
    has_ambiguous_relocation: bool
    has_not_found_or_path_missing: bool
    has_parent_absent_by_event: bool
    has_large_fallback_pool: bool
    has_anchor_local_diff: bool
    has_log_L_signal: bool
    has_pickaxe_signal: bool
    selection_types: set[str] = field(default_factory=set)
    reasons_zh: list[str] = field(default_factory=list)
    priority_counts: dict[str, int] = field(default_factory=dict)
    relocation_status_counts: dict[str, int] = field(default_factory=dict)


def _flatten_fixing_commits(entry: dict[str, Any]) -> list[str]:
    commits: list[str] = []
    for group in entry.get("fixing_commits") or []:
        if isinstance(group, list):
            commits.extend(str(item) for item in group if item)
        elif group:
            commits.append(str(group))
    return sorted(set(commits))


def _load_selected_taxonomy(selected_review_root: Path) -> dict[str, Any]:
    taxonomy: dict[str, Any] = {
        "available": False,
        "reference_cases": [],
        "summary": {},
        "notes": [],
    }
    labels_path = selected_review_root / "manual_semantic_labels_v1.json"
    report_path = selected_review_root / "manual_semantic_audit_report_zh.md"
    csv_path = selected_review_root / "manual_semantic_labels_v1.csv"
    taxonomy["files_checked"] = {
        "manual_semantic_labels_v1.json": labels_path.exists(),
        "manual_semantic_audit_report_zh.md": report_path.exists(),
        "manual_semantic_labels_v1.csv": csv_path.exists(),
    }
    if labels_path.exists():
        labels = _load_json(labels_path)
        taxonomy["available"] = True
        taxonomy["summary"] = labels.get("summary", {})
        taxonomy["reference_cases"] = [
            {
                "cve_id": case.get("cve_id", ""),
                "repo_id": case.get("repo_id", ""),
                "case_verdict": case.get("case_verdict", ""),
                "main_failure_or_risk": case.get("main_failure_or_risk", ""),
            }
            for case in labels.get("cases", [])
        ]
    if report_path.exists():
        taxonomy["notes"].append("manual_semantic_audit_report_zh.md 已存在，作为中文 taxonomy 参考。")
    if csv_path.exists():
        taxonomy["notes"].append("manual_semantic_labels_v1.csv 已存在，未修改。")
    return taxonomy


def _derive_selection_types(
    *,
    candidate_count: int,
    strong_count: int,
    fallback_count: int,
    fix_commit_count: int,
    flags: Counter[str],
    relocation_statuses: Counter[str],
    has_anchor_local_diff: bool,
) -> set[str]:
    types: set[str] = set()
    if strong_count > 0:
        types.add("strong_lane_ready")
    if fallback_count > 0 and strong_count == 0:
        types.add("fallback_only")
    if fallback_count > 0 and strong_count > 0:
        types.add("mixed_strong_fallback")
    if flags.get("blame_variant_disagreement", 0) > 0:
        types.add("blame_variant_disagreement")
    if flags.get("whitespace_sensitive", 0) > 0:
        types.add("whitespace_sensitive")
    if flags.get("move_copy_sensitive", 0) > 0:
        types.add("move_copy_sensitive")
    if (
        relocation_statuses.get("ambiguous", 0) > 0
        or relocation_statuses.get("not_found", 0) > 0
        or relocation_statuses.get("path_missing", 0) > 0
    ):
        types.add("relocation_problem")
    if relocation_statuses.get("absent_by_event", 0) > 0 or fallback_count > 0:
        types.add("add_only_or_weak_old_side")
    if fix_commit_count > 1 or flags.get("merge_candidate", 0) > 0 or flags.get("boundary_candidate", 0) > 0:
        types.add("merge_equivalent_or_multi_fix")
    if fix_commit_count > 1 or flags.get("boundary_candidate", 0) > 0:
        types.add("multi_branch_or_release_line_complex")
    if (
        candidate_count <= 2
        and strong_count > 0
        and fallback_count == 0
        and not flags
        and has_anchor_local_diff
        and relocation_statuses.get("ambiguous", 0) == 0
        and relocation_statuses.get("not_found", 0) == 0
        and relocation_statuses.get("path_missing", 0) == 0
    ):
        types.add("clean_low_noise")
    return types


def _reason_text(feature: SelectionFeature) -> list[str]:
    reasons: list[str] = []
    for coverage_type in REQUIRED_COVERAGE_TYPES:
        if coverage_type in feature.selection_types:
            reasons.append(f"覆盖 {COVERAGE_TYPE_ZH[coverage_type]}")
    if feature.repo_id:
        reasons.append(f"补充 repo 维度：{feature.repo_id}")
    if feature.candidate_count:
        reasons.append(
            f"候选池规模={feature.candidate_count}，strong={feature.strong_count}，fallback={feature.fallback_count}"
        )
    return reasons


def compute_selection_feature(
    cve_id: str,
    dataset_entry: dict[str, Any],
    audit_packets: list[dict[str, Any]],
    case_summary: dict[str, Any],
) -> SelectionFeature:
    rows = [
        _candidate_row(cve_id, case_summary.get("repo_id") or dataset_entry.get("repo", ""), packet)
        for packet in audit_packets
    ]
    flag_counter = Counter(flag for row in rows for flag in row["_flags"])
    relocation_counter = Counter()
    priority_counter = Counter()
    has_log_l = False
    has_pickaxe = False
    has_anchor_local_diff = False
    for row in rows:
        relocation_counter[row["parent_relocation_status"]] += 1
        relocation_counter[row["candidate_relocation_status"]] += 1
        priority_counter[row["suggested_review_priority"]] += 1
        has_anchor_local_diff = has_anchor_local_diff or row["anchor_local_diff_exists"] == "True"
        has_log_l = has_log_l or bool((row["_history"] or {}).get("log_L_top"))
        has_pickaxe = has_pickaxe or bool((row["_history"] or {}).get("log_S_top") or (row["_history"] or {}).get("log_G_top"))
    fix_count = len(_flatten_fixing_commits(dataset_entry))
    strong_count = int(case_summary.get("strong_candidate_count", sum(1 for row in rows if row["source_lane"] == "strong")))
    fallback_count = int(case_summary.get("fallback_candidate_count", sum(1 for row in rows if row["source_lane"] == "fallback")))
    candidate_count = len(rows)
    types = _derive_selection_types(
        candidate_count=candidate_count,
        strong_count=strong_count,
        fallback_count=fallback_count,
        fix_commit_count=fix_count,
        flags=flag_counter,
        relocation_statuses=relocation_counter,
        has_anchor_local_diff=has_anchor_local_diff,
    )
    feature = SelectionFeature(
        cve_id=cve_id,
        repo_id=case_summary.get("repo_id") or dataset_entry.get("repo", ""),
        candidate_count=candidate_count,
        strong_count=strong_count,
        fallback_count=fallback_count,
        fix_commit_count=fix_count,
        has_blame_disagreement=flag_counter.get("blame_variant_disagreement", 0) > 0,
        has_whitespace_sensitive=flag_counter.get("whitespace_sensitive", 0) > 0,
        has_move_copy_sensitive=flag_counter.get("move_copy_sensitive", 0) > 0,
        has_boundary_or_merge_candidate=flag_counter.get("boundary_candidate", 0) > 0
        or flag_counter.get("merge_candidate", 0) > 0
        or flag_counter.get("root_candidate", 0) > 0,
        has_ambiguous_relocation=relocation_counter.get("ambiguous", 0) > 0,
        has_not_found_or_path_missing=relocation_counter.get("not_found", 0) > 0
        or relocation_counter.get("path_missing", 0) > 0,
        has_parent_absent_by_event=relocation_counter.get("absent_by_event", 0) > 0,
        has_large_fallback_pool=fallback_count >= 3,
        has_anchor_local_diff=has_anchor_local_diff,
        has_log_L_signal=has_log_l,
        has_pickaxe_signal=has_pickaxe,
        selection_types=types,
        reasons_zh=[],
        priority_counts=dict(priority_counter),
        relocation_status_counts=dict(relocation_counter),
    )
    return SelectionFeature(**{**asdict(feature), "reasons_zh": _reason_text(feature), "selection_types": types})


def collect_dev30_features(
    judge_readiness_root: Path,
    dataset: dict[str, Any],
) -> dict[str, SelectionFeature]:
    features: dict[str, SelectionFeature] = {}
    for case_dir in sorted(judge_readiness_root.iterdir()):
        if not case_dir.is_dir() or not case_dir.name.startswith("CVE-"):
            continue
        cve_id = case_dir.name
        audit_path = case_dir / "judge_audit_history_event_packets.json"
        summary_path = case_dir / "judge_readiness_case_summary.json"
        if not audit_path.exists() or not summary_path.exists():
            continue
        features[cve_id] = compute_selection_feature(
            cve_id,
            dataset.get(cve_id, {}),
            _load_json(audit_path),
            _load_json(summary_path),
        )
    return features


def _feature_score(
    feature: SelectionFeature,
    selected: list[str],
    covered_types: set[str],
    repo_counts: Counter[str],
) -> tuple[int, int, int, int, int, str]:
    new_types = len(feature.selection_types - covered_types)
    repo_penalty = repo_counts[feature.repo_id]
    rare_problem_bonus = int(feature.has_blame_disagreement) + int(feature.has_move_copy_sensitive) + int(
        feature.has_not_found_or_path_missing
    )
    signal_bonus = int(feature.has_log_L_signal) + int(feature.has_pickaxe_signal) + int(feature.has_anchor_local_diff)
    fallback_bonus = int(feature.fallback_count > 0)
    return (new_types * 100 + rare_problem_bonus * 10 + signal_bonus + fallback_bonus, -repo_penalty, feature.fix_commit_count, feature.candidate_count, -len(selected), feature.cve_id)


def select_representative_cves(
    features: dict[str, SelectionFeature],
    *,
    exclude: set[str] = EXCLUDED_REVIEWED_CVES,
    count: int = 10,
) -> tuple[list[str], dict[str, Any]]:
    selected: list[str] = []
    covered_types: set[str] = set()
    repo_counts: Counter[str] = Counter()
    candidates = {cve_id: feature for cve_id, feature in features.items() if cve_id not in exclude}

    while len(selected) < count and candidates:
        best = max(
            candidates.values(),
            key=lambda feature: _feature_score(feature, selected, covered_types, repo_counts),
        )
        selected.append(best.cve_id)
        covered_types.update(best.selection_types)
        repo_counts[best.repo_id] += 1
        candidates.pop(best.cve_id, None)

    reused_reference: list[str] = []
    if len(selected) < count:
        for cve_id in sorted(exclude):
            if cve_id in features and cve_id not in selected:
                selected.append(cve_id)
                reused_reference.append(cve_id)
                covered_types.update(features[cve_id].selection_types)
                if len(selected) >= count:
                    break

    coverage = {
        "selected_count": len(selected),
        "covered_types": sorted(covered_types),
        "covered_type_count": len(covered_types),
        "missing_types": [item for item in REQUIRED_COVERAGE_TYPES if item not in covered_types],
        "repo_counts": dict(repo_counts),
        "reference_reuse_count": len(reused_reference),
        "reference_reused_cves": reused_reference,
    }
    return selected[:count], coverage


def compute_available_coverage_types(features: dict[str, SelectionFeature], *, exclude: set[str]) -> dict[str, list[str]]:
    available: dict[str, list[str]] = {coverage_type: [] for coverage_type in REQUIRED_COVERAGE_TYPES}
    for cve_id, feature in features.items():
        if cve_id in exclude:
            continue
        for coverage_type in feature.selection_types:
            if coverage_type in available:
                available[coverage_type].append(cve_id)
    return {coverage_type: sorted(cves) for coverage_type, cves in available.items()}


def _feature_to_public_dict(feature: SelectionFeature) -> dict[str, Any]:
    data = asdict(feature)
    data["selection_types"] = sorted(feature.selection_types)
    return data


def _write_feature_csv(path: Path, selected: list[str], features: dict[str, SelectionFeature]) -> None:
    fields = [
        "cve_id",
        "repo_id",
        "candidate_count",
        "strong_count",
        "fallback_count",
        "fix_commit_count",
        "has_blame_disagreement",
        "has_whitespace_sensitive",
        "has_move_copy_sensitive",
        "has_boundary_or_merge_candidate",
        "has_ambiguous_relocation",
        "has_not_found_or_path_missing",
        "has_parent_absent_by_event",
        "has_large_fallback_pool",
        "has_anchor_local_diff",
        "has_log_L_signal",
        "has_pickaxe_signal",
        "selection_types",
        "selection_reason_zh",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for cve_id in selected:
            feature = features[cve_id]
            writer.writerow(
                {
                    **{field: getattr(feature, field) for field in fields if hasattr(feature, field)},
                    "selection_types": ";".join(sorted(feature.selection_types)),
                    "selection_reason_zh": "；".join(feature.reasons_zh),
                }
            )


def _write_selection_reason(path: Path, feature: SelectionFeature) -> None:
    lines = [
        f"# {feature.cve_id} selection reason",
        "",
        "## 为什么选中",
        "",
    ]
    for reason in feature.reasons_zh:
        lines.append(f"- {reason}")
    lines.extend(
        [
            "",
            "## 深度审计重点",
            "",
            "- 判断候选 anchor 是否真正表达漏洞语义，而不是只是补丁附近上下文。",
            "- 判断 relocation 后的 parent/candidate 上下文是否可信。",
            "- 判断历史提交更像漏洞引入、前置条件、重构、fix-series 还是无关变化。",
            "- 如果是 fallback 或 relocation problem，需要显式标注证据弱点。",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_summary(
    path: Path,
    selected: list[str],
    features: dict[str, SelectionFeature],
    coverage: dict[str, Any],
    taxonomy: dict[str, Any],
) -> None:
    lines = [
        "# representative 10 HistoryEvent 人工审计集",
        "",
        "> 本目录是 deterministic artifact selection 结果；未调用模型，未运行 Judge/converter，未生成版本预测。",
        "",
        "## 已审计参考 taxonomy",
        "",
    ]
    if taxonomy.get("available"):
        for case in taxonomy.get("reference_cases", []):
            lines.append(
                f"- `{case.get('cve_id')}` repo=`{case.get('repo_id')}` verdict=`{case.get('case_verdict')}` risk=`{case.get('main_failure_or_risk')}`"
            )
    else:
        lines.append("- 未找到可解析的 selected semantic labels，仅使用 dev30 artifact features。")
    lines.extend(["", "## 入选 CVE", ""])
    for cve_id in selected:
        feature = features[cve_id]
        lines.append(
            f"- `{cve_id}` repo=`{feature.repo_id}` candidates={feature.candidate_count} strong={feature.strong_count} fallback={feature.fallback_count} types=`{';'.join(sorted(feature.selection_types))}`"
        )
    lines.extend(["", "## Coverage Matrix", ""])
    for coverage_type in REQUIRED_COVERAGE_TYPES:
        hits = [cve_id for cve_id in selected if coverage_type in features[cve_id].selection_types]
        if hits:
            lines.append(f"- {COVERAGE_TYPE_ZH[coverage_type]}: " + "、".join(f"`{item}`" for item in hits))
        elif coverage_type in coverage.get("unavailable_types", []):
            lines.append(f"- {COVERAGE_TYPE_ZH[coverage_type]}: dev30 排除已审 CVE 后无可选样本")
        else:
            lines.append(f"- {COVERAGE_TYPE_ZH[coverage_type]}: 未覆盖")
    lines.extend(
        [
            "",
            "## Reference Reuse",
            "",
            f"- reused_count: {coverage.get('reference_reuse_count', 0)}",
            f"- reused_cves: `{coverage.get('reference_reused_cves', [])}`",
            "",
            "## 审计边界",
            "",
            "- 不替人工填写 event_label。",
            "- 不把候选历史事件解释为最终结论。",
            "- 不使用标签真值写 selection 规则。",
            "- fallback、ambiguous、not_found、path_missing 不隐藏，保留给人工判断。",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_algorithm_notes(path: Path) -> None:
    lines = [
        "# Selection Algorithm Notes",
        "",
        "## 输入",
        "",
        "- dev30 Judge-readiness / anchor relocation artifacts",
        "- History Event reconstruction artifacts",
        "- BaseDataSet_30 中的 repo / CWE / fixing_commits 元数据",
        "- 既有 3-CVE manual semantic labels 仅作为 taxonomy reference，不参与打标签",
        "",
        "## 特征",
        "",
    ]
    for coverage_type in REQUIRED_COVERAGE_TYPES:
        lines.append(f"- `{coverage_type}`: {COVERAGE_TYPE_ZH[coverage_type]}")
    lines.extend(
        [
            "",
            "## 贪心策略",
            "",
            "1. 默认排除已审计的 CVE-2020-8231、CVE-2020-11647、CVE-2020-13904。",
            "2. 每轮选择能带来最多新增 coverage type 的 CVE。",
            "3. 对 blame/move-copy/relocation 这类稀有问题给轻微 bonus。",
            "4. 对同 repo 过度集中做 penalty。",
            "5. 如果 dev30 不能选满，才复用已审计 CVE，并在 manifest 中记录。",
            "",
            "## 禁止事项",
            "",
            "- 不调用模型。",
            "- 不运行 Judge 或 converter。",
            "- 不使用标签真值或版本标签构造规则。",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def build_representative_review(
    *,
    judge_readiness_root: Path,
    reconstruction_root: Path,
    selected_review_root: Path,
    dataset_path: Path,
    out_dir: Path,
    count: int = 10,
    reset: bool = False,
) -> dict[str, Any]:
    dataset = _load_json(dataset_path)
    taxonomy = _load_selected_taxonomy(selected_review_root)
    features = collect_dev30_features(judge_readiness_root, dataset)
    selected, coverage = select_representative_cves(features, exclude=EXCLUDED_REVIEWED_CVES, count=count)
    available_types = compute_available_coverage_types(features, exclude=EXCLUDED_REVIEWED_CVES)
    coverage["available_types"] = available_types
    coverage["unavailable_types"] = [
        coverage_type for coverage_type in REQUIRED_COVERAGE_TYPES if not available_types.get(coverage_type)
    ]
    if reset and out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_rows: list[dict[str, Any]] = []
    for cve_id in selected:
        case_dir = judge_readiness_root / cve_id
        recon_dir = reconstruction_root / cve_id
        dataset_entry = dataset.get(cve_id, {})
        case_summary = _load_json(case_dir / "judge_readiness_case_summary.json")
        audit_packets = _load_json(case_dir / "judge_audit_history_event_packets.json")
        rows = [
            _candidate_row(cve_id, case_summary.get("repo_id") or dataset_entry.get("repo", ""), packet)
            for packet in audit_packets
        ]
        rows.sort(key=_priority_score)
        all_rows.extend(rows)
        cve_out = out_dir / cve_id
        cve_out.mkdir(parents=True, exist_ok=True)
        _write_case_markdown(cve_out / "manual_review_brief_zh.md", cve_id, dataset_entry, rows, case_summary)
        _write_csv(cve_out / "candidate_review_table.csv", rows)
        _write_json(cve_out / "candidate_evidence_index.json", _evidence_index(rows))
        _write_links(cve_out / "raw_artifact_links.md", cve_id, case_dir, recon_dir)
        _write_selection_reason(cve_out / "selection_reason_zh.md", features[cve_id])
        _write_json(cve_out / "selection_features.json", _feature_to_public_dict(features[cve_id]))

    _write_csv(out_dir / "representative_10_candidate_review_table_all.csv", sorted(all_rows, key=_priority_score))
    _write_feature_csv(out_dir / "representative_10_selection_features.csv", selected, features)
    _write_summary(out_dir / "representative_10_summary_zh.md", selected, features, coverage, taxonomy)
    _write_algorithm_notes(out_dir / "selection_algorithm_notes.md")
    manifest = {
        "schema": "representative_manual_history_event_review_v1",
        "selected_count": len(selected),
        "selected_cves": selected,
        "excluded_reviewed_cves": sorted(EXCLUDED_REVIEWED_CVES),
        "coverage": coverage,
        "taxonomy_reference": taxonomy,
        "model_invocation_count": 0,
        "judge_invocation_count": 0,
        "converter_invocation_count": 0,
        "forbidden_key_violations": [],
        "features": {cve_id: _feature_to_public_dict(features[cve_id]) for cve_id in selected},
    }
    _write_json(out_dir / "representative_10_manifest.json", manifest)
    violations = _scan_forbidden_keys(out_dir)
    if violations:
        manifest["forbidden_key_violations"] = violations
        _write_json(out_dir / "representative_10_manifest.json", manifest)
        raise RuntimeError("forbidden key scan failed: " + "; ".join(violations[:10]))
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build representative 10-CVE manual HistoryEvent review package.")
    parser.add_argument("--dataset", default=r"E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json")
    parser.add_argument("--git-graph-index", default=r"E:\AI\Agent\workflow\VulnGraph\runs\batches\vulngraph-git-graph-index-v1")
    parser.add_argument("--reconstruction-root", default=r"E:\AI\Agent\workflow\VulnGraph\runs\batches\vulngraph-history-event-reconstruction-v1-dev30")
    parser.add_argument("--judge-readiness-root", default=r"E:\AI\Agent\workflow\VulnGraph\runs\batches\vulngraph-history-event-judge-readiness-v1-1-anchor-relocation-dev30")
    parser.add_argument("--selected-review-root", default=r"E:\AI\Agent\workflow\VulnGraph\runs\batches\vulngraph-manual-history-event-review-selected")
    parser.add_argument("--out-dir", default=r"E:\AI\Agent\workflow\VulnGraph\runs\batches\vulngraph-manual-history-event-review-representative-10")
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--reset", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    _ = Path(args.git_graph_index)
    build_representative_review(
        judge_readiness_root=Path(args.judge_readiness_root),
        reconstruction_root=Path(args.reconstruction_root),
        selected_review_root=Path(args.selected_review_root),
        dataset_path=Path(args.dataset),
        out_dir=Path(args.out_dir),
        count=args.count,
        reset=args.reset,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
