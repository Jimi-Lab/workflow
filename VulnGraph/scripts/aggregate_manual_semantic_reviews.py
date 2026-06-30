from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any


CSV_FIELDS = [
    "cve_id",
    "repo_id",
    "candidate_id",
    "candidate_commit_sha",
    "canonical_or_related_commit_sha",
    "source_lane",
    "manual_event_label",
    "manual_confidence",
    "anchor_semantically_valid",
    "relocated_context_valid",
    "is_recommended_intro",
    "manual_evidence_quality",
    "manual_notes",
]


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: Any) -> None:
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _display(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _candidate_source_lanes(case_dir: Path) -> dict[str, str]:
    table = case_dir / "candidate_review_table.csv"
    if not table.exists():
        return {}
    with table.open("r", encoding="utf-8-sig", newline="") as handle:
        return {
            row.get("candidate_id", ""): row.get("source_lane", "")
            for row in csv.DictReader(handle)
        }


def _load_cases(root: Path) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for case_dir in sorted(root.glob("CVE-*"), key=lambda path: path.name):
        labels_path = case_dir / "manual_semantic_labels_v1.json"
        audit_path = case_dir / "manual_semantic_audit_v1_zh.md"
        if not labels_path.exists() or not audit_path.exists():
            continue
        case = _load_json(labels_path)
        labels = case.get("labels")
        if not isinstance(labels, list):
            raise ValueError(f"{labels_path}: labels must be a list")
        lanes = _candidate_source_lanes(case_dir)
        for label in labels:
            label["source_lane"] = lanes.get(label.get("candidate_id", ""), "")
        case["audit_artifact"] = f"{case_dir.name}/manual_semantic_audit_v1_zh.md"
        cases.append(case)
    return cases


def _csv_rows(cases: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for case in cases:
        for label in case["labels"]:
            rows.append(
                {
                    "cve_id": case["cve_id"],
                    "repo_id": case["repo_id"],
                    "candidate_id": label.get("candidate_id", ""),
                    "candidate_commit_sha": label.get("candidate_commit_sha", ""),
                    "canonical_or_related_commit_sha": label.get(
                        "canonical_or_related_commit_sha", ""
                    ),
                    "source_lane": label.get("source_lane", ""),
                    "manual_event_label": label.get("manual_event_label", ""),
                    "manual_confidence": label.get("confidence", ""),
                    "anchor_semantically_valid": _display(
                        label.get("anchor_semantically_valid")
                    ),
                    "relocated_context_valid": _display(
                        label.get("relocated_context_valid")
                    ),
                    "is_recommended_intro": _display(
                        label.get("is_recommended_intro", False)
                    ),
                    "manual_evidence_quality": label.get("evidence_quality", ""),
                    "manual_notes": label.get("notes", ""),
                }
            )
    return rows


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def _summary(cases: list[dict[str, Any]], rows: list[dict[str, str]]) -> dict[str, Any]:
    label_counts = Counter(row["manual_event_label"] for row in rows)
    lane_counts = Counter(row["source_lane"] or "unknown" for row in rows)
    recommended_rows = [row for row in rows if row["is_recommended_intro"] == "true"]
    missing_event_cases = [
        case["cve_id"] for case in cases if "missing_history_event" in case
    ]
    unresolved_cases = [
        case["cve_id"]
        for case in cases
        if not case.get("recommended_introduction_commits")
    ]
    return {
        "label_counts": dict(sorted(label_counts.items())),
        "source_lane_counts": dict(sorted(lane_counts.items())),
        "recommended_candidate_count": len(recommended_rows),
        "cases_with_recommended_boundary": sum(
            bool(case.get("recommended_introduction_commits")) for case in cases
        ),
        "candidate_materialization_miss_cases": missing_event_cases,
        "no_unique_recommended_boundary_cases": unresolved_cases,
    }


def _aggregate_json(
    cases: list[dict[str, Any]],
    rows: list[dict[str, str]],
) -> dict[str, Any]:
    aggregate_cases = []
    for case in cases:
        item = {key: value for key, value in case.items() if key != "labels"}
        item["candidates"] = case["labels"]
        aggregate_cases.append(item)
    return {
        "schema": "manual_semantic_labels_v1",
        "created_at": date.today().isoformat(),
        "label_source": (
            "AI-assisted expert audit from local artifacts, targeted Git evidence, "
            "and explicitly cited upstream evidence where recorded"
        ),
        "gold_status": (
            "preliminary_semantic_label; suitable for engineering gates; "
            "promote to paper gold only after review policy is frozen"
        ),
        "cases_total": len(cases),
        "candidates_total": len(rows),
        "summary": _summary(cases, rows),
        "cases": aggregate_cases,
    }


def _report(
    cases: list[dict[str, Any]],
    rows: list[dict[str, str]],
) -> str:
    summary = _summary(cases, rows)
    label_counts = summary["label_counts"]
    lines = [
        "# Manual Semantic Audit v1 汇总",
        "",
        "本报告聚合各 CVE 子目录中已经冻结的 `manual_semantic_labels_v1.json`。",
        "它不重新执行 Root Cause、SZZ、Judge 或版本转换，也不改写逐案例判断。",
        "",
        "## 总体统计",
        "",
        f"- CVE cases：`{len(cases)}`",
        f"- candidate labels：`{len(rows)}`",
        f"- candidate 中被推荐为 introduction：`{summary['recommended_candidate_count']}`",
        f"- 存在推荐 boundary 的 cases：`{summary['cases_with_recommended_boundary']}/{len(cases)}`",
        "- source lane：" + "，".join(
            f"`{key}={value}`"
            for key, value in summary["source_lane_counts"].items()
        ),
        "",
        "## Case 结论",
        "",
        "| CVE | Repo | Candidates | Recommended boundary | Case verdict |",
        "|---|---|---:|---|---|",
    ]
    for case in cases:
        commits = case.get("recommended_introduction_commits") or []
        boundary = "<br>".join(f"`{sha}`" for sha in commits) if commits else "none"
        lines.append(
            f"| [{case['cve_id']}]({case['audit_artifact']}) "
            f"| {case['repo_id']} | {len(case['labels'])} | {boundary} "
            f"| `{case['case_verdict']}` |"
        )
    lines.extend(
        [
            "",
            "## Candidate 标签分布",
            "",
            "| Label | Count |",
            "|---|---:|",
        ]
    )
    for label, count in label_counts.items():
        lines.append(f"| `{label}` | {count} |")
    lines.extend(
        [
            "",
            "## 关键失败类型",
            "",
            "- Candidate materialization 已发现历史信号但遗漏正确事件："
            + (
                "、".join(
                    f"`{cve}`"
                    for cve in summary["candidate_materialization_miss_cases"]
                )
                or "无"
            ),
            "- 当前证据无法给出唯一 recommended boundary："
            + (
                "、".join(
                    f"`{cve}`"
                    for cve in summary["no_unique_recommended_boundary_cases"]
                )
                or "无"
            ),
            "- 其他 case 的详细 anchor、event-chain 和 commit 语义依据见各 CVE 中文审计文件。",
            "",
            "## 使用边界",
            "",
            "- 这些标签是 AI-assisted expert audit，不因文件名为 manual 就自动成为论文 gold。",
            "- `recommended_introduction_commits` 可以作为工程回归门，但不等同于最终 affected versions。",
            "- root/history-censored 与 feature-series case 不应被强制压成单一 BIC。",
            "- 聚合 CSV 只包含输入 candidate；`missing_history_event` 等非候选事件保留在 JSON 和逐案例报告中。",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Aggregate frozen per-CVE manual semantic review artifacts."
    )
    parser.add_argument(
        "--root",
        default="runs/batches/vulngraph-manual-history-event-review-selected",
    )
    args = parser.parse_args()
    root = Path(args.root)
    cases = _load_cases(root)
    if not cases:
        raise RuntimeError(f"no complete CVE semantic reviews found under {root}")
    rows = _csv_rows(cases)
    _write_json(root / "manual_semantic_labels_v1.json", _aggregate_json(cases, rows))
    _write_csv(root / "manual_semantic_labels_v1.csv", rows)
    (root / "manual_semantic_audit_report_zh.md").write_text(
        _report(cases, rows),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
