from __future__ import annotations

import argparse
import csv
import json
import shutil
from collections import Counter
from pathlib import Path
from typing import Any


DEFAULT_CVES = ["CVE-2020-8231", "CVE-2020-11647", "CVE-2020-13904"]
FORBIDDEN_KEYS = {"validated_bic", "correct_bic", "affected_versions", "bic", "ground_truth"}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _short_sha(value: str | None, n: int = 12) -> str:
    if not value:
        return ""
    return value[:n]


def _clip(value: Any, limit: int = 220) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if len(text) <= limit:
        return text
    return text[: limit - 15] + "...[truncated]"


def _true_flags(flags: dict[str, Any]) -> list[str]:
    return [key for key, value in sorted((flags or {}).items()) if bool(value)]


def _top_lines(history_block: dict[str, Any] | None, limit: int = 5) -> list[str]:
    if not history_block:
        return []
    excerpt = str(history_block.get("output_excerpt") or "")
    lines = [line.strip() for line in excerpt.splitlines() if line.strip()]
    return lines[:limit]


def _history_summary(source_packet: dict[str, Any], blind_packet: dict[str, Any]) -> dict[str, Any]:
    log_history = source_packet.get("log_history") or {}
    path_history = source_packet.get("path_history") or {}
    summary = blind_packet.get("history_reconstruction_summary") or {}
    return {
        "variant_agreement": summary.get("variant_agreement")
        or (source_packet.get("blame_variants") or {}).get("variant_agreement", ""),
        "canonical_blame_commit": summary.get("canonical_blame_commit")
        or (source_packet.get("blame_variants") or {}).get("canonical_blame_commit_sha", ""),
        "log_L_top": _top_lines(log_history.get("log_L"), 5),
        "log_S_top": _top_lines(log_history.get("log_S"), 5),
        "log_G_top": _top_lines(log_history.get("log_G"), 5),
        "log_follow_top": _top_lines(path_history.get("log_follow"), 5),
    }


def _blame_variant_summary(source_packet: dict[str, Any]) -> dict[str, Any]:
    blame = source_packet.get("blame_variants") or {}
    variants = blame.get("variants") or []
    by_name: dict[str, dict[str, Any]] = {}
    for item in variants:
        name = str(item.get("variant") or "")
        if name:
            by_name[name] = {
                "status": item.get("status", ""),
                "sha": item.get("blamed_commit_sha", ""),
                "path": item.get("blamed_original_path", ""),
                "line": item.get("blamed_original_line", ""),
                "boundary_marker": bool(item.get("boundary_marker", False)),
                "reason": item.get("reason", ""),
            }
    return {
        "variant_agreement": blame.get("variant_agreement", ""),
        "canonical_blame_commit_sha": blame.get("canonical_blame_commit_sha", ""),
        "normal": by_name.get("normal", {}),
        "w": by_name.get("w", {}),
        "M": by_name.get("M", {}),
        "C": by_name.get("C", {}),
        "unique_blamed_commit_count": blame.get("unique_blamed_commit_count", ""),
        "failure_count": blame.get("failure_count", ""),
    }


def _format_blame_for_csv(summary: dict[str, Any]) -> str:
    parts = [f"agreement={summary.get('variant_agreement')}", f"canonical={_short_sha(summary.get('canonical_blame_commit_sha'))}"]
    for variant in ["normal", "w", "M", "C"]:
        item = summary.get(variant) or {}
        sha = _short_sha(item.get("sha"))
        status = item.get("status", "")
        line = item.get("line", "")
        parts.append(f"{variant}:{status}:{sha}:{line}")
    return "; ".join(parts)


def _relocation_summary(packet: dict[str, Any]) -> dict[str, str]:
    parent = packet.get("parent_anchor_context") or {}
    candidate = packet.get("candidate_anchor_context") or {}
    relocation = packet.get("anchor_relocation") or {}
    candidate_resolution = relocation.get("candidate_resolution") or {}
    parent_resolutions = relocation.get("parent_resolutions") or []
    parent_resolution = parent_resolutions[relocation.get("selected_parent_index", 0)] if parent_resolutions else {}
    return {
        "parent_status": str(parent.get("relocation_status") or parent_resolution.get("status") or ""),
        "parent_strategy": str(parent.get("match_kind") or parent_resolution.get("strategy") or ""),
        "parent_reason": str(parent.get("reason") or parent_resolution.get("reason") or parent_resolution.get("ambiguity_reason") or ""),
        "candidate_status": str(candidate.get("relocation_status") or candidate_resolution.get("status") or ""),
        "candidate_strategy": str(candidate.get("match_kind") or candidate_resolution.get("strategy") or ""),
        "candidate_reason": str(candidate.get("reason") or candidate_resolution.get("reason") or candidate_resolution.get("ambiguity_reason") or ""),
        "parent_verified": str(bool(parent.get("anchor_verified", False))),
        "candidate_verified": str(bool(candidate.get("anchor_verified", False))),
    }


def _first_anchor_line(context: dict[str, Any]) -> dict[str, Any]:
    for line in context.get("lines") or []:
        if line.get("role") == "anchor":
            return line
    return {}


def _candidate_card_reason(packet: dict[str, Any], relocation: dict[str, str], flags: list[str]) -> str:
    source_lane = packet.get("source_lane", "")
    priority = packet.get("recommended_review_priority", "")
    reasons: list[str] = []
    if source_lane == "fallback":
        reasons.append("该候选来自 fallback lane，本身不是模型选择的 strong anchor，需要确认它是否只是上下文/宽泛 hunk。")
    if flags:
        reasons.append("存在冲突标志：" + "、".join(flags[:6]) + "，需要人工判断这些风险是否影响事件标签。")
    if relocation.get("parent_status") != "found" or relocation.get("candidate_status") != "found":
        reasons.append(
            f"relocation 未完全稳定：parent={relocation.get('parent_status')}，candidate={relocation.get('candidate_status')}。"
        )
    if not reasons:
        reasons.append("自动证据链较完整，但仍需人工判断该历史提交是漏洞引入、前置条件、重构还是无关变化。")
    if priority == "P0":
        reasons.append("系统给出的审计优先级为 P0，应优先检查。")
    return " ".join(reasons[:3])


def _candidate_row(cve_id: str, repo_id: str, audit_packet: dict[str, Any]) -> dict[str, Any]:
    packet = audit_packet.get("blind_packet") or {}
    source_packet = audit_packet.get("source_history_event_packet") or {}
    bindings = packet.get("root_cause_bindings") or {}
    event = packet.get("candidate_event_identity") or {}
    flags = _true_flags(packet.get("conflict_flags") or {})
    relocation = _relocation_summary(packet)
    blame = _blame_variant_summary(source_packet)
    history = _history_summary(source_packet, packet)
    parent_context = packet.get("parent_anchor_context") or {}
    candidate_context = packet.get("candidate_anchor_context") or {}
    parent_anchor = _first_anchor_line(parent_context)
    candidate_anchor = _first_anchor_line(candidate_context)
    old_text = bindings.get("anchor_old_line_text") or parent_anchor.get("text") or candidate_anchor.get("text") or ""
    log_parts: list[str] = []
    for name in ["log_L_top", "log_S_top", "log_G_top", "log_follow_top"]:
        values = history.get(name) or []
        if values:
            log_parts.append(f"{name}: " + " | ".join(values[:3]))
    row = {
        "cve_id": cve_id,
        "repo_id": repo_id,
        "candidate_id": packet.get("candidate_id", ""),
        "source_lane": packet.get("source_lane", ""),
        "anchor_path": bindings.get("anchor_path") or packet.get("before_path") or packet.get("after_path") or "",
        "anchor_old_line": bindings.get("anchor_old_line_start", ""),
        "anchor_old_line_text": old_text,
        "candidate_commit_sha": event.get("candidate_commit_sha", ""),
        "selected_parent_sha": event.get("selected_parent_sha", ""),
        "fix_commit_sha": event.get("fix_commit_sha", ""),
        "patch_family_id": bindings.get("patch_family", ""),
        "root_cause_hypothesis_ids": ";".join(bindings.get("root_cause_hypothesis_ids") or []),
        "vulnerable_predicate_ids": ";".join(bindings.get("vulnerable_predicate_ids") or []),
        "fix_predicate_ids": ";".join(bindings.get("fix_predicate_ids") or []),
        "blame_variants_summary": _format_blame_for_csv(blame),
        "log_history_summary": " || ".join(log_parts),
        "relocation_summary": (
            f"parent={relocation['parent_status']}/{relocation['parent_strategy']}; "
            f"candidate={relocation['candidate_status']}/{relocation['candidate_strategy']}"
        ),
        "parent_relocation_status": relocation["parent_status"],
        "candidate_relocation_status": relocation["candidate_status"],
        "parent_relocation_strategy": relocation["parent_strategy"],
        "candidate_relocation_strategy": relocation["candidate_strategy"],
        "anchor_local_diff_exists": str(packet.get("diff_extraction_status") == "found"),
        "conflict_flags": ";".join(flags),
        "suggested_review_priority": packet.get("recommended_review_priority", ""),
        "manual_reason_zh": _candidate_card_reason(packet, relocation, flags),
        "anchor_semantically_valid": "",
        "relocated_context_valid": "",
        "event_label": "",
        "evidence_quality": "",
        "notes": "",
        "_packet": packet,
        "_source_packet": source_packet,
        "_blame": blame,
        "_history": history,
        "_relocation": relocation,
        "_flags": flags,
    }
    return row


def _markdown_candidate_card(index: int, row: dict[str, Any]) -> str:
    blame = row["_blame"]
    history = row["_history"]
    relocation = row["_relocation"]
    lines = [
        f"### Candidate {index}: `{row['candidate_id']}`",
        "",
        f"- source_lane: `{row['source_lane']}`；review priority: `{row['suggested_review_priority']}`",
        f"- anchor: `{row['anchor_path']}:{row['anchor_old_line']}`",
        f"- old line text: `{_clip(row['anchor_old_line_text'], 180)}`",
        f"- candidate commit: `{row['candidate_commit_sha']}`",
        f"- selected parent: `{row['selected_parent_sha']}`",
        f"- fix commit: `{row['fix_commit_sha']}`",
        f"- root cause binding: H=`{row['root_cause_hypothesis_ids']}`；V=`{row['vulnerable_predicate_ids']}`；F=`{row['fix_predicate_ids']}`",
        "",
        "**Blame variants**",
        "",
        f"- agreement: `{blame.get('variant_agreement')}`；canonical: `{blame.get('canonical_blame_commit_sha')}`",
    ]
    for variant in ["normal", "w", "M", "C"]:
        item = blame.get(variant) or {}
        lines.append(
            f"- `{variant}`: status=`{item.get('status','')}` sha=`{item.get('sha','')}` path=`{item.get('path','')}` line=`{item.get('line','')}` boundary=`{item.get('boundary_marker','')}`"
        )
    lines.extend(["", "**History top commits**", ""])
    for title, key in [("log -L", "log_L_top"), ("pickaxe -S", "log_S_top"), ("pickaxe -G", "log_G_top"), ("log --follow", "log_follow_top")]:
        values = history.get(key) or []
        if values:
            lines.append(f"- {title}:")
            for value in values[:5]:
                lines.append(f"  - `{_clip(value, 180)}`")
        else:
            lines.append(f"- {title}: unavailable")
    lines.extend(
        [
            "",
            "**Relocation / local diff**",
            "",
            f"- parent relocation: status=`{relocation['parent_status']}` strategy=`{relocation['parent_strategy']}` verified=`{relocation['parent_verified']}` reason=`{_clip(relocation['parent_reason'], 160)}`",
            f"- candidate relocation: status=`{relocation['candidate_status']}` strategy=`{relocation['candidate_strategy']}` verified=`{relocation['candidate_verified']}` reason=`{_clip(relocation['candidate_reason'], 160)}`",
            f"- anchor-local diff exists: `{row['anchor_local_diff_exists']}`",
            f"- conflict flags: `{row['conflict_flags'] or 'none'}`",
            "",
            "**为什么需要人工判断**",
            "",
            row["manual_reason_zh"],
            "",
            "**人工填写**",
            "",
            "- anchor_semantically_valid: yes / no / uncertain",
            "- relocated_context_valid: yes / no / uncertain",
            "- event_label: vulnerability_introduction / prerequisite / refactor / fix_series / unrelated / uncertain",
            "- evidence_quality: strong / partial / weak / invalid",
            "- notes:",
            "",
        ]
    )
    return "\n".join(lines)


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = [
        "cve_id",
        "repo_id",
        "candidate_id",
        "source_lane",
        "anchor_path",
        "anchor_old_line",
        "anchor_old_line_text",
        "candidate_commit_sha",
        "selected_parent_sha",
        "blame_variants_summary",
        "log_history_summary",
        "relocation_summary",
        "conflict_flags",
        "suggested_review_priority",
        "anchor_semantically_valid",
        "relocated_context_valid",
        "event_label",
        "evidence_quality",
        "notes",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def _write_case_markdown(path: Path, cve_id: str, dataset_entry: dict[str, Any], rows: list[dict[str, Any]], case_summary: dict[str, Any]) -> None:
    repo = dataset_entry.get("repo") or case_summary.get("repo_id") or ""
    fixing_commits = dataset_entry.get("fixing_commits") or []
    cwes = dataset_entry.get("CWE") or dataset_entry.get("cwe") or []
    flag_counter = Counter(flag for row in rows for flag in row["_flags"])
    status_counter = Counter()
    for row in rows:
        status_counter[f"parent:{row['parent_relocation_status']}"] += 1
        status_counter[f"candidate:{row['candidate_relocation_status']}"] += 1
    lines = [
        f"# {cve_id} HistoryEvent 人工审计简报",
        "",
        "> 本材料只整理 `judge_ready_history_event_candidate` 的人工审计信息，不包含最终引入提交结论、版本预测或标签真值。",
        "",
        "## 基本信息",
        "",
        f"- CVE: `{cve_id}`",
        f"- repo: `{repo}`",
        f"- CWE: `{', '.join(cwes) if cwes else 'unavailable'}`",
        f"- fix commit set(s): `{json.dumps(fixing_commits, ensure_ascii=False)}`",
        f"- candidates: {len(rows)}；strong: {sum(1 for r in rows if r['source_lane']=='strong')}；fallback: {sum(1 for r in rows if r['source_lane']=='fallback')}",
        f"- relocation status: `{dict(status_counter)}`",
        f"- conflict flags: `{dict(flag_counter)}`",
        "",
        "## 人工审计问题清单",
        "",
        "对每个 candidate，只需要填写以下字段：",
        "",
        "- anchor_semantically_valid: yes / no / uncertain",
        "- relocated_context_valid: yes / no / uncertain",
        "- event_label: vulnerability_introduction / prerequisite / refactor / fix_series / unrelated / uncertain",
        "- evidence_quality: strong / partial / weak / invalid",
        "- notes: 简短说明依据",
        "",
        "## Candidate 审计卡片",
        "",
    ]
    for index, row in enumerate(rows, start=1):
        lines.append(_markdown_candidate_card(index, row))
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_links(path: Path, cve_id: str, case_dir: Path, recon_dir: Path) -> None:
    files = [
        ("judge blind packets", case_dir / "judge_blind_history_event_packets.json"),
        ("judge audit packets", case_dir / "judge_audit_history_event_packets.json"),
        ("anchor relocation trace", case_dir / "anchor_relocation_trace.json"),
        ("case summary", case_dir / "judge_readiness_case_summary.json"),
        ("history event packets", recon_dir / "history_event_packets.json"),
        ("blame variant trace", recon_dir / "blame_variant_trace.json"),
        ("log history trace", recon_dir / "log_history_trace.json"),
        ("path history trace", recon_dir / "path_history_trace.json"),
        ("candidate event chains", recon_dir / "candidate_event_chains.json"),
    ]
    lines = [f"# {cve_id} raw artifact links", ""]
    for label, item in files:
        if item.exists():
            lines.append(f"- [{label}]({item.resolve()})")
        else:
            lines.append(f"- {label}: missing `{item.resolve()}`")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _evidence_index(rows: list[dict[str, Any]]) -> dict[str, Any]:
    candidates = []
    for row in rows:
        packet = row["_packet"]
        candidates.append(
            {
                "candidate_id": row["candidate_id"],
                "source_lane": row["source_lane"],
                "candidate_commit_sha": row["candidate_commit_sha"],
                "selected_parent_sha": row["selected_parent_sha"],
                "fix_commit_sha": row["fix_commit_sha"],
                "anchor": {
                    "path": row["anchor_path"],
                    "old_line": row["anchor_old_line"],
                    "old_line_text": row["anchor_old_line_text"],
                },
                "blame_variants": row["_blame"],
                "history_top_commits": row["_history"],
                "relocation": row["_relocation"],
                "conflict_flags": row["_flags"],
                "recommended_review_priority": row["suggested_review_priority"],
                "anchor_local_diff_exists": row["anchor_local_diff_exists"] == "True",
                "evidence_refs": {
                    "parent_context": (packet.get("parent_anchor_context") or {}).get("evidence_refs", []),
                    "candidate_context": (packet.get("candidate_anchor_context") or {}).get("evidence_refs", []),
                    "anchor_relocation": (packet.get("anchor_relocation") or {}).get("anchor_reference", {}).get("provenance_refs", []),
                },
                "manual_review_fields": {
                    "anchor_semantically_valid": "",
                    "relocated_context_valid": "",
                    "event_label": "",
                    "evidence_quality": "",
                    "notes": "",
                },
            }
        )
    return {"schema": "selected_manual_history_event_review_v1", "candidates": candidates}


def _priority_score(row: dict[str, Any]) -> tuple[int, int, int, str]:
    priority_map = {"P0": 0, "P1": 1, "P2": 2}
    priority = priority_map.get(str(row.get("suggested_review_priority")), 3)
    unresolved = int(row["parent_relocation_status"] != "found") + int(row["candidate_relocation_status"] != "found")
    fallback = int(row["source_lane"] == "fallback")
    return (priority, -unresolved, -fallback, row["candidate_id"])


def _scan_forbidden_keys(path: Path) -> list[str]:
    violations: list[str] = []
    for item in path.rglob("*"):
        if not item.is_file():
            continue
        if item.suffix.lower() not in {".json", ".csv", ".md"}:
            continue
        text = item.read_text(encoding="utf-8", errors="ignore")
        for key in FORBIDDEN_KEYS:
            if f'"{key}"' in text:
                violations.append(f"{item}:{key}")
    return violations


def build_review(args: argparse.Namespace) -> int:
    cves = args.cves or DEFAULT_CVES
    judge_root = Path(args.judge_readiness_root)
    recon_root = Path(args.reconstruction_root)
    dataset_path = Path(args.dataset)
    out_dir = Path(args.out_dir)
    dataset = _load_json(dataset_path)
    if args.reset and out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_rows: list[dict[str, Any]] = []
    case_summaries: list[dict[str, Any]] = []
    for cve_id in cves:
        case_dir = judge_root / cve_id
        recon_dir = recon_root / cve_id
        if not case_dir.exists():
            raise FileNotFoundError(f"missing judge-readiness case dir: {case_dir}")
        if not recon_dir.exists():
            raise FileNotFoundError(f"missing reconstruction case dir: {recon_dir}")
        dataset_entry = dataset.get(cve_id, {})
        case_summary = _load_json(case_dir / "judge_readiness_case_summary.json")
        audit_packets = _load_json(case_dir / "judge_audit_history_event_packets.json")
        rows = [_candidate_row(cve_id, case_summary.get("repo_id") or dataset_entry.get("repo", ""), packet) for packet in audit_packets]
        rows.sort(key=_priority_score)
        all_rows.extend(rows)

        cve_out = out_dir / cve_id
        cve_out.mkdir(parents=True, exist_ok=True)
        _write_case_markdown(cve_out / "manual_review_brief_zh.md", cve_id, dataset_entry, rows, case_summary)
        _write_csv(cve_out / "candidate_review_table.csv", rows)
        _write_json(cve_out / "candidate_evidence_index.json", _evidence_index(rows))
        _write_links(cve_out / "raw_artifact_links.md", cve_id, case_dir, recon_dir)

        p_counter = Counter(row["suggested_review_priority"] for row in rows)
        status_counter = Counter()
        for row in rows:
            status_counter[row["parent_relocation_status"]] += 1
            status_counter[row["candidate_relocation_status"]] += 1
        case_summaries.append(
            {
                "cve_id": cve_id,
                "repo_id": case_summary.get("repo_id") or dataset_entry.get("repo", ""),
                "candidate_count": len(rows),
                "strong_count": sum(1 for row in rows if row["source_lane"] == "strong"),
                "fallback_count": sum(1 for row in rows if row["source_lane"] == "fallback"),
                "p0_count": p_counter.get("P0", 0),
                "p1_count": p_counter.get("P1", 0),
                "p2_count": p_counter.get("P2", 0),
                "ambiguous_count": status_counter.get("ambiguous", 0),
                "not_found_count": status_counter.get("not_found", 0),
                "path_missing_count": status_counter.get("path_missing", 0),
                "weak_evidence": bool(sum(1 for row in rows if row["source_lane"] == "fallback") or status_counter.get("ambiguous", 0) or status_counter.get("not_found", 0) or status_counter.get("path_missing", 0)),
            }
        )

    # Combined CSV across selected cases.
    _write_csv(out_dir / "candidate_review_table_all.csv", all_rows)
    sorted_rows = sorted(all_rows, key=_priority_score)
    lines = [
        "# selected CVE HistoryEvent 人工审计总报告",
        "",
        "> 本报告只汇总候选历史事件的人工审计材料；未调用模型，未运行 Judge/converter，未生成版本预测。",
        "",
        "## 本次整理的 CVE",
        "",
    ]
    for summary in case_summaries:
        weak = "是" if summary["weak_evidence"] else "否"
        lines.append(
            f"- `{summary['cve_id']}` repo=`{summary['repo_id']}` candidates={summary['candidate_count']} strong={summary['strong_count']} fallback={summary['fallback_count']} P0/P1/P2={summary['p0_count']}/{summary['p1_count']}/{summary['p2_count']} ambiguous/not_found/path_missing={summary['ambiguous_count']}/{summary['not_found_count']}/{summary['path_missing_count']} weak_evidence={weak}"
        )
    lines.extend(["", "## 最建议优先人工看的 candidate", ""])
    for index, row in enumerate(sorted_rows[:20], start=1):
        lines.append(
            f"{index}. `{row['cve_id']}` `{row['candidate_id']}` priority=`{row['suggested_review_priority']}` lane=`{row['source_lane']}` relocation=`{row['relocation_summary']}` flags=`{row['conflict_flags'] or 'none'}`"
        )
    weak_cases = [summary["cve_id"] for summary in case_summaries if summary["weak_evidence"]]
    lines.extend(
        [
            "",
            "## 候选质量较弱的 CVE",
            "",
            "- " + ("、".join(f"`{cve}`" for cve in weak_cases) if weak_cases else "无明显 weak evidence case。"),
            "",
            "## 审计边界",
            "",
            "- 不把 raw / judge-ready candidate 解释为最终引入提交。",
            "- 不输出正式版本预测。",
            "- 不使用 ground truth。",
            "- fallback、ambiguous、not_found、path_missing 均保留给人工判断。",
            "",
        ]
    )
    (out_dir / "manual_review_selected_summary_zh.md").write_text("\n".join(lines), encoding="utf-8")
    _write_json(
        out_dir / "summary.json",
        {
            "schema": "selected_manual_history_event_review_summary_v1",
            "cves": case_summaries,
            "candidate_count": len(all_rows),
            "model_invocation_count": 0,
            "judge_invocation_count": 0,
            "converter_invocation_count": 0,
            "forbidden_key_violations": [],
        },
    )
    violations = _scan_forbidden_keys(out_dir)
    if violations:
        summary_path = out_dir / "summary.json"
        summary = _load_json(summary_path)
        summary["forbidden_key_violations"] = violations
        _write_json(summary_path, summary)
        raise RuntimeError("forbidden key scan failed: " + "; ".join(violations[:10]))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build compact Chinese manual review packets for selected HistoryEvent candidates.")
    parser.add_argument("--judge-readiness-root", default="runs/batches/vulngraph-history-event-judge-readiness-v1-1-anchor-relocation-dev30")
    parser.add_argument("--reconstruction-root", default="runs/batches/vulngraph-history-event-reconstruction-v1-dev30")
    parser.add_argument("--git-graph-index", default="runs/batches/vulngraph-git-graph-index-v1", help="Recorded for interface symmetry; this script does not query Git.")
    parser.add_argument("--dataset", default=r"E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json")
    parser.add_argument("--repo-root", default=r"E:\AI\Agent\workflow\VulnVersion\repo", help="Recorded for interface symmetry; this script does not query Git.")
    parser.add_argument("--out-dir", default="runs/batches/vulngraph-manual-history-event-review-selected")
    parser.add_argument("--cves", nargs="*", default=DEFAULT_CVES)
    parser.add_argument("--reset", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(build_review(parse_args()))
