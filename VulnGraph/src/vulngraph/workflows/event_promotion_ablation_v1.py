from __future__ import annotations

import argparse
import csv
import json
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median
from typing import Any

from vulngraph.workflows.history_event_reconstruction_v1 import load_dataset_metadata_without_gt
from vulngraph.workflows.semantic_event_chain_reconstruction_v1 import (
    FORBIDDEN_OUTPUT_FIELDS,
    SEMANTIC_EVENT_LIFECYCLE,
    _expand_short_sha,
    _is_full_sha,
    _is_invalid_structural_anchor,
    _sha256,
    _top_commits,
    collect_fix_messages,
    parse_fixes_trailer_targets,
)


ABLATION_SCHEMA_VERSION = "dev13_event_promotion_ablation_v1"
VARIANTS = [
    "V0_direct",
    "V1_broad_expansion",
    "V2_gate_only",
    "V3_semantic_chain_plus_gate",
]
LABEL_LEAKAGE_KEYS = {
    "manual_event_label",
    "is_recommended_intro",
    "recommended_introduction_commits",
    "missing_history_event",
    "candidate_pool_recall",
}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


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


def _norm_sha(value: Any) -> str:
    value = str(value or "").lower()
    return value if _is_full_sha(value) else ""


def _event_id(cve_id: str, variant: str, sha: str) -> str:
    return f"event-promotion:{variant}:{cve_id}:{sha[:12]}"


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
    }.get(source, "trace_evidence")


def _candidate_anchor(packet: dict[str, Any]) -> tuple[str, str]:
    origin = packet.get("candidate_origin") or {}
    return str(origin.get("old_line_text") or ""), str(origin.get("anchor_path") or "")


def _is_noise_path(path: str) -> bool:
    lowered = (path or "").replace("\\", "/").lower()
    markers = [
        "/test",
        "tests/",
        "/doc",
        "docs/",
        "makefile",
        "fate/",
        "samples/",
        "changelog",
        ".md",
        ".txt",
    ]
    return any(marker in lowered for marker in markers)


def _packet_sources(packet: dict[str, Any], *, include_trace: bool) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    candidate_sha = _norm_sha((packet.get("candidate_event") or {}).get("candidate_commit_sha"))
    if candidate_sha:
        pairs.append(("direct_candidate", candidate_sha))
    for variant in (packet.get("blame_variants") or {}).get("variants") or []:
        sha = _norm_sha(variant.get("blamed_commit_sha"))
        if sha:
            pairs.append((f"blame_{variant.get('variant')}", sha))
    if not include_trace:
        return pairs
    log_history = packet.get("log_history") or {}
    for key in ["log_L", "log_S", "log_G"]:
        for sha in _top_commits(log_history.get(key)):
            pairs.append((key, sha))
    for sha in _top_commits((packet.get("path_history") or {}).get("log_follow")):
        pairs.append(("log_follow", sha))
    return pairs


def _new_event(cve_id: str, repo_id: str, sha: str) -> dict[str, Any]:
    return {
        "schema_version": ABLATION_SCHEMA_VERSION,
        "event_commit_sha": sha,
        "event_id": _event_id(cve_id, "candidate", sha),
        "cve_id": cve_id,
        "repo_id": repo_id,
        "lifecycle": SEMANTIC_EVENT_LIFECYCLE,
        "promotion_sources": [],
        "source_candidate_ids": [],
        "role_proposals": [],
        "gate_decision": "pending",
        "gate_reasons": [],
        "gate_score": 0,
        "anchor_quality": "unknown",
        "evidence_features": {
            "anchor_paths": [],
            "invalid_anchor_count": 0,
            "valid_anchor_count": 0,
            "noise_path_count": 0,
            "root_or_boundary_source": False,
            "direct_source": False,
            "trace_only": True,
            "source_lanes": [],
            "risk_flags": [],
            "conflict_flags": [],
        },
        "source_refs": [],
    }


def _add_source(
    events: dict[str, dict[str, Any]],
    *,
    cve_id: str,
    repo_id: str,
    sha: str,
    source: str,
    packet: dict[str, Any] | None,
    source_candidate_id: str,
) -> None:
    if not _is_full_sha(sha):
        return
    event = events.setdefault(sha, _new_event(cve_id, repo_id, sha))
    if source not in event["promotion_sources"]:
        event["promotion_sources"].append(source)
    role = _source_label(source)
    if role not in event["role_proposals"]:
        event["role_proposals"].append(role)
    if source_candidate_id and source_candidate_id not in event["source_candidate_ids"]:
        event["source_candidate_ids"].append(source_candidate_id)

    features = event["evidence_features"]
    if source in {"direct_candidate", "blame_normal", "blame_w", "blame_M", "blame_C"}:
        features["trace_only"] = False
    if source == "direct_candidate":
        features["direct_source"] = True

    anchor_text = ""
    anchor_path = ""
    if packet:
        anchor_text, anchor_path = _candidate_anchor(packet)
        if anchor_path and anchor_path not in features["anchor_paths"]:
            features["anchor_paths"].append(anchor_path)
        invalid = _is_invalid_structural_anchor(anchor_text, anchor_path)
        if invalid:
            features["invalid_anchor_count"] += 1
        else:
            features["valid_anchor_count"] += 1
        if _is_noise_path(anchor_path):
            features["noise_path_count"] += 1
        candidate_event = packet.get("candidate_event") or {}
        if candidate_event.get("is_root") or candidate_event.get("boundary_marker"):
            features["root_or_boundary_source"] = True
            for boundary_role in ["root_boundary" if candidate_event.get("is_root") else "unresolved_boundary"]:
                if boundary_role not in event["role_proposals"]:
                    event["role_proposals"].append(boundary_role)
        origin = packet.get("candidate_origin") or {}
        source_lane = str(packet.get("source_lane") or "")
        if source_lane and source_lane not in features["source_lanes"]:
            features["source_lanes"].append(source_lane)
        for flag in origin.get("risk_flags") or []:
            if flag not in features["risk_flags"]:
                features["risk_flags"].append(flag)
        for key, value in (packet.get("conflicts") or {}).items():
            if value and key not in features["conflict_flags"]:
                features["conflict_flags"].append(key)
    event["source_refs"].append(
        {
            "source": source,
            "candidate_id": source_candidate_id,
            "anchor_path": anchor_path,
            "anchor_text_hash": _sha256(anchor_text or ""),
        }
    )


def _collect_events(
    *,
    cve_id: str,
    repo_id: str,
    history_packets: list[dict[str, Any]],
    fixes_trailer_targets: list[str],
    include_trace: bool,
) -> dict[str, dict[str, Any]]:
    events: dict[str, dict[str, Any]] = {}
    for packet in history_packets:
        candidate_id = str(packet.get("candidate_id") or "")
        for source, sha in _packet_sources(packet, include_trace=include_trace):
            _add_source(
                events,
                cve_id=cve_id,
                repo_id=repo_id,
                sha=sha,
                source=source,
                packet=packet,
                source_candidate_id=candidate_id,
            )
    if include_trace:
        for sha in fixes_trailer_targets:
            _add_source(
                events,
                cve_id=cve_id,
                repo_id=repo_id,
                sha=sha,
                source="fixes_trailer",
                packet=None,
                source_candidate_id="fixes_trailer",
            )
    return events


def _case_root_boundary_mode(history_packets: list[dict[str, Any]]) -> bool:
    has_root_or_boundary = False
    has_non_root_strong_direct = False
    for packet in history_packets:
        event = packet.get("candidate_event") or {}
        is_boundary = bool(event.get("is_root") or event.get("boundary_marker"))
        has_root_or_boundary = has_root_or_boundary or is_boundary
        if not is_boundary and str(packet.get("source_lane") or "") == "strong":
            has_non_root_strong_direct = True
    return has_root_or_boundary and not has_non_root_strong_direct


def _score_event(event: dict[str, Any]) -> tuple[bool, int, list[str]]:
    sources = set(event["promotion_sources"])
    features = event["evidence_features"]
    reasons: list[str] = []
    score = 0

    if "fixes_trailer" in sources:
        score = max(score, 100)
        reasons.append("fixes_trailer_direct")
    if "log_L" in sources and {"log_S", "log_G"} & sources:
        score = max(score, 92)
        reasons.append("log_l_pickaxe_cross_hit")
    if "direct_candidate" in sources:
        score = max(score, 78 if "strong" in features["source_lanes"] else 66)
        reasons.append("direct_candidate")
    if "blame_w" in sources and "direct_candidate" not in sources:
        score = max(score, 68)
        reasons.append("whitespace_variant_candidate")
    if {"blame_M", "blame_C"} & sources and "direct_candidate" not in sources:
        score = max(score, 55)
        reasons.append("move_copy_variant_candidate")
    if "log_L" in sources and score < 60:
        score = max(score, 58)
        reasons.append("log_l_semantic_region_evidence")
    if {"log_S", "log_G"} & sources and score < 52:
        score = max(score, 50)
        reasons.append("pickaxe_token_evidence")
    if "log_follow" in sources and score < 45:
        score = max(score, 35)
        reasons.append("follow_history_evidence_only")

    if features["root_or_boundary_source"]:
        reasons.append("root_or_import_boundary_source")
    if features["invalid_anchor_count"] and not ("fixes_trailer" in sources or ("log_L" in sources and {"log_S", "log_G"} & sources)):
        score -= 25
        reasons.append("invalid_structural_anchor_penalty")
    if features["noise_path_count"]:
        score -= 45
        reasons.append("test_doc_build_path_rejected")
    if sources == {"log_follow"}:
        return False, score, reasons + ["trace_only_follow_not_candidate"]
    if features["noise_path_count"] and "fixes_trailer" not in sources and not ("log_L" in sources and {"log_S", "log_G"} & sources):
        return False, score, reasons
    if score <= 0:
        return False, score, reasons + ["no_candidate_promotion_feature"]
    return True, score, reasons


def _finalize_event(event: dict[str, Any], *, variant: str, case_root_boundary_mode: bool = False) -> dict[str, Any]:
    promoted, score, reasons = _score_event(event)
    item = json.loads(json.dumps(event))
    item["event_id"] = _event_id(item["cve_id"], variant, item["event_commit_sha"])
    item["promotion_sources"] = sorted(set(item["promotion_sources"]))
    item["source_candidate_ids"] = sorted(set(item["source_candidate_ids"]))
    item["role_proposals"] = sorted(set(item["role_proposals"]))
    item["gate_score"] = score
    item["gate_reasons"] = sorted(set(reasons))
    item["gate_decision"] = "promoted" if promoted else "rejected"
    item["anchor_quality"] = "invalid_structural_anchor" if item["evidence_features"]["invalid_anchor_count"] else "candidate_anchor"
    if case_root_boundary_mode:
        item["role_proposals"] = [role for role in item["role_proposals"] if role != "possible_introduction_event"]
        if "unresolved_boundary" not in item["role_proposals"]:
            item["role_proposals"].append("unresolved_boundary")
        if "case_root_boundary_mode" not in item["gate_reasons"]:
            item["gate_reasons"].append("case_root_boundary_mode")
        item["gate_score"] = min(int(item["gate_score"]), 30)
    elif promoted and "possible_introduction_event" not in item["role_proposals"] and not {"refactor_event", "branch_equivalent_event"} >= set(item["role_proposals"]):
        if "fixes_trailer_target" in item["role_proposals"] or "log_l_promoted_event" in item["role_proposals"] or "direct_blame_event" in item["role_proposals"]:
            item["role_proposals"].append("possible_introduction_event")
    item["role_proposals"] = sorted(set(item["role_proposals"]))
    return item


def _rank_candidates(items: list[dict[str, Any]], *, max_candidates: int | None = None) -> list[dict[str, Any]]:
    ranked = sorted(
        items,
        key=lambda item: (
            -int(item.get("gate_score") or 0),
            "unrelated_or_invalid_anchor" in item.get("role_proposals", []),
            item.get("event_commit_sha", ""),
        ),
    )
    if max_candidates is not None:
        ranked = ranked[:max_candidates]
    for index, item in enumerate(ranked, start=1):
        item["rank"] = index
    return ranked


def _variant_from_events(
    events: dict[str, dict[str, Any]],
    *,
    variant: str,
    promoted_only: bool,
    max_candidates: int | None,
    case_root_boundary_mode: bool = False,
) -> list[dict[str, Any]]:
    finalized = [_finalize_event(event, variant=variant, case_root_boundary_mode=case_root_boundary_mode) for event in events.values()]
    if promoted_only:
        finalized = [item for item in finalized if item["gate_decision"] == "promoted"]
    return _rank_candidates(finalized, max_candidates=max_candidates)


def _convert_broad_candidate(cve_id: str, repo_id: str, item: dict[str, Any]) -> dict[str, Any]:
    sha = _norm_sha(item.get("event_commit_sha"))
    event = _new_event(cve_id, repo_id, sha)
    event["promotion_sources"] = sorted(set(item.get("promotion_sources") or []))
    event["source_candidate_ids"] = sorted(set(item.get("source_candidate_ids") or []))
    event["role_proposals"] = sorted(set(item.get("role_proposals") or []))
    event["gate_decision"] = "broad_baseline"
    event["gate_score"] = int(item.get("priority") or 0)
    event["gate_reasons"] = ["previous_broad_expansion_candidate"]
    event["anchor_quality"] = item.get("anchor_quality") or "unknown"
    event["source_refs"] = item.get("source_refs") or []
    return event


def build_case_ablation_variants(
    *,
    cve_id: str,
    repo_id: str,
    history_packets: list[dict[str, Any]],
    broad_candidates: list[dict[str, Any]],
    fixes_trailer_targets: list[str],
) -> dict[str, list[dict[str, Any]]]:
    direct_events = _collect_events(
        cve_id=cve_id,
        repo_id=repo_id,
        history_packets=history_packets,
        fixes_trailer_targets=[],
        include_trace=False,
    )
    chain_events = _collect_events(
        cve_id=cve_id,
        repo_id=repo_id,
        history_packets=history_packets,
        fixes_trailer_targets=fixes_trailer_targets,
        include_trace=True,
    )
    boundary_mode = _case_root_boundary_mode(history_packets)
    v0 = _variant_from_events(direct_events, variant="V0_direct", promoted_only=False, max_candidates=None, case_root_boundary_mode=boundary_mode)
    v1 = _rank_candidates(
        [_convert_broad_candidate(cve_id, repo_id, item) for item in broad_candidates if _norm_sha(item.get("event_commit_sha"))],
        max_candidates=None,
    )
    v2 = _variant_from_events(direct_events, variant="V2_gate_only", promoted_only=True, max_candidates=None, case_root_boundary_mode=boundary_mode)
    v3 = _variant_from_events(chain_events, variant="V3_semantic_chain_plus_gate", promoted_only=True, max_candidates=8, case_root_boundary_mode=boundary_mode)
    return {
        "V0_direct": v0,
        "V1_broad_expansion": v1,
        "V2_gate_only": v2,
        "V3_semantic_chain_plus_gate": v3,
    }


def recommended_commits_from_label(label_case: dict[str, Any]) -> list[str]:
    recommended = [_norm_sha(item) for item in label_case.get("recommended_introduction_commits") or []]
    missing = (label_case.get("missing_history_event") or {}).get("commit_sha")
    if _norm_sha(missing):
        recommended.append(_norm_sha(missing))
    return [item for item in dict.fromkeys(recommended) if item]


def known_label_map(label_case: dict[str, Any]) -> dict[str, dict[str, Any]]:
    by_sha: dict[str, dict[str, Any]] = {}
    for candidate in label_case.get("candidates") or []:
        sha = _norm_sha(candidate.get("candidate_commit_sha"))
        if not sha:
            continue
        by_sha[sha] = {
            "is_recommended": bool(candidate.get("is_recommended_intro")),
            "manual_event_label": candidate.get("manual_event_label", ""),
        }
    return by_sha


def evaluate_candidates(candidates: list[dict[str, Any]], recommended: list[str], label_case: dict[str, Any] | None = None) -> dict[str, Any]:
    shas = [item["event_commit_sha"] for item in candidates]
    recommended = [sha for sha in dict.fromkeys(recommended) if sha]
    rank = None
    for index, sha in enumerate(shas, start=1):
        if sha in recommended:
            rank = index
            break
    label_map = known_label_map(label_case or {})
    known_top5 = [sha for sha in shas[:5] if sha in label_map]
    known_noise = [sha for sha in known_top5 if not label_map[sha]["is_recommended"]]
    return {
        "candidate_count": len(candidates),
        "candidate_pool_recall": bool(set(shas) & set(recommended)) if recommended else None,
        "recall_at_1": bool(set(shas[:1]) & set(recommended)) if recommended else None,
        "recall_at_3": bool(set(shas[:3]) & set(recommended)) if recommended else None,
        "recall_at_5": bool(set(shas[:5]) & set(recommended)) if recommended else None,
        "recommended_event_rank": rank,
        "top5_known_noise_ratio": (len(known_noise) / len(known_top5)) if known_top5 else None,
    }


def scan_candidate_payload_for_label_leakage(payload: Any) -> dict[str, Any]:
    leaks: list[dict[str, str]] = []

    def walk(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key in LABEL_LEAKAGE_KEYS or key in FORBIDDEN_OUTPUT_FIELDS:
                    leaks.append({"path": path or ".", "field_hash": _sha256(key)})
                walk(child, f"{path}.{key}" if path else key)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}[{index}]")

    walk(payload, "")
    return {"has_leakage": bool(leaks), "leakage_count": len(leaks), "leaks": leaks}


def _scan_output_for_forbidden(path: Path) -> dict[str, Any]:
    violations: list[dict[str, str]] = []

    def walk(value: Any, relpath: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key in FORBIDDEN_OUTPUT_FIELDS:
                    violations.append({"path": relpath, "field_hash": _sha256(key)})
                walk(child, relpath)
        elif isinstance(value, list):
            for child in value:
                walk(child, relpath)

    for item in path.rglob("*.json"):
        try:
            walk(_load_json(item), str(item.relative_to(path)))
        except Exception:
            continue
    return {"has_forbidden_terms": bool(violations), "violation_count": len(violations), "violations": violations}


def _load_labels(path: Path) -> dict[str, dict[str, Any]]:
    data = _load_json(path)
    return {case["cve_id"]: case for case in data.get("cases", [])}


def _load_broad_candidates(previous_broad_root: Path, cve_id: str) -> list[dict[str, Any]]:
    path = previous_broad_root / cve_id / "promoted_history_events.json"
    return _load_json(path) if path.exists() else []


def _case_report(cve_id: str, rows: list[dict[str, Any]], gates: dict[str, Any]) -> str:
    lines = [
        f"# {cve_id} Event Promotion Ablation",
        "",
        "本文件只比较候选池，不运行 Judge，不输出版本预测。",
        "",
        "## Variant Metrics",
        "",
    ]
    for row in rows:
        lines.append(
            f"- {row['variant']}: candidates={row['candidate_count']}, R@1/3/5={row['recall_at_1']}/{row['recall_at_3']}/{row['recall_at_5']}, rank={row['recommended_event_rank']}"
        )
    lines.extend(["", "## Gate Notes", ""])
    for key, value in gates.items():
        lines.append(f"- {key}: `{value}`")
    return "\n".join(lines) + "\n"


def _report_zh(summary: dict[str, Any], hard_gates: dict[str, Any]) -> str:
    lines = [
        "# VulnGraph dev13 Semantic Event Promotion Ablation",
        "",
        "本轮验证 B+A：root-cause-guided semantic event-chain search + evidence-constrained promotion gate。",
        "没有调用模型，没有运行 Judge，没有运行 affected-version converter。所有输出仍是 raw_history_event_candidate。",
        "",
        "## Key Results",
        "",
        f"- V0 direct total candidates: {summary['variants']['V0_direct']['candidate_count_total']}",
        f"- V1 broad total candidates: {summary['variants']['V1_broad_expansion']['candidate_count_total']}",
        f"- V2 gate-only total candidates: {summary['variants']['V2_gate_only']['candidate_count_total']}",
        f"- V3 B+A total candidates: {summary['variants']['V3_semantic_chain_plus_gate']['candidate_count_total']}",
        f"- V3 Recall@5: {summary['variants']['V3_semantic_chain_plus_gate']['recall_at_5']}",
        f"- V3 max candidates per CVE: {summary['variants']['V3_semantic_chain_plus_gate']['candidate_count_max']}",
        "",
        "## Answers",
        "",
        f"1. V3 是否比 V0 找到更多正确 event：`{summary['answers']['v3_more_correct_than_v0']}`。",
        f"2. V3 是否比 V1 显著减少噪声：`{summary['answers']['v3_less_noisy_than_v1']}`。",
        f"3. V2 是否证明 gate-only 不足以补 recall：`{summary['answers']['v2_gate_only_cannot_recover_trace_only_events']}`。",
        f"4. 剩余失败：{summary['answers']['remaining_failures']}",
        f"5. 下一步建议：{summary['answers']['next_step']}",
        "",
        "## Hard Gates",
        "",
    ]
    for key, value in hard_gates.items():
        lines.append(f"- {key}: `{value}`")
    return "\n".join(lines) + "\n"


def _percentile(values: list[int], pct: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round((len(ordered) - 1) * pct)))
    return ordered[index]


def run_dev13_event_promotion_ablation(
    *,
    dataset_path: str | Path,
    repo_root: str | Path,
    reconstruction_root: str | Path,
    readiness_root: str | Path,
    previous_broad_root: str | Path,
    labels_json: str | Path,
    out_dir: str | Path,
    reset: bool = False,
) -> dict[str, Any]:
    dataset = load_dataset_metadata_without_gt(dataset_path)
    labels = _load_labels(Path(labels_json))
    repo_root = Path(repo_root)
    reconstruction_root = Path(reconstruction_root)
    previous_broad_root = Path(previous_broad_root)
    output = Path(out_dir)
    if reset and output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    per_cve_rows: list[dict[str, Any]] = []
    topk_rows: list[dict[str, Any]] = []
    gate_rows: list[dict[str, Any]] = []
    rejected_rows: list[dict[str, Any]] = []
    feature_rows: list[dict[str, Any]] = []
    case_variant_counts: dict[str, list[int]] = defaultdict(list)
    recall_counts: dict[str, Counter] = {variant: Counter() for variant in VARIANTS}
    recall_denominator = 0
    source_distribution = Counter()
    rejection_distribution = Counter()

    for cve_id, label_case in labels.items():
        meta = dataset.get(cve_id, {})
        repo_id = str(label_case.get("repo_id") or meta.get("repo") or "")
        history_path = reconstruction_root / cve_id / "history_event_packets.json"
        history_packets = _load_json(history_path) if history_path.exists() else []
        broad_candidates = _load_broad_candidates(previous_broad_root, cve_id)
        fix_messages = collect_fix_messages(repo_root / repo_id, meta.get("fixing_commits") or [])
        fixes_targets = parse_fixes_trailer_targets(
            fix_messages,
            expand_short_sha=lambda value, repo=repo_root / repo_id: _expand_short_sha(repo, value),
        )
        variants = build_case_ablation_variants(
            cve_id=cve_id,
            repo_id=repo_id,
            history_packets=history_packets,
            broad_candidates=broad_candidates,
            fixes_trailer_targets=fixes_targets,
        )
        recommended = recommended_commits_from_label(label_case)
        if recommended:
            recall_denominator += 1
        case_dir = output / cve_id
        case_dir.mkdir(parents=True, exist_ok=True)
        case_rows: list[dict[str, Any]] = []
        for variant, candidates in variants.items():
            _write_json(case_dir / f"{variant.lower()}_candidates.json", candidates)
            # Also write task-required names.
            required_names = {
                "V0_direct": "v0_direct_candidates.json",
                "V1_broad_expansion": "v1_broad_candidates.json",
                "V2_gate_only": "v2_gate_only_candidates.json",
                "V3_semantic_chain_plus_gate": "v3_semantic_chain_plus_gate_candidates.json",
            }
            _write_json(case_dir / required_names[variant], candidates)
            metrics = evaluate_candidates(candidates, recommended, label_case)
            row = {"cve_id": cve_id, "repo_id": repo_id, "variant": variant, **metrics}
            per_cve_rows.append(row)
            case_rows.append(row)
            case_variant_counts[variant].append(len(candidates))
            if recommended:
                for key in ["candidate_pool_recall", "recall_at_1", "recall_at_3", "recall_at_5"]:
                    if metrics[key]:
                        recall_counts[variant][key] += 1
            for candidate in candidates[:5]:
                topk_rows.append(
                    {
                        "cve_id": cve_id,
                        "variant": variant,
                        "rank": candidate.get("rank", ""),
                        "event_commit_sha": candidate["event_commit_sha"],
                        "gate_score": candidate.get("gate_score", ""),
                        "gate_decision": candidate.get("gate_decision", ""),
                        "promotion_sources": ";".join(candidate.get("promotion_sources") or []),
                        "role_proposals": ";".join(candidate.get("role_proposals") or []),
                    }
                )
        # Decisions are based on all V3 promoted candidates plus rejected chain candidates.
        chain_events = _collect_events(
            cve_id=cve_id,
            repo_id=repo_id,
            history_packets=history_packets,
            fixes_trailer_targets=fixes_targets,
            include_trace=True,
        )
        all_finalized = [
            _finalize_event(
                event,
                variant="V3_semantic_chain_plus_gate",
                case_root_boundary_mode=_case_root_boundary_mode(history_packets),
            )
            for event in chain_events.values()
        ]
        _write_json(case_dir / "gate_decisions.json", all_finalized)
        for item in all_finalized:
            gate_rows.append(
                {
                    "cve_id": cve_id,
                    "event_commit_sha": item["event_commit_sha"],
                    "gate_decision": item["gate_decision"],
                    "gate_score": item["gate_score"],
                    "gate_reasons": ";".join(item["gate_reasons"]),
                    "promotion_sources": ";".join(item["promotion_sources"]),
                }
            )
            for source in item["promotion_sources"]:
                source_distribution[source] += 1
            feature_rows.append(
                {
                    "cve_id": cve_id,
                    "event_commit_sha": item["event_commit_sha"],
                    "promotion_sources": ";".join(item["promotion_sources"]),
                    "gate_reasons": ";".join(item["gate_reasons"]),
                    "invalid_anchor_count": item["evidence_features"]["invalid_anchor_count"],
                    "noise_path_count": item["evidence_features"]["noise_path_count"],
                    "root_or_boundary_source": item["evidence_features"]["root_or_boundary_source"],
                }
            )
            if item["gate_decision"] == "rejected":
                for reason in item["gate_reasons"]:
                    rejection_distribution[reason] += 1
                rejected_rows.append(
                    {
                        "cve_id": cve_id,
                        "event_commit_sha": item["event_commit_sha"],
                        "gate_score": item["gate_score"],
                        "rejection_reasons": ";".join(item["gate_reasons"]),
                        "promotion_sources": ";".join(item["promotion_sources"]),
                    }
                )
        _write_json(
            case_dir / "candidate_pool_before_after.json",
            {
                "v0_count": len(variants["V0_direct"]),
                "v1_count": len(variants["V1_broad_expansion"]),
                "v2_count": len(variants["V2_gate_only"]),
                "v3_count": len(variants["V3_semantic_chain_plus_gate"]),
            },
        )
        _write_json(case_dir / "case_ablation_metrics.json", case_rows)
        (case_dir / "case_ablation_report_zh.md").write_text(
            _case_report(
                cve_id,
                case_rows,
                {
                    "recommended_count_for_evaluation": len(recommended),
                    "v3_top5": " ".join(item["event_commit_sha"] for item in variants["V3_semantic_chain_plus_gate"][:5]),
                },
            ),
            encoding="utf-8",
        )

    ablation_rows: list[dict[str, Any]] = []
    variant_summary: dict[str, Any] = {}
    for variant in VARIANTS:
        counts = case_variant_counts[variant]
        row = {
            "variant": variant,
            "candidate_count_total": sum(counts),
            "candidate_count_p50": median(counts) if counts else 0,
            "candidate_count_p90": _percentile(counts, 0.9),
            "candidate_count_max": max(counts) if counts else 0,
            "candidate_pool_recall": recall_counts[variant]["candidate_pool_recall"] / recall_denominator if recall_denominator else None,
            "recall_at_1": recall_counts[variant]["recall_at_1"] / recall_denominator if recall_denominator else None,
            "recall_at_3": recall_counts[variant]["recall_at_3"] / recall_denominator if recall_denominator else None,
            "recall_at_5": recall_counts[variant]["recall_at_5"] / recall_denominator if recall_denominator else None,
        }
        ablation_rows.append(row)
        variant_summary[variant] = row

    v3_rows = [row for row in per_cve_rows if row["variant"] == "V3_semantic_chain_plus_gate"]
    v3_by_cve = {row["cve_id"]: row for row in v3_rows}
    hard_gates = {
        "v3_total_candidates_le_100": variant_summary["V3_semantic_chain_plus_gate"]["candidate_count_total"] <= 100,
        "v3_per_cve_candidates_le_10": variant_summary["V3_semantic_chain_plus_gate"]["candidate_count_max"] <= 10,
        "v3_recall_at_5_ge_0_85": (variant_summary["V3_semantic_chain_plus_gate"]["recall_at_5"] or 0) >= 0.85,
        "cve_2020_15466_target_retained": bool(v3_by_cve.get("CVE-2020-15466", {}).get("recall_at_5")),
        "cve_2022_0286_target_retained": bool(v3_by_cve.get("CVE-2022-0286", {}).get("recall_at_5")),
        "cve_2020_15389_target_top5": bool(v3_by_cve.get("CVE-2020-15389", {}).get("recall_at_5")),
        "cve_2020_19667_no_plain_intro": _cve_19667_no_plain_intro(output / "CVE-2020-19667" / "v3_semantic_chain_plus_gate_candidates.json"),
    }
    label_leakage = _scan_candidate_files_for_leakage(output)
    forbidden = _scan_output_for_forbidden(output)
    hard_gates["production_candidate_label_leakage_free"] = not label_leakage["has_leakage"]
    hard_gates["forbidden_field_scan_clean"] = not forbidden["has_forbidden_terms"]

    answers = {
        "v3_more_correct_than_v0": variant_summary["V3_semantic_chain_plus_gate"]["candidate_pool_recall"] > variant_summary["V0_direct"]["candidate_pool_recall"],
        "v3_less_noisy_than_v1": variant_summary["V3_semantic_chain_plus_gate"]["candidate_count_total"] < variant_summary["V1_broad_expansion"]["candidate_count_total"],
        "v2_gate_only_cannot_recover_trace_only_events": variant_summary["V2_gate_only"]["candidate_pool_recall"] <= variant_summary["V0_direct"]["candidate_pool_recall"],
        "remaining_failures": _remaining_failures(per_cve_rows),
        "next_step": "V3 passes dev13 gates; run dev30 only after freezing this promotion contract." if all(hard_gates.values()) else "Do not enter dev30; inspect failed hard gates and promotion ledger.",
    }
    summary = {
        "schema_version": ABLATION_SCHEMA_VERSION,
        "cases_total": len(labels),
        "model_invocation_count": 0,
        "judge_invocation_count": 0,
        "converter_invocation_count": 0,
        "highest_lifecycle": SEMANTIC_EVENT_LIFECYCLE,
        "recall_denominator_cases": recall_denominator,
        "variants": variant_summary,
        "promotion_source_distribution": dict(sorted(source_distribution.items())),
        "gate_rejection_reason_distribution": dict(sorted(rejection_distribution.items())),
        "hard_gates": hard_gates,
        "all_hard_gates_passed": all(hard_gates.values()),
        "answers": answers,
    }

    _write_csv(output / "ablation_metrics.csv", ablation_rows)
    _write_csv(output / "per_cve_ablation_metrics.csv", per_cve_rows)
    _write_csv(output / "topk_candidates_by_variant.csv", topk_rows)
    _write_csv(output / "gate_decision_ledger.csv", gate_rows)
    _write_csv(output / "rejected_event_ledger.csv", rejected_rows)
    _write_csv(output / "promotion_feature_ledger.csv", feature_rows)
    _write_json(output / "label_leakage_check.json", label_leakage)
    _write_json(output / "forbidden_field_scan.json", forbidden)
    _write_json(output / "summary.json", summary)
    (output / "event_promotion_ablation_report_zh.md").write_text(_report_zh(summary, hard_gates), encoding="utf-8")
    _write_json(
        output / "provenance_manifest.json",
        {
            "schema_version": ABLATION_SCHEMA_VERSION,
            "dataset_path": str(Path(dataset_path).resolve()),
            "reconstruction_root": str(Path(reconstruction_root).resolve()),
            "readiness_root": str(Path(readiness_root).resolve()),
            "previous_broad_root": str(Path(previous_broad_root).resolve()),
            "labels_used_only_for_evaluation": str(Path(labels_json).resolve()),
            "model_invocation_count": 0,
            "judge_invocation_count": 0,
            "converter_invocation_count": 0,
        },
    )
    return summary


def _cve_19667_no_plain_intro(path: Path) -> bool:
    if not path.exists():
        return False
    for item in _load_json(path):
        if "possible_introduction_event" in item.get("role_proposals", []):
            return False
    return True


def _scan_candidate_files_for_leakage(output: Path) -> dict[str, Any]:
    leaks: list[dict[str, str]] = []
    for path in output.glob("CVE-*/*_candidates.json"):
        scan = scan_candidate_payload_for_label_leakage(_load_json(path))
        for leak in scan["leaks"]:
            leaks.append({"file": str(path.relative_to(output)), **leak})
    return {"has_leakage": bool(leaks), "leakage_count": len(leaks), "leaks": leaks}


def _remaining_failures(rows: list[dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for row in rows:
        if row["variant"] != "V3_semantic_chain_plus_gate":
            continue
        if row["recall_at_5"] is False:
            failures.append(f"{row['cve_id']}:recommended_not_in_top5")
    return failures


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run dev13 Semantic Event Promotion Ablation.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--git-graph-index", required=True)
    parser.add_argument("--reconstruction-root", required=True)
    parser.add_argument("--readiness-root", required=True)
    parser.add_argument("--previous-broad-root", required=True)
    parser.add_argument("--labels-json", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--reset", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    _ = Path(args.git_graph_index)
    summary = run_dev13_event_promotion_ablation(
        dataset_path=args.dataset,
        repo_root=args.repo_root,
        reconstruction_root=args.reconstruction_root,
        readiness_root=args.readiness_root,
        previous_broad_root=args.previous_broad_root,
        labels_json=args.labels_json,
        out_dir=args.out_dir,
        reset=args.reset,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary["all_hard_gates_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
