from __future__ import annotations

import argparse
import json
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

from vulngraph.workflows.event_promotion_ablation_v1 import _load_json, _write_csv, _write_json
from vulngraph.workflows.history_root_boundary_v1 import HISTORY_ROOT_BOUNDARY_ROLE, is_invalid_primary_boundary_anchor
from vulngraph.workflows.topk_judge_packet_v1 import run_topk_judge_packet_v1


TARGET_CVES = [
    "CVE-2020-19667",
    "CVE-2020-8231",
    "CVE-2020-13904",
    "CVE-2020-15466",
    "CVE-2022-0286",
]

ROOT_BOUNDARY_CVE = "CVE-2020-19667"
ROOT_BOUNDARY_SHA = "3ed852eea50f9d4cd633efb8c2b054b8e33c2530"
RELATED_SHA = "13aeafe87d395d3a00f9907c7a8cada8588ae2a7"

KEY_EVENT_CHECKS = {
    "CVE-2020-8231": "d021f2e8a0067fc769652f27afec9024c0d02b3d",
    "CVE-2020-13904": "6cc7f1398257d4ffa89f79d52f10b2cabd9ad232",
    "CVE-2020-15466": "1e630b42e1f0573ca549643952017da315e695a0",
    "CVE-2022-0286": "18cb261afd7bf50134e5ccacc5ec91ea16efadd4",
}


def _candidate_shas(blind: dict[str, Any]) -> list[str]:
    return [str(item.get("event_commit_sha") or "") for item in blind.get("candidates") or []]


def _first_rank(shas: list[str], target: str) -> int | None:
    for index, sha in enumerate(shas, start=1):
        if sha == target:
            return index
    return None


def _has_role(candidate: dict[str, Any], role: str) -> bool:
    return role in set(candidate.get("judge_role_options") or [])


def _cve_blind(out_dir: Path, cve_id: str) -> dict[str, Any]:
    return _load_json(out_dir / cve_id / "judge_blind_history_event_packet.json")


def _boundary_case_row(blind: dict[str, Any]) -> dict[str, Any]:
    boundary_candidates = [
        item for item in blind.get("candidates") or [] if _has_role(item, HISTORY_ROOT_BOUNDARY_ROLE)
    ]
    boundary = (boundary_candidates[0].get("history_root_boundary") if boundary_candidates else {}) or {}
    invalid_refs = boundary.get("invalid_primary_anchor_refs") or []
    return {
        "cve_id": blind.get("cve_id", ""),
        "repo_id": blind.get("repo_id", ""),
        "detected_history_root_boundary": bool(boundary_candidates),
        "synthetic_candidate_id": boundary_candidates[0].get("candidate_id", "") if boundary_candidates else "",
        "boundary_commit_sha": boundary.get("boundary_commit_sha", ""),
        "boundary_subtype": boundary.get("boundary_subtype", ""),
        "invalid_primary_anchor_count": len(invalid_refs),
        "ordinary_introduction_not_observable": boundary.get("ordinary_introduction_not_observable", ""),
        "visible_paths_at_boundary": ";".join(boundary.get("visible_paths_at_boundary") or []),
    }


def _boundary_evidence_row(blind: dict[str, Any]) -> dict[str, Any]:
    boundary_candidates = [
        item for item in blind.get("candidates") or [] if _has_role(item, HISTORY_ROOT_BOUNDARY_ROLE)
    ]
    boundary = (boundary_candidates[0].get("history_root_boundary") if boundary_candidates else {}) or {}
    git = boundary.get("git_graph_evidence") or {}
    source = boundary.get("source_state_evidence") or {}
    return {
        "cve_id": blind.get("cve_id", ""),
        "repo_id": blind.get("repo_id", ""),
        "boundary_commit_sha": boundary.get("boundary_commit_sha", ""),
        "git_graph_parent_count": git.get("parent_count", ""),
        "git_graph_is_repo_root": git.get("is_repo_root", ""),
        "path_exists_at_root": source.get("path_exists_at_root", ""),
        "path_exists_at_fix_parent": source.get("path_exists_at_fix_parent", ""),
        "relevant_code_state_at_root": source.get("relevant_code_state_at_root", ""),
        "vulnerable_predicate_state_at_root": source.get("vulnerable_predicate_state_at_root", ""),
        "fix_predicate_state_at_root": source.get("fix_predicate_state_at_root", ""),
        "mechanism_signature_terms_present": ";".join(source.get("mechanism_signature_terms_present") or []),
        "fix_hardening_terms_present_at_root": source.get("fix_hardening_terms_present_at_root", ""),
        "boundary_to_fix_ancestry": json.dumps(
            git.get("boundary_to_fix_ancestry") or [],
            ensure_ascii=False,
            sort_keys=True,
        ),
        "state_at_boundary": boundary.get("state_at_boundary", ""),
        "evidence_status": source.get("evidence_status", boundary.get("verification_status", "")),
        "reason": source.get("reason", boundary.get("verification_reason", "")),
    }


def _packet_summary_row(blind: dict[str, Any]) -> dict[str, Any]:
    roles = Counter()
    for candidate in blind.get("candidates") or []:
        roles.update(candidate.get("judge_role_options") or [])
    return {
        "cve_id": blind.get("cve_id", ""),
        "repo_id": blind.get("repo_id", ""),
        "candidate_count": len(blind.get("candidates") or []),
        "history_root_boundary_count": roles.get(HISTORY_ROOT_BOUNDARY_ROLE, 0),
        "ordinary_boundary_count": roles.get("ordinary_boundary", 0),
        "feature_series_boundary_count": roles.get("feature_series_boundary", 0),
        "vulnerability_introduction_count": roles.get("vulnerability_introduction", 0),
        "uncertain_count": roles.get("uncertain", 0),
    }


def _invalid_primary_intro_anchor_count(blind: dict[str, Any]) -> int:
    count = 0
    for candidate in blind.get("candidates") or []:
        if not _has_role(candidate, "vulnerability_introduction"):
            continue
        for anchor in candidate.get("anchor_evidence") or []:
            if is_invalid_primary_boundary_anchor(anchor.get("old_anchor_text")):
                count += 1
    return count


def _invalid_primary_boundary_anchor_count(blind: dict[str, Any]) -> int:
    count = 0
    for candidate in blind.get("candidates") or []:
        if not _has_role(candidate, HISTORY_ROOT_BOUNDARY_ROLE):
            continue
        for anchor in candidate.get("anchor_evidence") or []:
            if (
                is_invalid_primary_boundary_anchor(anchor.get("old_anchor_text"))
                and anchor.get("evidence_role") != "supporting_invalid_anchor"
            ):
                count += 1
    return count


def _build_gates(out_dir: Path) -> tuple[list[dict[str, Any]], dict[str, bool]]:
    rows: list[dict[str, Any]] = []
    gates: dict[str, bool] = {}
    blind_by_cve = {cve_id: _cve_blind(out_dir, cve_id) for cve_id in TARGET_CVES}
    root_blind = blind_by_cve[ROOT_BOUNDARY_CVE]
    root_candidates = root_blind.get("candidates") or []
    root_boundary_candidates = [item for item in root_candidates if _has_role(item, HISTORY_ROOT_BOUNDARY_ROLE)]
    root_sha_candidates = [item for item in root_candidates if item.get("event_commit_sha") == ROOT_BOUNDARY_SHA]
    related_candidates = [item for item in root_candidates if item.get("event_commit_sha") == RELATED_SHA]
    root_boundary = (root_boundary_candidates[0].get("history_root_boundary") if root_boundary_candidates else {}) or {}
    git = root_boundary.get("git_graph_evidence") or {}
    source = root_boundary.get("source_state_evidence") or {}
    projection = root_boundary.get("projection_hint") or {}
    ancestry = git.get("boundary_to_fix_ancestry") or []
    root_binding = (root_boundary_candidates[0].get("root_cause_binding") if root_boundary_candidates else {}) or {}
    serialized_boundary = json.dumps(root_boundary, ensure_ascii=False, sort_keys=True)

    gates["cve_2020_19667_detected_history_root_boundary"] = bool(root_boundary_candidates)
    gates["cve_2020_19667_git_graph_parent_count_zero"] = git.get("parent_count") == 0
    gates["cve_2020_19667_git_graph_is_repo_root"] = git.get("is_repo_root") is True
    gates["cve_2020_19667_root_to_fix_ancestry_true"] = bool(ancestry) and any(
        item.get("is_descendant_of_boundary") is True for item in ancestry
    )
    gates["cve_2020_19667_path_exists_at_root"] = source.get("path_exists_at_root") is True
    gates["cve_2020_19667_path_exists_at_fix_parent"] = source.get("path_exists_at_fix_parent") is True
    gates["cve_2020_19667_relevant_code_present_at_root"] = (
        root_boundary.get("state_at_boundary") == "vulnerability_relevant_code_present_at_root"
        and source.get("relevant_code_state_at_root") == "present"
    )
    gates["cve_2020_19667_predicates_not_claimed_verified"] = (
        source.get("vulnerable_predicate_state_at_root") == "not_verified"
        and source.get("fix_predicate_state_at_root") == "not_verified"
        and "vulnerable_state_observed" not in serialized_boundary
    )
    gates["blind_packet_contains_git_graph_evidence"] = bool(git)
    gates["blind_packet_contains_source_state_evidence"] = bool(source)
    gates["cve_2020_19667_has_synthetic_root_boundary_event"] = any(
        str(item.get("candidate_id") or "").startswith("history-boundary:CVE-2020-19667:root:")
        for item in root_boundary_candidates
    )
    gates["cve_2020_19667_no_candidate_role_vulnerability_introduction"] = not any(
        _has_role(item, "vulnerability_introduction") for item in root_candidates
    )
    gates["root_snapshot_not_called_introduction"] = not any(
        _has_role(item, "vulnerability_introduction") for item in root_sha_candidates
    )
    gates["cve_2020_19667_introduction_commit_not_verified"] = (
        projection.get("first_observed_vulnerable_boundary") == ROOT_BOUNDARY_SHA
        and projection.get("introduction_status") == "censored_before_or_at_boundary"
        and projection.get("introduction_commit_verified") is False
        and "activation_lower_bound" not in projection
    )
    gates["cve_2020_19667_root_cause_binding_nonempty"] = bool(
        root_binding.get("root_cause_hypothesis_ids")
    )
    gates["cve_2020_19667_vulnerable_predicate_binding_nonempty"] = bool(
        root_binding.get("vulnerable_predicate_ids")
    )
    gates["cve_2020_19667_fix_predicate_binding_nonempty"] = bool(
        root_binding.get("fix_predicate_ids")
    )
    gates["invalid_structural_anchors_not_primary_evidence"] = (
        _invalid_primary_intro_anchor_count(root_blind) == 0
        and _invalid_primary_boundary_anchor_count(root_blind) == 0
    )
    gates["related_13aeafe_not_ordinary_introduction"] = not any(
        _has_role(item, "vulnerability_introduction") for item in related_candidates
    )
    for cve_id, target in KEY_EVENT_CHECKS.items():
        rank = _first_rank(_candidate_shas(blind_by_cve[cve_id]), target)
        gate_name = f"{cve_id.lower().replace('-', '_')}_target_in_topk"
        gates[gate_name] = rank is not None
        rows.append(
            {
                "gate": gate_name,
                "passed": rank is not None,
                "cve_id": cve_id,
                "target_commit_sha": target,
                "rank": rank or "",
                "details": "non-boundary regression target retained",
            }
        )
    for gate, passed in gates.items():
        if not any(row["gate"] == gate for row in rows):
            rows.append({"gate": gate, "passed": passed, "cve_id": ROOT_BOUNDARY_CVE, "target_commit_sha": "", "rank": "", "details": ""})
    return rows, gates


def _write_report(
    out_dir: Path,
    summary: dict[str, Any],
    boundary_rows: list[dict[str, Any]],
    evidence_rows: list[dict[str, Any]],
    gate_rows: list[dict[str, Any]],
) -> None:
    boundary = boundary_rows[0] if boundary_rows else {}
    evidence = evidence_rows[0] if evidence_rows else {}
    lines = [
        "# VulnGraph History Root Boundary Minimal Contract Correction v1.1.1",
        "",
        "本轮只处理 GitGraph-verified history/root boundary evidence，不调用模型，不运行 Judge，不运行 converter。",
        "",
        "## CVE-2020-19667 Before / After",
        "",
        "- Before: root/import commit was carried as an ordinary promoted history candidate, and invalid structural anchors such as `}` could dominate the evidence surface.",
        "- After: packet rank 1 is a synthetic case-level `history_root_boundary` event, accepted only after GitGraph root and root-to-fix ancestry verification plus bounded source relevance checks.",
        f"- Boundary commit: `{boundary.get('boundary_commit_sha', '')}`",
        f"- Synthetic candidate: `{boundary.get('synthetic_candidate_id', '')}`",
        f"- Invalid structural anchors downgraded: `{boundary.get('invalid_primary_anchor_count', '')}`",
        f"- GitGraph parent_count: `{evidence.get('git_graph_parent_count', '')}`",
        f"- GitGraph is_repo_root: `{evidence.get('git_graph_is_repo_root', '')}`",
        f"- path_exists_at_root: `{evidence.get('path_exists_at_root', '')}`",
        f"- path_exists_at_fix_parent: `{evidence.get('path_exists_at_fix_parent', '')}`",
        f"- source relevance at boundary: `{evidence.get('state_at_boundary', '')}`",
        f"- vulnerable predicate state at root: `{evidence.get('vulnerable_predicate_state_at_root', '')}`",
        f"- fix predicate state at root: `{evidence.get('fix_predicate_state_at_root', '')}`",
        "",
        "## Stop Gates",
        "",
    ]
    for row in gate_rows:
        lines.append(f"- {row['gate']}: `{row['passed']}`")
    lines.extend(
        [
            "",
            "## Future Converter Consumption",
            "",
            "- `history_root_boundary` means vulnerability-relevant code is present at the earliest visible local Git history boundary; term/excerpt matches do not verify either predicate.",
            "- `projection_hint.first_observed_vulnerable_boundary` is a censored history boundary fact, not a validated introduction event.",
            "- Related parser-state commits remain secondary evidence and need separate Judge reasoning if used.",
            "",
            "## Explicit Scope",
            "",
            "- This is only a history-root boundary contract correction.",
            "- This run does not validate BIC/VIC and does not output affected_versions.",
            f"- model_invocation_count: `{summary.get('model_invocation_count', 0)}`",
            f"- judge_invocation_count: `{summary.get('judge_invocation_count', 0)}`",
            f"- converter_invocation_count: `{summary.get('converter_invocation_count', 0)}`",
            "",
        ]
    )
    text = "\n".join(lines)
    (out_dir / "history_root_boundary_evidence_report_zh.md").write_text(text, encoding="utf-8")
    (out_dir / "history_root_boundary_report_zh.md").write_text(text, encoding="utf-8")


def run_history_root_boundary_v1(args: argparse.Namespace) -> dict[str, Any]:
    out_dir = Path(args.out_dir)
    if args.reset and out_dir.exists():
        shutil.rmtree(out_dir)
    summary = run_topk_judge_packet_v1(
        v3_replay_root=args.v3_replay_root,
        reconstruction_root=args.reconstruction_root,
        readiness_root=args.readiness_root,
        git_graph_index=args.git_graph_index,
        repo_root=args.repo_root,
        labels_json=args.labels_json,
        out_dir=out_dir,
        top_k=args.top_k,
        cves=args.cves or TARGET_CVES,
        reset=False,
    )
    boundary_rows = [_boundary_case_row(_cve_blind(out_dir, ROOT_BOUNDARY_CVE))]
    evidence_rows = [_boundary_evidence_row(_cve_blind(out_dir, ROOT_BOUNDARY_CVE))]
    packet_rows = [_packet_summary_row(_cve_blind(out_dir, cve_id)) for cve_id in (args.cves or TARGET_CVES)]
    gate_rows, gates = _build_gates(out_dir)
    forbidden_scan = _load_json(out_dir / "blind_packet_forbidden_scan.json")

    root_boundary_summary = {
        "run_type": "history_root_boundary_v1_1_1_targeted",
        "target_cves": args.cves or TARGET_CVES,
        "all_targeted_stop_gates_passed": all(gates.values()) and forbidden_scan.get("violation_count") == 0,
        "targeted_stop_gates": gates,
        "forbidden_field_scan": forbidden_scan,
        "base_topk_summary": summary,
        "model_invocation_count": 0,
        "judge_invocation_count": 0,
        "converter_invocation_count": 0,
    }
    _write_json(out_dir / "summary.json", root_boundary_summary)
    _write_csv(out_dir / "root_boundary_cases.csv", boundary_rows)
    _write_csv(out_dir / "root_boundary_evidence_ledger.csv", evidence_rows)
    _write_csv(out_dir / "topk_boundary_packet_summary.csv", packet_rows)
    _write_csv(out_dir / "regression_gate_summary.csv", gate_rows)
    _write_json(out_dir / "forbidden_field_scan.json", forbidden_scan)
    root_blind = _cve_blind(out_dir, ROOT_BOUNDARY_CVE)
    root_candidates = [
        item for item in root_blind.get("candidates") or [] if _has_role(item, HISTORY_ROOT_BOUNDARY_ROLE)
    ]
    root_boundary = (root_candidates[0].get("history_root_boundary") if root_candidates else {}) or {}
    _write_json(
        out_dir / "root_boundary_ancestry_ledger.json",
        {
            "cve_id": ROOT_BOUNDARY_CVE,
            "boundary_commit_sha": root_boundary.get("boundary_commit_sha", ""),
            "boundary_to_fix_ancestry": (root_boundary.get("git_graph_evidence") or {}).get(
                "boundary_to_fix_ancestry"
            )
            or [],
        },
    )
    _write_report(out_dir, root_boundary_summary, boundary_rows, evidence_rows, gate_rows)
    return root_boundary_summary


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build targeted History Root Boundary v1 packets.")
    parser.add_argument("--v3-replay-root", required=True)
    parser.add_argument("--reconstruction-root", required=True)
    parser.add_argument("--readiness-root", required=True)
    parser.add_argument("--git-graph-index", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--labels-json", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--top-k", type=int, default=8)
    parser.add_argument("--cves", nargs="*")
    parser.add_argument("--reset", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    summary = run_history_root_boundary_v1(parse_args(argv))
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("all_targeted_stop_gates_passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
