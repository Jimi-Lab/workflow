from __future__ import annotations

import csv
import json
from pathlib import Path

from scripts.build_representative_manual_history_event_review import (
    EXCLUDED_REVIEWED_CVES,
    REQUIRED_COVERAGE_TYPES,
    SelectionFeature,
    build_representative_review,
    select_representative_cves,
)


def _feature(
    cve_id: str,
    repo_id: str,
    *,
    strong: int = 1,
    fallback: int = 0,
    fix_count: int = 1,
    **flags: bool,
) -> SelectionFeature:
    return SelectionFeature(
        cve_id=cve_id,
        repo_id=repo_id,
        candidate_count=strong + fallback,
        strong_count=strong,
        fallback_count=fallback,
        fix_commit_count=fix_count,
        has_blame_disagreement=flags.get("has_blame_disagreement", False),
        has_whitespace_sensitive=flags.get("has_whitespace_sensitive", False),
        has_move_copy_sensitive=flags.get("has_move_copy_sensitive", False),
        has_boundary_or_merge_candidate=flags.get("has_boundary_or_merge_candidate", False),
        has_ambiguous_relocation=flags.get("has_ambiguous_relocation", False),
        has_not_found_or_path_missing=flags.get("has_not_found_or_path_missing", False),
        has_parent_absent_by_event=flags.get("has_parent_absent_by_event", False),
        has_large_fallback_pool=flags.get("has_large_fallback_pool", False),
        has_anchor_local_diff=flags.get("has_anchor_local_diff", True),
        has_log_L_signal=flags.get("has_log_L_signal", True),
        has_pickaxe_signal=flags.get("has_pickaxe_signal", True),
        selection_types=set(flags.get("selection_types", [])),
        reasons_zh=[],
        priority_counts={"P0": 1, "P1": 0, "P2": 0},
        relocation_status_counts={},
    )


def test_select_representative_cves_excludes_reviewed_and_covers_types() -> None:
    features = {
        "CVE-2020-8231": _feature("CVE-2020-8231", "curl"),
        "CVE-2020-11647": _feature("CVE-2020-11647", "wireshark", has_not_found_or_path_missing=True),
        "CVE-2020-13904": _feature("CVE-2020-13904", "FFmpeg", fallback=5, strong=0, has_large_fallback_pool=True),
    }
    for index, coverage_type in enumerate(REQUIRED_COVERAGE_TYPES):
        cve_id = f"CVE-TEST-{index:04d}"
        features[cve_id] = _feature(
            cve_id,
            repo_id=f"repo{index % 5}",
            fallback=3 if "fallback" in coverage_type else 0,
            strong=0 if coverage_type == "fallback_only" else 1,
            fix_count=2 if "multi" in coverage_type else 1,
            selection_types={coverage_type},
            has_blame_disagreement=coverage_type == "blame_variant_disagreement",
            has_whitespace_sensitive=coverage_type == "whitespace_sensitive",
            has_move_copy_sensitive=coverage_type == "move_copy_sensitive",
            has_not_found_or_path_missing=coverage_type == "relocation_problem",
            has_parent_absent_by_event=coverage_type == "add_only_or_weak_old_side",
            has_large_fallback_pool=coverage_type == "fallback_only",
        )

    selected, coverage = select_representative_cves(features, exclude=EXCLUDED_REVIEWED_CVES, count=10)

    assert len(selected) == 10
    assert not (set(selected) & EXCLUDED_REVIEWED_CVES)
    assert coverage["selected_count"] == 10
    assert coverage["reference_reuse_count"] == 0
    assert coverage["covered_type_count"] >= 8
    assert set(selected).issubset(set(features) - EXCLUDED_REVIEWED_CVES)


def _write_case_artifacts(root: Path, recon_root: Path, cve_id: str, repo_id: str, *, source_lane: str, flags: dict[str, bool]) -> None:
    case_dir = root / cve_id
    case_dir.mkdir(parents=True, exist_ok=True)
    recon_dir = recon_root / cve_id
    recon_dir.mkdir(parents=True, exist_ok=True)
    candidate_id = f"candidate:{cve_id}"
    packet = {
        "blind_packet": {
            "cve_id": cve_id,
            "repo_id": repo_id,
            "candidate_id": candidate_id,
            "source_lane": source_lane,
            "before_path": "src/a.c",
            "after_path": "src/a.c",
            "recommended_review_priority": "P0",
            "diff_extraction_status": "found",
            "conflict_flags": flags,
            "candidate_event_identity": {
                "candidate_commit_sha": "a" * 40,
                "selected_parent_sha": "b" * 40,
                "fix_commit_sha": "c" * 40,
                "is_merge": flags.get("merge_candidate", False),
                "is_root": flags.get("root_candidate", False),
                "boundary_marker": flags.get("boundary_candidate", False),
            },
            "root_cause_bindings": {
                "anchor_path": "src/a.c",
                "anchor_old_line_start": 12,
                "anchor_old_line_text": "dangerous_call(x);",
                "patch_family": "patch-family:1",
                "root_cause_hypothesis_ids": ["h1"],
                "vulnerable_predicate_ids": ["v1"],
                "fix_predicate_ids": ["f1"],
            },
            "parent_anchor_context": {
                "relocation_status": "absent_by_event" if flags.get("parent_context_not_found") else "found",
                "match_kind": "diff_hunk_mapped",
                "anchor_verified": not flags.get("parent_context_not_found"),
                "lines": [{"role": "anchor", "text": "dangerous_call(x);"}],
            },
            "candidate_anchor_context": {
                "relocation_status": "path_missing" if flags.get("candidate_context_not_found") else "found",
                "match_kind": "exact_hash",
                "anchor_verified": not flags.get("candidate_context_not_found"),
                "lines": [{"role": "anchor", "text": "dangerous_call(x);"}],
            },
            "history_reconstruction_summary": {
                "variant_agreement": "disagreement" if flags.get("blame_variant_disagreement") else "all_same",
                "log_L_top_commits": ["a" * 40],
                "log_S_top_commits": ["a" * 40],
                "log_G_top_commits": ["a" * 40],
                "log_follow_top_commits": ["a" * 40],
            },
            "anchor_relocation": {},
        },
        "source_history_event_packet": {
            "blame_variants": {
                "variant_agreement": "disagreement" if flags.get("blame_variant_disagreement") else "all_same",
                "canonical_blame_commit_sha": "a" * 40,
                "variants": [
                    {"variant": "normal", "status": "found", "blamed_commit_sha": "a" * 40, "blamed_original_path": "src/a.c", "blamed_original_line": 12},
                    {"variant": "w", "status": "found", "blamed_commit_sha": "d" * 40 if flags.get("whitespace_sensitive") else "a" * 40, "blamed_original_path": "src/a.c", "blamed_original_line": 12},
                ],
            },
            "log_history": {
                "log_L": {"output_excerpt": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa demo L"},
                "log_S": {"output_excerpt": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa demo S"},
                "log_G": {"output_excerpt": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa demo G"},
            },
            "path_history": {"log_follow": {"output_excerpt": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa demo follow"}},
        },
        "lifecycle": "judge_ready_history_event_candidate",
    }
    (case_dir / "judge_audit_history_event_packets.json").write_text(json.dumps([packet]), encoding="utf-8")
    (case_dir / "judge_readiness_case_summary.json").write_text(
        json.dumps(
            {
                "cve_id": cve_id,
                "repo_id": repo_id,
                "audit_packet_count": 1,
                "blind_packet_count": 1,
                "strong_candidate_count": 0 if source_lane == "fallback" else 1,
                "fallback_candidate_count": 1 if source_lane == "fallback" else 0,
            }
        ),
        encoding="utf-8",
    )
    for name in [
        "history_event_packets.json",
        "blame_variant_trace.json",
        "log_history_trace.json",
        "path_history_trace.json",
        "candidate_event_chains.json",
    ]:
        (recon_dir / name).write_text("[]", encoding="utf-8")


def test_build_representative_review_writes_ten_parseable_review_packages(tmp_path: Path) -> None:
    judge_root = tmp_path / "judge"
    recon_root = tmp_path / "recon"
    selected_root = tmp_path / "selected"
    out_dir = tmp_path / "out"
    selected_root.mkdir()
    (selected_root / "manual_semantic_labels_v1.json").write_text(
        json.dumps({"summary": {"clean_strong_success_cases": ["CVE-2020-8231"]}, "cases": []}),
        encoding="utf-8",
    )
    (selected_root / "manual_semantic_audit_report_zh.md").write_text("reference taxonomy", encoding="utf-8")
    (selected_root / "manual_semantic_labels_v1.csv").write_text("cve_id\nCVE-2020-8231\n", encoding="utf-8")
    dataset = {}
    for index in range(12):
        cve_id = f"CVE-BUILD-{index:04d}"
        flags = {
            "blame_variant_disagreement": index == 1,
            "whitespace_sensitive": index == 2,
            "move_copy_sensitive": index == 3,
            "boundary_candidate": index == 4,
            "candidate_context_not_found": index == 5,
            "parent_context_not_found": index == 6,
        }
        lane = "fallback" if index in {0, 7, 8} else "strong"
        repo = f"repo{index % 4}"
        _write_case_artifacts(judge_root, recon_root, cve_id, repo, source_lane=lane, flags=flags)
        dataset[cve_id] = {"repo": repo, "CWE": ["CWE-000"], "fixing_commits": [["c" * 40, "e" * 40] if index == 9 else ["c" * 40]]}
    dataset_path = tmp_path / "dataset.json"
    dataset_path.write_text(json.dumps(dataset), encoding="utf-8")

    result = build_representative_review(
        judge_readiness_root=judge_root,
        reconstruction_root=recon_root,
        selected_review_root=selected_root,
        dataset_path=dataset_path,
        out_dir=out_dir,
        count=10,
        reset=True,
    )

    assert len(result["selected_cves"]) == 10
    manifest = json.loads((out_dir / "representative_10_manifest.json").read_text(encoding="utf-8"))
    assert manifest["selected_count"] == 10
    assert not (set(manifest["selected_cves"]) & EXCLUDED_REVIEWED_CVES)
    with (out_dir / "representative_10_selection_features.csv").open(encoding="utf-8-sig", newline="") as handle:
        assert len(list(csv.DictReader(handle))) == 10
    for cve_id in manifest["selected_cves"]:
        case_dir = out_dir / cve_id
        assert (case_dir / "manual_review_brief_zh.md").exists()
        assert (case_dir / "candidate_review_table.csv").exists()
        assert (case_dir / "candidate_evidence_index.json").exists()
        assert (case_dir / "raw_artifact_links.md").exists()
        assert (case_dir / "selection_reason_zh.md").exists()
        json.loads((case_dir / "selection_features.json").read_text(encoding="utf-8"))
