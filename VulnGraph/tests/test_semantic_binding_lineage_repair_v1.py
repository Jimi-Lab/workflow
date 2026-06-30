from __future__ import annotations

import json
from pathlib import Path

from vulngraph.workflows.semantic_binding_lineage_repair_v1 import (
    build_semantic_binding_index,
    extract_root_cause_artifact_inventory,
    repair_candidate_semantic_bindings,
)


def _write_artifact(root: Path, *, status: str = "ingested_raw", fix_predicate_id: str = "fp-1") -> Path:
    root.mkdir(parents=True)
    parsed = {
        "agent_run": {"run_id": "run-1", "cve_id": "CVE-TEST"},
        "root_cause_hypotheses": [
            {
                "hypothesis_id": "hyp-1",
                "fix_commit_ids": ["fix-commit:demo:abc123"],
                "fix_set_ids": ["CVE-TEST:fix-set:1"],
                "vulnerable_predicate_ids": ["vp-1"],
                "fix_predicate_ids": [fix_predicate_id],
                "anchor_ids": ["anchor-1"],
                "git_observation_refs": ["obs-1"],
            }
        ],
        "vulnerable_predicates": [
            {
                "predicate_id": "vp-1",
                "anchor_ids": ["anchor-1"],
                "git_observation_refs": ["obs-1"],
            }
        ],
        "fix_predicates": [
            {
                "predicate_id": fix_predicate_id,
                "anchor_ids": ["anchor-1"],
                "git_observation_refs": ["obs-1"],
            }
        ],
        "code_anchors": [
            {
                "anchor_id": "anchor-1",
                "fix_commit_id": "fix-commit:demo:abc123",
                "patch_hunk_id": "patch-hunk:demo:abc123:src/a.c:1",
                "path": "src/a.c",
                "git_observation_refs": ["obs-1"],
            }
        ],
    }
    ingestion = {
        "status": status,
        "details": {
            "hypothesis_results": {
                "hyp-1": {"gate_valid": status == "ingested_raw", "lifecycle": "raw"}
            }
        },
    }
    (root / "parsed_output.json").write_text(json.dumps(parsed), encoding="utf-8")
    (root / "ingestion_result.json").write_text(json.dumps(ingestion), encoding="utf-8")
    return root


def test_extracts_accepted_root_cause_fix_predicate_inventory(tmp_path: Path) -> None:
    artifact = _write_artifact(tmp_path / "run" / "CVE-TEST")

    inventory = extract_root_cause_artifact_inventory(
        cve_id="CVE-TEST",
        artifact_path=artifact,
        source_run_name="run",
    )

    assert inventory["artifact_status"] == "accepted"
    assert inventory["root_cause_hypothesis_ids"] == ["hyp-1"]
    assert inventory["vulnerable_predicate_ids"] == ["vp-1"]
    assert inventory["fix_predicate_ids"] == ["fp-1"]
    assert inventory["entries"][0]["patch_hunk_id"] == "patch-hunk:demo:abc123:src/a.c:1"


def test_backfills_missing_fix_predicate_from_exact_fix_and_path(tmp_path: Path) -> None:
    inventory = extract_root_cause_artifact_inventory(
        cve_id="CVE-TEST",
        artifact_path=_write_artifact(tmp_path / "run" / "CVE-TEST"),
        source_run_name="run",
    )
    index = build_semantic_binding_index([inventory])
    candidate = {
        "candidate_id": "cand-1",
        "candidate_origin": {
            "fix_commit_id": "fix-commit:demo:abc123",
            "anchor_path": "src/a.c",
            "root_cause_hypothesis_bindings": ["fallback:root"],
            "vulnerable_predicate_bindings": ["fallback:vp"],
            "fix_predicate_bindings": [],
        },
    }

    repaired, ledger = repair_candidate_semantic_bindings(candidate, index, cve_id="CVE-TEST")

    origin = repaired["candidate_origin"]
    assert origin["root_cause_hypothesis_bindings"] == ["hyp-1"]
    assert origin["vulnerable_predicate_bindings"] == ["vp-1"]
    assert origin["fix_predicate_bindings"] == ["fp-1"]
    assert origin["semantic_binding_lineage"]["fix_predicate_binding_status"] == "backfilled_exact"
    assert ledger["binding_strategy"] == "exact_fix_commit_path_match"


def test_cve_level_only_match_is_fail_closed(tmp_path: Path) -> None:
    inventory = extract_root_cause_artifact_inventory(
        cve_id="CVE-TEST",
        artifact_path=_write_artifact(tmp_path / "run" / "CVE-TEST"),
        source_run_name="run",
    )
    index = build_semantic_binding_index([inventory])
    candidate = {
        "candidate_id": "cand-1",
        "candidate_origin": {
            "root_cause_hypothesis_bindings": ["fallback:root"],
            "vulnerable_predicate_bindings": ["fallback:vp"],
            "fix_predicate_bindings": [],
        },
    }

    repaired, ledger = repair_candidate_semantic_bindings(candidate, index, cve_id="CVE-TEST")

    assert repaired["candidate_origin"]["fix_predicate_bindings"] == []
    assert repaired["candidate_origin"]["semantic_binding_lineage"]["fix_predicate_binding_status"] == "ambiguous"
    assert ledger["missing_reason"] == "ambiguous_cve_level_only"


def test_conflicting_accepted_artifacts_do_not_silently_backfill(tmp_path: Path) -> None:
    inventory_a = extract_root_cause_artifact_inventory(
        cve_id="CVE-TEST",
        artifact_path=_write_artifact(tmp_path / "run-a" / "CVE-TEST", fix_predicate_id="fp-a"),
        source_run_name="run-a",
    )
    inventory_b = extract_root_cause_artifact_inventory(
        cve_id="CVE-TEST",
        artifact_path=_write_artifact(tmp_path / "run-b" / "CVE-TEST", fix_predicate_id="fp-b"),
        source_run_name="run-b",
    )
    index = build_semantic_binding_index([inventory_a, inventory_b])
    candidate = {
        "candidate_id": "cand-1",
        "candidate_origin": {
            "fix_commit_id": "fix-commit:demo:abc123",
            "anchor_path": "src/a.c",
            "fix_predicate_bindings": [],
        },
    }

    repaired, ledger = repair_candidate_semantic_bindings(candidate, index, cve_id="CVE-TEST")

    assert repaired["candidate_origin"]["fix_predicate_bindings"] == []
    assert repaired["candidate_origin"]["semantic_binding_lineage"]["fix_predicate_binding_status"] == "conflict"
    assert ledger["missing_reason"] == "source_artifact_conflict"
