from __future__ import annotations

import json
from pathlib import Path

from vulngraph.workflows.judge_input_readiness import build_judge_input_readiness


def _write_json(path: Path, data: object) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _anchor(candidate_id: str, *, fallback: bool = False) -> dict:
  return {
    "anchor_id": f"{'fallback-anchor' if fallback else 'pre-fix-anchor'}:{candidate_id}",
    "candidate_id": candidate_id,
    "cve_id": "CVE-X",
    "fix_set_id": "CVE-X:fix-set:1",
    "patch_family_id": "patch-family:one",
    "fix_commit_id": "fix-commit:repo:fix",
    "fix_commit_sha": "f" * 40,
    "parent_sha": "p" * 40,
    "patch_hunk_id": "patch-hunk:one",
    "path_before": "src/a.c",
    "path_after": "src/a.c",
    "old_line_start": 7,
    "old_line_end": 7,
    "line_text": "dangerous_use(ptr);",
    "line_text_sha256": "h" * 64,
    "candidate_source": "deleted_line",
    "role": "dangerous_use",
    "selection_mode": "modified_old_side",
    "root_cause_hypothesis_ids": ["hyp-1"],
    "predicate_ids": ["vp-1", "fix-pred-1"],
    "git_observation_refs": ["obs-1"],
    "rationale": "anchor rationale",
    "confidence": 0.8,
    "lifecycle": "raw_candidate",
    "uncertainty_reasons": [],
    "exclusion_reasons": [],
  }


def _candidate(commit_sha: str, candidate_id: str, *, mode: str, evidence: str) -> dict:
  return {
    "commit_sha": commit_sha,
    "anchor_ids": [f"{'fallback-anchor' if mode.startswith('fallback') else 'pre-fix-anchor'}:{candidate_id}"],
    "candidate_ids": [candidate_id],
    "roles": ["dangerous_use"],
    "selection_modes": ["modified_old_side"],
    "vote_count": 1,
    "line_provenance": [
      {
        "anchor_id": f"{'fallback-anchor' if mode.startswith('fallback') else 'pre-fix-anchor'}:{candidate_id}",
        "candidate_id": candidate_id,
        "fix_commit_sha": "f" * 40,
        "parent_sha": "p" * 40,
        "path_before": "src/a.c",
        "old_line": 7,
        "line_text_sha256": "h" * 64,
        "blamed_commit_sha": commit_sha,
        "boundary_marker": False,
        "role": "dangerous_use",
        "selection_mode": "modified_old_side",
        "status": "success",
        "lifecycle": "raw_candidate",
      }
    ],
    "lifecycle": "raw_candidate",
    "candidate_generation_mode": mode,
    "evidence_level": evidence,
  }


def test_judge_input_packet_contains_raw_candidate_fields_and_diagnostics(tmp_path: Path) -> None:
  anchor_run = tmp_path / "anchor"
  version_probe = tmp_path / "probe"
  ten_run = tmp_path / "ten"
  out_dir = tmp_path / "out"
  _write_json(
    anchor_run / "summary.json",
    {
      "cases_total": 2,
      "strong_candidate_ready_count": 1,
      "fallback_candidate_ready_count": 1,
      "judge_input_ready_count": 2,
      "no_candidate_count": 0,
      "no_candidate_cases": [],
      "strong_raw_candidate_commit_count": 1,
      "fallback_raw_candidate_commit_count": 1,
      "results": [
        {"cve_id": "CVE-X", "candidate_generation_mode": "strong_model_anchor", "candidate_commit_count": 1},
        {"cve_id": "CVE-F", "candidate_generation_mode": "fallback_inventory_anchor", "candidate_commit_count": 1},
      ],
    },
  )
  for cve_id, commit, mode, evidence, fallback in [
    ("CVE-X", "a" * 40, "strong_model_anchor", "strong", False),
    ("CVE-F", "b" * 40, "fallback_inventory_anchor", "fallback", True),
  ]:
    _write_json(anchor_run / cve_id / "candidate_commits.json", [_candidate(commit, f"cand-{cve_id}", mode=mode, evidence=evidence)])
    _write_json(anchor_run / cve_id / "resolved_pre_fix_anchors.json", [_anchor(f"cand-{cve_id}", fallback=fallback)])
    _write_json(anchor_run / cve_id / "blame_trace.json", {"status": "success", "line_records": []})
    _write_json(anchor_run / cve_id / "ingestion_result.json", {"status": "ingested_raw_candidate", "taxonomy": {}})
  _write_json(
    version_probe / "summary.json",
    {
      "release_line_overreach_cases": ["CVE-F"],
      "any_candidate_non_release_tag_noise_cases": [],
      "manual_anchor_review_required_cases": ["CVE-F"],
    },
  )
  _write_json(
    version_probe / "per_candidate_probe.json",
    {
      "CVE-X": {
        "release_tag_universe": [
          {"commit_sha": "a" * 40, "predicted_tags": ["v1"], "metrics": {"f1": 1.0}, "false_positive_taxonomy": {}}
        ],
        "ground_truth_affected_versions": ["v1"],
      },
      "CVE-F": {
        "release_tag_universe": [
          {"commit_sha": "b" * 40, "predicted_tags": ["v2"], "metrics": {"f1": 0.5}, "false_positive_taxonomy": {"release_line_overreach": ["v3"]}}
        ],
        "ground_truth_affected_versions": ["v2", "v3"],
      },
    },
  )
  _write_json(ten_run / "summary.json", {"cases_total": 1, "candidate_commit_ready_cases": 1})

  summary = build_judge_input_readiness(
    anchor_artifact=anchor_run,
    version_probe=version_probe,
    ten_artifact=ten_run,
    out_dir=out_dir,
  )

  packet = json.loads((out_dir / "CVE-F" / "judge_input_packet.json").read_text(encoding="utf-8"))
  candidate = packet["candidates"][0]
  assert candidate["candidate_commit_sha"] == "b" * 40
  assert candidate["candidate_source"] == "fallback"
  assert candidate["evidence_level"] == "fallback"
  assert candidate["lifecycle"] == "raw_candidate"
  assert candidate["fallback_anchor_id"].startswith("fallback-anchor:")
  assert candidate["predicted_release_tags_from_version_probe"] == ["v2"]
  assert candidate["diagnostic"]["gt_release_tags"] == ["v2", "v3"]
  assert "fallback_candidate" in candidate["risk_flags"]
  assert "release_line_overreach" in candidate["risk_flags"]
  assert summary["candidate_ready_before_fallback"] == 1
  assert summary["candidate_ready_after_fallback"] == 2
  assert summary["fallback_candidate_ready"] == 1
  assert (out_dir / "judge_input_summary.csv").exists()
  assert (out_dir / "fallback_quality_audit.csv").exists()
  serialized = "".join(path.read_text(encoding="utf-8") for path in out_dir.rglob("*") if path.is_file())
  assert '"validated_bic"' not in serialized
  assert '"correct_bic"' not in serialized
  assert '"affected_versions"' not in serialized


def test_no_candidate_case_is_reported_without_fabricated_candidate(tmp_path: Path) -> None:
  anchor_run = tmp_path / "anchor"
  version_probe = tmp_path / "probe"
  out_dir = tmp_path / "out"
  _write_json(
    anchor_run / "summary.json",
    {
      "cases_total": 1,
      "strong_candidate_ready_count": 0,
      "fallback_candidate_ready_count": 0,
      "judge_input_ready_count": 0,
      "no_candidate_count": 1,
      "no_candidate_cases": [{"cve_id": "CVE-NO", "no_fallback_candidate_reason": "no_blameable_old_side"}],
      "results": [{"cve_id": "CVE-NO", "candidate_commit_count": 0}],
    },
  )
  _write_json(anchor_run / "CVE-NO" / "candidate_commits.json", [])
  _write_json(anchor_run / "CVE-NO" / "candidate_inventory.json", {"candidates": [], "fix_families": {}, "git_trace": []})
  _write_json(anchor_run / "CVE-NO" / "ingestion_result.json", {"status": "raw_candidate_censored", "no_fallback_candidate_reason": "no_blameable_old_side"})
  _write_json(version_probe / "summary.json", {})
  _write_json(version_probe / "per_candidate_probe.json", {"CVE-NO": {"release_tag_universe": [], "ground_truth_affected_versions": ["v1"]}})

  summary = build_judge_input_readiness(
    anchor_artifact=anchor_run,
    version_probe=version_probe,
    ten_artifact=None,
    out_dir=out_dir,
  )

  packet = json.loads((out_dir / "CVE-NO" / "judge_input_packet.json").read_text(encoding="utf-8"))
  assert packet["candidates"] == []
  assert packet["case_status"] == "not_judge_ready"
  assert summary["no_candidate_cases"] == [{"cve_id": "CVE-NO", "no_fallback_candidate_reason": "no_blameable_old_side"}]
