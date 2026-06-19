from __future__ import annotations

import csv
import json
from pathlib import Path

from vulngraph.workflows.judge_v0 import FixtureJudgeBackend
from vulngraph.workflows.judge_v0_full_stress import (
  run_judge_v0_full_stress,
  scan_forbidden_full_stress_outputs,
)


def _write_json(path: Path, data: object) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _read_json(path: Path) -> dict:
  return json.loads(path.read_text(encoding="utf-8"))


def _sha(char: str) -> str:
  return char * 40


def _make_case(root: Path, cve_id: str, *, candidate_source: str = "strong", candidate_count: int = 1) -> None:
  judge_root = root / "judge"
  evidence_root = root / "evidence"
  slimming_root = root / "slimming"
  candidates = []
  evidence_candidates = []
  for index in range(candidate_count):
    candidate_id = f"prefx-{cve_id}-{index}"
    commit_sha = _sha(chr(ord("a") + index))
    candidate = {
      "cve_id": cve_id,
      "repo": "repo",
      "fix_commit_id": f"fix-commit:repo:{_sha('f')}",
      "patch_family_id": "patch-family:one",
      "candidate_commit_sha": commit_sha,
      "candidate_source": candidate_source,
      "candidate_generation_mode": "fallback_inventory_anchor" if candidate_source == "fallback" else "strong_model_anchor",
      "evidence_level": candidate_source,
      "lifecycle": "raw_candidate",
      "selected_anchor_id": f"anchor-{index}",
      "fallback_anchor_id": "",
      "candidate_ids": [candidate_id],
      "path_before": "src/a.c",
      "old_line_start": 10 + index,
      "old_line_end": 10 + index,
      "old_line_text": "dangerous_use(ptr);",
      "old_line_text_hash": "h" * 64,
      "blame_trace": {
        "status": "success",
        "line_provenance": [{"role": "dangerous_use", "selection_mode": "modified_old_side"}],
        "errors": [],
      },
      "root_cause_hypothesis_bindings": ["hyp-1"],
      "vulnerable_predicate_bindings": ["vp-1"],
      "fix_predicate_bindings": ["fp-1"],
      "predicate_bindings": ["vp-1", "fp-1"],
      "risk_flags": ["fallback_candidate"] if candidate_source == "fallback" else [],
      "uncertainty_flags": [],
      "release_tag_summary": {"count": 0, "tags": [], "truncated": False},
    }
    candidates.append(candidate)
    evidence_candidates.append(
      {
        "candidate_identity": {
          "candidate_commit_sha": commit_sha,
          "candidate_id": candidate_id,
          "candidate_ids": [candidate_id],
          "path_before": "src/a.c",
          "old_line_start": 10 + index,
          "old_line_end": 10 + index,
          "old_line_text_hash": "h" * 64,
        },
        "blame_variants": {
          "variant_agreement": "all_same",
          "canonical_blame_commit_sha": commit_sha,
          "success_count": 1,
          "failure_count": 0,
        },
        "line_survival_evidence": {"line_survival_status": "survives_to_fix_parent"},
        "commit_relation_evidence": {
          "candidate_is_ancestor_of_fix": True,
          "candidate_in_fix_series_hint": False,
          "candidate_is_merge_commit": False,
        },
        "release_reachability_summary": {
          "reachable_release_tag_count": 0,
          "release_line_count_estimate": 0,
          "release_reachability_too_broad": False,
          "release_reachability_artifact_ref": "",
        },
        "risk_flags": ["fallback_candidate"] if candidate_source == "fallback" else [],
        "confidence_features": ["root_cause_predicate_bound"],
        "lifecycle": "raw_candidate",
      }
    )
  _write_json(
    judge_root / cve_id / "judge_blind_input_packet.json",
    {
      "schema_version": "judge_blind_input_packet_v0",
      "cve_id": cve_id,
      "repo": "repo",
      "case_status": "judge_ready",
      "candidate_count": len(candidates),
      "lifecycle": "raw_candidate",
      "candidates": candidates,
    },
  )
  _write_json(
    evidence_root / cve_id / "judge_szz_evidence_packet.json",
    {
      "schema_version": "judge_szz_evidence_packet_v0",
      "cve_id": cve_id,
      "repo": "repo",
      "candidate_count": len(candidates),
      "lifecycle": "raw_candidate",
      "candidates": evidence_candidates,
    },
  )
  _write_json(evidence_root / cve_id / "szz_evidence_audit_packet.json", {"candidates": evidence_candidates})
  (slimming_root / "shadow_model_views" / "root_cause").mkdir(parents=True, exist_ok=True)
  (slimming_root / "shadow_model_views" / "root_cause" / f"{cve_id}.prompt.after.txt").write_text(
    "trigger: attacker controlled input\nsink: dangerous use\n",
    encoding="utf-8",
  )


def test_full_stress_tracks_duplicate_cves_and_writes_required_outputs(tmp_path: Path) -> None:
  _make_case(tmp_path, "CVE-A", candidate_source="strong", candidate_count=1)
  _make_case(tmp_path, "CVE-B", candidate_source="fallback", candidate_count=2)
  dataset = tmp_path / "dataset.json"
  _write_json(dataset, {"CVE-A": {"repo": "repo"}, "CVE-B": {"repo": "repo"}})
  out_dir = tmp_path / "out"

  summary = run_judge_v0_full_stress(
    cve_ids_10=["CVE-A", "CVE-B"],
    cve_ids_30=["CVE-A"],
    judge_packet_root=tmp_path / "judge",
    detailed_evidence_root=tmp_path / "evidence",
    slimming_root=tmp_path / "slimming",
    dataset=dataset,
    out_dir=out_dir,
    backend=FixtureJudgeBackend(),
    reset=True,
  )

  assert summary["input_case_count_10"] == 2
  assert summary["input_case_count_30"] == 1
  assert summary["total_input_cases"] == 3
  assert summary["unique_cve_count"] == 2
  assert summary["duplicate_cve_count"] == 1
  assert summary["duplicate_cves"] == ["CVE-A"]
  assert summary["all_candidates_accounted_rate"] == 1.0
  assert (out_dir / "cases" / "10" / "CVE-A" / "judge_result.json").exists()
  assert (out_dir / "cases" / "30" / "CVE-A" / "judge_result.json").exists()
  assert (out_dir / "summary.json").exists()
  assert (out_dir / "judge_full_stress_report.md").exists()
  for name in (
    "judge_rankings.csv",
    "judge_contract_summary.csv",
    "candidate_type_metrics.csv",
    "prompt_size_summary.csv",
    "session_manifest.json",
    "manual_review_queue.csv",
  ):
    assert (out_dir / name).exists()
  rankings = (out_dir / "judge_rankings.csv").read_text(encoding="utf-8")
  assert "top1_raw_candidate_judgment" in rankings
  assert "top1_bic" not in rankings.lower()
  contract_rows = list(csv.DictReader((out_dir / "judge_contract_summary.csv").open(encoding="utf-8")))
  assert len(contract_rows) == 3
  assert all(row["all_candidates_accounted"] == "True" for row in contract_rows)


def test_full_stress_forbidden_scan_skips_prompts_but_checks_json_keys(tmp_path: Path) -> None:
  (tmp_path / "case" / "judge_prompt.txt").parent.mkdir(parents=True)
  (tmp_path / "case" / "judge_prompt.txt").write_text('"bic": "allowed inside prompt text"', encoding="utf-8")
  _write_json(tmp_path / "case" / "bad.json", {"bic": "forbidden exact key"})

  scan = scan_forbidden_full_stress_outputs(tmp_path)

  assert scan["ok"] is False
  assert scan["violation_count"] == 1
  assert scan["violations"][0]["key"] == "bic"
