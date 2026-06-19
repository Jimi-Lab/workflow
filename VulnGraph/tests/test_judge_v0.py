from __future__ import annotations

import json
from pathlib import Path

from vulngraph.agent_io.judge_contract import lint_judge_output_v0, scan_forbidden_judge_fields
from vulngraph.agent_io.judge_schema import parse_judge_output_v0
from vulngraph.workflows.judge_v0 import (
  FixtureJudgeBackend,
  _repair_prompt,
  build_judge_input_v0,
  run_judge_v0_batch,
)


def _write_json(path: Path, data: object) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _read_json(path: Path) -> dict:
  return json.loads(path.read_text(encoding="utf-8"))


def _sha(char: str) -> str:
  return char * 40


def _make_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
  judge_root = tmp_path / "judge"
  evidence_root = tmp_path / "evidence"
  slimming_root = tmp_path / "slimming"
  dataset = tmp_path / "dataset.json"
  cve_id = "CVE-TEST-1"
  _write_json(
    dataset,
    {
      cve_id: {
        "repo": "openssl",
        "CWE": "CWE-476",
        "cwe": "CWE-476",
        "description": "A NULL pointer dereference can be triggered by attacker-controlled input.",
        "fixing_commits": [[_sha("f")]],
      }
    },
  )
  candidate = {
    "cve_id": cve_id,
    "repo": "openssl",
    "fix_commit_id": f"fix-commit:openssl:{_sha('f')}",
    "patch_family_id": "patch-family:one",
    "candidate_commit_sha": _sha("a"),
    "candidate_source": "strong",
    "candidate_generation_mode": "strong_model_anchor",
    "evidence_level": "strong",
    "lifecycle": "raw_candidate",
    "selected_anchor_id": "anchor-1",
    "fallback_anchor_id": "",
    "candidate_ids": ["prefx-1"],
    "path_before": "ssl/t1_lib.c",
    "old_line_start": 10,
    "old_line_end": 10,
    "old_line_text": "if (sig_nid == sigalg->sigandhash)",
    "old_line_text_hash": "h" * 64,
    "blame_trace": {"status": "success", "line_provenance": [{"role": "dangerous_use", "selection_mode": "modified_old_side"}], "errors": []},
    "root_cause_hypothesis_bindings": ["hyp-1"],
    "vulnerable_predicate_bindings": ["vp-1"],
    "fix_predicate_bindings": ["fp-1"],
    "predicate_bindings": ["vp-1", "fp-1"],
    "risk_flags": [],
    "uncertainty_flags": [],
    "release_tag_summary": {"count": 2, "tags": ["v1", "v2"], "truncated": False},
  }
  _write_json(
    judge_root / cve_id / "judge_blind_input_packet.json",
    {
      "schema_version": "judge_blind_input_packet_v0",
      "cve_id": cve_id,
      "repo": "openssl",
      "case_status": "judge_ready",
      "candidate_count": 1,
      "lifecycle": "raw_candidate",
      "candidates": [candidate],
    },
  )
  _write_json(
    evidence_root / cve_id / "judge_szz_evidence_packet.json",
    {
      "schema_version": "judge_szz_evidence_packet_v0",
      "cve_id": cve_id,
      "repo": "openssl",
      "candidate_count": 1,
      "lifecycle": "raw_candidate",
      "candidates": [
        {
          "candidate_identity": {
            "candidate_commit_sha": _sha("a"),
            "candidate_id": "prefx-1",
            "selected_anchor_id": "anchor-1",
            "path_before": "ssl/t1_lib.c",
            "old_line_start": 10,
            "old_line_end": 10,
            "old_line_text_hash": "h" * 64,
          },
          "blame_variants": {
            "variant_agreement": "all_same",
            "canonical_blame_commit_sha": _sha("a"),
            "success_count": 5,
            "failure_count": 0,
          },
          "line_survival_evidence": {"line_survival_status": "survives_to_fix_parent"},
          "commit_relation_evidence": {
            "candidate_is_ancestor_of_fix": True,
            "candidate_in_fix_series_hint": False,
            "candidate_is_merge_commit": False,
          },
          "fix_series_equivalent_backport_hints": {"candidate_in_same_fix_series_window": False},
          "release_reachability_summary": {
            "reachable_release_tag_count": 2,
            "release_line_count_estimate": 1,
            "release_reachability_too_broad": False,
            "release_reachability_artifact_ref": "release_reachability_full.json",
          },
          "risk_flags": [],
          "confidence_features": ["root_cause_predicate_bound", "stable_blame_variants"],
          "lifecycle": "raw_candidate",
        }
      ],
    },
  )
  (slimming_root / "shadow_model_views" / "root_cause").mkdir(parents=True)
  (slimming_root / "shadow_model_views" / "root_cause" / f"{cve_id}.prompt.after.txt").write_text(
    "failure_mode: NULL dereference\ntrigger: attacker-controlled signature algorithm\nsink: sigalg dereference\n",
    encoding="utf-8",
  )
  return judge_root, evidence_root, slimming_root, dataset


def _make_unavailable_attacker_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
  judge_root, evidence_root, slimming_root, dataset = _make_inputs(tmp_path)
  prompt_path = slimming_root / "shadow_model_views" / "root_cause" / "CVE-TEST-1.prompt.after.txt"
  prompt_path.write_text(
    'ROOT_CAUSE_MODEL_VIEW:\n{"schema_version":"root_cause_model_view_v1","ownership_contract":{"wrapper_owned_facts":["repo"]},"raw_context_summary":"context only"}',
    encoding="utf-8",
  )
  return judge_root, evidence_root, slimming_root, dataset


def _valid_output(cve_id: str = "CVE-TEST-1") -> dict:
  return {
    "schema_version": "judge_output_v0",
    "cve_id": cve_id,
    "case_disposition": "ranked",
    "candidate_judgments": [
      {
        "candidate_id": "prefx-1",
        "candidate_commit_sha": _sha("a"),
        "rank": 1,
        "judgment": "plausible_introduction_boundary",
        "confidence": "medium",
        "evidence_refs_used": ["szz:prefx-1", "root_cause:prefx-1"],
        "supporting_factors": ["root cause binding and stable blame variants support the boundary"],
        "contradicting_factors": [],
        "risk_flags_considered": [],
        "uncertainty_reasons": [],
      }
    ],
    "excluded_candidates": [],
    "judge_notes": {
      "attack_perspective_used": True,
      "root_cause_binding_used": True,
      "szz_evidence_used": True,
      "version_conversion_not_performed": True,
    },
  }


def test_build_judge_input_excludes_forbidden_fields(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, dataset = _make_inputs(tmp_path)

  packet = build_judge_input_v0(
    cve_id="CVE-TEST-1",
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    dataset=dataset,
  )

  assert packet["schema_version"] == "judge_input_v0"
  assert packet["candidate_set"][0]["candidate_id"] == "prefx-1"
  assert packet["candidate_set"][0]["candidate_commit_sha"] == _sha("a")
  assert packet["szz_evidence_cards"][0]["variant_agreement"] == "all_same"
  assert scan_forbidden_judge_fields(packet)["ok"] is True


def test_build_judge_input_marks_unavailable_attacker_perspective(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, dataset = _make_unavailable_attacker_inputs(tmp_path)

  packet = build_judge_input_v0(
    cve_id="CVE-TEST-1",
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    dataset=dataset,
  )

  assert packet["cve_context"]["attacker_perspective_available"] is False
  assert packet["cve_context"]["attacker_perspective_unavailable_reason"] == "no_structured_attacker_perspective_fields"


def test_build_judge_input_strips_root_cause_model_view_noise(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, dataset = _make_unavailable_attacker_inputs(tmp_path)

  packet = build_judge_input_v0(
    cve_id="CVE-TEST-1",
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    dataset=dataset,
  )

  context_text = json.dumps(packet["root_cause_context"], ensure_ascii=False)
  for token in ("schema_version", "ownership_contract", "wrapper_owned_facts", "model_owned_judgments", "raw_context_summary"):
    assert token not in context_text
  assert "root_cause_digest" in packet["root_cause_context"]
  assert "predicate_digest" in packet["root_cause_context"]
  assert "fix_digest" in packet["root_cause_context"]


def test_contract_rejects_invented_candidate_id_and_sha(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, dataset = _make_inputs(tmp_path)
  packet = build_judge_input_v0(
    cve_id="CVE-TEST-1",
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    dataset=dataset,
  )
  output = _valid_output()
  output["candidate_judgments"][0]["candidate_id"] = "invented"
  output["candidate_judgments"][0]["candidate_commit_sha"] = _sha("b")

  result = lint_judge_output_v0(output, packet)

  assert result.ok is False
  assert "unknown_candidate_id" in result.taxonomy
  assert "candidate_sha_mismatch" in result.taxonomy


def test_contract_rejects_attacker_perspective_claim_when_unavailable(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, dataset = _make_unavailable_attacker_inputs(tmp_path)
  packet = build_judge_input_v0(
    cve_id="CVE-TEST-1",
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    dataset=dataset,
  )
  output = _valid_output()
  output["judge_notes"]["attack_perspective_used"] = True

  result = lint_judge_output_v0(output, packet)

  assert result.ok is False
  assert "attacker_perspective_claimed_but_unavailable" in result.taxonomy


def test_contract_allows_attacker_perspective_unused_when_unavailable(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, dataset = _make_unavailable_attacker_inputs(tmp_path)
  packet = build_judge_input_v0(
    cve_id="CVE-TEST-1",
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    dataset=dataset,
  )
  output = _valid_output()
  output["judge_notes"]["attack_perspective_used"] = False

  result = lint_judge_output_v0(output, packet)

  assert result.ok is True


def test_contract_requires_all_candidates_accounted_and_unique_rank(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, dataset = _make_inputs(tmp_path)
  packet = build_judge_input_v0(
    cve_id="CVE-TEST-1",
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    dataset=dataset,
  )
  packet["candidate_set"].append({**packet["candidate_set"][0], "candidate_id": "prefx-2", "candidate_commit_sha": _sha("b")})
  output = _valid_output()

  result = lint_judge_output_v0(output, packet)

  assert result.ok is False
  assert "candidate_not_accounted" in result.taxonomy


def test_contract_rejects_fallback_high_confidence_without_explanation(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, dataset = _make_inputs(tmp_path)
  packet = build_judge_input_v0(
    cve_id="CVE-TEST-1",
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    dataset=dataset,
  )
  packet["candidate_set"][0]["candidate_source"] = "fallback"
  output = _valid_output()
  output["candidate_judgments"][0]["confidence"] = "high"
  output["candidate_judgments"][0]["supporting_factors"] = ["stable blame"]

  result = lint_judge_output_v0(output, packet)

  assert result.ok is False
  assert "fallback_high_confidence_without_explanation" in result.taxonomy


def test_release_overreach_cannot_be_only_exclusion_reason(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, dataset = _make_inputs(tmp_path)
  packet = build_judge_input_v0(
    cve_id="CVE-TEST-1",
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    dataset=dataset,
  )
  output = _valid_output()
  output["candidate_judgments"] = []
  output["excluded_candidates"] = [{"candidate_id": "prefx-1", "reason": "release_reachability_too_broad"}]

  result = lint_judge_output_v0(output, packet)

  assert result.ok is False
  assert "release_overreach_only_exclusion" in result.taxonomy


def test_ranked_judgment_must_use_evidence_refs(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, dataset = _make_inputs(tmp_path)
  packet = build_judge_input_v0(
    cve_id="CVE-TEST-1",
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    dataset=dataset,
  )
  output = _valid_output()
  output["candidate_judgments"][0]["evidence_refs_used"] = []

  result = lint_judge_output_v0(output, packet)

  assert result.ok is False
  assert "judgment_without_evidence_refs" in result.taxonomy


def test_conflicting_szz_candidate_must_be_uncertain_or_explained(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, dataset = _make_inputs(tmp_path)
  packet = build_judge_input_v0(
    cve_id="CVE-TEST-1",
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    dataset=dataset,
  )
  packet["candidate_set"][0]["risk_flags"] = ["move_copy_sensitive_blame"]
  output = _valid_output()
  output["candidate_judgments"][0]["supporting_factors"] = ["stable blame"]
  output["candidate_judgments"][0]["risk_flags_considered"] = []

  result = lint_judge_output_v0(output, packet)

  assert result.ok is False
  assert "conflicting_evidence_without_strict_explanation" in result.taxonomy


def test_conflicting_szz_candidate_allows_strict_evidence_explanation(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, dataset = _make_inputs(tmp_path)
  packet = build_judge_input_v0(
    cve_id="CVE-TEST-1",
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    dataset=dataset,
  )
  packet["candidate_set"][0]["risk_flags"] = ["move_copy_sensitive_blame"]
  output = _valid_output()
  output["candidate_judgments"][0]["supporting_factors"] = [
    "Acknowledges move_copy_sensitive_blame; normal and ignore-whitespace blame agree on this candidate, and move/copy disagreement is treated as refactor risk rather than direct contradiction."
  ]
  output["candidate_judgments"][0]["contradicting_factors"] = ["move_copy_sensitive_blame"]
  output["candidate_judgments"][0]["risk_flags_considered"] = ["move_copy_sensitive_blame"]
  output["candidate_judgments"][0]["uncertainty_reasons"] = ["move_copy_sensitive_blame remains a residual risk"]

  result = lint_judge_output_v0(output, packet)

  assert result.ok is True


def test_candidate_role_features_are_separated(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, dataset = _make_inputs(tmp_path)
  blind = _read_json(judge_root / "CVE-TEST-1" / "judge_blind_input_packet.json")
  blind["candidates"][0]["blame_trace"]["line_provenance"][0]["role"] = "state_declaration"
  _write_json(judge_root / "CVE-TEST-1" / "judge_blind_input_packet.json", blind)
  evidence = _read_json(evidence_root / "CVE-TEST-1" / "judge_szz_evidence_packet.json")
  evidence["candidates"][0]["confidence_features"] = ["dangerous_use_role", "stable_blame_variants"]
  _write_json(evidence_root / "CVE-TEST-1" / "judge_szz_evidence_packet.json", evidence)

  packet = build_judge_input_v0(
    cve_id="CVE-TEST-1",
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    dataset=dataset,
  )
  candidate = packet["candidate_set"][0]

  assert candidate["candidate_anchor_role"] == "state_declaration"
  assert "dangerous_use_role" in candidate["related_role_features"]
  assert "dangerous_use_role" not in candidate["evidence_confidence_features"]


def test_contract_rejects_supporting_factor_misreading_related_role_as_candidate_role(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, dataset = _make_inputs(tmp_path)
  blind = _read_json(judge_root / "CVE-TEST-1" / "judge_blind_input_packet.json")
  blind["candidates"][0]["blame_trace"]["line_provenance"][0]["role"] = "state_declaration"
  _write_json(judge_root / "CVE-TEST-1" / "judge_blind_input_packet.json", blind)
  evidence = _read_json(evidence_root / "CVE-TEST-1" / "judge_szz_evidence_packet.json")
  evidence["candidates"][0]["confidence_features"] = ["dangerous_use_role", "stable_blame_variants"]
  _write_json(evidence_root / "CVE-TEST-1" / "judge_szz_evidence_packet.json", evidence)
  packet = build_judge_input_v0(
    cve_id="CVE-TEST-1",
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    dataset=dataset,
  )
  output = _valid_output()
  output["candidate_judgments"][0]["supporting_factors"] = ["dangerous_use_role on this candidate"]

  result = lint_judge_output_v0(output, packet)

  assert result.ok is False
  assert "related_role_misread_as_candidate_role" in result.taxonomy


def test_cve_2020_11984_state_declaration_dangerous_use_regression() -> None:
  packet = build_judge_input_v0(
    cve_id="CVE-2020-11984",
    judge_packet_root=Path("runs/batches/vulngraph-judge-input-hardening-v1-30-p0-fix"),
    detailed_evidence_root=Path("runs/batches/vulngraph-detailed-szz-evidence-v0-30"),
    slimming_root=Path("runs/batches/vulngraph-core-dataflow-slimming-v1"),
    dataset=Path(r"E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json"),
  )
  state_candidates = [item for item in packet["candidate_set"] if item["candidate_anchor_role"] == "state_declaration"]
  assert state_candidates
  assert any("dangerous_use_role" in item["related_role_features"] for item in state_candidates)
  assert all("dangerous_use_role" not in item["evidence_confidence_features"] for item in state_candidates)


def test_parse_fenced_judge_output() -> None:
  parsed = parse_judge_output_v0("```json\n" + json.dumps(_valid_output()) + "\n```")

  assert parsed.ok is True
  assert parsed.format == "fenced_json"


def test_fixture_workflow_writes_judge_artifacts(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, dataset = _make_inputs(tmp_path)
  out_dir = tmp_path / "out"

  summary = run_judge_v0_batch(
    cve_ids=["CVE-TEST-1"],
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    dataset=dataset,
    out_dir=out_dir,
    backend=FixtureJudgeBackend(),
  )

  assert summary["cases_total"] == 1
  assert summary["contract_ok_count"] == 1
  assert summary["forbidden_field_scan_ok"] is True
  assert summary["attacker_context_available_count"] == 1
  assert summary["attacker_context_unavailable_count"] == 0
  assert (out_dir / "CVE-TEST-1" / "judge_input_v0.json").exists()
  assert _read_json(out_dir / "CVE-TEST-1" / "judge_result.json")["lifecycle"] == "raw_candidate_judged"
  summary_csv = (out_dir / "per_cve_judge_summary.csv").read_text(encoding="utf-8")
  assert ",0," in summary_csv


def test_repair_prompt_includes_schema_and_allowed_ids_without_full_evidence(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, dataset = _make_inputs(tmp_path)
  packet = build_judge_input_v0(
    cve_id="CVE-TEST-1",
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    dataset=dataset,
  )

  prompt = _repair_prompt("{", "assistant output does not contain a JSON object", {"ok": False}, packet)

  assert '"schema_version": "judge_output_v0"' in prompt
  assert "uncertain_boundary" in prompt
  assert '"rank": 1' in prompt
  assert "evidence_refs_used" in prompt
  assert "prefx-1" in prompt
  assert _sha("a") in prompt
  assert "if (sig_nid == sigalg->sigandhash)" not in prompt
