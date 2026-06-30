from __future__ import annotations

import json
from pathlib import Path

from vulngraph.agent_io.judge_boundary_contract import (
  derive_boundary_views,
  lint_judge_boundary_output_v1,
  scan_forbidden_boundary_fields,
)
from vulngraph.agent_io.judge_boundary_schema import parse_judge_boundary_output_v1
from vulngraph.workflows.judge_boundary_v1 import FixtureJudgeBoundaryBackend, build_judge_boundary_input_v1, run_judge_boundary_v1_batch
from vulngraph.agent_backends.base import AgentResponse


def _write_json(path: Path, data: object) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _sha(char: str) -> str:
  return char * 40


def _make_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
  judge_root = tmp_path / "judge"
  evidence_root = tmp_path / "evidence"
  slimming_root = tmp_path / "slimming"
  v0_root = tmp_path / "v0"
  dataset = tmp_path / "dataset.json"
  cve_id = "CVE-BOUNDARY-1"
  _write_json(dataset, {cve_id: {"repo": "repo", "CWE": "CWE-787", "description": "test", "fixing_commits": [[_sha("f")]]}})
  candidate = {
    "cve_id": cve_id,
    "repo": "repo",
    "fix_commit_id": f"fix-commit:repo:{_sha('f')}",
    "patch_family_id": "patch-family:one",
    "candidate_commit_sha": _sha("a"),
    "candidate_source": "strong",
    "candidate_generation_mode": "strong_model_anchor",
    "evidence_level": "strong",
    "lifecycle": "raw_candidate",
    "selected_anchor_id": "anchor-1",
    "candidate_ids": ["cand-1"],
    "path_before": "src/a.c",
    "old_line_start": 10,
    "old_line_end": 10,
    "old_line_text": "dangerous_use(ptr);",
    "old_line_text_hash": "h" * 64,
    "blame_trace": {"status": "success", "line_provenance": [{"role": "dangerous_use", "selection_mode": "modified_old_side"}], "errors": []},
    "root_cause_hypothesis_bindings": ["hyp-1"],
    "vulnerable_predicate_bindings": ["vp-1"],
    "fix_predicate_bindings": ["fp-1"],
    "risk_flags": [],
  }
  _write_json(
    judge_root / cve_id / "judge_blind_input_packet.json",
    {"schema_version": "judge_blind_input_packet_v0", "cve_id": cve_id, "repo": "repo", "candidate_count": 1, "candidates": [candidate]},
  )
  _write_json(
    evidence_root / cve_id / "judge_szz_evidence_packet.json",
    {
      "schema_version": "judge_szz_evidence_packet_v0",
      "cve_id": cve_id,
      "repo": "repo",
      "candidate_count": 1,
      "candidates": [
        {
          "candidate_identity": {"candidate_commit_sha": _sha("a"), "candidate_id": "cand-1", "candidate_ids": ["cand-1"]},
          "blame_variants": {"variant_agreement": "all_same", "canonical_blame_commit_sha": _sha("a"), "variants": [{"variant": "normal", "blamed_commit_sha": _sha("a")}]},
          "line_survival_evidence": {"line_survival_status": "survives_to_fix_parent"},
          "commit_relation_evidence": {"candidate_is_ancestor_of_fix": True, "candidate_in_fix_series_hint": False, "candidate_is_merge_commit": False},
          "release_reachability_summary": {"reachable_release_tag_count": 2, "release_line_count_estimate": 1, "release_reachability_too_broad": False},
          "risk_flags": [],
          "confidence_features": ["root_cause_predicate_bound", "stable_blame_variants"],
          "lifecycle": "raw_candidate",
        }
      ],
    },
  )
  _write_json(evidence_root / cve_id / "szz_evidence_audit_packet.json", {"candidates": []})
  (slimming_root / "shadow_model_views" / "root_cause").mkdir(parents=True, exist_ok=True)
  (slimming_root / "shadow_model_views" / "root_cause" / f"{cve_id}.prompt.after.txt").write_text("trigger: input\nsink: dangerous use", encoding="utf-8")
  _write_json(
    v0_root / "cases" / "30" / cve_id / "judge_result.json",
    {
      "cve_id": cve_id,
      "contract_ok": True,
      "candidate_rankings": [{"candidate_id": "cand-1", "candidate_commit_sha": _sha("a"), "rank": 1, "judgment": "plausible_introduction_boundary", "confidence": "medium"}],
      "lifecycle": "raw_candidate_judged",
    },
  )
  _write_json(
    v0_root / "cases" / "30" / cve_id / "parsed_judge_output.json",
    {
      "schema_version": "judge_output_v0",
      "cve_id": cve_id,
      "case_disposition": "ranked",
      "candidate_judgments": [
        {
          "candidate_id": "cand-1",
          "candidate_commit_sha": _sha("a"),
          "rank": 1,
          "judgment": "plausible_introduction_boundary",
          "confidence": "medium",
          "evidence_refs_used": ["candidate:cand-1", "szz:cand-1"],
          "supporting_factors": [],
          "contradicting_factors": [],
          "risk_flags_considered": [],
          "uncertainty_reasons": [],
        }
      ],
      "excluded_candidates": [],
      "judge_notes": {"attack_perspective_used": False, "root_cause_binding_used": True, "szz_evidence_used": True, "version_conversion_not_performed": True},
    },
  )
  return judge_root, evidence_root, slimming_root, v0_root, dataset


def _valid_output() -> dict:
  return {
    "schema_version": "judge_boundary_output_v1_1",
    "cve_id": "CVE-BOUNDARY-1",
    "candidate_judgments": [
      {
        "candidate_id": "cand-1",
        "candidate_commit_sha": _sha("a"),
        "boundary_role": "introduction",
        "decision": "selected",
        "confidence": "medium",
        "evidence_refs": ["candidate:cand-1", "szz:cand-1"],
        "reasoning_short": "direct old-side evidence and v0 ranking support this as a boundary event",
      }
    ],
  }


def test_boundary_schema_parses_fenced_json() -> None:
  parsed = parse_judge_boundary_output_v1("```json\n" + json.dumps(_valid_output()) + "\n```")

  assert parsed.ok is True
  assert parsed.format == "fenced_json"


def test_boundary_contract_rejects_invented_candidate_and_forbidden_fields(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, v0_root, dataset = _make_inputs(tmp_path)
  packet = build_judge_boundary_input_v1(
    cve_id="CVE-BOUNDARY-1",
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    judge_v0_run=v0_root,
    dataset=dataset,
  )
  output = _valid_output()
  output["candidate_judgments"][0]["candidate_id"] = "invented"

  result = lint_judge_boundary_output_v1(output, packet)

  assert result.ok is False
  assert "unknown_candidate_id" in result.taxonomy
  output["affected_versions"] = ["v1"]
  assert scan_forbidden_boundary_fields(output)["ok"] is False


def test_boundary_schema_rejects_model_owned_duplicate_views() -> None:
  output = _valid_output()
  output["selected_boundary_events"] = []

  parsed = parse_judge_boundary_output_v1(json.dumps(output))

  assert parsed.ok is False


def test_boundary_contract_derives_views_from_candidate_judgments(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, v0_root, dataset = _make_inputs(tmp_path)
  packet = build_judge_boundary_input_v1(
    cve_id="CVE-BOUNDARY-1",
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    judge_v0_run=v0_root,
    dataset=dataset,
  )
  output = _valid_output()

  result = lint_judge_boundary_output_v1(output, packet)
  views = derive_boundary_views(output, packet)

  assert result.ok is True
  assert [item["candidate_id"] for item in views["selected_boundary_events"]] == ["cand-1"]
  assert views["rejected_candidates"] == []
  assert views["uncertain_candidates"] == []


def test_boundary_contract_requires_each_input_candidate_exactly_once(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, v0_root, dataset = _make_inputs(tmp_path)
  packet = build_judge_boundary_input_v1(
    cve_id="CVE-BOUNDARY-1",
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    judge_v0_run=v0_root,
    dataset=dataset,
  )
  output = _valid_output()
  output["candidate_judgments"].append(dict(output["candidate_judgments"][0]))

  result = lint_judge_boundary_output_v1(output, packet)

  assert result.ok is False
  assert result.taxonomy["candidate_accounted_multiple_times"] == 1


def test_boundary_contract_enforces_decision_role_consistency(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, v0_root, dataset = _make_inputs(tmp_path)
  packet = build_judge_boundary_input_v1(
    cve_id="CVE-BOUNDARY-1",
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    judge_v0_run=v0_root,
    dataset=dataset,
  )
  output = _valid_output()
  output["candidate_judgments"][0]["boundary_role"] = "refactor_noise"

  result = lint_judge_boundary_output_v1(output, packet)

  assert result.ok is False
  assert result.taxonomy["decision_role_conflict"] == 1


def test_boundary_contract_rejects_selected_conflict_without_explanation(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, v0_root, dataset = _make_inputs(tmp_path)
  packet = build_judge_boundary_input_v1(
    cve_id="CVE-BOUNDARY-1",
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    judge_v0_run=v0_root,
    dataset=dataset,
  )
  packet["candidate_set"][0]["risk_flags"] = ["move_copy_sensitive_blame"]
  output = _valid_output()
  output["candidate_judgments"][0]["reasoning_short"] = "ranked highly"

  result = lint_judge_boundary_output_v1(output, packet)

  assert result.ok is False
  assert "conflict_without_uncertainty_or_explanation" in result.taxonomy


def test_boundary_parser_repairs_trailing_comma_without_semantic_retry() -> None:
  raw = json.dumps(_valid_output()).replace("]}", "],}")

  parsed = parse_judge_boundary_output_v1(raw)

  assert parsed.ok is True
  assert parsed.format == "deterministic_repair_json"


def test_boundary_workflow_fixture_writes_accepted_raw_boundary(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, v0_root, dataset = _make_inputs(tmp_path)
  out_dir = tmp_path / "out"

  summary = run_judge_boundary_v1_batch(
    cve_ids=["CVE-BOUNDARY-1"],
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    judge_v0_run=v0_root,
    dataset=dataset,
    out_dir=out_dir,
    backend=FixtureJudgeBoundaryBackend(),
  )

  assert summary["cases_total"] == 1
  assert summary["contract_ok_count"] == 1
  result = json.loads((out_dir / "CVE-BOUNDARY-1" / "judge_boundary_result.json").read_text(encoding="utf-8"))
  assert result["lifecycle"] == "raw_boundary_event_accepted"
  assert scan_forbidden_boundary_fields(result)["ok"] is True


def test_boundary_workflow_semantic_retry_repeats_full_evidence(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, v0_root, dataset = _make_inputs(tmp_path)

  class RepairBackend:
    backend_name = "repair-fixture"
    backend_type = "fixture"

    def __init__(self) -> None:
      self.calls: list[str] = []

    def generate(self, prompt: str, context: dict) -> AgentResponse:
      self.calls.append(prompt)
      if len(self.calls) == 1:
        invalid = _valid_output()
        invalid["candidate_judgments"][0]["candidate_commit_sha"] = _sha("b")
        return AgentResponse(raw_text=json.dumps(invalid), status="ok", backend_name=self.backend_name, backend_type=self.backend_type, usage={"session_id": "first"})
      return AgentResponse(raw_text=json.dumps(_valid_output()), status="ok", backend_name=self.backend_name, backend_type=self.backend_type, usage={"session_id": "repair"})

  backend = RepairBackend()
  summary = run_judge_boundary_v1_batch(
    cve_ids=["CVE-BOUNDARY-1"],
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    judge_v0_run=v0_root,
    dataset=dataset,
    out_dir=tmp_path / "out-repair",
    backend=backend,
  )

  assert summary["contract_ok_count"] == 1
  assert summary["repair_retry_count"] == 1
  assert "dangerous_use(ptr)" in backend.calls[1]
  assert "root_cause_context" in backend.calls[1]
  assert "szz_evidence_cards" in backend.calls[1]


def test_boundary_workflow_deterministic_syntax_repair_avoids_model_retry(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, v0_root, dataset = _make_inputs(tmp_path)

  class SyntaxBackend:
    backend_name = "syntax-fixture"
    backend_type = "fixture"

    def __init__(self) -> None:
      self.calls = 0

    def generate(self, prompt: str, context: dict) -> AgentResponse:
      self.calls += 1
      raw = json.dumps(_valid_output()).replace("]}", "],}")
      return AgentResponse(raw_text=raw, status="ok", backend_name=self.backend_name, backend_type=self.backend_type)

  backend = SyntaxBackend()
  summary = run_judge_boundary_v1_batch(
    cve_ids=["CVE-BOUNDARY-1"],
    judge_packet_root=judge_root,
    detailed_evidence_root=evidence_root,
    slimming_root=slimming_root,
    judge_v0_run=v0_root,
    dataset=dataset,
    out_dir=tmp_path / "out-syntax",
    backend=backend,
  )

  assert summary["contract_ok_count"] == 1
  assert summary["repair_retry_count"] == 0
  assert backend.calls == 1


def test_boundary_input_contains_wrapper_owned_boundary_and_fix_groups(tmp_path: Path) -> None:
  judge_root, evidence_root, slimming_root, v0_root, dataset = _make_inputs(tmp_path)
  packet = build_judge_boundary_input_v1(
    cve_id="CVE-BOUNDARY-1", judge_packet_root=judge_root, detailed_evidence_root=evidence_root,
    slimming_root=slimming_root, judge_v0_run=v0_root, dataset=dataset,
  )

  assert packet["schema_version"] == "judge_boundary_input_v1_1"
  assert packet["candidate_set"][0]["fix_set_id"] == "CVE-BOUNDARY-1:fix-set:1"
  assert packet["candidate_set"][0]["boundary_group_ids"]
  assert packet["fix_groups"][0]["completion_semantics"] == "all_patch_families"
  assert packet["fix_groups"][0]["patch_families"][0]["member_semantics"] == "any_equivalent_commit"


def test_boundary_prompt_has_single_model_owned_fact_source() -> None:
  from vulngraph.workflows.judge_boundary_v1 import PROMPT_PATH

  prompt = PROMPT_PATH.read_text(encoding="utf-8")

  assert "uncertain_boundary" not in prompt
  assert "\"selected_boundary_events\"" not in prompt
  assert "\"rejected_candidates\"" not in prompt
  assert "\"uncertainty\"" not in prompt
