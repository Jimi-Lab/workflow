import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnversion.stage1_semantic_aggregation.artifacts import _jsonl_write, step1_paths
from vulnversion.stage1_semantic_aggregation.schema import (
  FixFamilySemantics,
  RegionRefinementResult,
  SemanticRegion,
)
from vulnversion.stage2_rci_navigation.step1_adapter import (
  build_root_cause_vet_from_step1,
  load_step1_vet_seed,
)
from vulnversion.stage1_semantic_aggregation.schema import PatchSemantics
from vulnversion.stage2_rci_navigation.induce_rci import induce_rci
from vulnversion.stage2_rci_navigation.run import run_stage2
from vulnversion.stage2_rci_navigation.vet_schema import RootCauseVet
from vulnversion.utils.jsonschema import dump_json


def _prepare_step1_output(tmp_path: Path, *, with_refinement: bool = False) -> dict[str, Path]:
  paths = step1_paths(result_root=tmp_path, repo="demo", cve_id="CVE-P5")
  paths["output_dir"].mkdir(parents=True, exist_ok=True)
  dump_json(
    paths["fix_family"],
    FixFamilySemantics(
      cve_id="CVE-P5",
      repo="demo",
      primary_fix_commit="abc",
      fix_commits=["abc"],
      family_semantics="single_fix",
      confidence=0.8,
    ).model_dump(),
  )
  _jsonl_write(
    paths["semantic_regions"],
    [
      SemanticRegion(
        cve_id="CVE-P5",
        repo="demo",
        region_id="region_0001",
        commits=["abc"],
        file_path="parser.c",
        function_context="parse_len",
        chunk_ids=["chunk_0001"],
        patch_type="mixed",
        file_role="source",
        removed_critical_sequence=["size = len + 1;"],
        added_guard_sequence=["if (len < 0) return -1;"],
        root_cause_score=7.0,
        score_reasons=["source_file", "removed_dangerous_operation", "added_guard_check"],
        evidence_strength="medium",
        allowed_downstream_use=["prompt_context", "vet_candidate", "priority_signal"],
      ).model_dump()
    ],
  )
  if with_refinement:
    _jsonl_write(
      paths["region_refinements"],
      [
        RegionRefinementResult(
          cve_id="CVE-P5",
          repo="demo",
          packet_id="packet_0001",
          region_id="region_0001",
          region_role="primary_root_cause_region",
          evidence_strength="strong",
          allowed_downstream_use=["prompt_context", "vet_candidate", "priority_signal"],
          root_cause_relation="bounds_check",
          root_cause_likelihood=0.95,
          fix_guard_likelihood=0.9,
          vulnerable_sequence_likelihood=0.85,
          vulnerable_sequence=["size = len + 1;"],
          fix_guard_sequence=["if (len < 0) return -1;"],
          reasoning_summary="Agent localized the missing bounds check.",
        ).model_dump()
      ],
    )
  return paths


def test_step2_loads_step1_outputs_as_safe_vet_seed(tmp_path: Path):
  paths = _prepare_step1_output(tmp_path)

  seed = load_step1_vet_seed(paths["step1_dir"])
  vet = build_root_cause_vet_from_step1(seed)

  RootCauseVet.model_validate(vet.model_dump())
  assert vet.cve_id == "CVE-P5"
  assert vet.repo == "demo"
  assert vet.root_cause_files[0].value == "parser.c"
  assert vet.root_cause_functions[0].value == "parse_len"
  assert vet.vulnerable_sequences[0].value == "size = len + 1;"
  assert vet.fix_guards[0].value == "if (len < 0) return -1;"
  assert all("priority" in pattern.allowed_uses for pattern in vet.priority_patterns())
  assert vet.certificate_candidates() == []


def test_step2_prefers_agent_refinement_but_still_does_not_certificate_by_default(tmp_path: Path):
  paths = _prepare_step1_output(tmp_path, with_refinement=True)

  vet = build_root_cause_vet_from_step1(load_step1_vet_seed(paths["step1_dir"]))

  assert vet.root_cause_summary.startswith("Step1 supplied")
  assert vet.root_cause_files[0].strength == "strong"
  assert vet.vulnerable_sequences[0].strength == "strong"
  assert vet.fix_guards[0].strength == "strong"
  assert vet.certificate_candidates() == []
  assert vet.confidence["step1_refinement_regions"] == 1


def test_step2_can_promote_explicit_certificate_candidate_only_when_requested(tmp_path: Path):
  paths = _prepare_step1_output(tmp_path, with_refinement=True)

  seed = load_step1_vet_seed(paths["step1_dir"])
  seed.refinements[0].allowed_downstream_use.append("certificate_candidate")
  vet = build_root_cause_vet_from_step1(seed, allow_step1_certificates=True)

  candidates = vet.certificate_candidates()
  assert candidates
  assert all(pattern.strength == "strong" for pattern in candidates)


def test_step2_adapter_fails_fast_when_required_step1_outputs_are_missing(tmp_path: Path):
  paths = step1_paths(result_root=tmp_path, repo="demo", cve_id="CVE-MISSING")
  paths["output_dir"].mkdir(parents=True, exist_ok=True)

  try:
    load_step1_vet_seed(paths["step1_dir"])
  except FileNotFoundError as exc:
    assert "fix_family_semantics.json" in str(exc)
  else:
    raise AssertionError("missing Step1 artifacts should fail fast")


def test_stage2_no_agent_fallback_preserves_step1_vet_seed(tmp_path: Path):
  paths = _prepare_step1_output(tmp_path, with_refinement=True)
  vet = build_root_cause_vet_from_step1(load_step1_vet_seed(paths["step1_dir"]))

  rci = induce_rci(
    agent=None,
    session_id=None,
    cve_id="CVE-P5",
    repo_path="repo/demo",
    fix_commit="abc",
    fix_commits=["abc"],
    vuln_commit="abc^",
    cve_desc="bounds check",
    cwe=["CWE-125"],
    patch_semantics=PatchSemantics(cve_id="CVE-P5", repo_path="repo/demo", fix_commit="abc"),
    repomaster_hints=None,
    step1_vet_seed=vet.model_dump(),
  )

  assert rci["root_cause_vet"]["root_cause_files"][0]["value"] == "parser.c"
  assert rci["metadata"]["step1_vet_seed_consumed"] is True


def test_run_stage2_consumes_step1_outputs_when_present(tmp_path: Path):
  paths = _prepare_step1_output(tmp_path, with_refinement=True)
  out_dir = paths["step1_dir"].parent
  patch_path = out_dir / "patch_semantics.json"
  dump_json(
    patch_path,
    PatchSemantics(cve_id="CVE-P5", repo_path="repo/demo", fix_commit="abc", fix_commits=["abc"]).model_dump(),
  )

  rci = run_stage2(
    cve_id="CVE-P5",
    repo_path="repo/demo",
    fix_commit="abc",
    vuln_commit="abc^",
    cve_desc="bounds check",
    cwe=["CWE-125"],
    artifacts_dir=str(tmp_path / "demo"),
    patch_semantics_path=patch_path,
    agent=None,
    session_id=None,
  )

  assert (out_dir / "step1_vet_seed.json").is_file()
  assert rci["root_cause_vet"]["root_cause_files"][0]["value"] == "parser.c"
  assert rci["metadata"]["step1_vet_seed_consumed"] is True
