from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.run_vet_case_review_81 import (
  _fallback_json_prompt,
  _normalize_review,
  _prompt,
  quality_failed_case_ids,
  audit_review_quality,
  build_case_plan,
  should_resume_existing_review,
  write_dry_run_artifacts,
)


PROJECT = Path(__file__).resolve().parents[1]
SELECTED_CASES = PROJECT / "tests" / "vet_taxonomy_corpus" / "selected_cases.json"
DATASET_81 = PROJECT / "tests" / "vet_taxonomy_corpus" / "BaseDataOrder_vet_case_study_81.json"
VET_SEEDS = PROJECT / "tests" / "vet_taxonomy_corpus" / "vet_archetype_seed.jsonl"


def test_pilot_9_plan_covers_all_repos_and_core_patch_types() -> None:
  if not SELECTED_CASES.exists():
    pytest.skip("VET taxonomy corpus is not available")

  plan = build_case_plan(
    dataset_path=DATASET_81,
    selected_cases_path=SELECTED_CASES,
    vet_seeds_path=VET_SEEDS,
    stage="pilot_9",
  )

  assert len(plan) == 9
  assert sorted({case["repo"] for case in plan}) == [
    "FFmpeg",
    "ImageMagick",
    "curl",
    "httpd",
    "linux",
    "openjpeg",
    "openssl",
    "qemu",
    "wireshark",
  ]
  assert len({case["patch_type"] for case in plan}) >= 2
  assert any(case["fix_family_kind"] == "multi_commit" for case in plan)
  assert all(case["cve_id"] and case["deterministic_seed"] for case in plan)


def test_dry_run_writes_review_plan_without_agent_outputs(tmp_path: Path) -> None:
  if not SELECTED_CASES.exists():
    pytest.skip("VET taxonomy corpus is not available")

  plan = build_case_plan(
    dataset_path=DATASET_81,
    selected_cases_path=SELECTED_CASES,
    vet_seeds_path=VET_SEEDS,
    stage="pilot_9",
  )
  summary = write_dry_run_artifacts(out_dir=tmp_path, stage="pilot_9", plan=plan)

  assert summary["stage"] == "pilot_9"
  assert summary["dry_run"] is True
  assert summary["planned_cases"] == 9
  assert (tmp_path / "case_plan.json").is_file()
  assert (tmp_path / "case_plan.jsonl").is_file()
  assert (tmp_path / "summary.json").is_file()
  assert (tmp_path / "review_report.md").is_file()
  assert not (tmp_path / "per_case_vet.jsonl").exists()

  loaded = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
  assert loaded["planned_cases"] == 9


def test_expanded_27_plan_prioritizes_taxonomy_diversity() -> None:
  if not SELECTED_CASES.exists():
    pytest.skip("VET taxonomy corpus is not available")

  plan = build_case_plan(
    dataset_path=DATASET_81,
    selected_cases_path=SELECTED_CASES,
    vet_seeds_path=VET_SEEDS,
    stage="expanded_27",
  )

  repos = sorted({case["repo"] for case in plan})
  patch_types = {case["patch_type"] for case in plan}
  seeds = {case["deterministic_seed"] for case in plan}

  assert len(plan) == 27
  assert all(sum(1 for case in plan if case["repo"] == repo) == 3 for repo in repos)
  assert patch_types == {"add_only", "del_only", "mixed"}
  assert "multi_commit" in {case["fix_family_kind"] for case in plan}
  assert "unknown_requires_manual_review" in seeds
  assert "status_error_handling_or_logic_correction" in seeds
  assert "unsafe_operation_replacement" in seeds
  assert "vulnerable_branch_removed" in seeds


def test_expanded_27_v2_uses_same_case_set_as_expanded_27() -> None:
  if not SELECTED_CASES.exists():
    pytest.skip("VET taxonomy corpus is not available")

  v1_plan = build_case_plan(
    dataset_path=DATASET_81,
    selected_cases_path=SELECTED_CASES,
    vet_seeds_path=VET_SEEDS,
    stage="expanded_27",
  )
  v2_plan = build_case_plan(
    dataset_path=DATASET_81,
    selected_cases_path=SELECTED_CASES,
    vet_seeds_path=VET_SEEDS,
    stage="expanded_27_v2",
  )

  assert [case["cve_id"] for case in v2_plan] == [case["cve_id"] for case in v1_plan]
  assert len(v2_plan) == 27


def test_quality_audit_flags_pilot_schema_risks() -> None:
  reviews = [
    {
      "schema_version": "vet_case_review.v1",
      "cve_id": "CVE-X",
      "repo": "repo",
      "fix_commits": ["abc"],
      "patch_type": "add_only",
      "deterministic_seed": "missing_guard",
      "review_status": "reviewed",
      "vet_archetype": "missing_guard",
      "root_cause_summary": "root cause",
      "fix_summary": "fix",
      "theta": {
        "Scope": {"files": ["a.c"], "functions": ["f"], "source_refs": ["plain-string-ref"]},
        "VulnerableCondition": {
          "necessary_conditions": ["input reaches f"],
          "vulnerable_code_patterns": ["missing check"],
          "negative_evidence": [],
        },
        "FixEvidence": {"fix_code_patterns": ["if (x)"], "added_guards": ["if (x)"], "removed_vulnerable_logic": []},
        "CertificatePolicy": {
          "cert_absent_allowed": False,
          "cert_fixed_allowed": True,
          "priority_only_evidence": [],
          "forbidden_hard_certificates": [],
          "reason": "candidate only",
        },
      },
      "step3_usable_evidence": {"line_risk_signals": ["plain signal"]},
      "uncertainty": ["certificate not validated"],
      "agent_trace_id": "sid",
      "evidence_paths": [],
    }
  ]

  report = audit_review_quality(reviews)
  issues = {finding["issue"] for finding in report["findings"]}

  assert report["reviewed_cases"] == 1
  assert report["gate"]["json_schema_reload"] is True
  assert report["gate"]["step2_admission_ready"] is False
  assert "non_object_source_refs" in issues
  assert "non_object_line_risk_signals" in issues
  assert "reviewed_with_uncertainty" in issues
  assert "cert_fixed_without_hard_certificate_candidates" in issues
  assert "cert_fixed_without_admission_requirements" in issues


def test_quality_audit_flags_step2_v2_evidence_item_risks() -> None:
  reviews = [
    {
      "schema_version": "step2_vet.v2",
      "cve_id": "CVE-X",
      "repo": "repo",
      "fix_commits": ["abc"],
      "patch_type": "mixed",
      "deterministic_seed": "missing_guard",
      "review_status": "reviewed",
      "vet_archetype": "missing_guard",
      "reviewed_vet": {
        "root_cause_summary": "root",
        "vulnerability_mechanism": "mechanism",
        "fix_mechanism": "fix",
        "scope": {"files": ["a.c"], "functions": ["f"], "components": [], "source_refs": [{"source_ref": "repo@abc:a.c:1"}]},
        "vulnerable_condition": {
          "necessary_conditions": ["input reaches f"],
          "vulnerable_sequences": ["unchecked length"],
          "missing_guards": ["len bound"],
          "negative_evidence": [],
        },
        "fix_evidence": {"fix_guards": ["if (len)"], "changed_sequences": [], "semantic_change": "add bound"},
        "guards": {"configuration_guards": [], "version_or_feature_guards": [], "preconditions": []},
        "uncertainty": ["needs source review"],
      },
      "admission_evidence": {
        "evidence_items": [
          {
            "evidence_id": "ev_001",
            "kind": "fix_guard",
            "value": "if (len)",
            "scope": {"files": ["a.c"]},
            "source_refs": [],
            "local_validation": {},
            "confidence": "high",
            "risk_flags": [],
            "agent_claimed_uses": ["hard_certificate"],
            "allowed_uses": ["hard_certificate"],
            "blocked_uses": [],
            "block_reasons": [],
          }
        ]
      },
      "uncertainty": [],
      "agent_trace_id": "sid",
      "evidence_paths": [],
    }
  ]

  report = audit_review_quality(reviews)
  issues = {finding["issue"] for finding in report["findings"]}

  assert report["reviewed_cases"] == 1
  assert report["gate"]["json_schema_reload"] is True
  assert report["gate"]["step2_admission_ready"] is False
  assert "empty_evidence_item_source_refs" in issues
  assert "evidence_item_allows_hard_certificate" in issues
  assert "reviewed_vet_with_uncertainty" in issues


def test_retry_agent_failed_resume_policy() -> None:
  failed = {"review_status": "agent_failed"}
  reviewed = {"review_status": "reviewed"}

  assert should_resume_existing_review(failed, retry_agent_failed=False) is True
  assert should_resume_existing_review(failed, retry_agent_failed=True) is False
  assert should_resume_existing_review(reviewed, retry_agent_failed=True) is True


def test_quality_failed_case_ids_only_selects_error_cases(tmp_path: Path) -> None:
  (tmp_path / "quality_findings.json").write_text(
    json.dumps(
      [
        {"cve_id": "CVE-ERROR", "severity": "error", "issue": "empty_source_refs"},
        {"cve_id": "CVE-WARN", "severity": "warn", "issue": "empty_negative_evidence"},
        {"cve_id": "CVE-ERROR", "severity": "warn", "issue": "empty_negative_evidence"},
      ],
      ensure_ascii=False,
    ),
    encoding="utf-8",
  )

  assert quality_failed_case_ids(tmp_path) == {"CVE-ERROR"}


def test_retry_quality_failed_resume_policy() -> None:
  failed = {"cve_id": "CVE-X", "review_status": "reviewed"}
  clean = {"cve_id": "CVE-Y", "review_status": "reviewed"}

  assert should_resume_existing_review(
    failed,
    retry_agent_failed=False,
    retry_quality_failed=True,
    quality_failed_case_ids={"CVE-X"},
  ) is False
  assert should_resume_existing_review(
    clean,
    retry_agent_failed=False,
    retry_quality_failed=True,
    quality_failed_case_ids={"CVE-X"},
  ) is True


def test_fallback_json_prompt_is_compact_and_schema_bound() -> None:
  prompt = _fallback_json_prompt(
    {
      "cve_id": "CVE-X",
      "repo": "repo",
      "fix_commits": ["abc"],
      "patch_type": "mixed",
      "deterministic_seed": "unknown",
    }
  )

  assert "previous response was not parseable JSON" in prompt
  assert "No markdown" in prompt
  assert "step2_vet.v2" in prompt
  assert "reviewed_vet" in prompt
  assert "admission_evidence" in prompt
  assert "evidence_items" in prompt
  assert "hard_certificate_candidates" not in prompt
  assert "cert_fixed_allowed" not in prompt
  assert len(prompt) < 5000


def test_main_prompt_uses_step2_v2_schema_without_legacy_certificate_fields() -> None:
  prompt = _prompt(
    {
      "cve_id": "CVE-X",
      "repo": "repo",
      "fix_commits": ["abc"],
      "patch_type": "mixed",
      "deterministic_seed": "unknown",
    },
    {"top_semantic_regions": [], "fix_evidence_manifest": {}, "quality": {}},
  )

  assert "step2_vet.v2" in prompt
  assert "reviewed_vet" in prompt
  assert "admission_evidence" in prompt
  assert "evidence_items" in prompt
  assert "cert_fixed_allowed" not in prompt
  assert "cert_absent_allowed" not in prompt
  assert "hard_certificate_candidates" not in prompt
  assert "Do not leave reviewed_vet empty" in prompt
  assert "Do not omit any evidence item field" in prompt


def test_normalize_review_preserves_deterministic_case_metadata() -> None:
  case = {
    "cve_id": "CVE-REAL",
    "repo": "repo",
    "fix_commits": ["abc"],
    "patch_type": "del_only",
    "patch_chunk_count": 7,
    "semantic_region_count": 3,
    "fix_family_kind": "single_commit",
    "deterministic_seed": "unsafe_operation_replacement",
  }
  raw = {
    "cve_id": "CVE-WRONG",
    "repo": "wrong",
    "fix_commits": ["wrong"],
    "patch_type": "mixed",
    "deterministic_seed": "agent_rewritten_seed",
    "vet_archetype": "agent_refined_archetype",
  }

  review = _normalize_review(raw, case)

  assert review["cve_id"] == "CVE-REAL"
  assert review["repo"] == "repo"
  assert review["fix_commits"] == ["abc"]
  assert review["patch_type"] == "del_only"
  assert review["patch_chunk_count"] == 7
  assert review["semantic_region_count"] == 3
  assert review["fix_family_kind"] == "single_commit"
  assert review["deterministic_seed"] == "unsafe_operation_replacement"
  assert review["vet_archetype"] == "agent_refined_archetype"


def test_normalize_review_emits_step2_v2_structure_by_default() -> None:
  case = {
    "cve_id": "CVE-REAL",
    "repo": "repo",
    "fix_commits": ["abc"],
    "patch_type": "add_only",
    "patch_chunk_count": 1,
    "semantic_region_count": 1,
    "fix_family_kind": "single_commit",
    "deterministic_seed": "missing_guard",
  }

  review = _normalize_review({}, case)

  assert review["schema_version"] == "step2_vet.v2"
  assert isinstance(review["reviewed_vet"], dict)
  assert isinstance(review["admission_evidence"], dict)
  assert review["admission_evidence"]["evidence_items"] == []
  assert "theta" not in review
  assert "step3_usable_evidence" not in review
