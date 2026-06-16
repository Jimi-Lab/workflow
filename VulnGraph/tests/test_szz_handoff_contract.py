from __future__ import annotations

from copy import deepcopy

from vulngraph.agent_io.szz_handoff_contract import (
  lint_szz_handoff,
  resolve_szz_handoff,
  validate_szz_handoff,
)
from vulngraph.agent_io.szz_handoff_schema import PreFixCandidateInventoryV1


def _inventory(*, add_only: bool = False, context_only: bool = False) -> PreFixCandidateInventoryV1:
  source = "hunk_context" if context_only else ("pre_fix_function_body" if add_only else "deleted_line")
  eligibility = ["add_only_semantic_target", "context_fallback"] if context_only else (
    ["add_only_semantic_target"] if add_only else ["direct_deleted_line"]
  )
  return PreFixCandidateInventoryV1.model_validate(
    {
      "cve_id": "CVE-TEST-1",
      "repo_id": "repo",
      "repo_path": "repo",
      "fix_families": {"patch-family:1": ["b" * 40]},
      "issues": [],
      "git_trace": [],
      "candidates": [
        {
          "candidate_id": "pre-fix-line:1",
          "cve_id": "CVE-TEST-1",
          "repo_id": "repo",
          "fix_set_id": "fix-set:1",
          "patch_family_id": "patch-family:1",
          "fix_commit_id": "fix-commit:1",
          "fix_commit_sha": "b" * 40,
          "parent_sha": "a" * 40,
          "patch_hunk_id": "patch-hunk:1",
          "path_before": "src/a.c",
          "path_after": "src/a.c",
          "old_line_start": 17,
          "old_line_end": 17,
          "line_text": "dangerous_use(ptr);",
          "line_text_sha256": "hash",
          "function_id": "function:1",
          "function_name": "dangerous_use",
          "candidate_source": source,
          "change_type": "add_only" if add_only or context_only else "delete",
          "selection_mode_eligibility": eligibility,
          "git_observation_refs": ["obs:patch-diff"],
          "source_file": True,
        }
      ],
    }
  )


def _root_cause() -> dict:
  return {
    "root_cause_hypotheses": [
      {
        "hypothesis_id": "hypothesis:1",
        "git_observation_refs": ["obs:patch-diff"],
      }
    ],
    "vulnerable_predicates": [
      {
        "predicate_id": "predicate:1",
        "git_observation_refs": ["obs:patch-diff"],
      }
    ],
    "fix_predicates": [],
    "guard_conditions": [],
    "negative_conditions": [],
  }


def _selection(candidate_id: str = "pre-fix-line:1") -> dict:
  return {
    "agent_run": {"run_id": "szz-run:1", "cve_id": "CVE-TEST-1", "backend": "fixture"},
    "failure_mode": "Out-of-bounds access",
    "trigger": "Untrusted index",
    "violated_invariant": "Index must be in range",
    "vulnerable_state": "Unchecked index",
    "propagation": ["index", "lookup"],
    "sink": "array dereference",
    "fix_mechanism": "Bounds guard",
    "selected_anchors": [
      {
        "candidate_id": candidate_id,
        "role": "dangerous_use",
        "root_cause_hypothesis_ids": ["hypothesis:1"],
        "predicate_ids": ["predicate:1"],
        "rationale": "Parent-side dangerous use.",
        "confidence": 0.9,
      }
    ],
    "excluded_hunk_ids": [],
    "uncertainty_items": [],
  }


def test_invented_candidate_id_is_rejected():
  result = validate_szz_handoff(_selection("invented"), _inventory(), _root_cause())

  assert not result.ok
  assert result.invented_ids == ["invented"]
  assert result.taxonomy["unknown_candidate_id"] == 1


def test_candidate_scope_mismatch_is_rejected():
  selection = _selection()
  selection["agent_run"]["cve_id"] = "CVE-OTHER"

  result = validate_szz_handoff(selection, _inventory(), _root_cause())

  assert not result.ok
  assert result.taxonomy["candidate_scope_mismatch"] == 1


def test_direct_selection_requires_shared_root_cause_evidence():
  root_cause = _root_cause()
  root_cause["vulnerable_predicates"][0]["git_observation_refs"] = ["obs:other"]

  result = validate_szz_handoff(_selection(), _inventory(), root_cause)

  assert not result.ok
  assert result.taxonomy["weak_root_cause_binding"] == 1


def test_add_only_random_context_comment_is_rejected():
  inventory = _inventory(add_only=True, context_only=True)
  payload = inventory.model_dump(mode="json")
  payload["candidates"][0]["comment_only"] = True
  payload["candidates"][0]["exclusion_reasons"] = ["comment_only"]

  result = validate_szz_handoff(
    _selection(),
    PreFixCandidateInventoryV1.model_validate(payload),
    _root_cause(),
  )

  assert not result.ok
  assert result.taxonomy["comment_or_blank_anchor"] == 1


def test_one_hypothesis_can_select_multiple_complementary_anchors():
  inventory = _inventory()
  payload = inventory.model_dump(mode="json")
  second = deepcopy(payload["candidates"][0])
  second["candidate_id"] = "pre-fix-line:2"
  second["old_line_start"] = 18
  second["old_line_end"] = 18
  second["line_text"] = "sink(ptr);"
  payload["candidates"].append(second)
  selection = _selection()
  second_selection = deepcopy(selection["selected_anchors"][0])
  second_selection["candidate_id"] = "pre-fix-line:2"
  second_selection["role"] = "sink"
  selection["selected_anchors"].append(second_selection)

  result = validate_szz_handoff(
    selection,
    PreFixCandidateInventoryV1.model_validate(payload),
    _root_cause(),
  )

  assert result.ok
  assert len(result.resolved_anchors) == 2


def test_every_fix_family_requires_anchor_or_uncertainty():
  inventory = _inventory()
  payload = inventory.model_dump(mode="json")
  payload["fix_families"]["patch-family:2"] = ["c" * 40]

  result = validate_szz_handoff(
    _selection(),
    PreFixCandidateInventoryV1.model_validate(payload),
    _root_cause(),
  )

  assert not result.ok
  assert result.patch_family_coverage["patch-family:2"]["anchored"] is False
  assert result.patch_family_coverage["patch-family:2"]["accounted"] is False
  assert result.taxonomy["fix_family_incomplete"] == 1


def test_uncertainty_accounts_for_family_but_does_not_mark_it_anchored():
  inventory = _inventory()
  payload = inventory.model_dump(mode="json")
  payload["fix_families"]["patch-family:2"] = ["c" * 40]
  selection = _selection()
  second = deepcopy(payload["candidates"][0])
  second["candidate_id"] = "pre-fix-line:2"
  second["patch_family_id"] = "patch-family:2"
  second["fix_commit_id"] = "fix-commit:2"
  second["fix_commit_sha"] = "c" * 40
  second["patch_hunk_id"] = "patch-hunk:2"
  payload["candidates"].append(second)
  selection["uncertainty_items"] = [
    {
      "patch_family_id": "patch-family:2",
      "fix_commit_id": "fix-commit:2",
      "reason_code": "no_blameable_parent_line",
      "detail": "No reliable parent-side statement.",
    }
  ]

  result = validate_szz_handoff(
    selection,
    PreFixCandidateInventoryV1.model_validate(payload),
    _root_cause(),
  )

  assert result.ok
  assert result.patch_family_coverage["patch-family:1"]["anchored"] is True
  assert result.patch_family_coverage["patch-family:1"]["accounted"] is True
  assert result.patch_family_coverage["patch-family:2"]["anchored"] is False
  assert result.patch_family_coverage["patch-family:2"]["uncertain"] is True
  assert result.patch_family_coverage["patch-family:2"]["accounted"] is True
  assert result.fix_commit_coverage["fix-commit:2"]["anchored"] is False
  assert result.fix_commit_coverage["fix-commit:2"]["accounted"] is True


def test_family_with_two_fix_commits_rejects_selection_covering_only_one_commit():
  inventory = _inventory()
  payload = inventory.model_dump(mode="json")
  payload["fix_families"] = {"patch-family:1": ["b" * 40, "c" * 40]}
  second = deepcopy(payload["candidates"][0])
  second["candidate_id"] = "pre-fix-line:2"
  second["fix_commit_id"] = "fix-commit:2"
  second["fix_commit_sha"] = "c" * 40
  second["patch_hunk_id"] = "patch-hunk:2"
  payload["candidates"].append(second)

  result = validate_szz_handoff(
    _selection(),
    PreFixCandidateInventoryV1.model_validate(payload),
    _root_cause(),
  )

  assert not result.ok
  assert result.patch_family_coverage["patch-family:1"]["anchored"] is False
  assert result.fix_commit_coverage["fix-commit:1"]["anchored"] is True
  assert result.fix_commit_coverage["fix-commit:2"]["accounted"] is False
  assert result.taxonomy["fix_commit_incomplete"] == 1


def test_unknown_structured_uncertainty_ids_are_rejected():
  selection = _selection()
  selection["uncertainty_items"] = [
    {
      "patch_family_id": "patch-family:unknown",
      "fix_commit_id": "fix-commit:unknown",
      "reason_code": "no_blameable_parent_line",
      "detail": "Unknown IDs must not be accepted.",
    }
  ]

  result = validate_szz_handoff(selection, _inventory(), _root_cause())

  assert not result.ok
  assert result.taxonomy["unknown_uncertainty_patch_family"] == 1
  assert result.taxonomy["unknown_uncertainty_fix_commit"] == 1


def test_lint_and_resolver_share_the_same_pure_validation_result():
  args = (_selection(), _inventory(), _root_cause())

  lint = lint_szz_handoff(*args)
  resolved = resolve_szz_handoff(*args)

  assert lint == resolved
  assert lint.ok
  assert lint.resolved_anchors[0].lifecycle == "raw_candidate"


def test_empty_selection_returns_explicit_no_anchor_error():
  selection = _selection()
  selection["selected_anchors"] = []
  selection["uncertainty_items"] = [
    {
      "patch_family_id": "patch-family:1",
      "fix_commit_id": "fix-commit:1",
      "reason_code": "no_blameable_parent_line",
      "detail": "No blameable parent-side line.",
    }
  ]

  result = validate_szz_handoff(selection, _inventory(), _root_cause())

  assert not result.ok
  assert "no_blameable_anchor_selected" in result.errors
  assert result.taxonomy["no_blameable_anchor_selected"] == 1
