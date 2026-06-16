from __future__ import annotations

import json

from pydantic import ValidationError

from vulngraph.agent_io.szz_handoff_schema import (
  PreFixLineCandidateV1,
  ResolvedPreFixAnchorV1,
  parse_szz_anchor_selection,
)


def valid_selection_payload() -> dict:
  return {
    "agent_run": {
      "run_id": "szz-run:1",
      "cve_id": "CVE-TEST-1",
      "backend": "fixture",
    },
    "failure_mode": "Out-of-bounds access",
    "trigger": "An untrusted index reaches an operand lookup.",
    "violated_invariant": "The operand index must be within the operand array.",
    "vulnerable_state": "The unchecked index is used in the parent revision.",
    "propagation": ["input index", "operand lookup"],
    "sink": "array dereference",
    "fix_mechanism": "Validate the index before the lookup.",
    "selected_anchors": [
      {
        "candidate_id": "pre-fix-line:1",
        "role": "dangerous_use",
        "root_cause_hypothesis_ids": ["hypothesis:1"],
        "predicate_ids": ["predicate:1"],
        "rationale": "This parent-side dereference violates the invariant.",
        "confidence": 0.9,
      }
    ],
    "excluded_hunk_ids": [],
    "uncertainty_items": [],
  }


def test_anchor_selection_requires_wrapper_candidate_id():
  payload = valid_selection_payload()
  payload["selected_anchors"][0]["candidate_id"] = ""

  result = parse_szz_anchor_selection(json.dumps(payload))

  assert not result.ok
  assert "candidate_id" in (result.error or "")


def test_anchor_selection_accepts_fenced_json():
  result = parse_szz_anchor_selection(
    "```json\n" + json.dumps(valid_selection_payload()) + "\n```"
  )

  assert result.ok
  assert result.format == "fenced_json"
  assert result.output is not None
  assert result.output.selected_anchors[0].candidate_id == "pre-fix-line:1"


def test_resolved_anchor_preserves_parent_side_coordinates():
  anchor = ResolvedPreFixAnchorV1(
    anchor_id="pre-fix-anchor:1",
    candidate_id="pre-fix-line:1",
    cve_id="CVE-TEST-1",
    fix_set_id="fix-set:1",
    patch_family_id="patch-family:1",
    fix_commit_id="fix-commit:1",
    fix_commit_sha="b" * 40,
    parent_sha="a" * 40,
    patch_hunk_id="patch-hunk:1",
    path_before="src/a.c",
    path_after="src/a.c",
    old_line_start=17,
    old_line_end=17,
    line_text="dangerous_use(ptr);",
    line_text_sha256="hash",
    function_id="function:1",
    function_name="dangerous_use",
    candidate_source="deleted_line",
    role="dangerous_use",
    selection_mode="direct_deleted_line",
    root_cause_hypothesis_ids=["hypothesis:1"],
    predicate_ids=["predicate:1"],
    git_observation_refs=["git-observation:1"],
    rationale="This old-side use violates the stated invariant.",
    confidence=0.9,
    lifecycle="raw_candidate",
  )

  assert anchor.parent_sha == "a" * 40
  assert anchor.old_line_start == 17
  assert anchor.lifecycle == "raw_candidate"


def test_resolved_anchor_rejects_validated_bic_lifecycle():
  try:
    ResolvedPreFixAnchorV1(
      anchor_id="pre-fix-anchor:1",
      candidate_id="pre-fix-line:1",
      cve_id="CVE-TEST-1",
      fix_set_id="fix-set:1",
      patch_family_id="patch-family:1",
      fix_commit_id="fix-commit:1",
      fix_commit_sha="b" * 40,
      parent_sha="a" * 40,
      patch_hunk_id="patch-hunk:1",
      path_before="src/a.c",
      path_after="src/a.c",
      old_line_start=17,
      old_line_end=17,
      line_text="dangerous_use(ptr);",
      line_text_sha256="hash",
      candidate_source="deleted_line",
      role="dangerous_use",
      selection_mode="direct_deleted_line",
      root_cause_hypothesis_ids=["hypothesis:1"],
      predicate_ids=["predicate:1"],
      git_observation_refs=["git-observation:1"],
      rationale="Old-side use.",
      confidence=0.9,
      lifecycle="validated_bic",
    )
  except ValidationError as error:
    assert "raw_candidate" in str(error)
  else:
    raise AssertionError("validated_bic lifecycle must be rejected")


def test_pre_fix_line_candidate_rejects_multi_line_range():
  payload = {
    "candidate_id": "candidate:1",
    "cve_id": "CVE-TEST-1",
    "repo_id": "repo",
    "fix_set_id": "fix-set:1",
    "patch_family_id": "family:1",
    "fix_commit_id": "fix:1",
    "fix_commit_sha": "b" * 40,
    "parent_sha": "a" * 40,
    "patch_hunk_id": "hunk:1",
    "path_before": "src/a.c",
    "old_line_start": 17,
    "old_line_end": 18,
    "line_text": "danger();",
    "line_text_sha256": "hash",
    "candidate_source": "deleted_line",
    "change_type": "delete",
  }

  try:
    PreFixLineCandidateV1.model_validate(payload)
  except ValidationError as error:
    assert "single parent-side line" in str(error)
  else:
    raise AssertionError("PreFixLineCandidateV1 must reject multi-line ranges")


def test_free_text_uncertainty_reasons_field_is_rejected():
  payload = valid_selection_payload()
  payload.pop("uncertainty_items")
  payload["uncertainty_reasons"] = ["family:1 is uncertain"]

  result = parse_szz_anchor_selection(json.dumps(payload))

  assert not result.ok
  assert "uncertainty" in (result.error or "")
