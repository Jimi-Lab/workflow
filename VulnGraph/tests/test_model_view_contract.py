from __future__ import annotations

import json
from pathlib import Path

from vulngraph.agent_io.model_view_contract import (
  build_judge_blind_model_view,
  build_root_cause_model_view,
  build_szz_anchor_model_view,
  scan_forbidden_model_input,
)
from vulngraph.workflows.root_cause import render_root_cause_prompt_v2
from vulngraph.workflows.szz_anchor_audit import _render_handoff_prompt


def _sample_root_cause_packet() -> dict:
  return {
    "cve_id": "CVE-X",
    "context": {"cve": {"description": "integer overflow in parser"}, "cwe": ["CWE-190"]},
    "patch_evidence": [
      {
        "id": "fix-commit:repo:abc",
        "type": "FixCommit",
        "content": {
          "repo": "repo",
          "commit_sha": "abc",
          "message": "fix integer overflow by checking size",
          "fix_set_id": "CVE-X:fix-set:1",
        },
      },
      {
        "id": "patch-hunk:repo:abc:src/a.c:1",
        "type": "PatchHunk",
        "content": {
          "fix_commit_id": "fix-commit:repo:abc",
          "commit_sha": "abc",
          "path": "src/a.c",
          "function_id": "changed-function:repo:abc:src/a.c:parse",
          "function_symbol": "parse",
          "change_type": "modify",
          "deleted_lines": [{"old_line": 10, "text": "len = a * b;"}],
          "added_lines": [{"new_line": 10, "text": "if (a > SIZE_MAX / b) return false;"}],
          "context_lines": [{"old_line": 9, "new_line": 9, "text": "parse(input);"}],
          "hunk_text": "X" * 5000,
          "git_observation_refs": ["obs-patch"],
        },
      },
    ],
  }


def _sample_evidence_trace() -> dict:
  return {
    "backend_trusted": True,
    "repo": "repo",
    "git_observations": [
      {
        "id": "obs-patch",
        "observation_kind": "patch_diff",
        "valid_evidence": True,
        "fix_commit_ids": ["fix-commit:repo:abc"],
        "patch_hunk_ids": ["patch-hunk:repo:abc:src/a.c:1"],
        "claim": "patch modifies parse overflow check",
        "snippet": "Y" * 8000,
      }
    ],
    "tool_calls": [
      {
        "id": "tool-1",
        "command": ["git", "show", "abc"],
        "stdout_excerpt": "Z" * 6000,
        "stderr_excerpt": "",
      }
    ],
  }


def test_root_cause_model_view_keeps_semantics_without_full_trace() -> None:
  view = build_root_cause_model_view("CVE-X", _sample_root_cause_packet(), _sample_evidence_trace())
  serialized = json.dumps(view, ensure_ascii=False)

  assert view["schema_version"] == "root_cause_model_view_v1"
  assert "integer overflow" in serialized
  assert "patch-hunk:repo:abc:src/a.c:1" in serialized
  assert "len = a * b;" in serialized
  assert "if (a > SIZE_MAX / b)" in serialized
  assert "git_observations" not in view
  assert "tool_calls" not in view
  assert "Y" * 1000 not in serialized
  assert "Z" * 1000 not in serialized
  assert scan_forbidden_model_input(view)["ok"] is True


def test_render_root_cause_prompt_uses_compact_model_view() -> None:
  prompt = render_root_cause_prompt_v2("CVE-X", _sample_root_cause_packet(), _sample_evidence_trace())

  assert "ROOT_CAUSE_MODEL_VIEW" in prompt
  assert "ROOT_CAUSE_PACKET" not in prompt
  assert "WRAPPER_GIT_EVIDENCE_TRACE" not in prompt
  assert "git_observations" not in prompt
  assert "Y" * 1000 not in prompt


def test_szz_anchor_model_view_is_compact_candidate_inventory_not_full_inventory() -> None:
  root_cause = {
    "root_cause_hypotheses": [{"hypothesis_id": "hyp-1", "git_observation_refs": ["obs-patch"]}],
    "vulnerable_predicates": [{"predicate_id": "vp-1", "git_observation_refs": ["obs-patch"]}],
    "code_anchors": [{"patch_hunk_id": "hunk-1"}],
  }
  inventory = {
    "cve_id": "CVE-X",
    "repo_id": "repo",
    "fix_families": {"family-1": ["fix-1"]},
    "candidates": [
      {
        "candidate_id": "cand-1",
        "patch_family_id": "family-1",
        "fix_commit_id": "fix-1",
        "patch_hunk_id": "hunk-1",
        "path_before": "src/a.c",
        "old_line_start": 10,
        "old_line_end": 10,
        "line_text": "A" * 1000,
        "line_text_sha256": "h" * 64,
        "candidate_source": "deleted_line",
        "change_type": "modify",
        "selection_mode_eligibility": ["modified_old_side"],
        "git_observation_refs": ["obs-patch"],
        "source_file": True,
      }
    ],
  }

  view = build_szz_anchor_model_view(root_cause, inventory, top_k_per_patch_family=40)
  serialized = json.dumps(view, ensure_ascii=False)

  assert view["schema_version"] == "szz_anchor_model_view_v1"
  assert "full_candidate_inventory" not in serialized
  assert "cand-1" in serialized
  assert "A" * 500 not in serialized
  assert view["candidate_inventory"]["candidates"][0]["line_text_hash"] == "h" * 64
  assert scan_forbidden_model_input(view)["ok"] is True


def test_szz_handoff_prompt_uses_compact_model_view_label() -> None:
  root_cause = {
    "root_cause_hypotheses": [{"hypothesis_id": "hyp-1", "git_observation_refs": ["obs-patch"]}],
    "vulnerable_predicates": [{"predicate_id": "vp-1", "git_observation_refs": ["obs-patch"]}],
    "code_anchors": [{"patch_hunk_id": "hunk-1"}],
  }
  inventory = {
    "cve_id": "CVE-X",
    "repo_id": "repo",
    "fix_families": {"family-1": ["fix-1"]},
    "candidates": [
      {
        "candidate_id": "cand-1",
        "patch_family_id": "family-1",
        "fix_commit_id": "fix-1",
        "patch_hunk_id": "hunk-1",
        "path_before": "src/a.c",
        "old_line_start": 10,
        "old_line_end": 10,
        "line_text": "A" * 1000,
        "line_text_sha256": "h" * 64,
        "candidate_source": "deleted_line",
        "change_type": "modify",
        "selection_mode_eligibility": ["modified_old_side"],
        "git_observation_refs": ["obs-patch"],
        "source_file": True,
      }
    ],
  }

  prompt = _render_handoff_prompt(root_cause, inventory, top_k_per_patch_family=40)

  assert "SZZ_ANCHOR_MODEL_VIEW" in prompt
  assert "PRE_FIX_CANDIDATE_INVENTORY" not in prompt
  assert "A" * 500 not in prompt
  assert "cand-1" in prompt


def test_judge_blind_model_view_summarizes_large_release_tag_lists() -> None:
  packet = {
    "schema_version": "judge_blind_input_packet_v0",
    "cve_id": "CVE-X",
    "repo": "repo",
    "candidates": [
      {
        "candidate_commit_sha": "a" * 40,
        "candidate_source": "fallback",
        "candidate_generation_mode": "fallback_inventory_anchor",
        "evidence_level": "fallback",
        "lifecycle": "raw_candidate",
        "candidate_ids": ["cand-1"],
        "path_before": "src/a.c",
        "old_line_start": 10,
        "old_line_text_hash": "h" * 64,
        "predicted_release_tags_from_version_probe": [f"v1.{index}" for index in range(100)],
        "risk_flags": ["fallback_candidate"],
      }
    ],
  }

  view = build_judge_blind_model_view(packet, release_tag_inline_limit=10)
  candidate = view["candidates"][0]
  serialized = json.dumps(view, ensure_ascii=False)

  assert view["schema_version"] == "judge_blind_model_view_v1"
  assert "predicted_release_tags_from_version_probe" not in candidate
  assert candidate["release_tag_summary"]["count"] == 100
  assert candidate["release_tag_artifact_ref"]
  assert "gt_release_tags" not in serialized
  assert scan_forbidden_model_input(view)["ok"] is True
