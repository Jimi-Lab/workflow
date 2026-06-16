from __future__ import annotations

import json

from vulngraph.agent_io.root_cause_contract import lint_root_cause_contract
from vulngraph.agent_io.root_cause_schema import parse_root_cause_output
from vulngraph.workflows.root_cause import render_root_cause_prompt_v2


FIX_ID = "fix-commit:demo:sha-1"
HUNK_ID = "patch-hunk:demo:sha-1:src/parser.c:1"
FILE_ID = "file:demo:src/parser.c"
FUNC_ID = "changed-function:demo:sha-1:src/parser.c:parse"
FIX_SET_ID = "CVE-CONTRACT:fix-set:1"


def _packet() -> dict:
  return {
    "task": "root_cause_extraction",
    "mode": "production",
    "cve_id": "CVE-CONTRACT",
    "context": [{"id": "cve:CVE-CONTRACT", "type": "CVE", "allowed_use": "context_only", "content": {"cve_id": "CVE-CONTRACT"}}],
    "repo_navigation": [{"id": FILE_ID, "type": "File", "allowed_use": "navigation_only", "content": {"path": "src/parser.c"}}],
    "patch_evidence": [
      {
        "id": FIX_ID,
        "type": "FixCommit",
        "allowed_use": "root_cause_evidence",
        "content": {"cve_id": "CVE-CONTRACT", "repo": "demo", "commit_sha": "sha-1", "fix_set_id": FIX_SET_ID},
      },
      {
        "id": HUNK_ID,
        "type": "PatchHunk",
        "allowed_use": "root_cause_evidence",
        "content": {"cve_id": "CVE-CONTRACT", "repo": "demo", "commit_sha": "sha-1", "path": "src/parser.c", "hunk_index": 1, "function_id": FUNC_ID, "function_symbol": "parse"},
      },
      {
        "id": FUNC_ID,
        "type": "ChangedFunction",
        "allowed_use": "root_cause_evidence",
        "content": {"cve_id": "CVE-CONTRACT", "repo": "demo", "commit_sha": "sha-1", "path": "src/parser.c", "symbol": "parse"},
      },
    ],
    "forbidden": ["affected_version/offline_eval_only"],
  }


def _trace() -> dict:
  return {
    "source": "wrapper_git_trace",
    "cve_id": "CVE-CONTRACT",
    "trace_run_id": "trace-1",
    "git_observations": [
      {
        "id": "obs-1",
        "source": "wrapper_git_trace",
        "valid_evidence": True,
        "observation_kind": "patch_diff",
        "cve_id": "CVE-CONTRACT",
        "trace_run_id": "trace-1",
        "command_ref": "cmd-1",
        "tool_output_ref": "out-1",
        "fix_commit_ids": [FIX_ID],
        "patch_hunk_ids": [HUNK_ID],
        "file_ids": [FILE_ID],
        "function_ids": [FUNC_ID],
        "path": "src/parser.c",
        "snippet": "- memcpy(dst, src, len)\n+ if (len <= cap) memcpy(dst, src, len)",
      }
    ],
    "tool_calls": [{"id": "cmd-1", "source": "wrapper_git_trace", "cve_id": "CVE-CONTRACT", "trace_run_id": "trace-1", "command": "git show --unified=80 sha-1", "exit_code": 0}],
    "tool_outputs": [{"id": "out-1", "source": "wrapper_git_trace", "cve_id": "CVE-CONTRACT", "trace_run_id": "trace-1", "command_ref": "cmd-1", "text": "diff"}],
  }


def _valid_output() -> dict:
  return {
    "agent_run": {"run_id": "run-1", "cve_id": "CVE-CONTRACT", "backend": "test"},
    "root_cause_hypotheses": [
      {
        "hypothesis_id": "hyp-1",
        "summary": "unchecked length reaches memcpy",
        "mechanism": "the patch adds a bounds check before memcpy",
        "fix_set_ids": [FIX_SET_ID],
        "fix_commit_ids": [FIX_ID],
        "anchor_ids": ["anchor-1"],
        "vulnerable_predicate_ids": ["vp-1"],
        "fix_predicate_ids": ["fp-1"],
        "guard_condition_ids": [],
        "negative_condition_ids": [],
        "git_observation_refs": ["obs-1"],
      }
    ],
    "code_anchors": [
      {
        "anchor_id": "anchor-1",
        "fix_commit_id": FIX_ID,
        "patch_hunk_id": HUNK_ID,
        "file_id": FILE_ID,
        "path": "src/parser.c",
        "function_id": FUNC_ID,
        "function": "parse",
        "line_start": 1,
        "line_end": 3,
        "pattern": "memcpy(dst, src, len)",
        "git_observation_refs": ["obs-1"],
      }
    ],
    "vulnerable_predicates": [{"predicate_id": "vp-1", "description": "unchecked len reaches memcpy", "anchor_ids": ["anchor-1"], "git_observation_refs": ["obs-1"]}],
    "fix_predicates": [{"predicate_id": "fp-1", "description": "bounds check blocks oversized len", "anchor_ids": ["anchor-1"], "git_observation_refs": ["obs-1"]}],
    "guard_conditions": [],
    "negative_conditions": [],
    "git_observation_refs": ["obs-1"],
    "uncertainty_reasons": [],
    "learned_candidates": [],
    "risk_flags": [],
  }


def test_contract_linter_accepts_gate_shaped_output():
  result = lint_root_cause_contract(_valid_output(), _packet(), _trace())

  assert result.ok
  assert result.taxonomy == {}
  assert result.binding_complete_rate == 1.0


def test_contract_linter_reports_hypothesis_without_fix_predicate():
  output = _valid_output()
  output["root_cause_hypotheses"][0]["fix_predicate_ids"] = []

  result = lint_root_cause_contract(output, _packet(), _trace())

  assert not result.ok
  assert result.taxonomy["fix_predicate_without_anchor"] == 1


def test_contract_linter_reports_predicate_without_code_anchor_ids():
  output = _valid_output()
  output["vulnerable_predicates"][0]["anchor_ids"] = []

  result = lint_root_cause_contract(output, _packet(), _trace())

  assert not result.ok
  assert result.taxonomy["predicate_without_anchor"] == 1


def test_contract_linter_reports_code_anchor_without_patch_hunk_id():
  output = _valid_output()
  output["code_anchors"][0]["patch_hunk_id"] = None

  result = lint_root_cause_contract(output, _packet(), _trace())

  assert not result.ok
  assert result.taxonomy["missing_patch_hunk_id"] == 1
  assert result.taxonomy["explanatory_anchor_in_required_refs"] == 1


def test_contract_linter_reports_code_anchor_without_path():
  output = _valid_output()
  output["code_anchors"][0].pop("path")

  result = lint_root_cause_contract(output, _packet(), _trace())

  assert not result.ok
  assert result.taxonomy["missing_anchor_path"] == 1
  assert any("missing path" in error for error in result.errors)


def test_contract_linter_reports_function_name_without_function_id():
  output = _valid_output()
  output["code_anchors"][0].pop("function_id")

  result = lint_root_cause_contract(output, _packet(), _trace())

  assert not result.ok
  assert result.taxonomy["function_name_without_function_id"] == 1


def test_contract_linter_reports_function_id_function_alias_mismatch():
  output = _valid_output()
  output["code_anchors"][0]["function"] = "other_function"

  result = lint_root_cause_contract(output, _packet(), _trace())

  assert not result.ok
  assert result.taxonomy["function_id_function_alias_mismatch"] == 1


def test_contract_linter_reports_unknown_observation_refs():
  output = _valid_output()
  output["root_cause_hypotheses"][0]["git_observation_refs"] = ["obs-invented"]

  result = lint_root_cause_contract(output, _packet(), _trace())

  assert not result.ok
  assert result.taxonomy["unknown_observation_ref"] == 1
  assert "obs-invented" in result.invented_ids


def test_contract_linter_rejects_predicate_supported_only_by_weak_evidence():
  output = _valid_output()
  trace = _trace()
  trace["git_observations"][0]["observation_kind"] = "file_history"

  result = lint_root_cause_contract(output, _packet(), trace)

  assert not result.ok
  assert result.taxonomy["weak_predicate_evidence"] >= 2


def test_contract_linter_warns_when_mentioned_packet_function_is_unanchored():
  packet = _packet()
  packet["patch_evidence"].extend(
    [
      {
        "id": "patch-hunk:demo:sha-1:src/parser.c:2",
        "type": "PatchHunk",
        "allowed_use": "root_cause_evidence",
        "content": {"cve_id": "CVE-CONTRACT", "repo": "demo", "commit_sha": "sha-1", "path": "src/parser.c", "hunk_index": 2, "function_id": "changed-function:demo:sha-1:src/parser.c:cleanup", "function_symbol": "cleanup"},
      },
      {
        "id": "changed-function:demo:sha-1:src/parser.c:cleanup",
        "type": "ChangedFunction",
        "allowed_use": "root_cause_evidence",
        "content": {"cve_id": "CVE-CONTRACT", "repo": "demo", "commit_sha": "sha-1", "path": "src/parser.c", "symbol": "cleanup"},
      },
    ]
  )
  output = _valid_output()
  output["root_cause_hypotheses"][0]["summary"] = "parse and cleanup jointly cause the issue"

  result = lint_root_cause_contract(output, packet, _trace())

  assert result.ok
  assert result.taxonomy["hypothesis_mentions_unanchored_function"] == 1
  assert result.taxonomy["incomplete_function_hunk_coverage"] == 1


def test_contract_linter_warns_on_consequence_stated_as_root_cause():
  output = _valid_output()
  output["root_cause_hypotheses"][0]["mechanism"] = "the patch could lead to potential buffer overflow and out-of-bounds access"

  result = lint_root_cause_contract(output, _packet(), _trace())

  assert result.ok
  assert result.taxonomy["consequence_stated_as_root_cause"] == 1
  assert result.taxonomy["overbroad_vulnerability_effect"] == 1


def test_contract_linter_reports_multi_fix_metadata_missing():
  output = _valid_output()
  output["root_cause_hypotheses"][0]["fix_set_ids"] = []
  output["root_cause_hypotheses"][0]["fix_commit_ids"] = []

  result = lint_root_cause_contract(output, _packet(), _trace())

  assert not result.ok
  assert result.taxonomy["fix_set_incomplete"] == 1


def test_contract_linter_allows_unreferenced_explanatory_anchor_as_non_required_context():
  output = _valid_output()
  output["code_anchors"].append(
    {
      "anchor_id": "explain-only",
      "fix_commit_id": None,
      "patch_hunk_id": None,
      "path": "src/parser.c",
      "function": "parse",
      "pattern": "historical vulnerable callsite",
      "git_observation_refs": ["obs-1"],
    }
  )

  result = lint_root_cause_contract(output, _packet(), _trace())

  assert "explanatory_anchor_in_required_refs" not in result.taxonomy


def test_prompt_evidence_inventory_contains_observation_scope():
  prompt = render_root_cause_prompt_v2("CVE-CONTRACT", _packet(), _trace())

  assert "EVIDENCE_INVENTORY" in prompt
  assert "patch_hunk_ids" in prompt
  assert HUNK_ID in prompt
  assert "obs-1" in prompt
  assert "fix_commit_ids" in prompt


def test_prompt_uses_canonical_only_fields_and_evidence_strength_rules():
  prompt = render_root_cause_prompt_v2("CVE-CONTRACT", _packet(), _trace())

  assert "anchor_id" in prompt
  assert "predicate_id" in prompt
  assert "hypothesis_id" in prompt
  assert "code_anchor_ids" not in prompt
  assert "function_name" not in prompt
  assert "statement" not in prompt
  assert "patch_diff" in prompt
  assert "git show stat" in prompt
  assert "git log --follow" in prompt
  assert "uncertainty_reasons" in prompt


def test_schema_accepts_contract_aliases_and_normalizes_to_ingestion_names():
  payload = _valid_output()
  payload["root_cause_hypotheses"][0]["id"] = payload["root_cause_hypotheses"][0].pop("hypothesis_id")
  payload["root_cause_hypotheses"][0]["code_anchor_ids"] = payload["root_cause_hypotheses"][0].pop("anchor_ids")
  payload["code_anchors"][0]["id"] = payload["code_anchors"][0].pop("anchor_id")
  payload["code_anchors"][0]["line_range"] = [1, 3]
  payload["vulnerable_predicates"][0]["id"] = payload["vulnerable_predicates"][0].pop("predicate_id")
  payload["vulnerable_predicates"][0]["statement"] = payload["vulnerable_predicates"][0].pop("description")
  payload["vulnerable_predicates"][0]["code_anchor_ids"] = payload["vulnerable_predicates"][0].pop("anchor_ids")
  payload["fix_predicates"][0]["id"] = payload["fix_predicates"][0].pop("predicate_id")
  payload["fix_predicates"][0]["statement"] = payload["fix_predicates"][0].pop("description")
  payload["fix_predicates"][0]["code_anchor_ids"] = payload["fix_predicates"][0].pop("anchor_ids")

  parsed = parse_root_cause_output(json.dumps(payload))

  assert parsed.ok
  assert parsed.data["root_cause_hypotheses"][0]["hypothesis_id"] == "hyp-1"
  assert parsed.data["root_cause_hypotheses"][0]["anchor_ids"] == ["anchor-1"]
  assert parsed.data["vulnerable_predicates"][0]["predicate_id"] == "vp-1"
  assert parsed.data["vulnerable_predicates"][0]["anchor_ids"] == ["anchor-1"]


def test_schema_accepts_outputs_with_both_legacy_and_contract_anchor_keys():
  payload = _valid_output()
  payload["root_cause_hypotheses"][0]["code_anchor_ids"] = list(payload["root_cause_hypotheses"][0]["anchor_ids"])
  payload["vulnerable_predicates"][0]["code_anchor_ids"] = list(payload["vulnerable_predicates"][0]["anchor_ids"])
  payload["fix_predicates"][0]["code_anchor_ids"] = list(payload["fix_predicates"][0]["anchor_ids"])

  parsed = parse_root_cause_output(json.dumps(payload))

  assert parsed.ok
  assert parsed.data["root_cause_hypotheses"][0]["anchor_ids"] == ["anchor-1"]
  assert parsed.data["vulnerable_predicates"][0]["anchor_ids"] == ["anchor-1"]
  assert parsed.data["fix_predicates"][0]["anchor_ids"] == ["anchor-1"]
