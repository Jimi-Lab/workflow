from __future__ import annotations

import json

from vulngraph.agent_io.root_cause_schema import parse_root_cause_output


def _minimal_payload() -> dict:
  return {
    "agent_run": {"run_id": "r1", "cve_id": "CVE-X", "backend": "opencode"},
    "root_cause_hypotheses": [
      {
        "hypothesis_id": "h1",
        "summary": "root cause",
        "git_observation_refs": ["obs-1"],
      }
    ],
    "vulnerable_predicates": [],
    "fix_predicates": [],
    "guard_conditions": [],
    "negative_conditions": [],
    "code_anchors": [],
    "git_observation_refs": ["obs-1"],
    "uncertainty_reasons": [],
    "learned_candidates": [],
    "risk_flags": [],
  }


def test_parse_root_cause_output_marks_fenced_json():
  text = "```json\n" + json.dumps(_minimal_payload()) + "\n```"

  parsed = parse_root_cause_output(text)

  assert parsed.ok is True
  assert parsed.format == "fenced_json"


def test_parse_root_cause_output_marks_plain_json():
  parsed = parse_root_cause_output(json.dumps(_minimal_payload()))

  assert parsed.ok is True
  assert parsed.format == "json"
