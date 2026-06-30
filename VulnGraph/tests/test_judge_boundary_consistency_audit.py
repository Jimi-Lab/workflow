from __future__ import annotations

import json
from pathlib import Path

from vulngraph.workflows.judge_boundary_consistency_audit import audit_boundary_run


def _write(path: Path, data: object) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(data), encoding="utf-8")


def test_audit_reports_duplicate_view_inconsistencies(tmp_path: Path) -> None:
  case = tmp_path / "CVE-A"
  _write(
    case / "parsed_boundary_output.json",
    {
      "candidate_judgments": [
        {
          "candidate_id": "a",
          "candidate_commit_sha": "a" * 40,
          "boundary_role": "uncertain_boundary",
          "decision": "selected",
        },
        {
          "candidate_id": "b",
          "candidate_commit_sha": "b" * 40,
          "boundary_role": "refactor_noise",
          "decision": "rejected",
        },
      ],
      "selected_boundary_events": [],
      "rejected_candidates": [],
      "uncertainty": [],
    },
  )
  _write(
    case / "judge_boundary_result.json",
    {
      "contract_ok": True,
      "selected_boundary_event_count": 0,
      "rejected_count": 0,
      "uncertain_count": 0,
    },
  )

  audit = audit_boundary_run(tmp_path)

  assert audit["summary"]["selected_judgment_missing_event_count"] == 1
  assert audit["summary"]["decision_role_conflict_count"] == 1
  assert audit["summary"]["rejected_stat_mismatch_case_count"] == 1
  assert audit["cases"][0]["cve_id"] == "CVE-A"
