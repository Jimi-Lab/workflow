from __future__ import annotations

import json

from vulngraph.workflows.tri_state_audit_v1_2_2_1 import (
  compute_match_kind_metrics,
  run_tri_state_policy_audit,
)


def _row(tag: str, state: str, reason: str = "") -> dict:
  return {
    "branch_context_id": "branch-1",
    "tag": tag,
    "activation_state": "active" if state.startswith("present_") else "unknown",
    "activation_evidence": [{
      "event_candidate_id": "event-1",
      "state": state,
      "match_level": "function_scope",
      "reason": reason,
      "failure_reason": reason if state in {"absent", "unknown"} else "",
    }],
    "prerequisite_state": "complete",
    "prerequisite_evidence": [],
    "fix_state": "absent",
    "fix_evidence": {
      "state": "absent",
      "fix_presence": "absent",
      "evidence_reason": "no_fix_or_equivalent_reachable",
      "reachability": {"fix-a": "no"},
    },
  }


def test_match_kind_metrics_use_primary_prediction_not_unknown() -> None:
  ledger = [
    {
      "cve_id": "CVE-X", "tag": "v1",
      "function_scope_match_kind": "exact",
      "included_in_primary_prediction": True,
    },
    {
      "cve_id": "CVE-X", "tag": "v2",
      "function_scope_match_kind": "function_structural",
      "included_in_primary_prediction": False,
    },
    {
      "cve_id": "CVE-X", "tag": "v3",
      "function_scope_match_kind": "unavailable",
      "included_in_primary_prediction": False,
    },
  ]
  metrics = {
    row["match_kind"]: row
    for row in compute_match_kind_metrics(ledger, {"CVE-X": {"v1", "v2"}})
  }
  assert metrics["exact"]["tp"] == 1
  assert metrics["function_structural"]["fn"] == 1
  assert metrics["function_structural"]["predicted_positive_count"] == 0
  assert metrics["unavailable"]["tn"] == 1


def test_run_writes_confirmed_only_public_prediction(tmp_path) -> None:
  source = tmp_path / "source"
  case = source / "CVE-X"
  case.mkdir(parents=True)
  frozen = {
    "cve_id": "CVE-X",
    "repo": "repo",
    "release_tag_universe_size": 2,
    "confirmed_affected_versions": ["v1"],
    "confirmed_unaffected_versions": [],
    "unknown_versions": ["v2"],
    "predicted_affected_versions_for_metric": ["v1", "v2"],
    "fix_universe_audit": {
      "declared_fix_count": 1,
      "represented_declared_fix_count": 1,
      "unresolved_declared_fix_count": 0,
      "coverage": 1.0,
    },
    "evidence": [
      _row("v1", "present_exact"),
      _row("v2", "unknown", "path_unavailable"),
    ],
  }
  (case / "semantic_state_reconstruction.json").write_text(
    json.dumps(frozen), encoding="utf-8"
  )
  dataset = tmp_path / "dataset.json"
  dataset.write_text(json.dumps({
    "CVE-X": {
      "repo": "repo",
      "fixing_commits": ["fix-a"],
      "affected_version": ["v1"],
    }
  }), encoding="utf-8")
  out = tmp_path / "out"

  result = run_tri_state_policy_audit(
    source_run=source,
    dataset=dataset,
    out_dir=out,
    cve_ids=["CVE-X"],
  )

  public = json.loads((out / "CVE-X" / "public_prediction.json").read_text())
  assert public["affected_versions"] == ["v1"]
  assert public["unknown_versions"] == ["v2"]
  assert result["state_transition_audit"]["unknown_in_primary_prediction_count"] == 0
  assert result["state_transition_audit"]["per_tag_accounting_rate"] == 1.0
