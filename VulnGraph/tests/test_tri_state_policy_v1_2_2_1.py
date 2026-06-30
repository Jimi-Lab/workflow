from __future__ import annotations

from vulngraph.workflows.tri_state_policy_v1_2_2_1 import (
  aggregate_tag_state,
  audit_ledger_gates,
  build_tag_state_ledger,
  classify_context_state,
)


def _activation(state: str, *, level: str = "function_scope", reason: str = "") -> dict:
  return {
    "event_candidate_id": "event-1",
    "state": state,
    "match_level": level,
    "reason": reason,
    "failure_reason": reason if state in {"absent", "unknown"} else "",
  }


def _row(
  *, tag: str = "v1.0", context: str = "branch-1", activation: dict,
  fix_presence: str = "absent", fix_state: str = "absent",
  fix_reason: str = "no_fix_or_equivalent_reachable",
) -> dict:
  return {
    "branch_context_id": context, "tag": tag,
    "activation_state": (
      "active" if activation["state"].startswith("present_")
      else "unknown" if activation["state"] == "unknown" else "inactive"
    ),
    "activation_evidence": [activation],
    "prerequisite_state": "complete", "prerequisite_evidence": [],
    "fix_state": fix_state,
    "fix_evidence": {
      "state": fix_state, "fix_presence": fix_presence,
      "evidence_reason": fix_reason,
      "reachability": {"fix-a": "no" if fix_presence == "absent" else "yes"},
    },
  }


def test_unknown_is_never_included_in_primary_prediction() -> None:
  state = classify_context_state(
    _row(activation=_activation("unknown", reason="path_unavailable"))
  )
  assert state["final_tri_state"] == "unknown"
  assert state["included_in_primary_prediction"] is False


def test_function_structural_fingerprint_is_not_strong_presence() -> None:
  state = classify_context_state(
    _row(activation=_activation(
      "present_predicate_equivalent",
      reason="function_scope_predicate_fingerprint",
    ))
  )
  assert state["function_scope_match_kind"] == "function_structural"
  assert state["final_tri_state"] == "unknown"
  assert state["included_in_primary_prediction"] is False


def test_weak_predicate_absence_does_not_confirm_unaffected() -> None:
  state = classify_context_state(
    _row(activation=_activation("absent", reason="weak_predicate_fingerprint"))
  )
  assert state["function_scope_match_kind"] == "weak_fingerprint"
  assert state["final_tri_state"] == "unknown"


def test_fix_completion_conflict_prevents_confirmed_affected() -> None:
  state = classify_context_state(_row(
    activation=_activation("present_exact"),
    fix_presence="present", fix_state="fix_reachable", fix_reason="fix_reachable",
  ))
  assert state["final_tri_state"] == "confirmed_unaffected"
  assert state["included_in_primary_prediction"] is False


def test_conflicting_context_states_aggregate_to_unknown() -> None:
  affected = classify_context_state(_row(activation=_activation("present_exact")))
  unaffected = classify_context_state(_row(
    context="branch-2", activation=_activation("present_exact"),
    fix_presence="present", fix_state="fix_reachable", fix_reason="fix_reachable",
  ))
  combined = aggregate_tag_state("CVE-X", "repo", "v1.0", [affected, unaffected])
  assert combined["final_tri_state"] == "unknown"
  assert combined["final_reason"] == "conflicting_branch_context_states"


def test_ledger_has_exactly_one_row_per_release_tag() -> None:
  frozen = {
    "cve_id": "CVE-X", "repo": "repo", "release_tag_universe_size": 2,
    "evidence": [
      _row(tag="v1.0", activation=_activation("present_exact")),
      _row(tag="v1.0", context="branch-2", activation=_activation("unknown", reason="path_unavailable")),
      _row(tag="v2.0", activation=_activation("absent", reason="predicate_not_found_in_scope")),
    ],
  }
  ledger = build_tag_state_ledger(frozen)
  assert [row["tag"] for row in ledger] == ["v1.0", "v2.0"]
  assert ledger[0]["final_tri_state"] == "confirmed_affected"
  assert ledger[1]["final_tri_state"] == "confirmed_unaffected"


def test_ledger_gate_rejects_unknown_primary_prediction() -> None:
  ledger = [{
    "tag": "v1.0", "final_tri_state": "unknown",
    "included_in_primary_prediction": True,
    "function_scope_match_kind": "weak_fingerprint",
  }]
  audit = audit_ledger_gates(ledger, expected_tag_count=1)
  assert audit["unknown_in_primary_prediction_count"] == 1
  assert audit["weak_fingerprint_confirmed_count"] == 0
  assert audit["per_tag_accounting_rate"] == 1.0
  assert audit["gate_ok"] is False


def test_missing_evidence_tags_are_accounted_as_unknown() -> None:
  frozen = {
    "cve_id": "CVE-X",
    "repo": "repo",
    "release_tag_universe_size": 2,
    "evidence": [],
    "unknown_versions": ["v1.0", "v2.0"],
  }

  ledger = build_tag_state_ledger(frozen)

  assert [row["tag"] for row in ledger] == ["v1.0", "v2.0"]
  assert {row["final_tri_state"] for row in ledger} == {"unknown"}
  assert {row["final_reason"] for row in ledger} == {"missing_frozen_tag_local_evidence"}
