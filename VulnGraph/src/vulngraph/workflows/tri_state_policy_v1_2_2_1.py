from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any


TRI_STATES = {"confirmed_affected", "confirmed_unaffected", "unknown"}
_STRONG_ABSENT_REASONS = {"predicate_not_found_in_scope", "semantic_context_missing"}
_WEAK_REASONS = {
  "weak_predicate_fingerprint",
  "predicate_tokens_reordered",
  "function_scope_predicate_fingerprint",
}


def classify_context_state(row: dict[str, Any]) -> dict[str, Any]:
  predicate = _predicate_state(list(row.get("activation_evidence") or []))
  fix = _fix_states(dict(row.get("fix_evidence") or {}))
  prerequisite = str(row.get("prerequisite_state") or "unknown")
  context_id = str(row.get("branch_context_id") or "")
  branch_membership = (
    "confirmed"
    if context_id and (
      predicate["strength"] in {"strong_present", "strong_absent"}
      or fix["fix_reachability_state"] == "present"
    )
    else "unknown"
  )

  if fix["fix_reachability_state"] == "present" or fix["fix_predicate_state"] == "strong_present":
    final = "confirmed_unaffected"
    reason = "branch_local_fix_completion_present"
  elif predicate["strength"] == "strong_absent" and branch_membership == "confirmed":
    final = "confirmed_unaffected"
    reason = "vulnerability_predicate_strongly_absent"
  elif (
    predicate["strength"] == "strong_present"
    and fix["fix_predicate_state"] == "strong_absent"
    and fix["fix_reachability_state"] == "absent"
    and branch_membership == "confirmed"
    and prerequisite == "complete"
  ):
    final = "confirmed_affected"
    reason = "vulnerability_present_fix_completion_absent"
  else:
    final = "unknown"
    reason = _unknown_reason(predicate, fix, prerequisite, branch_membership)

  evidence_refs = sorted({
    str(item.get("event_candidate_id") or "")
    for item in [
      *(row.get("activation_evidence") or []),
      *(row.get("prerequisite_evidence") or []),
    ]
    if item.get("event_candidate_id")
  })
  evidence_refs.extend(
    f"fix:{sha}:{value}"
    for sha, value in sorted((row.get("fix_evidence") or {}).get("reachability", {}).items())
  )
  return {
    "tag": str(row.get("tag") or ""),
    "branch_context_id": context_id,
    "release_line": context_id,
    "vulnerability_predicate_state": predicate["state"],
    "vulnerability_predicate_strength": predicate["strength"],
    "fix_predicate_state": fix["fix_predicate_state"],
    "fix_reachability_state": fix["fix_reachability_state"],
    "boundary_state": _boundary_state(predicate["strength"], prerequisite),
    "branch_context_membership_state": branch_membership,
    "function_scope_match_kind": predicate["match_kind"],
    "match_level": predicate["match_level"],
    "evidence_refs": evidence_refs,
    "final_tri_state": final,
    "final_reason": reason,
    "included_in_primary_prediction": final == "confirmed_affected",
    "context_evidence": row,
  }


def aggregate_tag_state(
  cve_id: str,
  repo: str,
  tag: str,
  context_states: list[dict[str, Any]],
) -> dict[str, Any]:
  states = {str(item.get("final_tri_state") or "unknown") for item in context_states}
  if "confirmed_affected" in states and "confirmed_unaffected" in states:
    final = "unknown"
    reason = "conflicting_branch_context_states"
    selected = context_states
  elif "confirmed_affected" in states:
    final = "confirmed_affected"
    reason = "at_least_one_branch_context_confirmed_affected"
    selected = [item for item in context_states if item["final_tri_state"] == final]
  elif "confirmed_unaffected" in states:
    final = "confirmed_unaffected"
    reason = "at_least_one_branch_context_confirmed_unaffected"
    selected = [item for item in context_states if item["final_tri_state"] == final]
  else:
    final = "unknown"
    reason = _aggregate_unknown_reason(context_states)
    selected = context_states

  context_ids = sorted({
    str(item.get("branch_context_id") or "")
    for item in selected if item.get("branch_context_id")
  })
  return {
    "cve_id": cve_id,
    "repo": repo,
    "tag": tag,
    "release_line": "|".join(context_ids),
    "branch_context_id": "|".join(context_ids),
    "vulnerability_predicate_state": _join_values(selected, "vulnerability_predicate_state"),
    "fix_predicate_state": _join_values(selected, "fix_predicate_state"),
    "fix_reachability_state": _join_values(selected, "fix_reachability_state"),
    "boundary_state": _join_values(selected, "boundary_state"),
    "function_scope_match_kind": _dominant_match_kind(selected),
    "evidence_refs": sorted({
      ref for item in selected for ref in item.get("evidence_refs", [])
    }),
    "final_tri_state": final,
    "final_reason": reason,
    "included_in_primary_prediction": final == "confirmed_affected",
    "context_state_count": len(context_states),
    "context_states": context_states,
  }


def build_tag_state_ledger(frozen_prediction: dict[str, Any]) -> list[dict[str, Any]]:
  cve_id = str(frozen_prediction.get("cve_id") or "")
  repo = str(frozen_prediction.get("repo") or "")
  grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
  for row in frozen_prediction.get("evidence", []) or []:
    state = classify_context_state(row)
    if state["tag"]:
      grouped[state["tag"]].append(state)
  release_tags = set(grouped)
  for field in (
    "confirmed_affected_versions",
    "confirmed_unaffected_versions",
    "unknown_versions",
    "predicted_affected_versions_for_metric",
  ):
    release_tags.update(str(tag) for tag in frozen_prediction.get(field, []) or [])
  ledger = []
  for tag in sorted(release_tags):
    if grouped.get(tag):
      ledger.append(aggregate_tag_state(cve_id, repo, tag, grouped[tag]))
    else:
      ledger.append({
        "cve_id": cve_id,
        "repo": repo,
        "tag": tag,
        "release_line": "",
        "branch_context_id": "",
        "vulnerability_predicate_state": "unknown",
        "fix_predicate_state": "unknown",
        "fix_reachability_state": "unknown",
        "boundary_state": "unknown",
        "function_scope_match_kind": "unavailable",
        "evidence_refs": [],
        "final_tri_state": "unknown",
        "final_reason": "missing_frozen_tag_local_evidence",
        "included_in_primary_prediction": False,
        "context_state_count": 0,
        "context_states": [],
      })
  return ledger


def audit_ledger_gates(
  ledger: list[dict[str, Any]],
  *,
  expected_tag_count: int,
) -> dict[str, Any]:
  counts = Counter(str(row.get("final_tri_state") or "unknown") for row in ledger)
  unknown_primary = sum(
    1 for row in ledger
    if row.get("final_tri_state") == "unknown"
    and row.get("included_in_primary_prediction") is True
  )
  weak_confirmed = sum(
    1 for row in ledger
    if row.get("function_scope_match_kind") in {"weak_fingerprint", "function_structural"}
    and row.get("final_tri_state") == "confirmed_affected"
  )
  unique_tags = len({str(row.get("tag") or "") for row in ledger if row.get("tag")})
  accounting_rate = unique_tags / expected_tag_count if expected_tag_count else 1.0
  return {
    "tags_total": len(ledger),
    "confirmed_affected_tag_count": counts["confirmed_affected"],
    "confirmed_unaffected_tag_count": counts["confirmed_unaffected"],
    "unknown_tag_count": counts["unknown"],
    "unknown_tag_rate": counts["unknown"] / len(ledger) if ledger else 0.0,
    "unknown_in_primary_prediction_count": unknown_primary,
    "weak_fingerprint_confirmed_count": weak_confirmed,
    "per_tag_accounting_rate": accounting_rate,
    "gate_ok": (
      len(ledger) == expected_tag_count
      and unique_tags == expected_tag_count
      and unknown_primary == 0
      and weak_confirmed == 0
      and accounting_rate == 1.0
    ),
  }


def _predicate_state(evidence: list[dict[str, Any]]) -> dict[str, str]:
  states = [str(item.get("state") or "unknown") for item in evidence]
  reasons = {
    str(item.get("reason") or item.get("failure_reason") or "")
    for item in evidence
  }
  levels = {
    str(item.get("match_level") or "") for item in evidence if item.get("match_level")
  }
  if "present_exact" in states:
    return _predicate("present_exact", "strong_present", "exact", levels)
  if "present_normalized" in states:
    return _predicate("present_normalized", "strong_present", "normalized", levels)
  if "present_predicate_equivalent" in states:
    return _predicate(
      "present_predicate_equivalent", "weak_present", "function_structural", levels
    )
  if reasons & _WEAK_REASONS:
    return _predicate("unknown", "weak", "weak_fingerprint", levels)
  if states and all(state == "absent" for state in states) and reasons <= _STRONG_ABSENT_REASONS:
    return _predicate("absent", "strong_absent", "no_match", levels)
  if "unknown" in states or not states:
    return _predicate("unknown", "unknown", "unavailable", levels)
  if states and all(state == "absent" for state in states):
    return _predicate("unknown", "unknown", "unavailable", levels)
  return _predicate("unknown", "unknown", "mixed", levels)


def _predicate(state: str, strength: str, kind: str, levels: set[str]) -> dict[str, str]:
  return {
    "state": state,
    "strength": strength,
    "match_kind": kind,
    "match_level": "|".join(sorted(levels)),
  }


def _fix_states(evidence: dict[str, Any]) -> dict[str, str]:
  presence = str(evidence.get("fix_presence") or "unknown")
  state = str(evidence.get("state") or "unknown")
  semantic = str(evidence.get("semantic_state") or "")
  reachability = {str(value) for value in (evidence.get("reachability") or {}).values()}
  if presence == "present":
    reachability_state = "present"
  elif presence == "absent" and reachability and reachability <= {"no"}:
    reachability_state = "absent"
  else:
    reachability_state = "unknown"

  if semantic in {"present", "present_exact", "present_normalized"}:
    predicate_state = "strong_present"
  elif state == "absent" and reachability_state == "absent":
    # Frozen v1.2.2 did not retain an independent code-level fix predicate
    # result. This is a fix-completion absence proxy and is audited separately.
    predicate_state = "strong_absent"
  else:
    predicate_state = "unknown"
  return {
    "fix_predicate_state": predicate_state,
    "fix_reachability_state": reachability_state,
  }


def _boundary_state(predicate_strength: str, prerequisite: str) -> str:
  if predicate_strength == "strong_present" and prerequisite == "complete":
    return "active"
  if predicate_strength == "strong_absent" or prerequisite == "incomplete":
    return "inactive"
  return "unknown"


def _unknown_reason(
  predicate: dict[str, str],
  fix: dict[str, str],
  prerequisite: str,
  branch_membership: str,
) -> str:
  if predicate["strength"] in {"weak", "weak_present"}:
    return "weak_predicate_evidence"
  if branch_membership != "confirmed":
    return "branch_context_membership_unverified"
  if prerequisite == "unknown":
    return "prerequisite_state_unknown"
  if fix["fix_reachability_state"] == "unknown":
    return "fix_completion_state_unknown"
  return "insufficient_strong_state_evidence"


def _aggregate_unknown_reason(states: list[dict[str, Any]]) -> str:
  reasons = sorted({str(item.get("final_reason") or "") for item in states})
  return "all_branch_contexts_unknown:" + "|".join(reasons)


def _join_values(items: list[dict[str, Any]], field: str) -> str:
  return "|".join(sorted({str(item.get(field) or "unknown") for item in items}))


def _dominant_match_kind(items: list[dict[str, Any]]) -> str:
  priority = [
    "exact", "normalized", "function_structural", "weak_fingerprint",
    "no_match", "unavailable", "mixed",
  ]
  values = {str(item.get("function_scope_match_kind") or "unavailable") for item in items}
  return next((value for value in priority if value in values), "unavailable")
