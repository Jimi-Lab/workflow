from __future__ import annotations

import json
from typing import Any

from .base import AgentResponse


class FixtureSzzAnchorBackend:
  """Deterministic fixture backend for pipeline tests; never a real agent result."""

  backend_name = "fixture-szz-anchor"
  backend_type = "fixture"

  def generate(self, prompt: str, context: dict[str, Any]) -> AgentResponse:
    inventory = context.get("candidate_inventory") or {}
    root_cause = context.get("root_cause") or {}
    hypotheses = list(root_cause.get("root_cause_hypotheses") or [])
    predicates = list(root_cause.get("vulnerable_predicates") or [])
    selected: list[dict[str, Any]] = []
    uncertainties: list[dict[str, str]] = []
    candidates = list(inventory.get("candidates") or [])
    for family_id in (inventory.get("fix_families") or {}):
      family_candidates = [item for item in candidates if item.get("patch_family_id") == family_id]
      fix_commit_ids = sorted({str(item.get("fix_commit_id")) for item in family_candidates if item.get("fix_commit_id")})
      for fix_commit_id in fix_commit_ids:
        eligible = [
          item for item in family_candidates
          if item.get("fix_commit_id") == fix_commit_id
          and item.get("source_file") is True
          and item.get("comment_only") is not True
          and item.get("blank_line") is not True
        ]
        eligible.sort(key=_candidate_priority)
        chosen = None
        chosen_hypothesis = None
        chosen_predicate = None
        for candidate in eligible:
          candidate_refs = set(candidate.get("git_observation_refs") or [])
          hypothesis = next(
            (item for item in hypotheses if candidate_refs & set(item.get("git_observation_refs") or [])),
            None,
          )
          predicate = next(
            (item for item in predicates if candidate_refs & set(item.get("git_observation_refs") or [])),
            None,
          )
          if hypothesis and predicate:
            chosen, chosen_hypothesis, chosen_predicate = candidate, hypothesis, predicate
            break
        if chosen is None:
          uncertainties.append(
            {
              "patch_family_id": str(family_id),
              "fix_commit_id": fix_commit_id,
              "reason_code": "no_shared_root_cause_evidence",
              "detail": "No fixture candidate has shared Root Cause patch evidence.",
            }
          )
          continue
        selected.append(
          {
            "candidate_id": chosen["candidate_id"],
            "role": "dangerous_use" if chosen.get("candidate_source") != "hunk_context" else "control_predecessor",
            "root_cause_hypothesis_ids": [chosen_hypothesis.get("hypothesis_id") or chosen_hypothesis.get("id")],
            "predicate_ids": [chosen_predicate.get("predicate_id") or chosen_predicate.get("id")],
            "rationale": "Deterministic fixture selection of a wrapper-owned parent-side source line.",
            "confidence": 0.5,
          }
        )
    cve_id = str(context.get("cve_id") or inventory.get("cve_id") or "CVE-UNKNOWN")
    payload = {
      "agent_run": {"run_id": f"fixture-szz:{cve_id}", "cve_id": cve_id, "backend": self.backend_name},
      "failure_mode": "Fixture summary; not a semantic agent result.",
      "trigger": "Fixture trigger.",
      "violated_invariant": "Fixture invariant.",
      "vulnerable_state": "Fixture vulnerable state.",
      "propagation": [],
      "sink": "Fixture sink.",
      "fix_mechanism": "Fixture fix mechanism.",
      "selected_anchors": selected,
      "excluded_hunk_ids": [],
      "uncertainty_items": uncertainties,
    }
    return AgentResponse(
      raw_text=json.dumps(payload, ensure_ascii=False, indent=2),
      status="ok",
      backend_name=self.backend_name,
      backend_type=self.backend_type,
      usage={"prompt_chars": len(prompt), "fixture": True},
    )


def _candidate_priority(candidate: dict[str, Any]) -> tuple[int, str]:
  source_order = {"deleted_line": 0, "pre_fix_function_body": 1, "hunk_context": 2}
  return source_order.get(str(candidate.get("candidate_source")), 9), str(candidate.get("candidate_id") or "")
