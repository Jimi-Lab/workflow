from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from vulngraph.agent_io.judge_boundary_v1_2_schema import JudgeBoundaryOutputV12
from vulngraph.agent_io.judge_contract import scan_forbidden_judge_fields


@dataclass(frozen=True)
class ContractResultV12:
  ok: bool
  errors: list[str]
  taxonomy: dict[str, int]
  invented_candidate_ids: list[str]

  def to_dict(self) -> dict[str, Any]:
    return {"ok": self.ok, "errors": self.errors, "taxonomy": self.taxonomy, "invented_candidate_ids": self.invented_candidate_ids}


def lint_judge_boundary_output_v1_2(output: dict[str, Any], boundary_input: dict[str, Any]) -> ContractResultV12:
  errors: list[str] = []
  taxonomy: Counter[str] = Counter()
  forbidden = scan_forbidden_judge_fields(output)
  if not forbidden["ok"]:
    taxonomy["forbidden_field"] += forbidden["violation_count"]
    errors.extend(f"forbidden_field:{row['key']}:{row['location']}" for row in forbidden["violations"])
  try:
    model = JudgeBoundaryOutputV12.model_validate(output)
  except ValidationError as error:
    return ContractResultV12(False, [*errors, f"schema_validation:{error}"], {**taxonomy, "schema_validation": 1}, [])
  if model.cve_id != str(boundary_input.get("cve_id") or ""):
    taxonomy["cve_mismatch"] += 1
    errors.append(f"cve_mismatch:{model.cve_id}")
  candidates = {str(item.get("event_candidate_id") or ""): item for item in boundary_input.get("history_event_candidates", []) or []}
  ids = [item.event_candidate_id for item in model.candidate_judgments]
  for candidate_id, count in Counter(ids).items():
    if count > 1:
      taxonomy["candidate_accounted_multiple_times"] += 1
      errors.append(f"candidate_accounted_multiple_times:{candidate_id}")
  invented = sorted(set(ids) - set(candidates))
  for judgment in model.candidate_judgments:
    candidate = candidates.get(judgment.event_candidate_id)
    if not candidate:
      taxonomy["unknown_candidate_id"] += 1
      errors.append(f"unknown_candidate_id:{judgment.event_candidate_id}")
      continue
    if judgment.event_commit_sha != str(candidate.get("event_commit_sha") or ""):
      taxonomy["candidate_sha_mismatch"] += 1
      errors.append(f"candidate_sha_mismatch:{judgment.event_candidate_id}")
    allowed_refs = set(candidate.get("evidence_refs") or [])
    if not judgment.evidence_refs:
      taxonomy["judgment_without_evidence_refs"] += 1
      errors.append(f"judgment_without_evidence_refs:{judgment.event_candidate_id}")
    for ref in judgment.evidence_refs:
      if ref not in allowed_refs:
        taxonomy["unknown_evidence_ref"] += 1
        errors.append(f"unknown_evidence_ref:{judgment.event_candidate_id}:{ref}")
    if not _consistent(judgment.decision, judgment.boundary_role):
      taxonomy["decision_role_conflict"] += 1
      errors.append(f"decision_role_conflict:{judgment.event_candidate_id}")
  for missing in sorted(set(candidates) - set(ids)):
    taxonomy["candidate_not_accounted"] += 1
    errors.append(f"candidate_not_accounted:{missing}")
  return ContractResultV12(not errors, errors, dict(taxonomy), invented)


def derive_boundary_views_v1_2(output: dict[str, Any], boundary_input: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
  model = JudgeBoundaryOutputV12.model_validate(output)
  candidates = {str(item.get("event_candidate_id") or ""): item for item in boundary_input.get("history_event_candidates", []) or []}
  selected, rejected, uncertain = [], [], []
  for judgment in model.candidate_judgments:
    item = {**judgment.model_dump(mode="json"), **{key: value for key, value in candidates.get(judgment.event_candidate_id, {}).items() if key not in judgment.model_fields}}
    if judgment.decision == "selected":
      selected.append(item)
    elif judgment.decision == "rejected":
      rejected.append(item)
    else:
      uncertain.append(item)
  return {
    "selected_events": selected,
    "activation_events": [item for item in selected if item["boundary_role"] in {"primary_boundary", "branch_equivalent_boundary"}],
    "conjunctive_prerequisites": [item for item in selected if item["boundary_role"] == "conjunctive_prerequisite"],
    "supporting_evidence": [item for item in selected if item["boundary_role"] == "supporting_evidence_only"],
    "rejected_candidates": rejected,
    "uncertain_candidates": uncertain,
  }


def _consistent(decision: str, role: str) -> bool:
  if decision == "rejected":
    return role == "fix_refactor_noise"
  if decision == "selected":
    return role != "fix_refactor_noise"
  return decision == "uncertain"
