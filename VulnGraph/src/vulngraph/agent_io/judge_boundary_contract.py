from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from vulngraph.agent_io.judge_boundary_schema import JudgeBoundaryOutputV1
from vulngraph.agent_io.judge_contract import scan_forbidden_judge_fields


SELECTABLE_ROLES = {"introduction", "activation", "prerequisite"}
NOISE_ROLES = {"fix_series_noise", "refactor_noise", "equivalent_fix_noise"}


@dataclass(frozen=True)
class JudgeBoundaryContractResult:
  ok: bool
  errors: list[str]
  taxonomy: dict[str, int]
  invented_candidate_ids: list[str]
  parse_error: str | None = None

  def to_dict(self) -> dict[str, Any]:
    return {
      "ok": self.ok,
      "errors": self.errors,
      "taxonomy": self.taxonomy,
      "invented_candidate_ids": self.invented_candidate_ids,
      "parse_error": self.parse_error,
    }


def lint_judge_boundary_output_v1(
  output: dict[str, Any] | JudgeBoundaryOutputV1,
  boundary_input: dict[str, Any],
) -> JudgeBoundaryContractResult:
  taxonomy: Counter[str] = Counter()
  errors: list[str] = []
  invented: set[str] = set()
  forbidden = scan_forbidden_boundary_fields(output)
  if not forbidden["ok"]:
    taxonomy["forbidden_field"] += forbidden["violation_count"]
    errors.extend(f"forbidden_field:{item['key']}:{item['location']}" for item in forbidden["violations"])

  try:
    model = output if isinstance(output, JudgeBoundaryOutputV1) else JudgeBoundaryOutputV1.model_validate(output)
  except ValidationError as error:
    return JudgeBoundaryContractResult(
      ok=False,
      errors=[*errors, f"schema_validation:{error}"],
      taxonomy=_taxonomy_dict(taxonomy, schema_validation=1),
      invented_candidate_ids=[],
      parse_error=str(error),
    )

  if model.cve_id != str(boundary_input.get("cve_id") or ""):
    taxonomy["cve_mismatch"] += 1
    errors.append(f"cve_mismatch:{model.cve_id}")

  candidates = {
    str(item.get("candidate_id") or ""): item
    for item in boundary_input.get("candidate_set", []) or []
    if item.get("candidate_id")
  }
  allowed_shas = {str(item.get("candidate_commit_sha") or "") for item in candidates.values()}
  allowed_refs = set(_allowed_evidence_refs(boundary_input))
  judgment_ids = [item.candidate_id for item in model.candidate_judgments]

  for candidate_id in _duplicates(judgment_ids):
    taxonomy["candidate_accounted_multiple_times"] += 1
    errors.append(f"candidate_accounted_multiple_times:{candidate_id}")

  for judgment in model.candidate_judgments:
    candidate = candidates.get(judgment.candidate_id)
    if candidate is None:
      invented.add(judgment.candidate_id)
      taxonomy["unknown_candidate_id"] += 1
      errors.append(f"unknown_candidate_id:{judgment.candidate_id}")
      if judgment.candidate_commit_sha not in allowed_shas:
        taxonomy["candidate_sha_mismatch"] += 1
        errors.append(f"candidate_sha_mismatch:{judgment.candidate_id}")
      continue

    if judgment.candidate_commit_sha != str(candidate.get("candidate_commit_sha") or ""):
      taxonomy["candidate_sha_mismatch"] += 1
      errors.append(f"candidate_sha_mismatch:{judgment.candidate_id}")
    if not judgment.evidence_refs:
      taxonomy["judgment_without_evidence_refs"] += 1
      errors.append(f"judgment_without_evidence_refs:{judgment.candidate_id}")
    for evidence_ref in judgment.evidence_refs:
      if allowed_refs and evidence_ref not in allowed_refs:
        taxonomy["unknown_evidence_ref"] += 1
        errors.append(f"unknown_evidence_ref:{judgment.candidate_id}:{evidence_ref}")

    if not _decision_role_consistent(judgment.decision, judgment.boundary_role):
      taxonomy["decision_role_conflict"] += 1
      errors.append(
        f"decision_role_conflict:{judgment.candidate_id}:{judgment.decision}:{judgment.boundary_role}"
      )

    conflict_flags = _conflict_flags(candidate)
    if conflict_flags and judgment.decision == "selected":
      if not _explains_conflict(judgment.reasoning_short, conflict_flags):
        taxonomy["conflict_without_uncertainty_or_explanation"] += 1
        errors.append(
          f"conflict_without_uncertainty_or_explanation:{judgment.candidate_id}:"
          f"{','.join(sorted(conflict_flags))}"
        )

  accounted = set(judgment_ids)
  for candidate_id in sorted(set(candidates) - accounted):
    taxonomy["candidate_not_accounted"] += 1
    errors.append(f"candidate_not_accounted:{candidate_id}")

  return JudgeBoundaryContractResult(
    ok=not errors,
    errors=errors,
    taxonomy={key: value for key, value in taxonomy.items() if value},
    invented_candidate_ids=sorted(invented),
  )


def derive_boundary_views(
  output: dict[str, Any] | JudgeBoundaryOutputV1,
  boundary_input: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
  model = output if isinstance(output, JudgeBoundaryOutputV1) else JudgeBoundaryOutputV1.model_validate(output)
  candidates = {
    str(item.get("candidate_id") or ""): item
    for item in boundary_input.get("candidate_set", []) or []
    if item.get("candidate_id")
  }
  selected: list[dict[str, Any]] = []
  rejected: list[dict[str, Any]] = []
  uncertain: list[dict[str, Any]] = []
  for judgment in model.candidate_judgments:
    candidate = candidates.get(judgment.candidate_id, {})
    item = {
      **judgment.model_dump(mode="json"),
      "boundary_group_ids": list(candidate.get("boundary_group_ids") or []),
      "fix_set_id": str(candidate.get("fix_set_id") or ""),
      "patch_family_id": str(candidate.get("patch_family_id") or ""),
      "candidate_source": str(candidate.get("candidate_source") or ""),
      "candidate_selection_mode": str(candidate.get("candidate_selection_mode") or ""),
    }
    if judgment.decision == "selected":
      selected.append(item)
    elif judgment.decision == "rejected":
      rejected.append(item)
    else:
      uncertain.append(item)
  return {
    "selected_boundary_events": selected,
    "rejected_candidates": rejected,
    "uncertain_candidates": uncertain,
  }


def scan_forbidden_boundary_fields(data: Any) -> dict[str, Any]:
  return scan_forbidden_judge_fields(data)


def _decision_role_consistent(decision: str, role: str) -> bool:
  if decision == "selected":
    return role in SELECTABLE_ROLES
  if decision == "rejected":
    return role in NOISE_ROLES
  return decision == "uncertain" and role in SELECTABLE_ROLES | NOISE_ROLES


def _allowed_evidence_refs(boundary_input: dict[str, Any]) -> list[str]:
  refs: list[str] = []
  for item in boundary_input.get("candidate_set", []) or []:
    refs.extend(str(ref) for ref in item.get("evidence_refs", []) or [])
  for item in boundary_input.get("szz_evidence_cards", []) or []:
    refs.extend(str(ref) for ref in item.get("evidence_refs", []) or [])
  for item in boundary_input.get("judge_v0_rankings", []) or []:
    refs.extend(str(ref) for ref in item.get("evidence_refs_used", []) or [])
  return sorted(set(refs))


def _conflict_flags(candidate: dict[str, Any]) -> set[str]:
  flags = {str(item) for item in candidate.get("risk_flags", []) or []}
  return flags & {
    "whitespace_sensitive_blame",
    "move_copy_sensitive_blame",
    "candidate_not_ancestor_of_fix",
    "boundary_candidate_commit",
    "root_candidate_commit",
    "merge_candidate",
    "candidate_is_merge_commit",
  }


def _explains_conflict(reasoning: str, conflict_flags: set[str]) -> bool:
  text = str(reasoning).lower()
  mentions_conflict = any(flag.lower() in text for flag in conflict_flags) or any(
    token in text
    for token in (
      "conflict",
      "disagreement",
      "differs",
      "sensitive",
      "boundary",
      "merge",
      "not ancestor",
    )
  )
  has_evidence_reason = any(
    token in text
    for token in (
      "because",
      "despite",
      "although",
      "evidence",
      "normal",
      "stable",
      "ancestor",
      "root cause",
    )
  )
  return mentions_conflict and has_evidence_reason


def _duplicates(values: list[str]) -> list[str]:
  counts = Counter(values)
  return sorted(value for value, count in counts.items() if value and count > 1)


def _taxonomy_dict(counter: Counter[str], **extra: int) -> dict[str, int]:
  output = {key: value for key, value in counter.items() if value}
  output.update({key: value for key, value in extra.items() if value})
  return output
