from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from vulngraph.agent_io.judge_boundary_schema import JudgeBoundaryOutputV1
from vulngraph.agent_io.judge_contract import FORBIDDEN_JUDGE_KEYS, scan_forbidden_judge_fields


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


def lint_judge_boundary_output_v1(output: dict[str, Any] | JudgeBoundaryOutputV1, boundary_input: dict[str, Any]) -> JudgeBoundaryContractResult:
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

  candidates = {str(item.get("candidate_id") or ""): item for item in boundary_input.get("candidate_set", []) or [] if item.get("candidate_id")}
  allowed_shas = {str(item.get("candidate_commit_sha") or "") for item in candidates.values()}
  allowed_refs = set(_allowed_evidence_refs(boundary_input))
  accounted: set[str] = set()

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
    accounted.add(judgment.candidate_id)
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
    conflict_flags = _conflict_flags(candidate)
    if conflict_flags and judgment.decision == "selected" and judgment.boundary_role != "uncertain_boundary":
      if not _explains_conflict(judgment.reasoning_short, model.uncertainty, judgment.candidate_id, conflict_flags):
        taxonomy["conflict_without_uncertainty_or_explanation"] += 1
        errors.append(f"conflict_without_uncertainty_or_explanation:{judgment.candidate_id}:{','.join(sorted(conflict_flags))}")

  for event in model.selected_boundary_events:
    candidate = candidates.get(event.candidate_id)
    if candidate is None:
      invented.add(event.candidate_id)
      taxonomy["unknown_candidate_id"] += 1
      errors.append(f"unknown_candidate_id:{event.candidate_id}")
      continue
    if event.candidate_commit_sha != str(candidate.get("candidate_commit_sha") or ""):
      taxonomy["candidate_sha_mismatch"] += 1
      errors.append(f"candidate_sha_mismatch:{event.candidate_id}")
    if not event.evidence_refs:
      taxonomy["selected_event_without_evidence_refs"] += 1
      errors.append(f"selected_event_without_evidence_refs:{event.candidate_id}")
    for evidence_ref in event.evidence_refs:
      if allowed_refs and evidence_ref not in allowed_refs:
        taxonomy["unknown_evidence_ref"] += 1
        errors.append(f"unknown_evidence_ref:{event.candidate_id}:{evidence_ref}")

  for rejected in model.rejected_candidates:
    if rejected.candidate_id not in candidates:
      invented.add(rejected.candidate_id)
      taxonomy["unknown_candidate_id"] += 1
      errors.append(f"unknown_candidate_id:{rejected.candidate_id}")
    else:
      accounted.add(rejected.candidate_id)

  for candidate_id in sorted(set(candidates) - accounted):
    taxonomy["candidate_not_accounted"] += 1
    errors.append(f"candidate_not_accounted:{candidate_id}")
  for candidate_id in _duplicates([item.candidate_id for item in model.candidate_judgments] + [item.candidate_id for item in model.rejected_candidates]):
    taxonomy["candidate_accounted_multiple_times"] += 1
    errors.append(f"candidate_accounted_multiple_times:{candidate_id}")

  selected_ids = {item.candidate_id for item in model.selected_boundary_events}
  judgment_selected_ids = {item.candidate_id for item in model.candidate_judgments if item.decision == "selected"}
  for candidate_id in sorted(selected_ids - judgment_selected_ids):
    taxonomy["selected_event_without_selected_judgment"] += 1
    errors.append(f"selected_event_without_selected_judgment:{candidate_id}")

  return JudgeBoundaryContractResult(
    ok=not errors,
    errors=errors,
    taxonomy={key: value for key, value in taxonomy.items() if value},
    invented_candidate_ids=sorted(invented),
  )


def scan_forbidden_boundary_fields(data: Any) -> dict[str, Any]:
  return scan_forbidden_judge_fields(data)


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


def _explains_conflict(reasoning: str, uncertainty: list[Any], candidate_id: str, conflict_flags: set[str]) -> bool:
  text = str(reasoning).lower()
  for item in uncertainty:
    if getattr(item, "candidate_id", None) in {candidate_id, None}:
      text += " " + str(getattr(item, "reason", "")).lower()
  mentions_conflict = any(flag.lower() in text for flag in conflict_flags) or any(
    token in text for token in ("conflict", "disagreement", "differs", "sensitive", "boundary", "merge", "not ancestor")
  )
  has_evidence_reason = any(token in text for token in ("because", "despite", "although", "evidence", "normal", "stable", "ancestor", "root cause"))
  return mentions_conflict and has_evidence_reason


def _duplicates(values: list[str]) -> list[str]:
  counts = Counter(values)
  return sorted(value for value, count in counts.items() if value and count > 1)


def _taxonomy_dict(counter: Counter[str], **extra: int) -> dict[str, int]:
  output = {key: value for key, value in counter.items() if value}
  output.update({key: value for key, value in extra.items() if value})
  return output
