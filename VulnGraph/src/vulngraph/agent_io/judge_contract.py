from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from vulngraph.agent_io.judge_schema import JudgeOutputV0


FORBIDDEN_JUDGE_KEYS = {
  "validated_bic",
  "correct_bic",
  "affected_versions",
  "bic",
  "ground_truth",
  "gt_release_tags",
  "overlap_release_tags",
  "release_metrics",
  "false_positive_taxonomy",
  "precision",
  "recall",
  "f1",
  "exact_match",
}


@dataclass(frozen=True)
class JudgeContractResult:
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


def lint_judge_output_v0(output: dict[str, Any] | JudgeOutputV0, judge_input: dict[str, Any]) -> JudgeContractResult:
  taxonomy: Counter[str] = Counter()
  errors: list[str] = []
  invented: set[str] = set()

  forbidden = scan_forbidden_judge_fields(output)
  if not forbidden["ok"]:
    taxonomy["forbidden_field"] += forbidden["violation_count"]
    errors.extend(f"forbidden_field:{item['key']}:{item['location']}" for item in forbidden["violations"])

  try:
    model = output if isinstance(output, JudgeOutputV0) else JudgeOutputV0.model_validate(output)
  except ValidationError as error:
    return JudgeContractResult(
      ok=False,
      errors=[*errors, f"schema_validation:{error}"],
      taxonomy=_taxonomy_dict(taxonomy, schema_validation=1),
      invented_candidate_ids=[],
      parse_error=str(error),
    )

  if model.cve_id != str(judge_input.get("cve_id") or ""):
    taxonomy["cve_mismatch"] += 1
    errors.append(f"cve_mismatch:{model.cve_id}")
  if not model.judge_notes.version_conversion_not_performed:
    taxonomy["version_conversion_claimed"] += 1
    errors.append("version_conversion_claimed")
  cve_context = judge_input.get("cve_context") if isinstance(judge_input.get("cve_context"), dict) else {}
  if not bool(cve_context.get("attacker_perspective_available")) and model.judge_notes.attack_perspective_used:
    taxonomy["attacker_perspective_claimed_but_unavailable"] += 1
    errors.append("attacker_perspective_claimed_but_unavailable")

  candidates = {
    str(item.get("candidate_id") or ""): item
    for item in judge_input.get("candidate_set", []) or []
    if item.get("candidate_id")
  }
  allowed_shas = {str(item.get("candidate_commit_sha") or "") for item in candidates.values()}
  allowed_evidence_refs = set(_allowed_evidence_refs(judge_input))
  accounted: set[str] = set()
  ranks: Counter[int] = Counter()

  for judgment in model.candidate_judgments:
    candidate = candidates.get(judgment.candidate_id)
    if not judgment.evidence_refs_used:
      taxonomy["judgment_without_evidence_refs"] += 1
      errors.append(f"judgment_without_evidence_refs:{judgment.candidate_id}")
    if candidate is None:
      invented.add(judgment.candidate_id)
      taxonomy["unknown_candidate_id"] += 1
      errors.append(f"unknown_candidate_id:{judgment.candidate_id}")
      if judgment.candidate_commit_sha not in allowed_shas:
        taxonomy["candidate_sha_mismatch"] += 1
        errors.append(f"candidate_sha_mismatch:{judgment.candidate_id}")
    else:
      accounted.add(judgment.candidate_id)
      if judgment.candidate_commit_sha != str(candidate.get("candidate_commit_sha") or ""):
        taxonomy["candidate_sha_mismatch"] += 1
        errors.append(f"candidate_sha_mismatch:{judgment.candidate_id}")
      if judgment.confidence == "high":
        if not (
          model.judge_notes.root_cause_binding_used
          and model.judge_notes.szz_evidence_used
          and judgment.evidence_refs_used
        ):
          taxonomy["high_confidence_without_required_evidence"] += 1
          errors.append(f"high_confidence_without_required_evidence:{judgment.candidate_id}")
        if str(candidate.get("candidate_source") or "") == "fallback" and not _explains_fallback_high_confidence(judgment.supporting_factors):
          taxonomy["fallback_high_confidence_without_explanation"] += 1
          errors.append(f"fallback_high_confidence_without_explanation:{judgment.candidate_id}")
      conflict_flags = _conflicting_szz_risks(candidate)
      if conflict_flags and judgment.judgment != "uncertain_boundary" and not _explains_conflicting_szz_risk(judgment, conflict_flags):
        taxonomy["conflicting_evidence_without_strict_explanation"] += 1
        errors.append(f"conflicting_evidence_without_strict_explanation:{judgment.candidate_id}:{','.join(sorted(conflict_flags))}")
      if _misreads_related_role_as_candidate_role(candidate, judgment.supporting_factors):
        taxonomy["related_role_misread_as_candidate_role"] += 1
        errors.append(f"related_role_misread_as_candidate_role:{judgment.candidate_id}")
    ranks[judgment.rank] += 1
    for evidence_ref in judgment.evidence_refs_used:
      if allowed_evidence_refs and evidence_ref not in allowed_evidence_refs:
        taxonomy["unknown_evidence_ref"] += 1
        errors.append(f"unknown_evidence_ref:{judgment.candidate_id}:{evidence_ref}")

  for excluded in model.excluded_candidates:
    candidate = candidates.get(excluded.candidate_id)
    if candidate is None:
      invented.add(excluded.candidate_id)
      taxonomy["unknown_candidate_id"] += 1
      errors.append(f"unknown_candidate_id:{excluded.candidate_id}")
    else:
      accounted.add(excluded.candidate_id)
      if _is_release_overreach_only_reason(excluded.reason):
        taxonomy["release_overreach_only_exclusion"] += 1
        errors.append(f"release_overreach_only_exclusion:{excluded.candidate_id}")

  for rank, count in ranks.items():
    if count > 1:
      taxonomy["duplicate_rank"] += 1
      errors.append(f"duplicate_rank:{rank}")
  duplicate_accounting = _duplicate_ids([item.candidate_id for item in model.candidate_judgments] + [item.candidate_id for item in model.excluded_candidates])
  for candidate_id in duplicate_accounting:
    taxonomy["candidate_accounted_multiple_times"] += 1
    errors.append(f"candidate_accounted_multiple_times:{candidate_id}")
  for candidate_id in sorted(set(candidates) - accounted):
    taxonomy["candidate_not_accounted"] += 1
    errors.append(f"candidate_not_accounted:{candidate_id}")

  return JudgeContractResult(
    ok=not errors,
    errors=errors,
    taxonomy={key: value for key, value in taxonomy.items() if value},
    invented_candidate_ids=sorted(invented),
  )


def scan_forbidden_judge_fields(data: Any) -> dict[str, Any]:
  violations: list[dict[str, str]] = []
  for key in sorted(FORBIDDEN_JUDGE_KEYS):
    for location in _find_exact_key(data, key):
      violations.append({"key": key, "location": location})
  return {
    "ok": not violations,
    "forbidden_keys": sorted(FORBIDDEN_JUDGE_KEYS),
    "violation_count": len(violations),
    "violations": violations,
  }


def scan_forbidden_judge_output_dir(root: str | Any) -> dict[str, Any]:
  from pathlib import Path
  import json

  violations: list[dict[str, str]] = []
  for path in sorted(Path(root).rglob("*.json")):
    data = json.loads(path.read_text(encoding="utf-8"))
    scan = scan_forbidden_judge_fields(data)
    for item in scan["violations"]:
      violations.append({"path": str(path), **item})
  return {
    "ok": not violations,
    "forbidden_keys": sorted(FORBIDDEN_JUDGE_KEYS),
    "violation_count": len(violations),
    "violations": violations,
  }


def _allowed_evidence_refs(judge_input: dict[str, Any]) -> list[str]:
  refs: list[str] = []
  for item in judge_input.get("candidate_set", []) or []:
    refs.extend(str(ref) for ref in item.get("evidence_refs", []) or [])
  for item in judge_input.get("szz_evidence_cards", []) or []:
    refs.extend(str(ref) for ref in item.get("evidence_refs", []) or [])
  return sorted(set(refs))


def _explains_fallback_high_confidence(factors: list[str]) -> bool:
  text = " ".join(str(item).lower() for item in factors)
  return "fallback" in text and any(token in text for token in ("because", "despite", "although", "risk", "weak"))


def _conflicting_szz_risks(candidate: dict[str, Any]) -> set[str]:
  flags = {str(item) for item in candidate.get("risk_flags", []) or []}
  conflicts = set(flags & {"whitespace_sensitive_blame", "move_copy_sensitive_blame", "candidate_not_ancestor_of_fix"})
  if flags & {"boundary_candidate_commit", "root_candidate_commit", "merge_candidate", "candidate_is_merge_commit"}:
    conflicts |= flags & {"boundary_candidate_commit", "root_candidate_commit", "merge_candidate", "candidate_is_merge_commit"}
  return conflicts


def _explains_conflicting_szz_risk(judgment: Any, conflict_flags: set[str]) -> bool:
  considered = {str(item) for item in getattr(judgment, "risk_flags_considered", [])}
  contradicted = {str(item) for item in getattr(judgment, "contradicting_factors", [])}
  uncertainty = {str(item) for item in getattr(judgment, "uncertainty_reasons", [])}
  text = " ".join(
    str(item).lower()
    for item in [
      *getattr(judgment, "supporting_factors", []),
      *getattr(judgment, "contradicting_factors", []),
      *getattr(judgment, "risk_flags_considered", []),
      *getattr(judgment, "uncertainty_reasons", []),
    ]
  )
  if not conflict_flags <= (considered | contradicted | uncertainty):
    return False
  if not (set(getattr(judgment, "evidence_refs_used", []) or [])):
    return False
  acknowledges_conflict = any(
    token in text
    for token in (
      "conflict",
      "conflicting",
      "disagreement",
      "differs",
      "sensitive",
      "boundary",
      "merge",
      "not ancestor",
      "residual risk",
    )
  )
  evidence_reason = any(
    token in text
    for token in (
      "normal",
      "ignore-whitespace",
      "stable",
      "ancestor",
      "root cause",
      "direct old-side",
      "line survives",
      "evidence",
      "because",
      "despite",
      "although",
    )
  )
  return acknowledges_conflict and evidence_reason


def _misreads_related_role_as_candidate_role(candidate: dict[str, Any], factors: list[str]) -> bool:
  candidate_role = str(candidate.get("candidate_anchor_role") or candidate.get("anchor_role") or "")
  if candidate_role == "dangerous_use":
    return False
  related = {str(item) for item in candidate.get("related_role_features", []) or []}
  if "dangerous_use_role" not in related:
    return False
  text = " ".join(str(item).lower() for item in factors)
  return any(
    phrase in text
    for phrase in (
      "dangerous_use_role on this candidate",
      "dangerous use on this candidate",
      "this candidate is dangerous_use",
      "this candidate is a dangerous_use",
      "candidate itself is dangerous_use",
      "candidate is dangerous_use",
    )
  )


def _is_release_overreach_only_reason(reason: str) -> bool:
  normalized = " ".join(str(reason).lower().replace("-", "_").split())
  allowed = {"release_reachability_too_broad", "release line overreach", "release_line_overreach"}
  return normalized in allowed or normalized.replace(" ", "_") in allowed


def _duplicate_ids(values: list[str]) -> list[str]:
  counts = Counter(values)
  return sorted(value for value, count in counts.items() if value and count > 1)


def _find_exact_key(data: Any, key: str, path: str = "$") -> list[str]:
  matches: list[str] = []
  if isinstance(data, dict):
    for child_key, value in data.items():
      child_path = f"{path}.{child_key}"
      if child_key == key:
        matches.append(child_path)
      matches.extend(_find_exact_key(value, key, child_path))
  elif isinstance(data, list):
    for index, value in enumerate(data):
      matches.extend(_find_exact_key(value, key, f"{path}[{index}]"))
  return matches


def _taxonomy_dict(counter: Counter[str], **extra: int) -> dict[str, int]:
  output = {key: value for key, value in counter.items() if value}
  output.update({key: value for key, value in extra.items() if value})
  return output
