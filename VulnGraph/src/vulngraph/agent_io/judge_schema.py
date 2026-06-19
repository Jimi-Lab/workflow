from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


CaseDisposition = Literal["ranked", "uncertain", "insufficient_evidence"]
BoundaryJudgment = Literal["plausible_introduction_boundary", "unlikely_boundary", "uncertain_boundary"]
JudgeConfidence = Literal["high", "medium", "low"]


class StrictJudgeModel(BaseModel):
  model_config = ConfigDict(extra="forbid")


class JudgeCandidateJudgmentV0(StrictJudgeModel):
  candidate_id: str
  candidate_commit_sha: str
  rank: int = Field(ge=1)
  judgment: BoundaryJudgment
  confidence: JudgeConfidence
  evidence_refs_used: list[str] = Field(default_factory=list)
  supporting_factors: list[str] = Field(default_factory=list)
  contradicting_factors: list[str] = Field(default_factory=list)
  risk_flags_considered: list[str] = Field(default_factory=list)
  uncertainty_reasons: list[str] = Field(default_factory=list)

  @field_validator("candidate_id", "candidate_commit_sha", "judgment", "confidence")
  @classmethod
  def _non_empty(cls, value: str) -> str:
    return _required_text(value)


class JudgeExcludedCandidateV0(StrictJudgeModel):
  candidate_id: str
  reason: str

  @field_validator("candidate_id", "reason")
  @classmethod
  def _non_empty(cls, value: str) -> str:
    return _required_text(value)


class JudgeNotesV0(StrictJudgeModel):
  attack_perspective_used: bool
  root_cause_binding_used: bool
  szz_evidence_used: bool
  version_conversion_not_performed: bool


class JudgeOutputV0(StrictJudgeModel):
  schema_version: Literal["judge_output_v0"]
  cve_id: str
  case_disposition: CaseDisposition
  candidate_judgments: list[JudgeCandidateJudgmentV0] = Field(default_factory=list)
  excluded_candidates: list[JudgeExcludedCandidateV0] = Field(default_factory=list)
  judge_notes: JudgeNotesV0

  @field_validator("cve_id")
  @classmethod
  def _non_empty(cls, value: str) -> str:
    return _required_text(value)


@dataclass(frozen=True)
class JudgeOutputParseResult:
  ok: bool
  output: JudgeOutputV0 | None = None
  data: dict[str, Any] | None = None
  error: str | None = None
  empty: bool = False
  format: str = "unknown"


def parse_judge_output_v0(text: str) -> JudgeOutputParseResult:
  if not text or not text.strip():
    return JudgeOutputParseResult(ok=False, error="empty assistant message", empty=True)
  try:
    data, output_format = _extract_json_object(text)
    output = JudgeOutputV0.model_validate(data)
    return JudgeOutputParseResult(
      ok=True,
      output=output,
      data=output.model_dump(mode="json"),
      format=output_format,
    )
  except (json.JSONDecodeError, ValueError, ValidationError) as error:
    return JudgeOutputParseResult(ok=False, error=str(error))


def _extract_json_object(text: str) -> tuple[dict[str, Any], str]:
  candidate = text.strip()
  output_format = "json"
  if candidate.startswith("```"):
    blocks = candidate.split("```")
    for block in blocks[1::2]:
      block = block.strip()
      if block.lower().startswith("json"):
        block = block[4:].strip()
      if block.startswith("{"):
        candidate = block
        output_format = "fenced_json"
        break
  first = candidate.find("{")
  last = candidate.rfind("}")
  if first < 0 or last <= first:
    raise ValueError("assistant output does not contain a JSON object")
  parsed = json.loads(candidate[first : last + 1])
  if not isinstance(parsed, dict):
    raise ValueError("assistant output must be a JSON object")
  return parsed, output_format


def _required_text(value: str) -> str:
  normalized = str(value).strip()
  if not normalized:
    raise ValueError("value must not be empty")
  return normalized
