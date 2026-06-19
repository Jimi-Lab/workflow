from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


BoundaryRole = Literal[
  "introduction",
  "activation",
  "prerequisite",
  "fix_series_noise",
  "refactor_noise",
  "equivalent_fix_noise",
  "uncertain_boundary",
]
BoundaryDecision = Literal["selected", "rejected", "uncertain"]
BoundaryConfidence = Literal["high", "medium", "low"]


class StrictBoundaryModel(BaseModel):
  model_config = ConfigDict(extra="forbid")


class BoundaryCandidateJudgmentV1(StrictBoundaryModel):
  candidate_id: str
  candidate_commit_sha: str
  boundary_role: BoundaryRole
  decision: BoundaryDecision
  confidence: BoundaryConfidence
  evidence_refs: list[str] = Field(default_factory=list)
  reasoning_short: str

  @field_validator("candidate_id", "candidate_commit_sha", "reasoning_short")
  @classmethod
  def _non_empty(cls, value: str) -> str:
    return _required_text(value)


class SelectedBoundaryEventV1(StrictBoundaryModel):
  candidate_id: str
  candidate_commit_sha: str
  boundary_role: BoundaryRole
  evidence_refs: list[str] = Field(default_factory=list)

  @field_validator("candidate_id", "candidate_commit_sha")
  @classmethod
  def _non_empty(cls, value: str) -> str:
    return _required_text(value)


class BoundaryUncertaintyV1(StrictBoundaryModel):
  candidate_id: str | None = None
  reason: str

  @field_validator("reason")
  @classmethod
  def _reason_non_empty(cls, value: str) -> str:
    return _required_text(value)


class RejectedBoundaryCandidateV1(StrictBoundaryModel):
  candidate_id: str
  reason: str

  @field_validator("candidate_id", "reason")
  @classmethod
  def _non_empty(cls, value: str) -> str:
    return _required_text(value)


class JudgeBoundaryOutputV1(StrictBoundaryModel):
  schema_version: Literal["judge_boundary_output_v1"]
  cve_id: str
  candidate_judgments: list[BoundaryCandidateJudgmentV1] = Field(default_factory=list)
  selected_boundary_events: list[SelectedBoundaryEventV1] = Field(default_factory=list)
  uncertainty: list[BoundaryUncertaintyV1] = Field(default_factory=list)
  rejected_candidates: list[RejectedBoundaryCandidateV1] = Field(default_factory=list)

  @field_validator("cve_id")
  @classmethod
  def _non_empty(cls, value: str) -> str:
    return _required_text(value)


@dataclass(frozen=True)
class JudgeBoundaryParseResult:
  ok: bool
  output: JudgeBoundaryOutputV1 | None = None
  data: dict[str, Any] | None = None
  error: str | None = None
  empty: bool = False
  format: str = "unknown"


def parse_judge_boundary_output_v1(text: str) -> JudgeBoundaryParseResult:
  if not text or not text.strip():
    return JudgeBoundaryParseResult(ok=False, error="empty assistant message", empty=True)
  try:
    data, output_format = _extract_json_object(text)
    output = JudgeBoundaryOutputV1.model_validate(data)
    return JudgeBoundaryParseResult(ok=True, output=output, data=output.model_dump(mode="json"), format=output_format)
  except (json.JSONDecodeError, ValueError, ValidationError) as error:
    return JudgeBoundaryParseResult(ok=False, error=str(error))


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
