from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


BoundaryRoleV12 = Literal[
  "primary_boundary",
  "branch_equivalent_boundary",
  "conjunctive_prerequisite",
  "supporting_evidence_only",
  "fix_refactor_noise",
]


class _Strict(BaseModel):
  model_config = ConfigDict(extra="forbid")


class BoundaryCandidateJudgmentV12(_Strict):
  event_candidate_id: str
  event_commit_sha: str
  boundary_role: BoundaryRoleV12
  decision: Literal["selected", "rejected", "uncertain"]
  confidence: Literal["high", "medium", "low"]
  evidence_refs: list[str] = Field(default_factory=list)
  reasoning_short: str

  @field_validator("event_candidate_id", "event_commit_sha", "reasoning_short")
  @classmethod
  def non_empty(cls, value: str) -> str:
    if not str(value).strip():
      raise ValueError("value must not be empty")
    return str(value).strip()


class JudgeBoundaryOutputV12(_Strict):
  schema_version: Literal["judge_boundary_output_v1_2"]
  cve_id: str
  candidate_judgments: list[BoundaryCandidateJudgmentV12]


@dataclass(frozen=True)
class ParseResultV12:
  ok: bool
  data: dict[str, Any] | None = None
  error: str | None = None
  format: str = "unknown"


def parse_judge_boundary_output_v1_2(text: str) -> ParseResultV12:
  if not text or not text.strip():
    return ParseResultV12(ok=False, error="empty assistant message")
  value = text.strip().lstrip("\ufeff")
  output_format = "json"
  if value.startswith("```"):
    for block in value.split("```")[1::2]:
      block = block.strip()
      if block.lower().startswith("json"):
        block = block[4:].strip()
      if block.startswith("{"):
        value = block
        output_format = "fenced_json"
        break
  try:
    start, end = value.find("{"), value.rfind("}")
    if start < 0 or end <= start:
      raise ValueError("assistant output does not contain a JSON object")
    data = json.loads(value[start:end + 1])
    model = JudgeBoundaryOutputV12.model_validate(data)
    return ParseResultV12(ok=True, data=model.model_dump(mode="json"), format=output_format)
  except (ValueError, json.JSONDecodeError, ValidationError) as error:
    return ParseResultV12(ok=False, error=str(error))
