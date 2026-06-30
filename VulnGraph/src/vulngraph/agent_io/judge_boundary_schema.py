from __future__ import annotations

import json
import re
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
]
BoundaryDecision = Literal["selected", "rejected", "uncertain"]
BoundaryConfidence = Literal["high", "medium", "low"]


class StrictBoundaryModel(BaseModel):
  model_config = ConfigDict(extra="forbid")


class BoundaryCandidateJudgmentV11(StrictBoundaryModel):
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


class JudgeBoundaryOutputV11(StrictBoundaryModel):
  schema_version: Literal["judge_boundary_output_v1_1"]
  cve_id: str
  candidate_judgments: list[BoundaryCandidateJudgmentV11] = Field(default_factory=list)

  @field_validator("cve_id")
  @classmethod
  def _non_empty(cls, value: str) -> str:
    return _required_text(value)


# Compatibility aliases keep existing service imports stable while enforcing v1.1.
BoundaryCandidateJudgmentV1 = BoundaryCandidateJudgmentV11
JudgeBoundaryOutputV1 = JudgeBoundaryOutputV11


@dataclass(frozen=True)
class JudgeBoundaryParseResult:
  ok: bool
  output: JudgeBoundaryOutputV11 | None = None
  data: dict[str, Any] | None = None
  error: str | None = None
  empty: bool = False
  format: str = "unknown"


def parse_judge_boundary_output_v1(text: str) -> JudgeBoundaryParseResult:
  if not text or not text.strip():
    return JudgeBoundaryParseResult(ok=False, error="empty assistant message", empty=True)
  try:
    candidate, output_format = _extract_json_text(text)
    try:
      data = json.loads(candidate)
    except json.JSONDecodeError:
      repaired = _repair_json_syntax(candidate)
      if repaired == candidate:
        raise
      data = json.loads(repaired)
      output_format = "deterministic_repair_json"
    if not isinstance(data, dict):
      raise ValueError("assistant output must be a JSON object")
    output = JudgeBoundaryOutputV11.model_validate(data)
    return JudgeBoundaryParseResult(ok=True, output=output, data=output.model_dump(mode="json"), format=output_format)
  except (json.JSONDecodeError, ValueError, ValidationError) as error:
    return JudgeBoundaryParseResult(ok=False, error=str(error))


def _extract_json_text(text: str) -> tuple[str, str]:
  candidate = text.strip().lstrip("﻿")
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
  return candidate[first : last + 1], output_format


def _repair_json_syntax(candidate: str) -> str:
  """Repair punctuation-only JSON defects without inventing semantic fields."""
  return re.sub(r",\s*([}\]])", r"\1", candidate)


def _required_text(value: str) -> str:
  normalized = str(value).strip()
  if not normalized:
    raise ValueError("value must not be empty")
  return normalized
