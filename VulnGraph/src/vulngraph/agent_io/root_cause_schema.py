from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, ValidationError, model_validator


class StrictRootCauseModel(BaseModel):
  model_config = ConfigDict(extra="forbid", populate_by_name=True)


class RootCauseAgentRunV2(StrictRootCauseModel):
  run_id: str
  cve_id: str
  backend: str


class RootCauseCodeAnchorV2(StrictRootCauseModel):
  anchor_id: str = Field(validation_alias=AliasChoices("anchor_id", "id"))
  id: str | None = None
  fix_commit_id: str | None = None
  patch_hunk_id: str | None = None
  file_id: str | None = None
  path: str
  function_id: str | None = None
  function: str | None = Field(default=None, validation_alias=AliasChoices("function", "function_name"))
  function_name: str | None = None
  line_start: int | None = Field(default=None, ge=1)
  line_end: int | None = Field(default=None, ge=1)
  line_range: list[int] | None = None
  pattern: str | None = None
  git_observation_refs: list[str] = Field(default_factory=list)
  confidence: float = Field(default=0.5, ge=0.0, le=1.0)

  @model_validator(mode="before")
  @classmethod
  def _reject_conflicting_aliases(cls, value: Any) -> Any:
    if not isinstance(value, dict):
      return value
    _require_alias_match(value, "anchor_id", "id")
    _require_alias_match(value, "function", "function_name")
    if value.get("line_range") is not None:
      line_range = value.get("line_range")
      if not isinstance(line_range, list) or len(line_range) != 2:
        raise ValueError("line_range must contain exactly [line_start, line_end]")
      if value.get("line_start") is not None and value.get("line_start") != line_range[0]:
        raise ValueError("alias conflict: line_start does not match line_range[0]")
      if value.get("line_end") is not None and value.get("line_end") != line_range[1]:
        raise ValueError("alias conflict: line_end does not match line_range[1]")
    return value

  @model_validator(mode="after")
  def _normalize_line_range_and_function_name(self) -> "RootCauseCodeAnchorV2":
    if self.line_range and len(self.line_range) >= 2:
      if self.line_start is None:
        self.line_start = self.line_range[0]
      if self.line_end is None:
        self.line_end = self.line_range[1]
    if self.function is None and self.function_name:
      self.function = self.function_name
    self.anchor_id = _non_empty_identifier(self.anchor_id, "anchor_id")
    return self


class RootCausePredicateV2(StrictRootCauseModel):
  predicate_id: str = Field(validation_alias=AliasChoices("predicate_id", "id"))
  id: str | None = None
  description: str = Field(validation_alias=AliasChoices("description", "statement"))
  statement: str | None = None
  anchor_ids: list[str] = Field(default_factory=list, validation_alias=AliasChoices("anchor_ids", "code_anchor_ids"))
  code_anchor_ids: list[str] | None = None
  git_observation_refs: list[str] = Field(default_factory=list)
  confidence: float = Field(default=0.5, ge=0.0, le=1.0)

  @model_validator(mode="before")
  @classmethod
  def _reject_conflicting_aliases(cls, value: Any) -> Any:
    if not isinstance(value, dict):
      return value
    _require_alias_match(value, "predicate_id", "id")
    _require_alias_match(value, "description", "statement")
    _require_alias_match(value, "anchor_ids", "code_anchor_ids")
    return value

  @model_validator(mode="after")
  def _normalize_contract_aliases(self) -> "RootCausePredicateV2":
    if not self.anchor_ids and self.code_anchor_ids:
      self.anchor_ids = self.code_anchor_ids
    if not self.description and self.statement:
      self.description = self.statement
    self.predicate_id = _non_empty_identifier(self.predicate_id, "predicate_id")
    return self


class RootCauseHypothesisV2(StrictRootCauseModel):
  hypothesis_id: str = Field(validation_alias=AliasChoices("hypothesis_id", "id"))
  id: str | None = None
  summary: str
  mechanism: str = ""
  fix_commit_ids: list[str] = Field(default_factory=list)
  fix_set_ids: list[str] = Field(default_factory=list)
  vulnerable_predicate_ids: list[str] = Field(default_factory=list)
  fix_predicate_ids: list[str] = Field(default_factory=list)
  guard_condition_ids: list[str] = Field(default_factory=list)
  negative_condition_ids: list[str] = Field(default_factory=list)
  anchor_ids: list[str] = Field(default_factory=list, validation_alias=AliasChoices("anchor_ids", "code_anchor_ids"))
  code_anchor_ids: list[str] | None = None
  git_observation_refs: list[str] = Field(default_factory=list)
  confidence: float = Field(default=0.5, ge=0.0, le=1.0)

  @model_validator(mode="before")
  @classmethod
  def _reject_conflicting_aliases(cls, value: Any) -> Any:
    if not isinstance(value, dict):
      return value
    _require_alias_match(value, "hypothesis_id", "id")
    _require_alias_match(value, "anchor_ids", "code_anchor_ids")
    return value

  @model_validator(mode="after")
  def _normalize_contract_aliases(self) -> "RootCauseHypothesisV2":
    if not self.anchor_ids and self.code_anchor_ids:
      self.anchor_ids = self.code_anchor_ids
    self.hypothesis_id = _non_empty_identifier(self.hypothesis_id, "hypothesis_id")
    return self


class RootCauseUncertaintyV2(StrictRootCauseModel):
  reason_id: str
  reason: str
  git_observation_refs: list[str] = Field(default_factory=list)


class RootCauseLearnedCandidateV2(StrictRootCauseModel):
  candidate_id: str
  memory_type: str
  hint: str
  scope: str = "cve"


class RootCauseRiskFlagV2(StrictRootCauseModel):
  risk_id: str
  description: str
  git_observation_refs: list[str] = Field(default_factory=list)


class RootCauseAgentOutputV2(StrictRootCauseModel):
  agent_run: RootCauseAgentRunV2
  root_cause_hypotheses: list[RootCauseHypothesisV2] = Field(min_length=1)
  vulnerable_predicates: list[RootCausePredicateV2] = Field(default_factory=list)
  fix_predicates: list[RootCausePredicateV2] = Field(default_factory=list)
  guard_conditions: list[RootCausePredicateV2] = Field(default_factory=list)
  negative_conditions: list[RootCausePredicateV2] = Field(default_factory=list)
  code_anchors: list[RootCauseCodeAnchorV2] = Field(default_factory=list)
  git_observation_refs: list[str] = Field(default_factory=list)
  uncertainty_reasons: list[RootCauseUncertaintyV2] = Field(default_factory=list)
  learned_candidates: list[RootCauseLearnedCandidateV2] = Field(default_factory=list)
  risk_flags: list[RootCauseRiskFlagV2] = Field(default_factory=list)

  @model_validator(mode="after")
  def _references_exist(self) -> "RootCauseAgentOutputV2":
    semantic_ids = [
      *(item.hypothesis_id for item in self.root_cause_hypotheses),
      *(item.anchor_id for item in self.code_anchors),
      *(item.predicate_id for item in self.vulnerable_predicates),
      *(item.predicate_id for item in self.fix_predicates),
      *(item.predicate_id for item in self.guard_conditions),
      *(item.predicate_id for item in self.negative_conditions),
    ]
    duplicates = sorted({item_id for item_id in semantic_ids if semantic_ids.count(item_id) > 1})
    if duplicates:
      raise ValueError(f"duplicate semantic IDs: {duplicates}")
    anchors = {item.anchor_id for item in self.code_anchors}
    vulnerable = {item.predicate_id for item in self.vulnerable_predicates}
    fixes = {item.predicate_id for item in self.fix_predicates}
    guards = {item.predicate_id for item in self.guard_conditions}
    negatives = {item.predicate_id for item in self.negative_conditions}
    for predicate in (*self.vulnerable_predicates, *self.fix_predicates, *self.guard_conditions, *self.negative_conditions):
      missing = set(predicate.anchor_ids) - anchors
      if missing:
        raise ValueError(f"unknown anchor_ids: {sorted(missing)}")
    for hypothesis in self.root_cause_hypotheses:
      checks = (
        (hypothesis.anchor_ids, anchors, "anchor_ids"),
        (hypothesis.vulnerable_predicate_ids, vulnerable, "vulnerable_predicate_ids"),
        (hypothesis.fix_predicate_ids, fixes, "fix_predicate_ids"),
        (hypothesis.guard_condition_ids, guards, "guard_condition_ids"),
        (hypothesis.negative_condition_ids, negatives, "negative_condition_ids"),
      )
      for values, known, field_name in checks:
        missing = set(values) - known
        if missing:
          raise ValueError(f"unknown {field_name}: {sorted(missing)}")
    return self


def root_cause_agent_output_schema() -> dict[str, Any]:
  """Return the generation contract without parser-only compatibility aliases."""
  schema = copy.deepcopy(RootCauseAgentOutputV2.model_json_schema())
  compatibility_aliases = {"id", "code_anchor_ids", "function_name", "line_range", "statement"}

  def remove_aliases(value: Any) -> None:
    if isinstance(value, dict):
      properties = value.get("properties")
      if isinstance(properties, dict):
        for alias in compatibility_aliases:
          properties.pop(alias, None)
      required = value.get("required")
      if isinstance(required, list):
        value["required"] = [field for field in required if field not in compatibility_aliases]
      for child in value.values():
        remove_aliases(child)
    elif isinstance(value, list):
      for child in value:
        remove_aliases(child)

  remove_aliases(schema)
  return schema


def _require_alias_match(value: dict[str, Any], primary: str, alias: str) -> None:
  if primary not in value or alias not in value:
    return
  primary_value = value.get(primary)
  alias_value = value.get(alias)
  if primary_value is None or alias_value is None:
    return
  if primary_value != alias_value:
    raise ValueError(f"alias conflict: {primary} and {alias} must be identical")


def _non_empty_identifier(value: str, field_name: str) -> str:
  normalized = str(value).strip()
  if not normalized:
    raise ValueError(f"{field_name} must not be empty")
  return normalized


@dataclass(frozen=True)
class RootCauseParseResult:
  ok: bool
  output: RootCauseAgentOutputV2 | None = None
  data: dict[str, Any] | None = None
  error: str | None = None
  empty: bool = False
  format: str = "unknown"


def parse_root_cause_output(text: str) -> RootCauseParseResult:
  if not text or not text.strip():
    return RootCauseParseResult(ok=False, error="empty assistant message", empty=True)
  try:
    data, output_format = _extract_json_object(text)
    output = RootCauseAgentOutputV2.model_validate(data)
    return RootCauseParseResult(ok=True, output=output, data=output.model_dump(mode="json"), format=output_format)
  except (json.JSONDecodeError, ValueError, ValidationError) as error:
    return RootCauseParseResult(ok=False, error=str(error), empty=False)


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
