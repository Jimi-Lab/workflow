from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator


AnchorRole = Literal[
  "dangerous_use",
  "missing_guard_target",
  "state_declaration",
  "control_predecessor",
  "data_source",
  "propagation",
  "sink",
  "cleanup_target",
  "callback_registration",
  "recursion_entry",
]

SelectionMode = Literal[
  "direct_deleted_line",
  "modified_old_side",
  "add_only_semantic_target",
  "context_fallback",
]

CandidateSource = Literal[
  "deleted_line",
  "hunk_context",
  "pre_fix_function_body",
]


class StrictSzzHandoffModel(BaseModel):
  model_config = ConfigDict(extra="forbid")


class SzzAgentRunV1(StrictSzzHandoffModel):
  run_id: str
  cve_id: str
  backend: str

  @field_validator("run_id", "cve_id", "backend")
  @classmethod
  def _non_empty(cls, value: str) -> str:
    return _required_text(value)


class PreFixLineCandidateV1(StrictSzzHandoffModel):
  candidate_id: str
  cve_id: str
  repo_id: str
  fix_set_id: str
  patch_family_id: str
  fix_commit_id: str
  fix_commit_sha: str
  parent_sha: str
  patch_hunk_id: str
  path_before: str
  path_after: str | None = None
  old_line_start: int = Field(ge=1)
  old_line_end: int = Field(ge=1)
  line_text: str
  line_text_sha256: str
  function_id: str | None = None
  function_name: str | None = None
  candidate_source: CandidateSource
  change_type: Literal["delete", "modify", "add_only", "rename"]
  selection_mode_eligibility: list[SelectionMode] = Field(default_factory=list)
  git_observation_refs: list[str] = Field(default_factory=list)
  generated_file: bool = False
  test_file: bool = False
  documentation_file: bool = False
  changelog_file: bool = False
  comment_only: bool = False
  blank_line: bool = False
  source_file: bool = True
  exclusion_reasons: list[str] = Field(default_factory=list)

  @field_validator(
    "candidate_id",
    "cve_id",
    "repo_id",
    "fix_set_id",
    "patch_family_id",
    "fix_commit_id",
    "fix_commit_sha",
    "parent_sha",
    "patch_hunk_id",
    "path_before",
    "line_text_sha256",
  )
  @classmethod
  def _non_empty(cls, value: str) -> str:
    return _required_text(value)

  @model_validator(mode="after")
  def _single_parent_side_line(self) -> "PreFixLineCandidateV1":
    if self.old_line_start != self.old_line_end:
      raise ValueError("PreFixLineCandidateV1 must identify exactly one single parent-side line")
    return self


class PreFixCandidateInventoryV1(StrictSzzHandoffModel):
  cve_id: str
  repo_id: str
  repo_path: str
  candidates: list[PreFixLineCandidateV1] = Field(default_factory=list)
  fix_families: dict[str, list[str]] = Field(default_factory=dict)
  issues: list[str] = Field(default_factory=list)
  git_trace: list[dict[str, Any]] = Field(default_factory=list)


class SelectedPreFixAnchorV1(StrictSzzHandoffModel):
  candidate_id: str
  role: AnchorRole
  root_cause_hypothesis_ids: list[str] = Field(min_length=1)
  predicate_ids: list[str] = Field(min_length=1)
  rationale: str
  confidence: float = Field(ge=0.0, le=1.0)

  @field_validator("candidate_id", "rationale")
  @classmethod
  def _non_empty(cls, value: str) -> str:
    return _required_text(value)


class UncertaintyItemV1(StrictSzzHandoffModel):
  patch_family_id: str
  fix_commit_id: str
  reason_code: str
  detail: str

  @field_validator("patch_family_id", "fix_commit_id", "reason_code", "detail")
  @classmethod
  def _non_empty(cls, value: str) -> str:
    return _required_text(value)


class RootCauseSzzHandoffV1(StrictSzzHandoffModel):
  agent_run: SzzAgentRunV1
  failure_mode: str
  trigger: str
  violated_invariant: str
  vulnerable_state: str
  propagation: list[str] = Field(default_factory=list)
  sink: str
  fix_mechanism: str
  selected_anchors: list[SelectedPreFixAnchorV1] = Field(default_factory=list)
  excluded_hunk_ids: list[str] = Field(default_factory=list)
  uncertainty_items: list[UncertaintyItemV1] = Field(default_factory=list)


class ResolvedPreFixAnchorV1(StrictSzzHandoffModel):
  anchor_id: str
  candidate_id: str
  cve_id: str
  fix_set_id: str
  patch_family_id: str
  fix_commit_id: str
  fix_commit_sha: str
  parent_sha: str
  patch_hunk_id: str
  path_before: str
  path_after: str | None = None
  old_line_start: int = Field(ge=1)
  old_line_end: int = Field(ge=1)
  line_text: str
  line_text_sha256: str
  function_id: str | None = None
  function_name: str | None = None
  candidate_source: CandidateSource
  role: AnchorRole
  selection_mode: SelectionMode
  root_cause_hypothesis_ids: list[str] = Field(min_length=1)
  predicate_ids: list[str] = Field(min_length=1)
  git_observation_refs: list[str] = Field(default_factory=list)
  rationale: str
  confidence: float = Field(ge=0.0, le=1.0)
  lifecycle: Literal["raw_candidate"] = "raw_candidate"
  uncertainty_reasons: list[str] = Field(default_factory=list)
  exclusion_reasons: list[str] = Field(default_factory=list)


@dataclass(frozen=True)
class SzzAnchorSelectionParseResult:
  ok: bool
  output: RootCauseSzzHandoffV1 | None = None
  data: dict[str, Any] | None = None
  error: str | None = None
  empty: bool = False
  format: str = "unknown"


def parse_szz_anchor_selection(text: str) -> SzzAnchorSelectionParseResult:
  if not text or not text.strip():
    return SzzAnchorSelectionParseResult(
      ok=False,
      error="empty assistant message",
      empty=True,
    )
  try:
    data, output_format = _extract_json_object(text)
    output = RootCauseSzzHandoffV1.model_validate(data)
    return SzzAnchorSelectionParseResult(
      ok=True,
      output=output,
      data=output.model_dump(mode="json"),
      format=output_format,
    )
  except (json.JSONDecodeError, ValueError, ValidationError) as error:
    return SzzAnchorSelectionParseResult(ok=False, error=str(error))


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
