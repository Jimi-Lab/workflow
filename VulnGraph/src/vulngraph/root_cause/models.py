from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from vulngraph.agent_io.models import AgentCommandInvocation, AgentLearnedCandidate


class _StrictModel(BaseModel):
  model_config = ConfigDict(extra="forbid")


class RootCauseRunPayload(_StrictModel):
  run_id: str
  cve_id: str
  repo: str
  repo_path: str
  backend: str = "opencode"


class RootCauseCodeAnchor(_StrictModel):
  anchor_id: str
  path: str
  symbol: str | None = None
  tokens: list[str] = Field(default_factory=list)
  line_start: int | None = Field(default=None, ge=1)
  line_end: int | None = Field(default=None, ge=1)
  command_refs: list[str] = Field(default_factory=list)
  confidence: float = Field(ge=0.0, le=1.0)


class RootCausePredicate(_StrictModel):
  predicate_id: str
  description: str
  anchor_ids: list[str] = Field(default_factory=list)
  command_refs: list[str] = Field(default_factory=list)
  confidence: float = Field(ge=0.0, le=1.0)


class RootCauseRiskFlag(_StrictModel):
  risk_flag_id: str
  kind: Literal[
    "incomplete_patch",
    "refactor_noise",
    "multi_commit_fix",
    "missing_parent",
    "ambiguous_causality",
    "generated_or_vendor_code",
    "other",
  ]
  description: str
  command_refs: list[str] = Field(default_factory=list)
  confidence: float = Field(ge=0.0, le=1.0)


class RootCauseHypothesis(_StrictModel):
  hypothesis_id: str
  summary: str
  mechanism: str
  scope_files: list[str] = Field(default_factory=list)
  scope_functions: list[str] = Field(default_factory=list)
  vulnerable_predicate_ids: list[str] = Field(default_factory=list)
  fix_predicate_ids: list[str] = Field(default_factory=list)
  guard_condition_ids: list[str] = Field(default_factory=list)
  negative_condition_ids: list[str] = Field(default_factory=list)
  risk_flag_ids: list[str] = Field(default_factory=list)
  command_refs: list[str] = Field(default_factory=list)
  confidence: float = Field(ge=0.0, le=1.0)


class RootCauseAgentOutput(_StrictModel):
  agent_run: RootCauseRunPayload
  command_invocations: list[AgentCommandInvocation] = Field(default_factory=list)
  code_anchors: list[RootCauseCodeAnchor] = Field(default_factory=list)
  vulnerable_predicates: list[RootCausePredicate] = Field(default_factory=list)
  fix_predicates: list[RootCausePredicate] = Field(default_factory=list)
  guard_conditions: list[RootCausePredicate] = Field(default_factory=list)
  negative_applicability_conditions: list[RootCausePredicate] = Field(default_factory=list)
  root_cause_hypotheses: list[RootCauseHypothesis] = Field(min_length=1)
  risk_flags: list[RootCauseRiskFlag] = Field(default_factory=list)
  learned_candidates: list[AgentLearnedCandidate] = Field(default_factory=list)

  @model_validator(mode="after")
  def _references_exist(self) -> "RootCauseAgentOutput":
    commands = {item.invocation_id for item in self.command_invocations}
    anchors = {item.anchor_id for item in self.code_anchors}
    vulnerable = {item.predicate_id for item in self.vulnerable_predicates}
    fixes = {item.predicate_id for item in self.fix_predicates}
    guards = {item.predicate_id for item in self.guard_conditions}
    negatives = {item.predicate_id for item in self.negative_applicability_conditions}
    risks = {item.risk_flag_id for item in self.risk_flags}

    referenced_commands: set[str] = set()
    for item in (
      *self.code_anchors,
      *self.vulnerable_predicates,
      *self.fix_predicates,
      *self.guard_conditions,
      *self.negative_applicability_conditions,
      *self.root_cause_hypotheses,
      *self.risk_flags,
    ):
      referenced_commands.update(item.command_refs)
    missing_commands = referenced_commands - commands
    if missing_commands:
      raise ValueError(f"unknown command_refs: {sorted(missing_commands)}")

    for predicate in (
      *self.vulnerable_predicates,
      *self.fix_predicates,
      *self.guard_conditions,
      *self.negative_applicability_conditions,
    ):
      missing = set(predicate.anchor_ids) - anchors
      if missing:
        raise ValueError(f"unknown anchor_ids: {sorted(missing)}")

    for hypothesis in self.root_cause_hypotheses:
      checks = (
        (hypothesis.vulnerable_predicate_ids, vulnerable, "vulnerable_predicate_ids"),
        (hypothesis.fix_predicate_ids, fixes, "fix_predicate_ids"),
        (hypothesis.guard_condition_ids, guards, "guard_condition_ids"),
        (hypothesis.negative_condition_ids, negatives, "negative_condition_ids"),
        (hypothesis.risk_flag_ids, risks, "risk_flag_ids"),
      )
      for values, known, field_name in checks:
        missing = set(values) - known
        if missing:
          raise ValueError(f"unknown {field_name}: {sorted(missing)}")
    return self
