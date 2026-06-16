from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


EvidenceUse = Literal["priority", "prompt_context", "certificate_candidate"]
EvidenceStrength = Literal["weak", "medium", "strong"]


class VetEvidenceRef(BaseModel):
  """A local source reference for one VET evidence item."""

  source: str = ""
  ref: str = ""
  snippet: str = ""


class VetPattern(BaseModel):
  """A root-cause-level pattern that can be checked cheaply across tags."""

  pattern_id: str
  kind: Literal[
    "file",
    "function",
    "vulnerable_sequence",
    "fix_guard",
    "feature_introduction",
    "negative_condition",
    "grep_pattern",
    "git_log_sg_query",
  ]
  value: str
  scope_files: list[str] = Field(default_factory=list)
  strength: EvidenceStrength = "weak"
  allowed_uses: list[EvidenceUse] = Field(default_factory=lambda: ["priority", "prompt_context"])
  evidence: list[VetEvidenceRef] = Field(default_factory=list)
  notes: str = ""


class RootCauseVet(BaseModel):
  """Root-cause-level VET contract produced by Step2 and consumed by Step3.

  This schema deliberately separates weak priority evidence from certificate
  candidates.  Ordinary touched files and generic tokens must not be encoded as
  strong CERT_ABSENT/CERT_FIXED evidence.
  """

  cve_id: str
  repo: str = ""
  root_cause_summary: str = ""
  root_cause_files: list[VetPattern] = Field(default_factory=list)
  root_cause_functions: list[VetPattern] = Field(default_factory=list)
  vulnerable_sequences: list[VetPattern] = Field(default_factory=list)
  fix_guards: list[VetPattern] = Field(default_factory=list)
  feature_introduction_clues: list[VetPattern] = Field(default_factory=list)
  component_scope: list[VetPattern] = Field(default_factory=list)
  negative_applicability_conditions: list[VetPattern] = Field(default_factory=list)
  grep_patterns: list[VetPattern] = Field(default_factory=list)
  git_log_sg_queries: list[VetPattern] = Field(default_factory=list)
  certificate_policy: dict = Field(
    default_factory=lambda: {
      "default_use": "priority_only",
      "cert_absent_requires": [
        "strong root_cause_file/function evidence",
        "strong feature absence evidence",
      ],
      "cert_fixed_requires": [
        "strong fix_guard evidence",
        "strong vulnerable_sequence absence evidence",
      ],
    }
  )
  confidence: dict = Field(default_factory=dict)

  def priority_patterns(self) -> list[VetPattern]:
    """Return all patterns that are allowed to influence scheduling priority."""

    groups = [
      self.root_cause_files,
      self.root_cause_functions,
      self.vulnerable_sequences,
      self.fix_guards,
      self.feature_introduction_clues,
      self.component_scope,
      self.negative_applicability_conditions,
      self.grep_patterns,
      self.git_log_sg_queries,
    ]
    return [
      pattern
      for group in groups
      for pattern in group
      if "priority" in pattern.allowed_uses
    ]

  def certificate_candidates(self) -> list[VetPattern]:
    """Return patterns that are explicitly allowed to support a certificate."""

    return [
      pattern
      for pattern in self.priority_patterns()
      if "certificate_candidate" in pattern.allowed_uses
      and pattern.strength == "strong"
    ]
