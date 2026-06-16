from __future__ import annotations

from pydantic import BaseModel, Field

from .vet_schema import RootCauseVet


class ConfidenceComponents(BaseModel):
  align_patch_cve: float = 0.0
  discriminative_power: float = 0.0
  guard_strength: float = 0.0
  robustness: float = 0.0


class Confidence(BaseModel):
  total: float = 0.0
  components: ConfidenceComponents = Field(default_factory=ConfidenceComponents)


class RCIAnchor(BaseModel):
  file_paths: list[str] = Field(default_factory=list)
  function_names: list[str] = Field(default_factory=list)
  stable_tokens: list[str] = Field(default_factory=list)
  context_window: int = 50
  fuzzy_rules: dict = Field(default_factory=dict)
  # Cross-version anchor support (Stage 3 Hybrid Anchor Relocation)
  alternative_tokens: list[str] = Field(default_factory=list)


class RCIPredicate(BaseModel):
  id: str
  kind: str
  args: dict
  scope: dict = Field(default_factory=dict)
  evidence: list[dict] = Field(default_factory=list)


class RCIModel(BaseModel):
  cve_id: str
  fix_commit: str
  vuln_commit: str
  related_chunks: list[str] = Field(default_factory=list)
  anchor: RCIAnchor = Field(default_factory=RCIAnchor)
  # Cross-version anchor: paths/names at vuln_commit (may differ from fix_commit for old versions)
  anchor_at_vuln: RCIAnchor = Field(default_factory=RCIAnchor)
  # Known file renames between vuln_commit and current versions
  known_renames: list[dict] = Field(default_factory=list)
  root_cause: dict = Field(default_factory=dict)
  root_cause_vet: RootCauseVet = Field(default_factory=lambda: RootCauseVet(cve_id=""))
  vuln_predicates: list[RCIPredicate] = Field(default_factory=list)
  fix_predicates: list[RCIPredicate] = Field(default_factory=list)
  guards: list[RCIPredicate] = Field(default_factory=list)
  trigger_conditions: dict = Field(default_factory=dict)
  patch_logic: dict = Field(default_factory=dict)
  evidence_pack: list[dict] = Field(default_factory=list)
  confidence: Confidence = Field(default_factory=Confidence)
  self_checks: dict = Field(default_factory=dict)
  metadata: dict = Field(default_factory=dict)
