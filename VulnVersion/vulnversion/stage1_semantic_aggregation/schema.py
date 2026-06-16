from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class Chunk(BaseModel):
  chunk_id: str
  file_path: str
  hunk_header: str
  source_commit: str | None = None
  removed: list[str] = Field(default_factory=list)
  added: list[str] = Field(default_factory=list)


class ChunkRole(BaseModel):
  chunk_id: str
  role: str
  uncertainty: str | None = None
  evidence_refs: list[dict] = Field(default_factory=list)
  reasoning_summary: str | None = None


class PatchSemantics(BaseModel):
  cve_id: str
  repo_path: str
  fix_commit: str
  fix_commits: list[str] = Field(default_factory=list)
  all_chunks: list[Chunk] = Field(default_factory=list)
  chunk_roles: list[ChunkRole] = Field(default_factory=list)
  rci_relevant_chunks: list[str] = Field(default_factory=list)
  excluded_chunks: list[dict] = Field(default_factory=list)
  aggregation_confidence: float = 0.0
  dataset_record: dict | None = None


EvidenceKind = Literal[
  "git_diff",
  "git_show",
  "git_log",
  "git_grep",
  "nvd_description",
  "cvss",
  "commit_message",
]
EvidenceStrength = Literal["weak", "medium", "strong"]
DiffLineChangeType = Literal["added", "removed", "context"]


class EvidenceRef(BaseModel):
  schema_version: str = "evidence_ref.v1"
  ref_id: str
  kind: EvidenceKind
  change_type: DiffLineChangeType | None = None
  commit: str | None = None
  parent_commit: str | None = None
  file_path: str | None = None
  function_context: str | None = None
  hunk_header: str | None = None
  line_start: int | None = None
  line_end: int | None = None
  old_line_no: int | None = None
  new_line_no: int | None = None
  snippet: str = ""
  snippet_hash: str = ""
  strength_hint: EvidenceStrength = "weak"


CommitRole = Literal[
  "primary_fix",
  "backport_equivalent",
  "component_fix",
  "possible_composite_fix",
  "wrapper_or_merge",
  "test_doc_only",
  "changelog_only",
  "refactor_noise",
  "unknown",
]
PatchType = Literal["add_only", "del_only", "mixed", "empty_or_merge"]


class CommitSemantics(BaseModel):
  schema_version: str = "commit_semantics.v1"
  cve_id: str
  repo: str
  commit: str
  role: CommitRole = "unknown"
  patch_type: PatchType = "empty_or_merge"
  diff_extraction_mode: str = "default"
  parent_count: int = 0
  changed_files: list[str] = Field(default_factory=list)
  source_files: list[str] = Field(default_factory=list)
  test_files: list[str] = Field(default_factory=list)
  doc_files: list[str] = Field(default_factory=list)
  build_files: list[str] = Field(default_factory=list)
  hunk_count: int = 0
  security_relevant_hunk_count: int = 0
  message_signals: list[str] = Field(default_factory=list)
  risk_flags: list[str] = Field(default_factory=list)
  confidence: float = 0.0
  source_refs: list[EvidenceRef] = Field(default_factory=list)


ChunkRoleV1 = Literal[
  "primary_fix",
  "supporting_fix",
  "contextual_change",
  "unrelated",
  "test_or_doc",
  "refactor_noise",
  "unknown",
  "unknown_agent_failed",
]
FileRole = Literal["source", "test", "doc", "build", "generated", "unknown"]


class ChunkSemantics(BaseModel):
  schema_version: str = "chunk_semantics.v1"
  cve_id: str
  repo: str
  chunk_id: str
  commit: str
  file_path: str
  function_context: str | None = None
  line_start: int | None = None
  line_end: int | None = None
  local_window_key: str | None = None
  patch_type: PatchType = "empty_or_merge"
  file_role: FileRole = "unknown"
  chunk_role: ChunkRoleV1 = "unknown"
  root_cause_likelihood: float = 0.0
  fix_guard_likelihood: float = 0.0
  vulnerable_sequence_likelihood: float = 0.0
  evidence_refs: list[dict] = Field(default_factory=list)
  source_refs: list[EvidenceRef] = Field(default_factory=list)
  reasoning_summary: str = ""
  risk_flags: list[str] = Field(default_factory=list)


RegionRole = Literal[
  "primary_root_cause_region",
  "supporting_fix_region",
  "context_region",
  "noise_region",
  "unknown_region",
  "unknown_agent_failed",
]
AllowedDownstreamUse = Literal[
  "prompt_context",
  "vet_candidate",
  "priority_signal",
  "certificate_candidate",
]
RootCauseRelation = Literal[
  "missing_guard",
  "unsafe_operation",
  "bounds_check",
  "null_check",
  "state_validation",
  "type_confusion",
  "integer_overflow",
  "parser_state",
  "memory_lifetime",
  "permission_check",
  "component_exposure",
  "unknown",
]


class SemanticRegion(BaseModel):
  schema_version: str = "semantic_region.v1"
  cve_id: str
  repo: str
  region_id: str
  commits: list[str] = Field(default_factory=list)
  file_path: str
  function_context: str | None = None
  line_start: int | None = None
  line_end: int | None = None
  local_window_key: str | None = None
  chunk_ids: list[str] = Field(default_factory=list)
  compression_input_chunks: int = 0
  compression_ratio: float | None = None
  patch_type: PatchType = "empty_or_merge"
  file_role: FileRole = "unknown"
  removed_critical_sequence: list[str] = Field(default_factory=list)
  added_guard_sequence: list[str] = Field(default_factory=list)
  nearby_dangerous_operation: list[str] = Field(default_factory=list)
  data_or_control_flow_hint: list[str] = Field(default_factory=list)
  root_cause_score: float = 0.0
  score_reasons: list[str] = Field(default_factory=list)
  evidence_strength: EvidenceStrength = "weak"
  allowed_downstream_use: list[AllowedDownstreamUse] = Field(default_factory=list)
  region_role: RegionRole = "unknown_region"
  root_cause_relation: RootCauseRelation = "unknown"
  risk_flags: list[str] = Field(default_factory=list)
  source_refs: list[EvidenceRef] = Field(default_factory=list)


FamilySemantics = Literal[
  "single_fix",
  "or_backport_bundle",
  "component_parallel_fix",
  "possible_composite_fix",
  "mixed_noise",
]


class FixFamilySemantics(BaseModel):
  schema_version: str = "fix_family_semantics.v1"
  cve_id: str
  repo: str
  primary_fix_commit: str
  fix_commits: list[str] = Field(default_factory=list)
  commit_groups: list[dict] = Field(default_factory=list)
  family_semantics: FamilySemantics = "single_fix"
  risk_flags: list[str] = Field(default_factory=list)
  confidence: float = 0.0


Step1Mode = Literal["agent_refined", "deterministic_only"]


class Step1QualityReport(BaseModel):
  schema_version: str = "step1_quality_report.v1"
  cve_id: str
  repo: str
  mode: Step1Mode = "agent_refined"
  deterministic_complete: bool = False
  schema_reload_passed: bool = False
  hard_deletion_count: int = 0
  agent_failure_to_noise_count: int = 0
  patch_chunk_count: int = 0
  semantic_region_count: int = 0
  compression_ratio: float | None = None
  packet_too_large_count: int = 0
  missing_context_fields: list[str] = Field(default_factory=list)
  risk_flags: list[str] = Field(default_factory=list)
  artifact_paths: dict[str, str] = Field(default_factory=dict)


class RegionRefinementResult(BaseModel):
  schema_version: str = "step1_region_refinement_result.v1"
  cve_id: str
  repo: str
  packet_id: str
  session_id: str | None = None
  region_id: str
  region_role: RegionRole = "unknown_region"
  evidence_strength: EvidenceStrength = "weak"
  allowed_downstream_use: list[AllowedDownstreamUse] = Field(default_factory=list)
  root_cause_relation: RootCauseRelation = "unknown"
  root_cause_likelihood: float = 0.0
  fix_guard_likelihood: float = 0.0
  vulnerable_sequence_likelihood: float = 0.0
  vulnerable_sequence: list[str] = Field(default_factory=list)
  fix_guard_sequence: list[str] = Field(default_factory=list)
  evidence_refs_used: list[str] = Field(default_factory=list)
  reasoning_summary: str = ""
  risk_flags: list[str] = Field(default_factory=list)


class AgentRegionRefinementResponse(BaseModel):
  schema_version: str = "step1_agent_region_refinement.v1"
  cve_id: str
  repo: str
  region_results: list[dict] = Field(default_factory=list)
  global_risk_flags: list[str] = Field(default_factory=list)
