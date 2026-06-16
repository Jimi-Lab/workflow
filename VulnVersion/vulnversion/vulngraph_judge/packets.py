from __future__ import annotations

from pydantic import BaseModel, Field

from .schema import GraphDocument, GraphNode


FORBIDDEN_CONTEXT = [
  "ground_truth_affected_versions",
  "version_planning_state",
  "neighbor_target_verdicts",
  "affected_range_aggregation",
]

ROOT_CAUSE_GIT_OPERATIONS = [
  "git show <fix_commit> -- <path>",
  "git show <fix_commit>^:<path>",
  "git diff <fix_commit>^ <fix_commit> -- <path>",
  "git log --follow -- <path>",
]

TARGET_GIT_OPERATIONS = [
  "git show <target>:<path>",
  "git grep <pattern> <target>",
  "git log --follow -- <path>",
]


class RootCausePacket(BaseModel):
  task: str = "root_cause_extraction"
  repo: str
  cve_id: str
  context_nodes: list[GraphNode] = Field(default_factory=list)
  root_cause_evidence_nodes: list[GraphNode] = Field(default_factory=list)
  navigation_hints: list[GraphNode] = Field(default_factory=list)
  procedure_hints: list[GraphNode] = Field(default_factory=list)
  allowed_git_operations: list[str] = Field(default_factory=lambda: list(ROOT_CAUSE_GIT_OPERATIONS))
  forbidden_context: list[str] = Field(default_factory=lambda: list(FORBIDDEN_CONTEXT))


class TargetPacket(BaseModel):
  task: str = "target_judgement"
  repo: str
  cve_id: str
  target: str
  context_nodes: list[GraphNode] = Field(default_factory=list)
  root_cause_evidence_nodes: list[GraphNode] = Field(default_factory=list)
  navigation_hints: list[GraphNode] = Field(default_factory=list)
  procedure_hints: list[GraphNode] = Field(default_factory=list)
  allowed_git_operations: list[str] = Field(default_factory=lambda: list(TARGET_GIT_OPERATIONS))
  forbidden_context: list[str] = Field(default_factory=lambda: list(FORBIDDEN_CONTEXT))
  required_target_evidence_allowed_use: str = "target_verdict_evidence"


def _runtime_eligible(node: GraphNode) -> bool:
  if node.lifecycle not in {"raw", "validated"}:
    return False
  if node.allowed_use in {"offline_eval_only", "forbidden_runtime"}:
    return False
  return True


def _select_nodes(doc: GraphDocument, allowed_use: str) -> list[GraphNode]:
  return [
    node
    for node in doc.nodes
    if node.allowed_use == allowed_use and _runtime_eligible(node)
  ]


def build_root_cause_packet(
  doc: GraphDocument,
  *,
  repo: str,
  cve_id: str,
) -> RootCausePacket:
  return RootCausePacket(
    repo=repo,
    cve_id=cve_id,
    context_nodes=_select_nodes(doc, "context_only"),
    root_cause_evidence_nodes=_select_nodes(doc, "root_cause_evidence"),
    navigation_hints=_select_nodes(doc, "navigation_only"),
    procedure_hints=_select_nodes(doc, "procedure_only"),
  )


def build_target_packet(
  doc: GraphDocument,
  *,
  repo: str,
  cve_id: str,
  target: str,
) -> TargetPacket:
  return TargetPacket(
    repo=repo,
    cve_id=cve_id,
    target=target,
    context_nodes=_select_nodes(doc, "context_only"),
    root_cause_evidence_nodes=_select_nodes(doc, "root_cause_evidence"),
    navigation_hints=_select_nodes(doc, "navigation_only"),
    procedure_hints=_select_nodes(doc, "procedure_only"),
  )
