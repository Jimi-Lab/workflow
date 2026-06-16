from __future__ import annotations

from pydantic import BaseModel, Field

from vulngraph.ontology import CONTEXT_NODE_TYPES, packet_eligible
from vulngraph.schema import GraphDocument, GraphNode


FORBIDDEN_CONTEXT = [
  "ground_truth_affected_versions",
  "version_planning_state",
  "neighbor_target_verdicts",
  "affected_range_aggregation",
]


class GraphPacket(BaseModel):
  task: str
  cve_id: str
  repo: str | None = None
  target: str | None = None
  context_nodes: list[GraphNode] = Field(default_factory=list)
  root_cause_evidence_nodes: list[GraphNode] = Field(default_factory=list)
  navigation_hints: list[GraphNode] = Field(default_factory=list)
  procedure_hints: list[GraphNode] = Field(default_factory=list)
  forbidden_context: list[str] = Field(default_factory=lambda: list(FORBIDDEN_CONTEXT))

  def all_node_ids(self) -> set[str]:
    return {
      node.id
      for group in (
        self.context_nodes,
        self.root_cause_evidence_nodes,
        self.navigation_hints,
        self.procedure_hints,
      )
      for node in group
    }


def build_root_cause_packet(graph: GraphDocument, *, cve_id: str, repo: str | None = None) -> GraphPacket:
  return _build_packet(graph, task="root_cause_extraction", cve_id=cve_id, repo=repo, target=None)


def build_target_packet(
  graph: GraphDocument,
  *,
  cve_id: str,
  target: str,
  repo: str | None = None,
) -> GraphPacket:
  return _build_packet(graph, task="target_judgement", cve_id=cve_id, repo=repo, target=target)


def _build_packet(
  graph: GraphDocument,
  *,
  task: str,
  cve_id: str,
  repo: str | None,
  target: str | None,
) -> GraphPacket:
  nodes = [node for node in graph.nodes if packet_eligible(node)]
  return GraphPacket(
    task=task,
    cve_id=cve_id,
    repo=repo,
    target=target,
    context_nodes=[node for node in nodes if node.allowed_use == "context_only" and node.type in CONTEXT_NODE_TYPES],
    root_cause_evidence_nodes=[node for node in nodes if node.allowed_use == "root_cause_evidence"],
    navigation_hints=[node for node in nodes if node.allowed_use == "navigation_only"],
    procedure_hints=[node for node in nodes if node.allowed_use == "procedure_only"],
  )
