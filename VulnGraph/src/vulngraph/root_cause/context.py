from __future__ import annotations

import json

from pydantic import BaseModel, Field

from vulngraph.agent_backend import READ_ONLY_GIT_TOOLS
from vulngraph.ontology import packet_eligible
from vulngraph.packets.extractors import FORBIDDEN_CONTEXT
from vulngraph.schema import GraphDocument, GraphEdge, GraphNode


class RootCauseContextConfig(BaseModel):
  max_nodes: int = Field(default=40, ge=1)
  max_chars: int = Field(default=24000, ge=1000)
  max_hops: int = Field(default=3, ge=0, le=8)


class RootCauseContextPacket(BaseModel):
  task: str = "root_cause_extraction"
  cve_id: str
  repo: str
  repo_path: str
  nodes: list[GraphNode]
  edges: list[GraphEdge]
  allowed_git_tools: list[str] = Field(default_factory=lambda: list(READ_ONLY_GIT_TOOLS))
  forbidden_context: list[str] = Field(default_factory=lambda: list(FORBIDDEN_CONTEXT))
  omitted_node_count: int = 0


def build_root_cause_context(
  graph: GraphDocument,
  *,
  cve_id: str,
  repo: str,
  repo_path: str,
  config: RootCauseContextConfig | None = None,
) -> RootCauseContextPacket:
  config = config or RootCauseContextConfig()
  eligible = {node.id: node for node in graph.nodes if packet_eligible(node)}
  adjacency: dict[str, set[str]] = {node_id: set() for node_id in eligible}
  for edge in graph.edges:
    if edge.source in eligible and edge.target in eligible and edge.lifecycle in {"raw", "validated"}:
      adjacency[edge.source].add(edge.target)
      adjacency[edge.target].add(edge.source)

  seeds = {
    node.id
    for node in eligible.values()
    if _is_seed(node, cve_id=cve_id, repo=repo)
  }
  selected_ids = set(seeds)
  frontier = set(seeds)
  for _ in range(config.max_hops):
    next_frontier = {neighbor for node_id in frontier for neighbor in adjacency.get(node_id, set())}
    next_frontier -= selected_ids
    if not next_frontier:
      break
    selected_ids.update(next_frontier)
    frontier = next_frontier

  candidates = sorted(
    (eligible[node_id] for node_id in selected_ids),
    key=lambda node: (_priority(node), -node.confidence, node.id),
  )
  nodes: list[GraphNode] = []
  used_chars = 0
  for node in candidates:
    size = len(json.dumps(node.model_dump(mode="json"), ensure_ascii=False))
    if len(nodes) >= config.max_nodes or used_chars + size > config.max_chars:
      continue
    nodes.append(node)
    used_chars += size

  included = {node.id for node in nodes}
  edges = [
    edge
    for edge in graph.edges
    if edge.source in included
    and edge.target in included
    and edge.lifecycle in {"raw", "validated"}
    and edge.allowed_use not in {"learning_candidate", "offline_eval_only"}
  ]
  return RootCauseContextPacket(
    cve_id=cve_id,
    repo=repo,
    repo_path=repo_path,
    nodes=nodes,
    edges=edges,
    omitted_node_count=max(0, len(candidates) - len(nodes)),
  )


def _is_seed(node: GraphNode, *, cve_id: str, repo: str) -> bool:
  cve_match = node.id.lower() == f"cve:{cve_id}".lower() or str(node.content.get("cve_id", "")).lower() == cve_id.lower()
  repo_match = node.id.lower() == f"repo:{repo}".lower() or str(node.content.get("repo", "")).lower() == repo.lower()
  return cve_match or repo_match


def _priority(node: GraphNode) -> int:
  if node.type == "CVE":
    return 0
  if node.type in {"FixCommit", "PatchHunk", "ChangedFile", "ChangedFunction", "CodeAnchor"}:
    return 1
  if node.allowed_use == "root_cause_evidence":
    return 2
  if node.type in {"CWE", "CAPEC", "Advisory", "Reference"}:
    return 3
  if node.type == "Repo":
    return 4
  if node.allowed_use in {"navigation_only", "procedure_only"}:
    return 5
  return 6
