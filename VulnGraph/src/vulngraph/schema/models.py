from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


GraphScope = Literal["global", "repo", "cwe", "cve", "target", "agent_run", "experiment"]
AllowedUse = Literal[
  "context_only",
  "navigation_only",
  "procedure_only",
  "root_cause_evidence",
  "target_verdict_evidence",
  "learning_candidate",
  "offline_eval_only",
]
Lifecycle = Literal["raw", "candidate", "validated", "deprecated", "rejected"]
GraphEventType = Literal["upsert_node", "upsert_edge", "lifecycle_transition"]


def utc_now() -> str:
  return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class SourceRef(BaseModel):
  kind: str
  ref: str
  path: str | None = None
  line: int | None = None
  snippet: str | None = None
  sha256: str | None = None

  @field_validator("kind", "ref")
  @classmethod
  def _not_empty(cls, value: str) -> str:
    if not value.strip():
      raise ValueError("must not be empty")
    return value


class GraphNode(BaseModel):
  id: str
  type: str
  scope: GraphScope
  source_refs: list[SourceRef]
  allowed_use: AllowedUse
  confidence: float = Field(ge=0.0, le=1.0)
  lifecycle: Lifecycle
  created_from: str
  updated_at: str = Field(default_factory=utc_now)
  content: dict[str, Any] = Field(default_factory=dict)

  @field_validator("id", "type", "created_from")
  @classmethod
  def _not_empty(cls, value: str) -> str:
    if not value.strip():
      raise ValueError("must not be empty")
    return value

  @field_validator("source_refs")
  @classmethod
  def _source_refs_required(cls, refs: list[SourceRef]) -> list[SourceRef]:
    if not refs:
      raise ValueError("source_refs must contain at least one source")
    return refs


class GraphEdge(BaseModel):
  id: str
  type: str
  source: str
  target: str
  scope: GraphScope
  source_refs: list[SourceRef]
  allowed_use: AllowedUse
  confidence: float = Field(ge=0.0, le=1.0)
  lifecycle: Lifecycle
  created_from: str
  updated_at: str = Field(default_factory=utc_now)
  content: dict[str, Any] = Field(default_factory=dict)

  @field_validator("id", "type", "source", "target", "created_from")
  @classmethod
  def _not_empty(cls, value: str) -> str:
    if not value.strip():
      raise ValueError("must not be empty")
    return value

  @field_validator("source_refs")
  @classmethod
  def _source_refs_required(cls, refs: list[SourceRef]) -> list[SourceRef]:
    if not refs:
      raise ValueError("source_refs must contain at least one source")
    return refs


class GraphEvent(BaseModel):
  event_id: str = Field(default_factory=lambda: f"event:{uuid4().hex}")
  event_type: GraphEventType
  created_at: str = Field(default_factory=utc_now)
  created_from: str
  source_refs: list[SourceRef]
  node: GraphNode | None = None
  edge: GraphEdge | None = None
  content: dict[str, Any] = Field(default_factory=dict)

  @field_validator("event_id", "created_from")
  @classmethod
  def _not_empty(cls, value: str) -> str:
    if not value.strip():
      raise ValueError("must not be empty")
    return value

  @field_validator("source_refs")
  @classmethod
  def _source_refs_required(cls, refs: list[SourceRef]) -> list[SourceRef]:
    if not refs:
      raise ValueError("source_refs must contain at least one source")
    return refs

  @model_validator(mode="after")
  def _event_payload_matches_type(self) -> "GraphEvent":
    if self.event_type == "upsert_node" and self.node is None:
      raise ValueError("upsert_node requires node")
    if self.event_type == "upsert_edge" and self.edge is None:
      raise ValueError("upsert_edge requires edge")
    if self.event_type == "lifecycle_transition":
      if not self.content.get("target_id") or not self.content.get("new_lifecycle"):
        raise ValueError("lifecycle_transition requires target_id and new_lifecycle")
    return self

  @classmethod
  def upsert_node(cls, node: GraphNode, *, created_from: str) -> "GraphEvent":
    return cls(
      event_type="upsert_node",
      created_from=created_from,
      source_refs=node.source_refs,
      node=node,
    )

  @classmethod
  def upsert_edge(cls, edge: GraphEdge, *, created_from: str) -> "GraphEvent":
    return cls(
      event_type="upsert_edge",
      created_from=created_from,
      source_refs=edge.source_refs,
      edge=edge,
    )

  @classmethod
  def lifecycle_transition(
    cls,
    *,
    target_id: str,
    new_lifecycle: Lifecycle,
    source_refs: list[SourceRef],
    created_from: str,
    reason: str = "",
  ) -> "GraphEvent":
    return cls(
      event_type="lifecycle_transition",
      created_from=created_from,
      source_refs=source_refs,
      content={"target_id": target_id, "new_lifecycle": new_lifecycle, "reason": reason},
    )


class GraphDocument(BaseModel):
  nodes: list[GraphNode] = Field(default_factory=list)
  edges: list[GraphEdge] = Field(default_factory=list)

  @classmethod
  def from_events(cls, events: list[GraphEvent]) -> "GraphDocument":
    nodes: dict[str, GraphNode] = {}
    edges: dict[str, GraphEdge] = {}
    for event in events:
      if event.event_type == "upsert_node" and event.node is not None:
        nodes[event.node.id] = event.node
      elif event.event_type == "upsert_edge" and event.edge is not None:
        edges[event.edge.id] = event.edge
      elif event.event_type == "lifecycle_transition":
        target_id = str(event.content.get("target_id") or "")
        new_lifecycle = event.content.get("new_lifecycle")
        if target_id in nodes and new_lifecycle:
          nodes[target_id] = nodes[target_id].model_copy(update={"lifecycle": new_lifecycle, "updated_at": event.created_at})
        if target_id in edges and new_lifecycle:
          edges[target_id] = edges[target_id].model_copy(update={"lifecycle": new_lifecycle, "updated_at": event.created_at})
    return cls(nodes=list(nodes.values()), edges=list(edges.values()))
