from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


GraphScope = Literal["global", "repo", "cwe", "cve", "target", "experiment"]
AllowedUse = Literal[
  "context_only",
  "navigation_only",
  "procedure_only",
  "root_cause_evidence",
  "target_verdict_evidence",
  "offline_eval_only",
  "forbidden_runtime",
]
Lifecycle = Literal["raw", "candidate", "validated", "deprecated", "rejected"]


def _utc_now() -> str:
  return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class SourceRef(BaseModel):
  kind: str
  ref: str
  path: str | None = None
  line: int | None = None
  snippet: str | None = None

  @field_validator("kind", "ref")
  @classmethod
  def _must_not_be_empty(cls, value: str) -> str:
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
  updated_at: str = Field(default_factory=_utc_now)
  content: dict[str, Any] = Field(default_factory=dict)

  @field_validator("id", "type", "created_from")
  @classmethod
  def _must_not_be_empty(cls, value: str) -> str:
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
  updated_at: str = Field(default_factory=_utc_now)
  content: dict[str, Any] = Field(default_factory=dict)

  @field_validator("id", "type", "source", "target", "created_from")
  @classmethod
  def _must_not_be_empty(cls, value: str) -> str:
    if not value.strip():
      raise ValueError("must not be empty")
    return value

  @field_validator("source_refs")
  @classmethod
  def _source_refs_required(cls, refs: list[SourceRef]) -> list[SourceRef]:
    if not refs:
      raise ValueError("source_refs must contain at least one source")
    return refs


class GraphDocument(BaseModel):
  nodes: list[GraphNode] = Field(default_factory=list)
  edges: list[GraphEdge] = Field(default_factory=list)

  def nodes_by_allowed_use(self, allowed_use: AllowedUse) -> list[GraphNode]:
    return [node for node in self.nodes if node.allowed_use == allowed_use]

  def nodes_by_type(self, node_type: str) -> list[GraphNode]:
    return [node for node in self.nodes if node.type == node_type]
