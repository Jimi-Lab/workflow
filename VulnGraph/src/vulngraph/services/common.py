from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from vulngraph.schema import GraphEdge, GraphEvent, GraphNode, SourceRef


ServiceStatus = Literal["accepted", "ingested_raw", "rejected"]


@dataclass(frozen=True)
class IngestionResult:
  status: ServiceStatus
  lifecycle: str
  appended_events: int
  errors: list[str] = field(default_factory=list)
  warnings: list[str] = field(default_factory=list)
  failure_case_id: str | None = None
  raw_hypothesis_count: int = 0
  rejected_hypothesis_count: int = 0
  details: dict[str, Any] = field(default_factory=dict)


def safe_id(value: str) -> str:
  return re.sub(r"[^A-Za-z0-9_.:-]+", "-", str(value).strip() or "unknown")


def node_to_dict(node: GraphNode) -> dict[str, Any]:
  return node.model_dump(mode="json", exclude_none=True)


def edge_to_dict(edge: GraphEdge) -> dict[str, Any]:
  return edge.model_dump(mode="json", exclude_none=True)


def source_ref(kind: str, ref: str, **kwargs: Any) -> list[SourceRef]:
  return [SourceRef(kind=kind, ref=ref, **{key: value for key, value in kwargs.items() if value})]


def node_event(
  node_id: str,
  node_type: str,
  scope: str,
  allowed_use: str,
  source_refs: list[SourceRef],
  content: dict[str, Any],
  *,
  lifecycle: str = "raw",
  confidence: float = 0.7,
  created_from: str = "service",
) -> GraphEvent:
  return GraphEvent.upsert_node(
    GraphNode(
      id=node_id,
      type=node_type,
      scope=scope,
      source_refs=source_refs,
      allowed_use=allowed_use,
      confidence=confidence,
      lifecycle=lifecycle,
      created_from=created_from,
      content=content,
    ),
    created_from=created_from,
  )


def edge_event(
  edge_type: str,
  source: str,
  target: str,
  scope: str,
  allowed_use: str,
  source_refs: list[SourceRef],
  *,
  lifecycle: str = "raw",
  confidence: float = 0.7,
  content: dict[str, Any] | None = None,
  created_from: str = "service",
) -> GraphEvent:
  return GraphEvent.upsert_edge(
    GraphEdge(
      id=f"edge:{source}:{edge_type}:{target}",
      type=edge_type,
      source=source,
      target=target,
      scope=scope,
      source_refs=source_refs,
      allowed_use=allowed_use,
      confidence=confidence,
      lifecycle=lifecycle,
      created_from=created_from,
      content=content or {},
    ),
    created_from=created_from,
  )


def failure_case_event(
  *,
  cve_id: str,
  stage: str,
  reason: str,
  source_refs: list[SourceRef],
  target_id: str | None = None,
  related_ids: list[str] | None = None,
  run_id: str | None = None,
  hypothesis_id: str | None = None,
  gate_stage: str | None = None,
  rejected_ids: list[str] | None = None,
) -> GraphEvent:
  identity = "|".join([cve_id, stage, reason, target_id or "", run_id or "", hypothesis_id or ""])
  digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
  failure_id = f"failure:{safe_id(cve_id)}:{safe_id(run_id or stage)}:{safe_id(hypothesis_id or 'run')}:{digest}"
  return node_event(
    failure_id,
    "FailureCase",
    "cve" if target_id is None else "target",
    "learning_candidate",
    source_refs,
    {
      "cve_id": cve_id,
      "target_id": target_id,
      "stage": stage,
      "gate_stage": gate_stage or stage,
      "run_id": run_id,
      "hypothesis_id": hypothesis_id,
      "reason": reason,
      "rejected_ids": rejected_ids or [],
      "related_node_ids": related_ids or [],
    },
    lifecycle="candidate",
    confidence=0.3,
    created_from="service_ingestion",
  )
