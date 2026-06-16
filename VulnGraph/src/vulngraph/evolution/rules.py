from __future__ import annotations

import re

from vulngraph.schema import GraphEdge, GraphEvent, GraphNode, Lifecycle, SourceRef


def candidate_memories_from_failure(failure: GraphNode) -> list[GraphEvent]:
  if failure.type != "FailureCase":
    raise ValueError("candidate memories can only be derived from FailureCase nodes")

  source_refs = [SourceRef(kind="failure_case", ref=failure.id, snippet=str(failure.content.get("summary") or "")), *failure.source_refs]
  events: list[GraphEvent] = []

  candidates = [
    ("repo_hint", "RepoMemory", "repo"),
    ("cwe_hint", "CWEMemory", "cwe"),
    ("procedure_hint", "ProcedureMemory", "cve"),
  ]
  for key, node_type, scope in candidates:
    hint = failure.content.get(key)
    if not hint:
      continue
    node_id = f"memory:{_safe(node_type)}:{_safe(failure.id)}:{key}"
    node = GraphNode(
      id=node_id,
      type=node_type,
      scope=scope,
      source_refs=source_refs,
      allowed_use="learning_candidate",
      confidence=0.25,
      lifecycle="candidate",
      created_from=failure.id,
      content={
        "hint": str(hint),
        "origin_failure_id": failure.id,
        "promotion_status": "candidate_only",
      },
    )
    events.append(GraphEvent.upsert_node(node, created_from="failure_case"))
    edge = GraphEdge(
      id=f"edge:{failure.id}:candidate_updates:{node_id}",
      type="candidate_updates",
      source=failure.id,
      target=node_id,
      scope=scope,
      source_refs=source_refs,
      allowed_use="learning_candidate",
      confidence=0.25,
      lifecycle="candidate",
      created_from="failure_case",
    )
    events.append(GraphEvent.upsert_edge(edge, created_from="failure_case"))
  return events


def lifecycle_transition(
  *,
  target_id: str,
  new_lifecycle: Lifecycle,
  source_refs: list[SourceRef],
  created_from: str,
  reason: str,
) -> GraphEvent:
  return GraphEvent.lifecycle_transition(
    target_id=target_id,
    new_lifecycle=new_lifecycle,
    source_refs=source_refs,
    created_from=created_from,
    reason=reason,
  )


def _safe(value: str) -> str:
  return re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip() or "unknown")
