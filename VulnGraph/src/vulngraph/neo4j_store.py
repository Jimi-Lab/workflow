from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Iterable

from vulngraph.schema import GraphDocument, GraphEdge, GraphNode


V1_NODE_LABELS = (
  "CVE",
  "CWE",
  "Reference",
  "Advisory",
  "Repo",
  "File",
  "Function",
  "Symbol",
  "PathAlias",
  "FixCommit",
  "PatchHunk",
  "ChangedFunction",
  "CodeAnchor",
  "RootCauseHypothesis",
  "VulnerablePredicate",
  "FixPredicate",
  "GuardCondition",
  "NegativeCondition",
  "NegativeApplicabilityCondition",
  "AgentRun",
  "ToolCall",
  "ToolOutput",
  "GitObservation",
  "PredicateEvaluation",
  "Target",
  "TargetSnapshot",
  "TargetVerdict",
  "UncertaintyReason",
  "BICCandidate",
  "VersionBoundary",
  "VerdictAggregation",
  "MemoryCandidate",
  "RepoMemory",
  "CWEMemory",
  "ProcedureMemory",
  "FailureCase",
  "SuccessCase",
)

V1_RELATIONSHIP_TYPES = (
  "HAS_CWE",
  "HAS_REFERENCE",
  "TARGETS_REPO",
  "FIXED_BY",
  "HAS_PATCH_HUNK",
  "TOUCHES_FILE",
  "TOUCHES_FUNCTION",
  "YIELDS_ANCHOR",
  "PROPOSES",
  "REQUIRES",
  "BLOCKED_BY",
  "CONSTRAINED_BY",
  "EXCLUDED_BY",
  "ANCHORED_BY",
  "HAS_STEP",
  "INVOKES",
  "PRODUCES",
  "DERIVES",
  "SUPPORTS",
  "CONTRADICTS",
  "SUPPORTS_VERDICT",
  "HAS_SNAPSHOT",
  "EVALUATES_TARGET",
  "CANDIDATE_UPDATES",
  "RANKS_BIC",
  "HAS_BOUNDARY",
  "HAS_UNCERTAINTY",
  "GENERATES_CANDIDATE",
  "PROMOTED_TO",
  "HAS_OFFLINE_AFFECTED_VERSION",
)


@dataclass(frozen=True)
class Neo4jNodeRecord:
  label: str
  properties: dict[str, Any]


@dataclass(frozen=True)
class Neo4jEdgeRecord:
  type: str
  source_id: str
  target_id: str
  properties: dict[str, Any]


@dataclass(frozen=True)
class Neo4jConfig:
  uri: str
  user: str
  password: str

  @classmethod
  def from_env(cls) -> "Neo4jConfig":
    return cls(
      uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
      user=os.getenv("NEO4J_USER", "neo4j"),
      password=os.getenv("NEO4J_PASSWORD", ""),
    )


def node_to_neo4j_record(node: GraphNode) -> Neo4jNodeRecord:
  label = _safe_label(node.type)
  return Neo4jNodeRecord(
    label=label,
    properties={
      "id": node.id,
      "node_type": node.type,
      "scope": node.scope,
      "allowed_use": node.allowed_use,
      "confidence": float(node.confidence),
      "lifecycle": node.lifecycle,
      "created_from": node.created_from,
      "updated_at": node.updated_at,
      "source_refs_json": json.dumps([ref.model_dump(mode="json", exclude_none=True) for ref in node.source_refs], ensure_ascii=False),
      "content_json": json.dumps(node.content, ensure_ascii=False, sort_keys=True),
      "schema_version": "neo4j-v1",
    },
  )


def edge_to_neo4j_record(edge: GraphEdge) -> Neo4jEdgeRecord:
  rel_type = _safe_relationship_type(edge.type)
  return Neo4jEdgeRecord(
    type=rel_type,
    source_id=edge.source,
    target_id=edge.target,
    properties={
      "id": edge.id,
      "edge_type": edge.type,
      "scope": edge.scope,
      "allowed_use": edge.allowed_use,
      "confidence": float(edge.confidence),
      "lifecycle": edge.lifecycle,
      "created_from": edge.created_from,
      "updated_at": edge.updated_at,
      "source_refs_json": json.dumps([ref.model_dump(mode="json", exclude_none=True) for ref in edge.source_refs], ensure_ascii=False),
      "content_json": json.dumps(edge.content, ensure_ascii=False, sort_keys=True),
      "schema_version": "neo4j-v1",
    },
  )


def iter_schema_cypher() -> Iterable[str]:
  for label in V1_NODE_LABELS:
    safe = _safe_label(label)
    yield f"CREATE CONSTRAINT {safe}_id_unique IF NOT EXISTS FOR (n:{safe}) REQUIRE n.id IS UNIQUE"
  for rel_type in V1_RELATIONSHIP_TYPES:
    safe = _safe_relationship_type(rel_type)
    yield f"CREATE CONSTRAINT {safe}_id_unique IF NOT EXISTS FOR ()-[r:{safe}]-() REQUIRE r.id IS UNIQUE"


class Neo4jGraphStore:
  def __init__(self, config: Neo4jConfig | None = None) -> None:
    self.config = config or Neo4jConfig.from_env()
    self._driver = None

  def close(self) -> None:
    if self._driver is not None:
      self._driver.close()
      self._driver = None

  def create_schema(self) -> None:
    with self._driver_instance().session() as session:
      for statement in iter_schema_cypher():
        session.run(statement)

  def upsert_graph(self, graph: GraphDocument, *, create_schema: bool = False) -> None:
    if create_schema:
      self.create_schema()
    with self._driver_instance().session() as session:
      for node in graph.nodes:
        record = node_to_neo4j_record(node)
        session.run(
          f"MERGE (n:{record.label} {{id: $id}}) SET n += $properties",
          id=record.properties["id"],
          properties=record.properties,
        )
      for edge in graph.edges:
        record = edge_to_neo4j_record(edge)
        session.run(
          f"""
          MATCH (source {{id: $source_id}})
          MATCH (target {{id: $target_id}})
          MERGE (source)-[rel:{record.type} {{id: $id}}]->(target)
          SET rel += $properties
          """,
          source_id=record.source_id,
          target_id=record.target_id,
          id=record.properties["id"],
          properties=record.properties,
        )

  def counts(self) -> dict[str, int]:
    with self._driver_instance().session() as session:
      node_count = session.run("MATCH (n) RETURN count(n) AS count").single()["count"]
      edge_count = session.run("MATCH ()-[r]->() RETURN count(r) AS count").single()["count"]
    return {"nodes": int(node_count), "edges": int(edge_count)}

  def _driver_instance(self):
    if self._driver is None:
      try:
        from neo4j import GraphDatabase
      except (ImportError, ModuleNotFoundError) as error:
        raise RuntimeError(
          "Install the official neo4j Python driver and ensure no local neo4j directory shadows it"
        ) from error
      auth = (self.config.user, self.config.password) if self.config.password else None
      self._driver = GraphDatabase.driver(self.config.uri, auth=auth)
    return self._driver


def _safe_label(value: str) -> str:
  cleaned = "".join(ch if ch.isalnum() else "_" for ch in value)
  if not cleaned or cleaned[0].isdigit():
    cleaned = f"N_{cleaned}"
  return cleaned


def _safe_relationship_type(value: str) -> str:
  cleaned = "".join(ch if ch.isalnum() else "_" for ch in value).upper()
  if not cleaned or cleaned[0].isdigit():
    cleaned = f"R_{cleaned}"
  return cleaned
