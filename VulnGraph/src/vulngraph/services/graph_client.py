from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from vulngraph.neo4j_store import Neo4jConfig, Neo4jGraphStore
from vulngraph.schema import GraphDocument
from vulngraph.store import JsonlGraphStore

from .common import IngestionResult
from .ingestion import ingest_judge_output, ingest_root_cause_output, record_root_cause_failure
from .packets import build_judge_packet, build_root_cause_packet, get_cve_graph
from .queries import infer_bic_candidates, get_target_verdicts


class VulnGraphClient:
  """Workflow-facing API over the append-only VulnGraph store.

  JSONL remains the audit source. Neo4j is an optional materialized query target
  reached through sync_to_neo4j(), not the only source of truth.
  """

  def __init__(self, store: str | Path | JsonlGraphStore):
    self.store = store if isinstance(store, JsonlGraphStore) else JsonlGraphStore(store)

  def append_graph(self, graph: GraphDocument, *, created_from: str) -> None:
    self.store.append_graph(graph, created_from=created_from)
    self.store.write_snapshot(self.store.materialize())

  def append_events(self, events, *, write_snapshot: bool = True) -> None:
    self.store.append_events(events)
    if write_snapshot:
      self.store.write_snapshot(self.store.materialize())

  def materialize(self) -> GraphDocument:
    return self.store.materialize()

  def get_cve_graph(self, cve_id: str, include_debug: bool = False) -> dict[str, Any]:
    return get_cve_graph(self.materialize(), cve_id, include_debug=include_debug)

  def build_root_cause_packet(
    self,
    cve_id: str,
    mode: Literal["production", "debug"] = "production",
  ) -> dict[str, Any]:
    return build_root_cause_packet(self.materialize(), cve_id, mode=mode)

  def ingest_root_cause_output(
    self,
    cve_id: str,
    agent_output: dict[str, Any],
    trace: dict[str, Any] | None = None,
    packet: dict[str, Any] | None = None,
  ) -> IngestionResult:
    effective_packet = packet or build_root_cause_packet(self.materialize(), cve_id, mode="production")
    return ingest_root_cause_output(self.store, cve_id, agent_output, trace=trace, packet=effective_packet)

  def record_root_cause_failure(
    self,
    cve_id: str,
    *,
    reason: str,
    backend_name: str,
    raw_text: str = "",
    trace: dict[str, Any] | None = None,
  ) -> IngestionResult:
    return record_root_cause_failure(
      self.store,
      cve_id,
      reason=reason,
      backend_name=backend_name,
      raw_text=raw_text,
      trace=trace,
    )

  def build_judge_packet(
    self,
    cve_id: str,
    target_id: str,
    repo_ref: str | None = None,
    mode: Literal["production", "debug"] = "production",
  ) -> dict[str, Any]:
    return build_judge_packet(self.materialize(), cve_id, target_id, repo_ref=repo_ref, mode=mode)

  def ingest_judge_output(
    self,
    cve_id: str,
    target_id: str,
    agent_output: dict[str, Any],
    trace: dict[str, Any] | None = None,
  ) -> IngestionResult:
    return ingest_judge_output(self.store, cve_id, target_id, agent_output, trace=trace)

  def get_target_verdicts(self, cve_id: str, target_ids: list[str]) -> dict[str, Any]:
    return get_target_verdicts(self.materialize(), cve_id, target_ids)

  def infer_bic_candidates(
    self,
    cve_id: str,
    target_ids: list[str],
    strategy: Literal["blame", "boundary", "hybrid"] = "hybrid",
  ) -> dict[str, Any]:
    return infer_bic_candidates(self.materialize(), cve_id, target_ids, strategy=strategy)

  def sync_to_neo4j(self, *, config: Neo4jConfig | None = None, create_schema: bool = False) -> dict[str, int]:
    store = Neo4jGraphStore(config)
    try:
      store.upsert_graph(self.materialize(), create_schema=create_schema)
      return store.counts()
    finally:
      store.close()
