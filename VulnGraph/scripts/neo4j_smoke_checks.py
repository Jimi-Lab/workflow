from __future__ import annotations

import argparse
import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from neo4j import GraphDatabase

from vulngraph.store import JsonlGraphStore


REQUIRED_NODE_PROPERTIES = (
  "id",
  "node_type",
  "scope",
  "allowed_use",
  "lifecycle",
  "source_refs_json",
)

REQUIRED_EDGE_PROPERTIES = (
  "id",
  "edge_type",
  "scope",
  "allowed_use",
  "lifecycle",
  "source_refs_json",
)


def main() -> None:
  parser = argparse.ArgumentParser(description="Run scoped Neo4j smoke checks for a VulnGraph JSONL store.")
  parser.add_argument("--store", required=True, help="Path to the JSONL graph store used as the smoke-check scope.")
  parser.add_argument("--uri", default=os.getenv("NEO4J_URI", "bolt://localhost:7687"))
  parser.add_argument("--user", default=os.getenv("NEO4J_USER", "neo4j"))
  parser.add_argument("--password", default=os.getenv("NEO4J_PASSWORD", ""))
  parser.add_argument("--output", help="Optional JSON output path.")
  args = parser.parse_args()

  graph = JsonlGraphStore(args.store).materialize()
  node_ids = [node.id for node in graph.nodes]
  edge_ids = [edge.id for edge in graph.edges]
  cve_ids = [node.id for node in graph.nodes if node.type == "CVE"]
  fix_commit_ids = [node.id for node in graph.nodes if node.type == "FixCommit"]

  auth = (args.user, args.password) if args.password else None
  driver = GraphDatabase.driver(args.uri, auth=auth)
  try:
    driver.verify_connectivity()
    with driver.session() as session:
      result = {
        "store": str(Path(args.store)),
        "neo4j": {
          "uri": args.uri,
          "connected": True,
        },
        "jsonl_scope": _jsonl_scope_summary(graph),
        "neo4j_scope": _neo4j_scope_summary(session, node_ids=node_ids, edge_ids=edge_ids),
        "coverage": _coverage_summary(session, cve_ids=cve_ids, fix_commit_ids=fix_commit_ids),
        "policy": _policy_summary(session, node_ids=node_ids, edge_ids=edge_ids),
        "cve_table": _cve_table(graph),
      }
  finally:
    driver.close()

  payload = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
  if args.output:
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(payload + "\n", encoding="utf-8")
  print(payload)


def _jsonl_scope_summary(graph) -> dict[str, Any]:
  node_types = Counter(node.type for node in graph.nodes)
  edge_types = Counter(edge.type for edge in graph.edges)
  return {
    "node_count": len(graph.nodes),
    "edge_count": len(graph.edges),
    "node_types": dict(sorted(node_types.items())),
    "edge_types": dict(sorted(edge_types.items())),
  }


def _neo4j_scope_summary(session, *, node_ids: list[str], edge_ids: list[str]) -> dict[str, Any]:
  return {
    "node_count": _single_value(
      session,
      "MATCH (n) WHERE n.id IN $node_ids RETURN count(n) AS value",
      node_ids=node_ids,
    ),
    "edge_count": _single_value(
      session,
      "MATCH ()-[r]->() WHERE r.id IN $edge_ids RETURN count(r) AS value",
      edge_ids=edge_ids,
    ),
    "node_types": _keyed_count(
      session,
      "MATCH (n) WHERE n.id IN $node_ids RETURN n.node_type AS key, count(n) AS count ORDER BY key",
      node_ids=node_ids,
    ),
    "edge_types": _keyed_count(
      session,
      "MATCH ()-[r]->() WHERE r.id IN $edge_ids RETURN r.edge_type AS key, count(r) AS count ORDER BY key",
      edge_ids=edge_ids,
    ),
  }


def _coverage_summary(session, *, cve_ids: list[str], fix_commit_ids: list[str]) -> dict[str, Any]:
  fixed_by = session.run(
    """
    MATCH (c:CVE)-[r:FIXED_BY]->(f:FixCommit)
    WHERE c.id IN $cve_ids
    RETURN count(DISTINCT c) AS cves_with_fix_commit,
           count(DISTINCT f) AS fix_commits_linked,
           count(r) AS fixed_by_edges
    """,
    cve_ids=cve_ids,
  ).single()
  patch_hunks = session.run(
    """
    MATCH (f:FixCommit)-[r:HAS_PATCH_HUNK]->(h:PatchHunk)
    WHERE f.id IN $fix_commit_ids
    RETURN count(DISTINCT f) AS fix_commits_with_patch_hunk,
           count(DISTINCT h) AS patch_hunks_linked,
           count(r) AS has_patch_hunk_edges
    """,
    fix_commit_ids=fix_commit_ids,
  ).single()
  return {
    "cve_to_fix_commit": dict(fixed_by.data()),
    "fix_commit_to_patch_hunk": dict(patch_hunks.data()),
  }


def _policy_summary(session, *, node_ids: list[str], edge_ids: list[str]) -> dict[str, Any]:
  missing_node_predicate = " OR ".join(f"n.{prop} IS NULL" for prop in REQUIRED_NODE_PROPERTIES)
  missing_edge_predicate = " OR ".join(f"r.{prop} IS NULL" for prop in REQUIRED_EDGE_PROPERTIES)
  context_as_verdict = session.run(
    """
    MATCH (n)
    WHERE n.id IN $node_ids
      AND n.node_type IN ['CVE', 'CWE', 'Reference', 'Advisory']
      AND n.allowed_use = 'target_verdict_evidence'
    RETURN count(n) AS value
    """,
    node_ids=node_ids,
  ).single()["value"]
  offline_as_verdict = session.run(
    """
    MATCH (n)
    WHERE n.id IN $node_ids
      AND n.id STARTS WITH 'offline-affected:'
      AND n.allowed_use = 'target_verdict_evidence'
    RETURN count(n) AS value
    """,
    node_ids=node_ids,
  ).single()["value"]
  return {
    "nodes_missing_required_metadata": _single_value(
      session,
      f"MATCH (n) WHERE n.id IN $node_ids AND ({missing_node_predicate}) RETURN count(n) AS value",
      node_ids=node_ids,
    ),
    "edges_missing_required_metadata": _single_value(
      session,
      f"MATCH ()-[r]->() WHERE r.id IN $edge_ids AND ({missing_edge_predicate}) RETURN count(r) AS value",
      edge_ids=edge_ids,
    ),
    "context_nodes_marked_target_verdict_evidence": int(context_as_verdict),
    "offline_eval_nodes_marked_target_verdict_evidence": int(offline_as_verdict),
  }


def _cve_table(graph) -> list[dict[str, Any]]:
  cwe_by_cve: dict[str, set[str]] = defaultdict(set)
  repo_by_cve: dict[str, str] = {}
  fix_by_cve: dict[str, set[str]] = defaultdict(set)
  hunks_by_cve: dict[str, int] = defaultdict(int)
  anchors_by_cve: dict[str, int] = defaultdict(int)
  functions_by_cve: dict[str, set[str]] = defaultdict(set)
  offline_by_cve: dict[str, int] = defaultdict(int)

  nodes_by_id = {node.id: node for node in graph.nodes}
  for edge in graph.edges:
    source = nodes_by_id.get(edge.source)
    target = nodes_by_id.get(edge.target)
    if not source or not target:
      continue
    if source.type == "CVE" and edge.type == "has_cwe":
      cwe_by_cve[source.content.get("cve_id", source.id)].add(str(target.content.get("cwe_id", target.id)))
    elif source.type == "CVE" and edge.type == "targets_repo":
      repo_by_cve[str(source.content.get("cve_id", source.id))] = str(target.content.get("repo", target.id))
    elif source.type == "CVE" and edge.type == "fixed_by":
      fix_by_cve[str(source.content.get("cve_id", source.id))].add(target.id)
    elif source.type == "CVE" and edge.type == "has_offline_affected_version":
      offline_by_cve[str(source.content.get("cve_id", source.id))] += 1

  for node in graph.nodes:
    cve_id = str(node.content.get("cve_id") or "")
    if not cve_id:
      continue
    if node.type == "PatchHunk":
      hunks_by_cve[cve_id] += 1
    elif node.type == "CodeAnchor":
      anchors_by_cve[cve_id] += 1
    elif node.type == "ChangedFunction":
      functions_by_cve[cve_id].add(node.id)

  rows = []
  for node in graph.nodes:
    if node.type != "CVE":
      continue
    cve_id = str(node.content.get("cve_id", node.id))
    rows.append(
      {
        "cve_id": cve_id,
        "repo": repo_by_cve.get(cve_id, ""),
        "cwe_count": len(cwe_by_cve[cve_id]),
        "fix_commit_count": len(fix_by_cve[cve_id]),
        "patch_hunk_count": hunks_by_cve[cve_id],
        "code_anchor_count": anchors_by_cve[cve_id],
        "changed_function_count": len(functions_by_cve[cve_id]),
        "offline_affected_version_count": offline_by_cve[cve_id],
      }
    )
  return rows


def _keyed_count(session, query: str, **parameters: Any) -> dict[str, int]:
  rows = session.run(query, **parameters)
  return {str(row["key"]): int(row["count"]) for row in rows}


def _single_value(session, query: str, **parameters: Any) -> int:
  row = session.run(query, **parameters).single()
  return int(row["value"])


if __name__ == "__main__":
  main()
