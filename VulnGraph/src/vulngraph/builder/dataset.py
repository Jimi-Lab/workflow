from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulngraph.schema import GraphDocument, GraphEdge, GraphNode, SourceRef


def build_dataset_graph(
  dataset_path: str | Path,
  *,
  limit: int | None = None,
  cve_ids: list[str] | None = None,
  include_offline_eval: bool = False,
) -> GraphDocument:
  data = json.loads(Path(dataset_path).read_text(encoding="utf-8"))
  if not isinstance(data, dict):
    raise ValueError("BaseDataOrder-style dataset must be a JSON object keyed by CVE")

  nodes: dict[str, GraphNode] = {}
  edges: dict[str, GraphEdge] = {}
  if cve_ids is None:
    items = list(data.items())
  else:
    requested = set(cve_ids)
    items = [(cve_id, record) for cve_id, record in data.items() if cve_id in requested]
  if limit is not None:
    items = items[:limit]

  for cve_id, record in items:
    if not isinstance(record, dict):
      continue
    source = [SourceRef(kind="dataset", ref=f"dataset:{cve_id}", path=str(dataset_path))]
    repo = str(record.get("repo") or "").strip()
    cwe_ids = [str(value).strip() for value in record.get("CWE", []) if str(value).strip()]
    affected_versions = [str(value).strip() for value in record.get("affected_version", []) if str(value).strip()]

    cve_node_id = f"cve:{cve_id}"
    nodes[cve_node_id] = _node(
      cve_node_id,
      "CVE",
      "cve",
      "context_only",
      source,
      {"cve_id": cve_id, "affected_versions_count": len(affected_versions)},
      confidence=0.8,
    )

    if repo:
      repo_node_id = f"repo:{repo}"
      nodes.setdefault(
        repo_node_id,
        _node(repo_node_id, "Repo", "repo", "context_only", source, {"repo": repo}, confidence=0.8),
      )
      _add_edge(edges, "targets_repo", cve_node_id, repo_node_id, "cve", "context_only", source)

    for cwe_id in cwe_ids:
      cwe_node_id = f"cwe:{cwe_id}"
      nodes.setdefault(
        cwe_node_id,
        _node(cwe_node_id, "CWE", "cwe", "context_only", source, {"cwe_id": cwe_id}, confidence=0.8),
      )
      _add_edge(edges, "has_cwe", cve_node_id, cwe_node_id, "cve", "context_only", source)

    for group_index, order, commit_sha in _iter_fix_commits(record.get("fixing_commits")):
      commit_node_id = f"fix-commit:{repo}:{commit_sha}" if repo else f"fix-commit:{commit_sha}"
      nodes.setdefault(
        commit_node_id,
        _node(
          commit_node_id,
          "FixCommit",
          "cve",
          "root_cause_evidence",
          source,
          {
            "cve_id": cve_id,
            "repo": repo,
            "commit_sha": commit_sha,
            "fix_set_id": f"{cve_id}:fix-set:{group_index}",
            "group_index": group_index,
            "order": order,
          },
          confidence=0.9,
        ),
      )
      _add_edge(
        edges,
        "fixed_by",
        cve_node_id,
        commit_node_id,
        "cve",
        "root_cause_evidence",
        source,
        content={"fix_set_id": f"{cve_id}:fix-set:{group_index}", "order": order},
        confidence=0.9,
      )

    if include_offline_eval:
      for version in affected_versions:
        version_node_id = f"offline-affected:{cve_id}:{version}"
        nodes[version_node_id] = _node(
          version_node_id,
          "TargetVerdict",
          "experiment",
          "offline_eval_only",
          source,
          {
            "cve_id": cve_id,
            "repo": repo,
            "target": version,
            "verdict": "AFFECTED",
            "origin": "ground_truth_affected_version",
          },
          confidence=1.0,
          lifecycle="validated",
        )
        _add_edge(
          edges,
          "has_offline_affected_version",
          cve_node_id,
          version_node_id,
          "experiment",
          "offline_eval_only",
          source,
          confidence=1.0,
        )

  return GraphDocument(nodes=list(nodes.values()), edges=list(edges.values()))


def _iter_fix_commits(value: Any) -> list[tuple[int, int, str]]:
  commits: list[tuple[int, int, str]] = []
  if not isinstance(value, list):
    return commits
  for group_index, group in enumerate(value, start=1):
    if isinstance(group, list):
      for order, commit in enumerate(group, start=1):
        commit_sha = str(commit).strip()
        if commit_sha:
          commits.append((group_index, order, commit_sha))
    else:
      commit_sha = str(group).strip()
      if commit_sha:
        commits.append((group_index, 1, commit_sha))
  return commits


def _node(
  node_id: str,
  node_type: str,
  scope: str,
  allowed_use: str,
  source_refs: list[SourceRef],
  content: dict,
  *,
  confidence: float,
  lifecycle: str = "raw",
) -> GraphNode:
  return GraphNode(
    id=node_id,
    type=node_type,
    scope=scope,
    source_refs=source_refs,
    allowed_use=allowed_use,
    confidence=confidence,
    lifecycle=lifecycle,
    created_from="dataset_import",
    content=content,
  )


def _add_edge(
  edges: dict[str, GraphEdge],
  edge_type: str,
  source: str,
  target: str,
  scope: str,
  allowed_use: str,
  source_refs: list[SourceRef],
  *,
  content: dict | None = None,
  confidence: float = 0.8,
) -> None:
  edge_id = f"edge:{source}:{edge_type}:{target}"
  edges[edge_id] = GraphEdge(
    id=edge_id,
    type=edge_type,
    source=source,
    target=target,
    scope=scope,
    source_refs=source_refs,
    allowed_use=allowed_use,
    confidence=confidence,
    lifecycle="raw",
    created_from="dataset_import",
    content=content or {},
  )
