from __future__ import annotations

from pydantic import BaseModel, Field

from vulngraph.schema import GraphDocument, GraphEdge, GraphNode, SourceRef


class SeedGraphInput(BaseModel):
  cve_id: str
  repo: str
  cwe_id: str | None = None
  cve_description: str = ""
  fix_commit: str | None = None
  root_cause_hypothesis: str | None = None
  references: list[str] = Field(default_factory=list)
  product_hints: list[str] = Field(default_factory=list)


def build_seed_graph(seed: SeedGraphInput) -> GraphDocument:
  source_refs = [SourceRef(kind="manual_seed", ref=f"seed:{seed.cve_id}", snippet=seed.cve_description or None)]
  nodes: list[GraphNode] = []
  edges: list[GraphEdge] = []

  def node(
    node_id: str,
    node_type: str,
    *,
    scope: str = "cve",
    allowed_use: str = "context_only",
    confidence: float = 0.7,
    content: dict | None = None,
  ) -> None:
    nodes.append(
      GraphNode(
        id=node_id,
        type=node_type,
        scope=scope,
        source_refs=source_refs,
        allowed_use=allowed_use,
        confidence=confidence,
        lifecycle="raw",
        created_from="manual_seed",
        content=content or {},
      )
    )

  def edge(edge_type: str, source: str, target: str, *, allowed_use: str = "context_only") -> None:
    edges.append(
      GraphEdge(
        id=f"edge:{seed.cve_id}:{len(edges) + 1}:{edge_type}",
        type=edge_type,
        source=source,
        target=target,
        scope="cve",
        source_refs=source_refs,
        allowed_use=allowed_use,
        confidence=0.7,
        lifecycle="raw",
        created_from="manual_seed",
      )
    )

  cve_id = f"cve:{seed.cve_id}"
  repo_id = f"repo:{seed.repo}"
  node(cve_id, "CVE", content={"cve_id": seed.cve_id, "description": seed.cve_description})
  node(repo_id, "Repo", scope="repo", content={"repo": seed.repo})

  if seed.cwe_id:
    cwe_id = f"cwe:{seed.cwe_id}"
    node(cwe_id, "CWE", scope="cwe", content={"cwe_id": seed.cwe_id})
    edge("has_cwe", cve_id, cwe_id)

  if seed.fix_commit:
    commit_id = f"fix-commit:{seed.fix_commit}"
    node(commit_id, "FixCommit", allowed_use="root_cause_evidence", content={"commit": seed.fix_commit})
    edge("fixed_by", cve_id, commit_id, allowed_use="root_cause_evidence")

  if seed.root_cause_hypothesis:
    hypothesis_id = f"hypothesis:{seed.cve_id}"
    node(
      hypothesis_id,
      "RootCauseHypothesis",
      allowed_use="root_cause_evidence",
      content={"hypothesis": seed.root_cause_hypothesis},
    )
    edge("requires", hypothesis_id, cve_id, allowed_use="root_cause_evidence")

  for index, ref in enumerate(seed.references):
    ref_id = f"reference:{seed.cve_id}:{index + 1}"
    node(ref_id, "Reference", content={"url": ref})
    edge("has_reference", cve_id, ref_id)

  for index, hint in enumerate(seed.product_hints):
    hint_id = f"product:{seed.cve_id}:{index + 1}"
    node(hint_id, "ProductHint", content={"hint": hint})
    edge("affects_product_hint", cve_id, hint_id)

  return GraphDocument(nodes=nodes, edges=edges)
