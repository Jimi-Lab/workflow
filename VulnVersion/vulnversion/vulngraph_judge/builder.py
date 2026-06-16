from __future__ import annotations

import re
from typing import Any

from vulnversion.stage2_rci_navigation.vet_schema import RootCauseVet, VetPattern

from .schema import GraphDocument, GraphEdge, GraphNode, SourceRef


_STRENGTH_CONFIDENCE = {
  "strong": 0.9,
  "medium": 0.6,
  "weak": 0.35,
}


def build_per_cve_graph_from_vet(
  vet: RootCauseVet,
  *,
  fix_commit: str | None = None,
  cwe_id: str | None = None,
  cve_description: str | None = None,
) -> GraphDocument:
  """Materialize a Per-CVE Judge Graph from the Step2 RootCauseVet contract."""

  nodes: list[GraphNode] = []
  edges: list[GraphEdge] = []
  edge_counter = 0
  base_refs = [_base_source_ref(vet)]
  cve_node_id = f"cve:{vet.cve_id}"
  theorem_id = f"theorem:{vet.cve_id}"

  def add_node(node: GraphNode) -> str:
    nodes.append(node)
    return node.id

  def add_edge(
    edge_type: str,
    source: str,
    target: str,
    *,
    allowed_use: str = "root_cause_evidence",
    source_refs: list[SourceRef] | None = None,
    confidence: float = 0.7,
    content: dict[str, Any] | None = None,
  ) -> str:
    nonlocal edge_counter
    edge_counter += 1
    edge = GraphEdge(
      id=f"edge:{vet.cve_id}:{edge_counter}:{edge_type}",
      type=edge_type,
      source=source,
      target=target,
      scope="cve",
      source_refs=source_refs or base_refs,
      allowed_use=allowed_use,
      confidence=confidence,
      lifecycle="raw",
      created_from="root_cause_vet",
      content=content or {},
    )
    edges.append(edge)
    return edge.id

  add_node(
    GraphNode(
      id=cve_node_id,
      type="CVE",
      scope="cve",
      source_refs=base_refs,
      allowed_use="context_only",
      confidence=0.8,
      lifecycle="raw",
      created_from="root_cause_vet",
      content={
        "cve_id": vet.cve_id,
        "repo": vet.repo,
        "description": cve_description or "",
      },
    )
  )

  if cwe_id:
    cwe_node_id = f"cwe:{cwe_id}"
    add_node(
      GraphNode(
        id=cwe_node_id,
        type="CWE",
        scope="cwe",
        source_refs=base_refs,
        allowed_use="context_only",
        confidence=0.6,
        lifecycle="raw",
        created_from="root_cause_vet",
        content={"cwe_id": cwe_id},
      )
    )
    add_edge("has_cwe", cve_node_id, cwe_node_id, allowed_use="context_only", confidence=0.6)

  if fix_commit:
    fix_node_id = f"commit:{fix_commit}"
    add_node(
      GraphNode(
        id=fix_node_id,
        type="FixCommit",
        scope="cve",
        source_refs=base_refs,
        allowed_use="root_cause_evidence",
        confidence=0.8,
        lifecycle="raw",
        created_from="root_cause_vet",
        content={"commit": fix_commit, "repo": vet.repo},
      )
    )
    add_edge("fixed_by", cve_node_id, fix_node_id)

  scope_ids = _pattern_nodes(
    vet,
    groups=[
      ("root_cause_files", vet.root_cause_files),
      ("root_cause_functions", vet.root_cause_functions),
      ("component_scope", vet.component_scope),
      ("feature_introduction_clues", vet.feature_introduction_clues),
    ],
    node_type="Scope",
    id_prefix="scope",
    allowed_use="root_cause_evidence",
    nodes=nodes,
  )
  vuln_ids = _pattern_nodes(
    vet,
    groups=[("vulnerable_sequences", vet.vulnerable_sequences)],
    node_type="VulnerablePredicate",
    id_prefix="vuln-pred",
    allowed_use="root_cause_evidence",
    nodes=nodes,
  )
  fix_ids = _pattern_nodes(
    vet,
    groups=[("fix_guards", vet.fix_guards)],
    node_type="FixPredicate",
    id_prefix="fix-pred",
    allowed_use="root_cause_evidence",
    nodes=nodes,
  )
  guard_ids = _pattern_nodes(
    vet,
    groups=[("negative_applicability_conditions", vet.negative_applicability_conditions)],
    node_type="NegativeApplicabilityCondition",
    id_prefix="negative",
    allowed_use="root_cause_evidence",
    nodes=nodes,
  )
  anchor_ids = _pattern_nodes(
    vet,
    groups=[("grep_patterns", vet.grep_patterns)],
    node_type="Anchor",
    id_prefix="anchor",
    allowed_use="root_cause_evidence",
    nodes=nodes,
  )
  navigation_ids = _pattern_nodes(
    vet,
    groups=[("git_log_sg_queries", vet.git_log_sg_queries)],
    node_type="RepoNavigationHint",
    id_prefix="repo-nav",
    allowed_use="navigation_only",
    nodes=nodes,
  )

  add_node(
    GraphNode(
      id=theorem_id,
      type="RootCauseTheorem",
      scope="cve",
      source_refs=base_refs,
      allowed_use="root_cause_evidence",
      confidence=_theorem_confidence(vet),
      lifecycle="raw",
      created_from="root_cause_vet",
      content={
        "cve_id": vet.cve_id,
        "repo": vet.repo,
        "summary": vet.root_cause_summary,
        "theta": {
          "S": scope_ids,
          "V": vuln_ids,
          "F": fix_ids,
          "G": guard_ids,
          "C": vet.certificate_policy,
        },
      },
    )
  )

  for scope_id in scope_ids:
    add_edge("has_scope", theorem_id, scope_id)
  for vuln_id in vuln_ids:
    add_edge("requires", theorem_id, vuln_id)
  for fix_id in fix_ids:
    add_edge("blocked_by", theorem_id, fix_id)
  for guard_id in guard_ids:
    add_edge("constrained_by", theorem_id, guard_id)
    for scope_id in scope_ids:
      add_edge("excludes", guard_id, scope_id)
  for vuln_id in vuln_ids:
    for anchor_id in anchor_ids:
      add_edge("anchored_by", vuln_id, anchor_id)
  for nav_id in navigation_ids:
    add_edge("suggests", nav_id, theorem_id, allowed_use="navigation_only", confidence=0.5)

  return GraphDocument(nodes=nodes, edges=edges)


def _pattern_nodes(
  vet: RootCauseVet,
  *,
  groups: list[tuple[str, list[VetPattern]]],
  node_type: str,
  id_prefix: str,
  allowed_use: str,
  nodes: list[GraphNode],
) -> list[str]:
  node_ids: list[str] = []
  for group_name, patterns in groups:
    for pattern in patterns:
      node_id = f"{id_prefix}:{vet.cve_id}:{_safe(pattern.pattern_id)}"
      nodes.append(
        GraphNode(
          id=node_id,
          type=node_type,
          scope="cve",
          source_refs=_pattern_source_refs(vet, pattern),
          allowed_use=allowed_use,
          confidence=_STRENGTH_CONFIDENCE.get(pattern.strength, 0.4),
          lifecycle="raw",
          created_from="root_cause_vet",
          content={
            "pattern_group": group_name,
            "pattern_id": pattern.pattern_id,
            "kind": pattern.kind,
            "value": pattern.value,
            "scope_files": pattern.scope_files,
            "strength": pattern.strength,
            "allowed_uses": pattern.allowed_uses,
            "notes": pattern.notes,
          },
        )
      )
      node_ids.append(node_id)
  return node_ids


def _pattern_source_refs(vet: RootCauseVet, pattern: VetPattern) -> list[SourceRef]:
  refs = [
    SourceRef(
      kind=evidence.source or "vet_evidence",
      ref=evidence.ref or f"vet:{vet.cve_id}:{pattern.pattern_id}",
      snippet=evidence.snippet or None,
    )
    for evidence in pattern.evidence
  ]
  if refs:
    return refs
  return [
    SourceRef(
      kind="root_cause_vet",
      ref=f"vet:{vet.cve_id}:{pattern.pattern_id}",
      snippet=pattern.value,
    )
  ]


def _base_source_ref(vet: RootCauseVet) -> SourceRef:
  return SourceRef(
    kind="root_cause_vet",
    ref=f"vet:{vet.cve_id}",
    snippet=vet.root_cause_summary or None,
  )


def _theorem_confidence(vet: RootCauseVet) -> float:
  total = vet.confidence.get("total") if isinstance(vet.confidence, dict) else None
  if isinstance(total, int | float):
    return max(0.0, min(1.0, float(total)))
  return 0.7


def _safe(value: str) -> str:
  return re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip() or "unknown")
