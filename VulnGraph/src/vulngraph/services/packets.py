from __future__ import annotations

from typing import Any, Literal

from vulngraph.schema import GraphDocument, GraphNode

from .common import node_to_dict


PacketMode = Literal["production", "debug"]

CONTEXT_TYPES = {"CVE", "CWE", "CAPEC", "Reference", "Advisory", "ProductHint"}
PATCH_EVIDENCE_TYPES = {"FixCommit", "PatchHunk", "ChangedFile", "ChangedFunction", "Function", "CodeAnchor"}
REPO_NAV_TYPES = {"Repo", "File", "PathAlias", "RepoComponent", "FilePath", "FunctionSymbol", "Symbol"}
ROOT_CAUSE_TYPES = {
  "RootCauseHypothesis",
  "VulnerablePredicate",
  "FixPredicate",
  "GuardCondition",
  "NegativeCondition",
  "NegativeApplicabilityCondition",
  "CodeAnchor",
}
MEMORY_TYPES = {"MemoryCandidate", "RepoMemory", "CWEMemory", "PredicateMemory", "ProcedureMemory", "SkillProcedure"}

FORBIDDEN_CONTEXT = [
  "affected_version/offline_eval_only",
  "target verdicts as root-cause evidence",
  "neighbor CVE verdicts",
  "version planning state",
  "affected-range aggregation",
]


def get_cve_graph(graph: GraphDocument, cve_id: str, *, include_debug: bool = False) -> dict[str, Any]:
  nodes = _cve_nodes(graph, cve_id, include_debug=include_debug)
  by_type: dict[str, list[dict[str, Any]]] = {}
  for node in nodes:
    by_type.setdefault(node.type, []).append(node_to_dict(node))
  return {
    "cve": _first(by_type.get("CVE", [])),
    "cwe": by_type.get("CWE", []),
    "references": by_type.get("Reference", []),
    "advisories": by_type.get("Advisory", []),
    "repo": _first(by_type.get("Repo", [])),
    "fix_commits": by_type.get("FixCommit", []),
    "patch_hunks": by_type.get("PatchHunk", []),
    "changed_files": by_type.get("ChangedFile", []) + by_type.get("File", []),
    "changed_functions": by_type.get("ChangedFunction", []) + by_type.get("Function", []),
    "code_anchors": by_type.get("CodeAnchor", []),
    "existing_root_causes": by_type.get("RootCauseHypothesis", []),
    "agent_runs": _agent_run_summary(nodes),
    "memory_candidates": _memory_candidates(nodes) if include_debug else [],
  }


def build_root_cause_packet(
  graph: GraphDocument,
  cve_id: str,
  *,
  mode: PacketMode = "production",
) -> dict[str, Any]:
  include_debug = mode == "debug"
  nodes = _packet_eligible(_cve_nodes(graph, cve_id, include_debug=include_debug), mode=mode)
  return {
    "task": "root_cause_extraction",
    "mode": mode,
    "cve_id": cve_id,
    "context": [
      _packet_node_to_dict(node, cve_id)
      for node in nodes
      if node.type in CONTEXT_TYPES and node.allowed_use in {"context_only", "procedure_only"}
    ],
    "patch_evidence": [
      _packet_node_to_dict(node, cve_id)
      for node in nodes
      if node.type in PATCH_EVIDENCE_TYPES
      and node.allowed_use in {"root_cause_evidence", "navigation_only"}
      and not (node.type == "CodeAnchor" and node.created_from == "service_ingestion")
    ],
    "repo_navigation": [
      _packet_node_to_dict(node, cve_id)
      for node in nodes
      if node.type in REPO_NAV_TYPES and node.allowed_use in {"context_only", "navigation_only"}
    ],
    "procedure_hints": [
      _packet_node_to_dict(node, cve_id)
      for node in nodes
      if node.type == "ProcedureMemory"
      and node.allowed_use == "procedure_only"
      and node.lifecycle == "validated"
    ],
    "output_contract": {
      "required": [
        "RootCauseHypothesis",
        "VulnerablePredicate",
        "FixPredicate",
        "GuardCondition",
        "CodeAnchor",
      ],
      "evidence_gate": "RootCauseHypothesis and each referenced semantic node must share wrapper-owned GitObservation evidence; multi-fix outputs must map every FixCommit to a PatchHunk and CodeAnchor.",
      "risk_flag_policy": "RiskFlag is learning_candidate/context only and cannot be root cause evidence by default.",
    },
    "forbidden": list(FORBIDDEN_CONTEXT),
  }


def build_judge_packet(
  graph: GraphDocument,
  cve_id: str,
  target_id: str,
  *,
  repo_ref: str | None = None,
  mode: PacketMode = "production",
) -> dict[str, Any]:
  include_debug = mode == "debug"
  nodes = _packet_eligible(_cve_nodes(graph, cve_id, include_debug=include_debug), mode=mode)
  hypotheses = sorted(
    [node for node in nodes if node.type == "RootCauseHypothesis" and node.allowed_use == "root_cause_evidence"],
    key=lambda node: (node.lifecycle == "validated", node.updated_at, node.confidence),
    reverse=True,
  )
  selected_hypothesis = hypotheses[0] if hypotheses else None
  closure_ids = _hypothesis_closure_ids(graph, selected_hypothesis.id) if selected_hypothesis else set()
  anchors = sorted(
    [node for node in nodes if node.id in closure_ids and node.type == "CodeAnchor" and node.allowed_use == "root_cause_evidence"],
    key=lambda node: node.confidence,
    reverse=True,
  )
  predicates = [
    node
    for node in nodes
    if node.id in closure_ids and node.type in {"VulnerablePredicate", "FixPredicate", "GuardCondition", "NegativeCondition", "NegativeApplicabilityCondition"}
  ]
  return {
    "task": "target_judgement",
    "mode": mode,
    "cve_id": cve_id,
    "target": {"target_id": target_id, "repo_ref": repo_ref},
    "repo": _repo_info(nodes),
    "root_cause_hypothesis": _packet_node_to_dict(selected_hypothesis, cve_id) if selected_hypothesis else None,
    "code_anchors": [_packet_node_to_dict(node, cve_id) for node in anchors[:10]],
    "predicates": [_packet_node_to_dict(node, cve_id) for node in predicates],
    "recommended_git_operations": [
      "git show <target>:<path>",
      "git grep <anchor tokens> <target>",
      "git blame <target> -- <path>",
      "git merge-base --is-ancestor <commit> <target>",
    ],
    "candidate_paths": sorted({str(node.content.get("path")) for node in nodes if node.content.get("path")}),
    "candidate_functions": sorted({str(node.content.get("symbol")) for node in nodes if node.content.get("symbol")}),
    "required_evidence_schema": {
      "GitObservation": ["target_id", "path", "claim", "snippet", "command_ref"],
      "PredicateEvaluation": ["predicate_id", "result", "observation_ids"],
      "TargetVerdict": ["target_id", "verdict", "evidence_evaluation_ids"],
      "final_verdict_requires": "target-local GitObservation",
    },
    "forbidden": [
      "CVE/CWE/CAPEC as final verdict evidence",
      "offline_eval_only affected_version labels",
      "neighbor CVE verdicts",
      "target verdict without target-local GitObservation",
    ],
  }


def _packet_eligible(nodes: list[GraphNode], *, mode: PacketMode) -> list[GraphNode]:
  allowed_lifecycles = {"raw", "validated"} if mode == "production" else {"raw", "candidate", "validated"}
  filtered = []
  for node in nodes:
    if node.lifecycle not in allowed_lifecycles:
      continue
    if node.allowed_use == "offline_eval_only":
      continue
    if mode == "production" and node.allowed_use == "learning_candidate":
      continue
    if node.type == "TargetVerdict":
      continue
    filtered.append(node)
  return filtered


def _hypothesis_closure_ids(graph: GraphDocument, hypothesis_id: str) -> set[str]:
  closure: set[str] = set()
  predicate_ids: set[str] = set()
  for edge in graph.edges:
    if edge.source != hypothesis_id or edge.lifecycle not in {"raw", "validated"}:
      continue
    if edge.type in {"requires", "blocked_by", "constrained_by", "excluded_by"}:
      predicate_ids.add(edge.target)
      closure.add(edge.target)
    elif edge.type == "anchored_by":
      closure.add(edge.target)
  for edge in graph.edges:
    if edge.source in predicate_ids and edge.type == "anchored_by" and edge.lifecycle in {"raw", "validated"}:
      closure.add(edge.target)
  return closure


def _cve_nodes(graph: GraphDocument, cve_id: str, *, include_debug: bool) -> list[GraphNode]:
  nodes_by_id = {node.id: node for node in graph.nodes}
  selected_ids: set[str] = {f"cve:{cve_id}"}
  changed = True
  while changed:
    changed = False
    for edge in graph.edges:
      if edge.source in selected_ids and edge.target not in selected_ids:
        selected_ids.add(edge.target)
        changed = True
      if edge.target in selected_ids and edge.source not in selected_ids and edge.type in {"supports", "contradicts", "requires", "blocked_by", "constrained_by", "excluded_by", "anchored_by"}:
        selected_ids.add(edge.source)
        changed = True
  for node in graph.nodes:
    if str(node.content.get("cve_id") or "") == cve_id:
      selected_ids.add(node.id)
    if include_debug and node.type in MEMORY_TYPES and str(node.content.get("cve_id") or "") == cve_id:
      selected_ids.add(node.id)
  return [nodes_by_id[node_id] for node_id in selected_ids if node_id in nodes_by_id]


def _first(items: list[dict[str, Any]]) -> dict[str, Any] | None:
  return items[0] if items else None


def _packet_node_to_dict(node: GraphNode, cve_id: str) -> dict[str, Any]:
  data = node_to_dict(node)
  content = dict(data.get("content") or {})
  for key in list(content):
    if key.lower().startswith("affected_version"):
      content.pop(key, None)
  data["content"] = content

  current_dataset_ref = f"dataset:{cve_id}"
  data["source_refs"] = [
    ref
    for ref in data.get("source_refs", [])
    if not (
      ref.get("kind") == "dataset"
      and str(ref.get("ref") or "").startswith("dataset:CVE-")
      and ref.get("ref") != current_dataset_ref
    )
  ]
  return data


def _agent_run_summary(nodes: list[GraphNode]) -> list[dict[str, Any]]:
  return [
    {
      "id": node.id,
      "lifecycle": node.lifecycle,
      "backend": node.content.get("backend"),
      "run_id": node.content.get("run_id"),
      "stage": node.content.get("stage"),
    }
    for node in nodes
    if node.type == "AgentRun"
  ]


def _memory_candidates(nodes: list[GraphNode]) -> list[dict[str, Any]]:
  return [node_to_dict(node) for node in nodes if node.type in MEMORY_TYPES and node.lifecycle == "candidate"]


def _repo_info(nodes: list[GraphNode]) -> dict[str, Any] | None:
  repos = [node for node in nodes if node.type == "Repo"]
  if not repos:
    return None
  return node_to_dict(repos[0])
