from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnversion.stage2_rci_navigation.vet_schema import RootCauseVet, VetEvidenceRef, VetPattern
from vulnversion.vulngraph_judge.builder import build_per_cve_graph_from_vet
from vulnversion.vulngraph_judge.learning import candidate_memories_from_failure
from vulnversion.vulngraph_judge.packets import build_root_cause_packet, build_target_packet
from vulnversion.vulngraph_judge.schema import GraphDocument, GraphEdge, GraphNode, SourceRef
from vulnversion.vulngraph_judge.store import JudgeGraphStore


def _src(kind: str = "fixture") -> SourceRef:
  return SourceRef(kind=kind, ref="tests://vulngraph")


def _node(
  node_id: str,
  node_type: str,
  *,
  scope: str = "cve",
  allowed_use: str = "context_only",
  lifecycle: str = "raw",
  content: dict | None = None,
) -> GraphNode:
  return GraphNode(
    id=node_id,
    type=node_type,
    scope=scope,
    source_refs=[_src()],
    allowed_use=allowed_use,
    confidence=0.8,
    lifecycle=lifecycle,
    created_from="unit-test",
    content=content or {},
  )


def _edge(edge_id: str, edge_type: str, source: str, target: str) -> GraphEdge:
  return GraphEdge(
    id=edge_id,
    type=edge_type,
    source=source,
    target=target,
    scope="cve",
    source_refs=[_src()],
    allowed_use="root_cause_evidence",
    confidence=0.8,
    lifecycle="raw",
    created_from="unit-test",
  )


def test_node_and_edge_require_core_metadata():
  with pytest.raises(ValidationError):
    GraphNode.model_validate(
      {
        "id": "n1",
        "type": "CVE",
        "scope": "cve",
        "allowed_use": "context_only",
        "confidence": 0.5,
        "lifecycle": "raw",
        "created_from": "bad-fixture",
      }
    )

  with pytest.raises(ValidationError):
    GraphEdge.model_validate(
      {
        "id": "e1",
        "type": "fixed_by",
        "source": "cve:CVE-TEST",
        "target": "commit:fix",
        "scope": "cve",
        "source_refs": [{"kind": "fixture", "ref": "tests://edge"}],
        "allowed_use": "root_cause_evidence",
        "confidence": 0.5,
        "lifecycle": "raw",
      }
    )


def test_root_cause_packet_contains_vet_context_but_excludes_candidate_learning():
  doc = GraphDocument(
    nodes=[
      _node("cve:CVE-TEST", "CVE", content={"description": "bounds bug"}),
      _node("cwe:CWE-20", "CWE", scope="cwe", content={"name": "Improper Input Validation"}),
      _node("commit:fix", "FixCommit", allowed_use="root_cause_evidence"),
      _node("hunk:fix:1", "PatchHunk", allowed_use="root_cause_evidence"),
      _node("pred:vuln", "VulnerablePredicate", allowed_use="root_cause_evidence"),
      _node("guard:fix", "GuardCondition", allowed_use="root_cause_evidence"),
      _node("repo-memory:candidate", "RepoMemory", scope="repo", allowed_use="navigation_only", lifecycle="candidate"),
    ],
    edges=[
      _edge("e1", "fixed_by", "cve:CVE-TEST", "commit:fix"),
      _edge("e2", "modifies", "commit:fix", "hunk:fix:1"),
      _edge("e3", "requires", "theorem:root", "pred:vuln"),
    ],
  )

  packet = build_root_cause_packet(doc, repo="repo", cve_id="CVE-TEST")

  assert packet.task == "root_cause_extraction"
  assert "repo-memory:candidate" not in {n.id for n in packet.context_nodes}
  assert "hunk:fix:1" in {n.id for n in packet.root_cause_evidence_nodes}
  assert "pred:vuln" in {n.id for n in packet.root_cause_evidence_nodes}
  assert packet.forbidden_context == [
    "ground_truth_affected_versions",
    "version_planning_state",
    "neighbor_target_verdicts",
    "affected_range_aggregation",
  ]


def test_target_packet_keeps_only_admissible_sections():
  doc = GraphDocument(
    nodes=[
      _node("cve:CVE-TEST", "CVE", content={"description": "bounds bug"}),
      _node("theorem:root", "RootCauseTheorem", allowed_use="root_cause_evidence"),
      _node("pred:vuln", "VulnerablePredicate", allowed_use="root_cause_evidence"),
      _node("anchor:main", "Anchor", allowed_use="root_cause_evidence"),
      _node("repo-memory:validated", "RepoMemory", scope="repo", allowed_use="navigation_only", lifecycle="validated"),
      _node("skill:cwe20", "SkillProcedure", scope="cwe", allowed_use="procedure_only", lifecycle="validated"),
      _node("gt:forbidden", "TargetVerdict", scope="experiment", allowed_use="offline_eval_only", lifecycle="validated"),
      _node("memory:candidate", "CWEMemory", scope="cwe", allowed_use="procedure_only", lifecycle="candidate"),
    ],
    edges=[
      _edge("e1", "requires", "theorem:root", "pred:vuln"),
      _edge("e2", "anchored_by", "pred:vuln", "anchor:main"),
    ],
  )

  packet = build_target_packet(doc, repo="repo", cve_id="CVE-TEST", target="v1.0.0")

  assert packet.task == "target_judgement"
  assert packet.target == "v1.0.0"
  assert "repo-memory:validated" in {n.id for n in packet.navigation_hints}
  assert "skill:cwe20" in {n.id for n in packet.procedure_hints}
  assert "memory:candidate" not in {n.id for n in packet.procedure_hints}
  assert "gt:forbidden" not in {n.id for n in packet.context_nodes}
  assert packet.required_target_evidence_allowed_use == "target_verdict_evidence"


def test_candidate_memories_from_failure_are_not_packet_eligible_by_default():
  failure = _node(
    "failure:CVE-TEST:v1.0.0",
    "FailureCase",
    scope="target",
    allowed_use="context_only",
    lifecycle="raw",
    content={
      "repo": "repo",
      "cwe_id": "CWE-20",
      "target": "v1.0.0",
      "summary": "path rename caused anchor miss",
      "suggested_repo_memory": "check renamed parser path with git log --follow",
      "suggested_cwe_memory": "CWE-20 needs local input validation guard evidence",
    },
  )

  memories = candidate_memories_from_failure(failure)

  assert {m.type for m in memories} == {"RepoMemory", "CWEMemory"}
  assert all(m.lifecycle == "candidate" for m in memories)
  assert all(m.source_refs for m in memories)

  doc = GraphDocument(nodes=memories, edges=[])
  packet = build_target_packet(doc, repo="repo", cve_id="CVE-TEST", target="v1.0.0")
  assert packet.navigation_hints == []
  assert packet.procedure_hints == []


def test_store_appends_nodes_edges_and_observations(tmp_path: Path):
  store = JudgeGraphStore(tmp_path)
  node = _node("cve:CVE-TEST", "CVE")
  edge = _edge("e1", "fixed_by", "cve:CVE-TEST", "commit:fix")
  observation = _node(
    "obs:CVE-TEST:v1.0.0",
    "GitObservation",
    scope="target",
    allowed_use="target_verdict_evidence",
    content={"target": "v1.0.0", "snippet": "if (len > max) return;"},
  )

  store.append_node("repo", "CVE-TEST", node)
  store.append_edge("repo", "CVE-TEST", edge)
  store.append_observation("repo", "CVE-TEST", observation)

  graph = store.load_graph("repo", "CVE-TEST")
  assert [n.id for n in graph.nodes] == ["cve:CVE-TEST"]
  assert [e.id for e in graph.edges] == ["e1"]

  observations = [
    json.loads(line)
    for line in (tmp_path / "per_cve_graph" / "repo" / "CVE-TEST" / "observations.jsonl").read_text(encoding="utf-8").splitlines()
  ]
  assert observations[0]["id"] == "obs:CVE-TEST:v1.0.0"


def test_build_per_cve_graph_from_vet_materializes_theta_terms():
  vet = RootCauseVet(
    cve_id="CVE-TEST",
    repo="repo",
    root_cause_summary="unchecked parser length reaches memcpy",
    root_cause_files=[
      VetPattern(
        pattern_id="file-main",
        kind="file",
        value="lib/parser.c",
        strength="strong",
        evidence=[VetEvidenceRef(source="patch", ref="commit:abc123", snippet="lib/parser.c")],
      )
    ],
    vulnerable_sequences=[
      VetPattern(
        pattern_id="vuln-copy",
        kind="vulnerable_sequence",
        value="memcpy(dst, src, len)",
        scope_files=["lib/parser.c"],
        strength="strong",
        allowed_uses=["priority", "prompt_context", "certificate_candidate"],
        evidence=[VetEvidenceRef(source="patch", ref="commit:abc123^", snippet="memcpy(dst, src, len)")],
      )
    ],
    fix_guards=[
      VetPattern(
        pattern_id="fix-bounds",
        kind="fix_guard",
        value="if (len > dst_len) return ERR;",
        scope_files=["lib/parser.c"],
        strength="strong",
        evidence=[VetEvidenceRef(source="patch", ref="commit:abc123", snippet="len > dst_len")],
      )
    ],
    negative_applicability_conditions=[
      VetPattern(
        pattern_id="guard-feature-off",
        kind="negative_condition",
        value="feature disabled at compile time",
        scope_files=["lib/parser.c"],
        strength="medium",
      )
    ],
    grep_patterns=[
      VetPattern(
        pattern_id="anchor-copy",
        kind="grep_pattern",
        value="memcpy(dst, src, len)",
        scope_files=["lib/parser.c"],
        strength="medium",
      )
    ],
    git_log_sg_queries=[
      VetPattern(
        pattern_id="query-copy",
        kind="git_log_sg_query",
        value="-S'memcpy(dst, src, len)' -- lib/parser.c",
      )
    ],
  )

  graph = build_per_cve_graph_from_vet(
    vet,
    fix_commit="abc123",
    cwe_id="CWE-787",
    cve_description="Out-of-bounds parser copy",
  )

  by_type = {node.type: node for node in graph.nodes}
  theorem = by_type["RootCauseTheorem"]
  theta = theorem.content["theta"]

  assert theta["S"]
  assert theta["V"]
  assert theta["F"]
  assert theta["G"]
  assert theta["C"]["default_use"] == "priority_only"
  assert {"CVE", "CWE", "FixCommit", "Scope", "VulnerablePredicate", "FixPredicate", "NegativeApplicabilityCondition", "Anchor", "RepoNavigationHint"} <= {node.type for node in graph.nodes}
  assert {"has_cwe", "fixed_by", "has_scope", "requires", "blocked_by", "anchored_by", "suggests"} <= {edge.type for edge in graph.edges}
  assert all(node.allowed_use != "target_verdict_evidence" for node in graph.nodes)


def test_vet_graph_feeds_target_packet_without_candidate_or_gt_context():
  vet = RootCauseVet(
    cve_id="CVE-TEST",
    repo="repo",
    root_cause_summary="missing bounds check",
    root_cause_files=[VetPattern(pattern_id="file-main", kind="file", value="lib/parser.c")],
    vulnerable_sequences=[VetPattern(pattern_id="vuln-copy", kind="vulnerable_sequence", value="memcpy(dst, src, len)")],
    fix_guards=[VetPattern(pattern_id="fix-bounds", kind="fix_guard", value="if (len > dst_len) return ERR;")],
    git_log_sg_queries=[VetPattern(pattern_id="query-copy", kind="git_log_sg_query", value="-S'memcpy(dst, src, len)'")],
  )
  graph = build_per_cve_graph_from_vet(vet, fix_commit="abc123")
  graph.nodes.append(
    _node("gt:should-not-enter", "TargetVerdict", scope="experiment", allowed_use="offline_eval_only", lifecycle="validated")
  )

  packet = build_target_packet(graph, repo="repo", cve_id="CVE-TEST", target="v1.0.0")

  assert "theorem:CVE-TEST" in {node.id for node in packet.root_cause_evidence_nodes}
  assert "repo-nav:CVE-TEST:query-copy" in {node.id for node in packet.navigation_hints}
  assert "gt:should-not-enter" not in {node.id for node in packet.context_nodes}
  assert packet.required_target_evidence_allowed_use == "target_verdict_evidence"
