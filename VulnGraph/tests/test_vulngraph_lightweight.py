from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vulngraph.agent_io import AgentOutput, agent_output_to_events
from vulngraph.builder import SeedGraphInput, build_seed_graph
from vulngraph.evolution import candidate_memories_from_failure
from vulngraph.packets import build_target_packet
from vulngraph.schema import GraphDocument, GraphEdge, GraphEvent, GraphNode, SourceRef
from vulngraph.store import JsonlGraphStore


def _src() -> SourceRef:
  return SourceRef(kind="test", ref="tests://vulngraph")


def _node(
  node_id: str,
  node_type: str,
  *,
  allowed_use: str = "context_only",
  lifecycle: str = "raw",
  content: dict | None = None,
) -> GraphNode:
  return GraphNode(
    id=node_id,
    type=node_type,
    scope="cve",
    source_refs=[_src()],
    allowed_use=allowed_use,
    confidence=0.8,
    lifecycle=lifecycle,
    created_from="unit-test",
    content=content or {},
  )


def test_graph_node_and_edge_require_core_metadata():
  with pytest.raises(ValidationError):
    GraphNode.model_validate(
      {
        "id": "cve:CVE-TEST",
        "type": "CVE",
        "scope": "cve",
        "allowed_use": "context_only",
        "confidence": 0.8,
        "lifecycle": "raw",
        "created_from": "bad-fixture",
      }
    )

  with pytest.raises(ValidationError):
    GraphEdge.model_validate(
      {
        "id": "edge:1",
        "type": "has_cwe",
        "source": "cve:CVE-TEST",
        "target": "cwe:CWE-787",
        "scope": "cve",
        "source_refs": [{"kind": "test", "ref": "tests://edge"}],
        "allowed_use": "context_only",
        "confidence": 0.8,
        "lifecycle": "raw",
      }
    )


def test_seed_graph_and_packet_filtering_keep_candidate_out():
  graph = build_seed_graph(
    SeedGraphInput(
      cve_id="CVE-TEST",
      repo="demo",
      cwe_id="CWE-787",
      cve_description="Out-of-bounds copy",
      fix_commit="abc123",
      root_cause_hypothesis="unchecked length reaches copy operation",
    )
  )
  graph.nodes.append(
    _node(
      "memory:candidate",
      "RepoMemory",
      allowed_use="learning_candidate",
      lifecycle="candidate",
    )
  )
  graph.nodes.append(
    _node(
      "gt:offline",
      "TargetVerdict",
      allowed_use="offline_eval_only",
      lifecycle="validated",
    )
  )

  packet = build_target_packet(graph, cve_id="CVE-TEST", target="v1.0.0", repo="demo")

  assert "cve:CVE-TEST" in {node.id for node in packet.context_nodes}
  assert "hypothesis:CVE-TEST" in {node.id for node in packet.root_cause_evidence_nodes}
  assert "memory:candidate" not in packet.all_node_ids()
  assert "gt:offline" not in packet.all_node_ids()
  assert packet.forbidden_context == [
    "ground_truth_affected_versions",
    "version_planning_state",
    "neighbor_target_verdicts",
    "affected_range_aggregation",
  ]


def test_jsonl_store_appends_events_and_materializes_snapshot(tmp_path: Path):
  store = JsonlGraphStore(tmp_path)
  node = _node("cve:CVE-TEST", "CVE")
  event = GraphEvent.upsert_node(node, created_from="unit-test")

  store.append_event(event)
  graph = store.materialize()
  store.write_snapshot(graph)

  assert [event.event_type for event in store.load_events()] == ["upsert_node"]
  assert [node.id for node in graph.nodes] == ["cve:CVE-TEST"]
  assert (tmp_path / "events.jsonl").exists()
  assert (tmp_path / "nodes.jsonl").exists()


def test_agent_output_becomes_auditable_graph_events():
  output = AgentOutput.model_validate(
    {
      "agent_run": {
        "run_id": "run-1",
        "cve_id": "CVE-TEST",
        "repo": "demo",
        "target": "v1.0.0",
      },
      "command_invocations": [
        {
          "invocation_id": "cmd-1",
          "step_id": "step-1",
          "command": "git show v1.0.0:lib/parser.c",
          "output": {"output_id": "out-1", "text": "memcpy(dst, src, len)"},
        }
      ],
      "git_observations": [
        {
          "observation_id": "obs-1",
          "command_ref": "cmd-1",
          "target": "v1.0.0",
          "path": "lib/parser.c",
          "claim": "vulnerable copy exists",
          "snippet": "memcpy(dst, src, len)",
        }
      ],
      "predicate_evaluations": [
        {
          "evaluation_id": "eval-1",
          "predicate_id": "pred:vulnerable-copy",
          "result": "satisfied",
          "observation_ids": ["obs-1"],
          "polarity": "supports",
        }
      ],
      "target_verdict": {
        "verdict_id": "verdict-1",
        "target": "v1.0.0",
        "verdict": "AFFECTED",
        "evidence_evaluation_ids": ["eval-1"],
      },
      "uncertainty_reasons": [],
      "learned_candidates": [
        {
          "candidate_id": "repo-memory-1",
          "memory_type": "RepoMemory",
          "scope": "repo",
          "hint": "git show is reliable for this target path",
        }
      ],
    }
  )

  events = agent_output_to_events(output)
  graph = GraphDocument.from_events(events)

  node_by_id = {node.id: node for node in graph.nodes}
  assert node_by_id["git-observation:obs-1"].allowed_use == "target_verdict_evidence"
  assert node_by_id["memory:repo-memory-1"].lifecycle == "candidate"
  assert node_by_id["memory:repo-memory-1"].allowed_use == "learning_candidate"
  assert {"produces", "derives", "supports", "candidate_updates"} <= {edge.type for edge in graph.edges}


def test_failure_case_generates_candidate_memory_only():
  failure = _node(
    "failure:1",
    "FailureCase",
    allowed_use="learning_candidate",
    content={
      "repo": "demo",
      "cwe_id": "CWE-787",
      "summary": "path alias caused missed evidence",
      "repo_hint": "check PathAlias before grep",
      "procedure_hint": "verify target evidence before verdict",
    },
  )

  events = candidate_memories_from_failure(failure)
  graph = GraphDocument.from_events(events)

  assert {node.type for node in graph.nodes} == {"RepoMemory", "ProcedureMemory"}
  assert all(node.lifecycle == "candidate" for node in graph.nodes)
  assert all(node.allowed_use == "learning_candidate" for node in graph.nodes)
