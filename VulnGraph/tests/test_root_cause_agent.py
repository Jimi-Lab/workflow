from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from vulngraph.agent_backend import readonly_permission_rules
from vulngraph.builder import SeedGraphInput, build_seed_graph
from vulngraph.root_cause import (
  RootCauseAgentOutput,
  RootCauseAgentService,
  RootCauseContextConfig,
  build_root_cause_context,
  render_root_cause_prompt,
  root_cause_output_to_events,
)
from vulngraph.root_cause.batch import RootCauseBatchCase, run_root_cause_batch
from vulngraph.schema import GraphDocument
from vulngraph.store import JsonlGraphStore


def _output_payload() -> dict:
  return {
    "agent_run": {
      "run_id": "rc-run-1",
      "cve_id": "CVE-TEST",
      "repo": "demo",
      "repo_path": "C:/repos/demo",
      "backend": "fake",
    },
    "command_invocations": [
      {
        "invocation_id": "cmd-1",
        "step_id": "inspect-fix",
        "command": "git_diff(repo_path=C:/repos/demo, commit=abc123)",
        "output": {
          "output_id": "out-1",
          "text": "- memcpy(dst, src, len)\n+ if (len <= cap) memcpy(dst, src, len)",
        },
      }
    ],
    "code_anchors": [
      {
        "anchor_id": "anchor-1",
        "path": "src/parser.c",
        "symbol": "parse_record",
        "tokens": ["memcpy", "len", "cap"],
        "command_refs": ["cmd-1"],
        "confidence": 0.95,
      }
    ],
    "vulnerable_predicates": [
      {
        "predicate_id": "vp-1",
        "description": "attacker-controlled len reaches memcpy without a capacity check",
        "anchor_ids": ["anchor-1"],
        "command_refs": ["cmd-1"],
        "confidence": 0.9,
      }
    ],
    "fix_predicates": [
      {
        "predicate_id": "fp-1",
        "description": "copy executes only when len does not exceed destination capacity",
        "anchor_ids": ["anchor-1"],
        "command_refs": ["cmd-1"],
        "confidence": 0.9,
      }
    ],
    "guard_conditions": [],
    "negative_applicability_conditions": [],
    "root_cause_hypotheses": [
      {
        "hypothesis_id": "hyp-1",
        "summary": "missing length validation before a record copy",
        "mechanism": "untrusted record length controls the copy size before the fix",
        "scope_files": ["src/parser.c"],
        "scope_functions": ["parse_record"],
        "vulnerable_predicate_ids": ["vp-1"],
        "fix_predicate_ids": ["fp-1"],
        "guard_condition_ids": [],
        "negative_condition_ids": [],
        "risk_flag_ids": [],
        "command_refs": ["cmd-1"],
        "confidence": 0.9,
      }
    ],
    "risk_flags": [],
    "learned_candidates": [],
  }


def test_root_cause_output_contract_has_no_target_verdict_requirement():
  output = RootCauseAgentOutput.model_validate(_output_payload())

  assert output.agent_run.cve_id == "CVE-TEST"
  assert output.root_cause_hypotheses[0].vulnerable_predicate_ids == ["vp-1"]
  assert "target_verdict" not in output.model_dump()


def test_root_cause_context_is_cve_scoped_and_bounded():
  graph = build_seed_graph(
    SeedGraphInput(
      cve_id="CVE-TEST",
      repo="demo",
      cwe_id="CWE-787",
      cve_description="Out-of-bounds copy",
      fix_commit="abc123",
    )
  )
  other = build_seed_graph(
    SeedGraphInput(
      cve_id="CVE-OTHER",
      repo="other",
      cwe_id="CWE-79",
      cve_description="Unrelated XSS",
      fix_commit="def456",
    )
  )
  graph.nodes.extend(other.nodes)
  graph.edges.extend(other.edges)

  packet = build_root_cause_context(
    graph,
    cve_id="CVE-TEST",
    repo="demo",
    repo_path="C:/repos/demo",
    config=RootCauseContextConfig(max_nodes=6, max_chars=6000),
  )

  assert packet.repo_path == "C:/repos/demo"
  assert len(packet.nodes) <= 6
  assert "cve:CVE-TEST" in {node.id for node in packet.nodes}
  assert all("CVE-OTHER" not in node.id for node in packet.nodes)
  assert "ground_truth_affected_versions" in packet.forbidden_context


def test_root_cause_prompt_enforces_task_and_read_only_git_boundary():
  graph = build_seed_graph(
    SeedGraphInput(
      cve_id="CVE-TEST",
      repo="demo",
      cve_description="Out-of-bounds copy",
      fix_commit="abc123",
    )
  )
  packet = build_root_cause_context(
    graph,
    cve_id="CVE-TEST",
    repo="demo",
    repo_path="C:/repos/demo",
  )

  prompt = render_root_cause_prompt(packet)

  assert "Do not judge affected versions" in prompt.system
  assert "read-only Git tools" in prompt.system
  assert "C:/repos/demo" in prompt.user
  assert '"root_cause_hypotheses"' in prompt.user
  assert "target_verdict" not in RootCauseAgentOutput.model_json_schema()["properties"]


def test_root_cause_output_becomes_auditable_semantic_graph():
  output = RootCauseAgentOutput.model_validate(_output_payload())
  graph = GraphDocument.from_events(root_cause_output_to_events(output))

  node_by_id = {node.id: node for node in graph.nodes}
  assert node_by_id["root-cause-hypothesis:hyp-1"].allowed_use == "root_cause_evidence"
  assert node_by_id["vulnerable-predicate:vp-1"].type == "VulnerablePredicate"
  assert "TargetVerdict" not in {node.type for node in graph.nodes}
  assert {"proposes", "requires", "blocked_by", "anchored_by", "supports"} <= {
    edge.type for edge in graph.edges
  }


def test_opencode_permissions_are_read_only_by_default():
  rules = readonly_permission_rules(allow_bash=False)
  actions = {(rule["permission"], rule["action"]) for rule in rules}

  assert ("write", "deny") in actions
  assert ("edit", "deny") in actions
  assert ("bash", "deny") in actions
  assert ("vg_git_diff", "allow") in actions
  assert ("vg_git_show", "allow") in actions
  assert ("git_diff", "deny") in actions
  assert ("git_show", "deny") in actions
  assert ("read", "deny") in actions
  assert ("grep", "deny") in actions
  assert ("task", "deny") in actions
  assert ("todowrite", "deny") in actions
  assert ("websearch", "deny") in actions


class _FakeBackend:
  def __init__(self, payload: dict):
    self.payload = payload
    self.prompts: list[str] = []

  def health(self) -> dict:
    return {"healthy": True}

  def create_readonly_session(self, *, title: str) -> str:
    return "session-1"

  def run_json(self, *, session_id: str, prompt: str, system: str, timeout_s: float | None = None) -> dict:
    self.prompts.append(prompt)
    return self.payload


class _SequentialFakeBackend(_FakeBackend):
  def __init__(self, payloads: list[dict]):
    super().__init__(payloads[0])
    self.payloads = payloads

  def run_json(self, *, session_id: str, prompt: str, system: str, timeout_s: float | None = None) -> dict:
    self.prompts.append(prompt)
    return self.payloads[len(self.prompts) - 1]


def test_root_cause_service_runs_backend_and_writes_graph_and_artifacts(tmp_path: Path):
  store = JsonlGraphStore(tmp_path / "graph")
  seed = build_seed_graph(
    SeedGraphInput(
      cve_id="CVE-TEST",
      repo="demo",
      cve_description="Out-of-bounds copy",
      fix_commit="abc123",
    )
  )
  store.append_graph(seed, created_from="test-seed")
  backend = _FakeBackend(_output_payload())
  service = RootCauseAgentService(backend=backend, store=store, runs_root=tmp_path / "runs")

  result = service.run(cve_id="CVE-TEST", repo="demo", repo_path="C:/repos/demo")

  materialized = store.materialize()
  assert result.session_id == "session-1"
  assert result.hypothesis_count == 1
  assert "RootCauseHypothesis" in {node.type for node in materialized.nodes}
  run_dir = tmp_path / "runs" / "CVE-TEST" / "rc-run-1"
  assert (run_dir / "prompt.json").exists()
  assert json.loads((run_dir / "output.json").read_text(encoding="utf-8"))["agent_run"]["run_id"] == "rc-run-1"


def test_root_cause_service_repairs_schema_once_without_new_evidence(tmp_path: Path):
  store = JsonlGraphStore(tmp_path / "graph")
  seed = build_seed_graph(
    SeedGraphInput(cve_id="CVE-TEST", repo="demo", cve_description="Out-of-bounds copy", fix_commit="abc123")
  )
  store.append_graph(seed, created_from="test-seed")
  invalid = deepcopy(_output_payload())
  invalid["root_cause_hypotheses"][0]["guard_condition_ids"] = ["missing-guard"]
  backend = _SequentialFakeBackend([invalid, _output_payload()])
  service = RootCauseAgentService(backend=backend, store=store, runs_root=tmp_path / "runs")

  result = service.run(cve_id="CVE-TEST", repo="demo", repo_path="C:/repos/demo")

  assert result.hypothesis_count == 1
  assert len(backend.prompts) == 2
  assert "Do not call tools" in backend.prompts[1]
  assert "unknown guard_condition_ids" in backend.prompts[1]


def test_root_cause_batch_continues_after_failure_and_writes_summary(tmp_path: Path):
  cases = [
    RootCauseBatchCase(
      cve_id="CVE-ONE",
      repo="demo",
      repo_path="C:/repos/demo",
      cwe_ids=["CWE-787"],
      description="first case",
      fix_commits=["abc123"],
    ),
    RootCauseBatchCase(
      cve_id="CVE-TWO",
      repo="demo",
      repo_path="C:/repos/demo",
      cwe_ids=[],
      description="second case",
      fix_commits=["def456"],
    ),
  ]

  class _CaseBackend(_FakeBackend):
    def run_json(self, *, session_id: str, prompt: str, system: str, timeout_s: float | None = None) -> dict:
      if "CVE-TWO" in prompt:
        raise RuntimeError("simulated backend failure")
      payload = deepcopy(_output_payload())
      payload["agent_run"]["cve_id"] = "CVE-ONE"
      return payload

  summary = run_root_cause_batch(
    cases=cases,
    backend=_CaseBackend(_output_payload()),
    output_root=tmp_path / "batch",
  )

  assert summary.total == 2
  assert summary.succeeded == 1
  assert summary.failed == 1
  assert summary.results[0].status == "success"
  assert summary.results[1].error_type == "RuntimeError"
  assert (tmp_path / "batch" / "summary.json").exists()
  assert (tmp_path / "batch" / "graphs" / "CVE-ONE" / "events.jsonl").exists()
