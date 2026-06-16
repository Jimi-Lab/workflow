from __future__ import annotations

import json
from pathlib import Path

from vulngraph.builder.patch import build_patch_graph_from_text
from vulngraph.schema import GraphDocument, GraphEdge, GraphNode, SourceRef
from vulngraph.services import VulnGraphClient


def _src() -> SourceRef:
  return SourceRef(kind="test", ref="tests://services")


def _node(
  node_id: str,
  node_type: str,
  *,
  scope: str = "cve",
  allowed_use: str = "context_only",
  lifecycle: str = "raw",
  content: dict | None = None,
  source_refs: list[SourceRef] | None = None,
) -> GraphNode:
  return GraphNode(
    id=node_id,
    type=node_type,
    scope=scope,
    source_refs=source_refs or [_src()],
    allowed_use=allowed_use,
    confidence=0.8,
    lifecycle=lifecycle,
    created_from="unit-test",
    content=content or {},
  )


def _edge(
  source: str,
  edge_type: str,
  target: str,
  *,
  allowed_use: str = "context_only",
  lifecycle: str = "raw",
  content: dict | None = None,
) -> GraphEdge:
  return GraphEdge(
    id=f"edge:{source}:{edge_type}:{target}",
    type=edge_type,
    source=source,
    target=target,
    scope="cve",
    source_refs=[_src()],
    allowed_use=allowed_use,
    confidence=0.8,
    lifecycle=lifecycle,
    created_from="unit-test",
    content=content or {},
  )


def _seed_client(tmp_path: Path) -> VulnGraphClient:
  client = VulnGraphClient(tmp_path / "graph")
  base = GraphDocument(
    nodes=[
      _node(
        "cve:CVE-TEST",
        "CVE",
        content={"cve_id": "CVE-TEST", "description": "demo overflow", "affected_versions_count": 12},
      ),
      _node(
        "cwe:CWE-787",
        "CWE",
        scope="cwe",
        content={"cwe_id": "CWE-787"},
        source_refs=[
          SourceRef(kind="dataset", ref="dataset:CVE-OTHER", path="dataset.json"),
          SourceRef(kind="dataset", ref="dataset:CVE-TEST", path="dataset.json"),
        ],
      ),
      _node("repo:demo", "Repo", scope="repo", content={"repo": "demo"}),
      _node(
        "fix-commit:demo:abc123",
        "FixCommit",
        allowed_use="root_cause_evidence",
        content={"cve_id": "CVE-TEST", "repo": "demo", "commit_sha": "abc123", "fix_set_id": "set-1", "order": 1},
      ),
      _node(
        "offline-affected:CVE-TEST:v1.0.0",
        "TargetVerdict",
        scope="experiment",
        allowed_use="offline_eval_only",
        lifecycle="validated",
        content={"cve_id": "CVE-TEST", "target_id": "v1.0.0", "verdict": "AFFECTED"},
      ),
      _node(
        "memory:candidate",
        "ProcedureMemory",
        allowed_use="learning_candidate",
        lifecycle="candidate",
        content={"cve_id": "CVE-TEST", "hint": "candidate must stay out of production"},
      ),
      _node(
        "memory:validated-procedure",
        "ProcedureMemory",
        allowed_use="procedure_only",
        lifecycle="validated",
        content={"cve_id": "CVE-TEST", "hint": "inspect removed guard and added guard separately"},
      ),
    ],
    edges=[
      _edge("cve:CVE-TEST", "has_cwe", "cwe:CWE-787"),
      _edge("cve:CVE-TEST", "targets_repo", "repo:demo"),
      _edge("cve:CVE-TEST", "fixed_by", "fix-commit:demo:abc123", allowed_use="root_cause_evidence"),
      _edge(
        "cve:CVE-TEST",
        "has_offline_affected_version",
        "offline-affected:CVE-TEST:v1.0.0",
        allowed_use="offline_eval_only",
      ),
    ],
  )
  patch = build_patch_graph_from_text(
    cve_id="CVE-TEST",
    repo="demo",
    commit_sha="abc123",
    patch_text="""commit abc123
diff --git a/src/parser.c b/src/parser.c
--- a/src/parser.c
+++ b/src/parser.c
@@ -10,4 +10,5 @@ static int previous(void)
 int parse_record(int len) {
-  memcpy(dst, src, len);
+  if (len <= cap)
+    memcpy(dst, src, len);
 }
""",
    fix_commit_content={"cve_id": "CVE-TEST", "repo": "demo", "commit_sha": "abc123", "fix_set_id": "set-1", "order": 1},
  )
  client.append_graph(base, created_from="test-seed")
  client.append_graph(patch, created_from="test-patch")
  return client


def _root_cause_output() -> dict:
  return {
    "agent_run": {"run_id": "rc-1", "backend": "unit-test"},
    "code_anchors": [
      {
        "anchor_id": "anchor-1",
        "fix_commit_id": "fix-commit:demo:abc123",
        "patch_hunk_id": "patch-hunk:demo:abc123:src/parser.c:1",
        "path": "src/parser.c",
        "git_observation_refs": ["obs-1"],
        "confidence": 0.9,
      }
    ],
    "vulnerable_predicates": [
      {
        "predicate_id": "vp-1",
        "description": "copy uses unchecked len",
        "anchor_ids": ["anchor-1"],
        "git_observation_refs": ["obs-1"],
      }
    ],
    "fix_predicates": [
      {
        "predicate_id": "fp-1",
        "description": "copy is guarded by cap check",
        "anchor_ids": ["anchor-1"],
        "git_observation_refs": ["obs-1"],
      }
    ],
    "guard_conditions": [],
    "negative_conditions": [],
    "root_cause_hypotheses": [
      {
        "hypothesis_id": "hyp-1",
        "summary": "unchecked length reaches memcpy",
        "fix_commit_ids": ["fix-commit:demo:abc123"],
        "fix_set_ids": ["set-1"],
        "vulnerable_predicate_ids": ["vp-1"],
        "fix_predicate_ids": ["fp-1"],
        "guard_condition_ids": [],
        "negative_condition_ids": [],
        "anchor_ids": ["anchor-1"],
        "git_observation_refs": ["obs-1"],
      }
    ],
    "uncertainty_reasons": [],
    "risk_flags": [{"risk_id": "risk-1", "description": "broad pattern"}],
  }


def _root_cause_trace() -> dict:
  return {
    "source": "wrapper_git_trace",
    "cve_id": "CVE-TEST",
    "trace_run_id": "trace-1",
    "tool_calls": [
      {
        "id": "cmd-1",
        "source": "wrapper_git_trace",
        "cve_id": "CVE-TEST",
        "trace_run_id": "trace-1",
        "command": "git show abc123 -- src/parser.c",
        "exit_code": 0,
      }
    ],
    "tool_outputs": [
      {
        "id": "out-1",
        "source": "wrapper_git_trace",
        "cve_id": "CVE-TEST",
        "trace_run_id": "trace-1",
        "command_ref": "cmd-1",
        "text": "-memcpy(dst, src, len)\n+if (len <= cap)",
        "exit_code": 0,
      }
    ],
    "git_observations": [
      {
        "id": "obs-1",
        "source": "wrapper_git_trace",
        "valid_evidence": True,
        "observation_kind": "patch_diff",
        "cve_id": "CVE-TEST",
        "trace_run_id": "trace-1",
        "command_ref": "cmd-1",
        "tool_output_ref": "out-1",
        "fix_commit_ids": ["fix-commit:demo:abc123"],
        "patch_hunk_ids": ["patch-hunk:demo:abc123:src/parser.c:1"],
        "file_ids": ["file:demo:src/parser.c"],
        "function_ids": ["changed-function:demo:abc123:src/parser.c:parse_record"],
        "path": "src/parser.c",
        "claim": "fix adds cap guard before memcpy",
        "snippet": "+if (len <= cap)",
      }
    ],
  }


def _add_trusted_observation(trace: dict, observation_id: str, command_id: str, output_id: str, *, fix_id: str = "fix-commit:demo:abc123", hunk_id: str = "patch-hunk:demo:abc123:src/parser.c:1", path: str = "src/parser.c") -> None:
  trace["tool_calls"].append({"id": command_id, "source": "wrapper_git_trace", "cve_id": "CVE-TEST", "trace_run_id": "trace-1", "command": "git show", "exit_code": 0})
  trace["tool_outputs"].append({"id": output_id, "source": "wrapper_git_trace", "cve_id": "CVE-TEST", "trace_run_id": "trace-1", "command_ref": command_id, "text": "output", "exit_code": 0})
  trace["git_observations"].append({"id": observation_id, "source": "wrapper_git_trace", "valid_evidence": True, "observation_kind": "patch_diff", "cve_id": "CVE-TEST", "trace_run_id": "trace-1", "command_ref": command_id, "tool_output_ref": output_id, "fix_commit_ids": [fix_id], "patch_hunk_ids": [hunk_id], "file_ids": [], "function_ids": [], "path": path, "claim": "trusted context", "snippet": "output"})


def _judge_output(target_id: str, *, commit: str = "badc0de") -> dict:
  return {
    "agent_run": {"run_id": f"judge-{target_id}", "backend": "unit-test"},
    "predicate_evaluations": [
      {
        "evaluation_id": f"eval-{target_id}",
        "predicate_id": "vp-1",
        "result": "satisfied",
        "observation_ids": [f"obs-{target_id}"],
        "polarity": "supports",
      }
    ],
    "target_verdict": {
      "verdict_id": f"verdict-{target_id}",
      "target_id": target_id,
      "verdict": "AFFECTED",
      "evidence_evaluation_ids": [f"eval-{target_id}"],
    },
  }


def _judge_trace(target_id: str, *, commit: str = "badc0de") -> dict:
  return {
    "tool_calls": [
      {
        "id": f"cmd-{target_id}",
        "command": f"git blame {target_id} -- src/parser.c",
        "output": f"{commit} memcpy(dst, src, len)",
        "exit_code": 0,
      }
    ],
    "git_observations": [
      {
        "id": f"obs-{target_id}",
        "command_ref": f"cmd-{target_id}",
        "target_id": target_id,
        "path": "src/parser.c",
        "claim": "target contains vulnerable copy",
        "snippet": "memcpy(dst, src, len)",
        "blame_commit": commit,
        "supports": [f"eval-{target_id}"],
      }
    ],
  }


def test_build_root_cause_packet_production_filters_candidate_offline_and_target_verdict(tmp_path: Path):
  client = _seed_client(tmp_path)

  packet = client.build_root_cause_packet("CVE-TEST", mode="production")
  all_ids = {item["id"] for section in ("context", "patch_evidence", "repo_navigation", "procedure_hints") for item in packet[section]}

  assert "cve:CVE-TEST" in {item["id"] for item in packet["context"]}
  assert "fix-commit:demo:abc123" in {item["id"] for item in packet["patch_evidence"]}
  assert any(item["type"] == "CodeAnchor" for item in packet["patch_evidence"])
  assert "memory:validated-procedure" in {item["id"] for item in packet["procedure_hints"]}
  assert "memory:candidate" not in all_ids
  assert "offline-affected:CVE-TEST:v1.0.0" not in all_ids
  assert "affected_version" in " ".join(packet["forbidden"])
  serialized = json.dumps(packet, ensure_ascii=False)
  assert "affected_versions_count" not in serialized
  assert "CVE-OTHER" not in serialized


def test_ingest_root_cause_output_without_git_observation_is_rejected(tmp_path: Path):
  client = _seed_client(tmp_path)

  result = client.ingest_root_cause_output("CVE-TEST", _root_cause_output(), trace={"git_observations": []})
  graph = client.materialize()
  hypothesis = next(node for node in graph.nodes if node.type == "RootCauseHypothesis")

  assert result.status == "rejected"
  assert hypothesis.lifecycle == "rejected"
  assert any(node.type == "FailureCase" for node in graph.nodes)


def test_build_judge_packet_includes_hypothesis_but_not_final_verdict_evidence(tmp_path: Path):
  client = _seed_client(tmp_path)
  client.ingest_root_cause_output("CVE-TEST", _root_cause_output(), trace=_root_cause_trace())

  packet = client.build_judge_packet("CVE-TEST", "v1.0.0")

  assert packet["target"]["target_id"] == "v1.0.0"
  assert packet["root_cause_hypothesis"]["content"]["hypothesis_id"] == "hyp-1"
  assert packet["code_anchors"]
  assert "TargetVerdict" not in {item["type"] for item in packet["code_anchors"]}
  assert packet["required_evidence_schema"]["final_verdict_requires"] == "target-local GitObservation"


def test_ingest_judge_output_without_target_local_git_observation_is_rejected(tmp_path: Path):
  client = _seed_client(tmp_path)
  client.ingest_root_cause_output("CVE-TEST", _root_cause_output(), trace=_root_cause_trace())

  result = client.ingest_judge_output("CVE-TEST", "v1.0.0", _judge_output("v1.0.0"), trace={"git_observations": []})
  graph = client.materialize()
  verdict = next(node for node in graph.nodes if node.id == "target-verdict:CVE-TEST:v1.0.0:verdict-v1.0.0")

  assert result.status == "rejected"
  assert verdict.lifecycle == "rejected"
  assert any(node.type == "FailureCase" and node.content.get("stage") == "judge" for node in graph.nodes)


def test_get_target_verdicts_returns_multiple_structured_verdicts(tmp_path: Path):
  client = _seed_client(tmp_path)
  client.ingest_root_cause_output("CVE-TEST", _root_cause_output(), trace=_root_cause_trace())
  client.ingest_judge_output("CVE-TEST", "v1.0.0", _judge_output("v1.0.0"), trace=_judge_trace("v1.0.0"))
  client.ingest_judge_output("CVE-TEST", "v1.1.0", _judge_output("v1.1.0", commit="c0ffee"), trace=_judge_trace("v1.1.0", commit="c0ffee"))

  verdicts = client.get_target_verdicts("CVE-TEST", ["v1.0.0", "v1.1.0", "v2.0.0"])

  assert verdicts["targets"]["v1.0.0"][0]["verdict"] == "AFFECTED"
  assert verdicts["targets"]["v1.1.0"][0]["verdict"] == "AFFECTED"
  assert verdicts["targets"]["v2.0.0"] == []


def test_infer_bic_candidates_uses_blame_evidence_not_target_version_as_commit(tmp_path: Path):
  client = _seed_client(tmp_path)
  client.ingest_root_cause_output("CVE-TEST", _root_cause_output(), trace=_root_cause_trace())
  client.ingest_judge_output("CVE-TEST", "v1.0.0", _judge_output("v1.0.0"), trace=_judge_trace("v1.0.0", commit="badc0de"))

  candidates = client.infer_bic_candidates("CVE-TEST", ["v1.0.0"], strategy="hybrid")

  assert candidates["candidates"][0]["commit_sha"] == "badc0de"
  assert candidates["candidates"][0]["commit_sha"] != "v1.0.0"
  assert candidates["candidates"][0]["evidence_type"] == "blame"


def test_root_cause_gate_ignores_observation_supports_and_agent_observations(tmp_path: Path):
  client = _seed_client(tmp_path)
  output = _root_cause_output()
  output["root_cause_hypotheses"][0]["git_observation_refs"] = ["agent-obs"]
  output["git_observations"] = [
    {"id": "agent-obs", "supports": ["hyp-1"], "claim": "agent-created evidence"}
  ]
  trace = {
    "git_observations": [
      {"id": "obs-1", "command_ref": "cmd-1", "supports": ["hyp-1"], "claim": "trusted trace"}
    ]
  }

  result = client.ingest_root_cause_output("CVE-TEST", output, trace=trace)
  graph = client.materialize()
  hypothesis = next(node for node in graph.nodes if node.type == "RootCauseHypothesis")

  assert result.status == "rejected"
  assert hypothesis.lifecycle == "rejected"
  assert not any(edge.type == "supports" and edge.target == hypothesis.id for edge in graph.edges)


def test_root_cause_gate_is_per_hypothesis_and_links_only_explicit_observations(tmp_path: Path):
  client = _seed_client(tmp_path)
  output = _root_cause_output()
  output["root_cause_hypotheses"].append(
    {
      "hypothesis_id": "hyp-2",
      "summary": "unsupported alternative",
      "vulnerable_predicate_ids": [],
      "fix_predicate_ids": [],
      "guard_condition_ids": [],
      "negative_condition_ids": [],
      "anchor_ids": [],
      "git_observation_refs": [],
    }
  )
  trace = _root_cause_trace()
  _add_trusted_observation(trace, "obs-2", "cmd-2", "out-2")

  result = client.ingest_root_cause_output("CVE-TEST", output, trace=trace)
  graph = client.materialize()
  hypotheses = {node.content["hypothesis_id"]: node for node in graph.nodes if node.type == "RootCauseHypothesis"}
  support_edges = [edge for edge in graph.edges if edge.type == "supports" and edge.target == hypotheses["hyp-1"].id]
  source_observations = {next(node for node in graph.nodes if node.id == edge.source).content["id"] for edge in support_edges}

  assert result.status == "ingested_raw"
  assert hypotheses["hyp-1"].lifecycle == "raw"
  assert hypotheses["hyp-2"].lifecycle == "rejected"
  assert source_observations == {"obs-1"}
  assert result.raw_hypothesis_count == 1
  assert result.rejected_hypothesis_count == 1


def test_root_cause_gate_requires_shared_evidence_with_referenced_semantics(tmp_path: Path):
  client = _seed_client(tmp_path)
  output = _root_cause_output()
  for collection in ("code_anchors", "vulnerable_predicates", "fix_predicates"):
    output[collection][0]["git_observation_refs"] = ["obs-2"]
  trace = _root_cause_trace()
  _add_trusted_observation(trace, "obs-2", "cmd-2", "out-2")

  result = client.ingest_root_cause_output("CVE-TEST", output, trace=trace)
  hypothesis = next(node for node in client.materialize().nodes if node.type == "RootCauseHypothesis")

  assert result.status == "rejected"
  assert hypothesis.lifecycle == "rejected"
  assert any("shared GitObservation" in error for error in result.errors)


def test_root_cause_gate_rejects_ambiguous_duplicate_observation_ids(tmp_path: Path):
  client = _seed_client(tmp_path)
  trace = _root_cause_trace()
  _add_trusted_observation(trace, "obs-1", "cmd-2", "out-2")

  result = client.ingest_root_cause_output("CVE-TEST", _root_cause_output(), trace=trace)

  assert result.status == "rejected"
  assert any("ambiguous" in error for error in result.errors)


def test_root_cause_semantic_support_edges_follow_explicit_refs(tmp_path: Path):
  client = _seed_client(tmp_path)
  trace = _root_cause_trace()
  _add_trusted_observation(trace, "obs-2", "cmd-2", "out-2")

  result = client.ingest_root_cause_output("CVE-TEST", _root_cause_output(), trace=trace)
  graph = client.materialize()
  semantic_nodes = {
    node.id
    for node in graph.nodes
    if node.type in {"CodeAnchor", "VulnerablePredicate", "FixPredicate"} and node.content.get("run_id") == "rc-1"
  }
  semantic_supports = [edge for edge in graph.edges if edge.type == "supports" and edge.target in semantic_nodes]
  source_observation_ids = {
    next(node for node in graph.nodes if node.id == edge.source).content["id"]
    for edge in semantic_supports
  }

  assert result.status == "ingested_raw"
  assert {edge.target for edge in semantic_supports} == semantic_nodes
  assert source_observation_ids == {"obs-1"}


def test_root_cause_multi_fix_incomplete_mapping_is_rejected(tmp_path: Path):
  client = _seed_client(tmp_path)
  output = _root_cause_output()
  output["root_cause_hypotheses"][0]["fix_commit_ids"] = ["fix-1", "fix-2"]
  output["root_cause_hypotheses"][0]["fix_set_ids"] = ["set-1"]
  output["code_anchors"][0].update({"fix_commit_id": "fix-1", "patch_hunk_id": "hunk-1"})
  trace = _root_cause_trace()
  trace["git_observations"][0].update({"fix_commit_ids": ["fix-1"], "patch_hunk_ids": ["hunk-1"], "file_ids": [], "function_ids": []})
  _add_trusted_observation(trace, "obs-2", "cmd-2", "out-2", fix_id="fix-2", hunk_id="hunk-2", path="src/second.c")
  packet = {
    "patch_evidence": [
      {"id": "fix-1", "type": "FixCommit", "content": {"commit_sha": "one", "fix_set_id": "set-1", "order": 1}},
      {"id": "fix-2", "type": "FixCommit", "content": {"commit_sha": "two", "fix_set_id": "set-1", "order": 2}},
      {"id": "hunk-1", "type": "PatchHunk", "content": {"commit_sha": "one", "path": "src/parser.c"}},
      {"id": "hunk-2", "type": "PatchHunk", "content": {"commit_sha": "two", "path": "src/second.c"}},
    ]
  }

  result = client.ingest_root_cause_output("CVE-TEST", output, trace=trace, packet=packet)

  assert result.status == "rejected"
  assert any("complete gated CodeAnchor coverage" in error for error in result.errors)
  assert all(
    node.lifecycle == "rejected"
    for node in client.materialize().nodes
    if node.type in {"RootCauseHypothesis", "CodeAnchor"} and node.content.get("run_id") == "rc-1"
  )


def test_root_cause_multi_fix_complete_mapping_is_ingested_raw(tmp_path: Path):
  client = _seed_client(tmp_path)
  output = _root_cause_output()
  output["root_cause_hypotheses"][0]["fix_commit_ids"] = ["fix-1", "fix-2"]
  output["root_cause_hypotheses"][0]["fix_set_ids"] = ["set-1"]
  output["root_cause_hypotheses"][0]["anchor_ids"] = ["anchor-1", "anchor-2"]
  output["code_anchors"][0].update({"fix_commit_id": "fix-1", "patch_hunk_id": "hunk-1"})
  output["code_anchors"].append(
    {
      "anchor_id": "anchor-2",
      "fix_commit_id": "fix-2",
      "patch_hunk_id": "hunk-2",
      "path": "src/second.c",
      "git_observation_refs": ["obs-2"],
    }
  )
  output["root_cause_hypotheses"][0]["git_observation_refs"] = ["obs-1", "obs-2"]
  trace = _root_cause_trace()
  trace["git_observations"][0].update({"fix_commit_ids": ["fix-1"], "patch_hunk_ids": ["hunk-1"], "file_ids": [], "function_ids": []})
  _add_trusted_observation(trace, "obs-2", "cmd-2", "out-2", fix_id="fix-2", hunk_id="hunk-2", path="src/second.c")
  packet = {
    "patch_evidence": [
      {"id": "fix-1", "type": "FixCommit", "content": {"commit_sha": "one", "fix_set_id": "set-1", "order": 1}},
      {"id": "fix-2", "type": "FixCommit", "content": {"commit_sha": "two", "fix_set_id": "set-1", "order": 2}},
      {"id": "hunk-1", "type": "PatchHunk", "content": {"commit_sha": "one", "path": "src/parser.c"}},
      {"id": "hunk-2", "type": "PatchHunk", "content": {"commit_sha": "two", "path": "src/second.c"}},
    ]
  }

  result = client.ingest_root_cause_output("CVE-TEST", output, trace=trace, packet=packet)

  assert result.status == "ingested_raw"
  assert result.raw_hypothesis_count == 1
  assert result.rejected_hypothesis_count == 0


def test_root_cause_semantic_nodes_are_run_scoped_and_never_validated(tmp_path: Path):
  client = _seed_client(tmp_path)
  first = _root_cause_output()
  second = _root_cause_output()
  first["agent_run"]["run_id"] = "run-1"
  second["agent_run"]["run_id"] = "run-2"

  first_result = client.ingest_root_cause_output("CVE-TEST", first, trace=_root_cause_trace())
  second_result = client.ingest_root_cause_output("CVE-TEST", second, trace=_root_cause_trace())
  graph = client.materialize()
  hypotheses = [node for node in graph.nodes if node.type == "RootCauseHypothesis"]
  anchors = [node for node in graph.nodes if node.type == "CodeAnchor" and node.content.get("anchor_id") == "anchor-1"]

  assert first_result.status == "ingested_raw"
  assert second_result.status == "ingested_raw"
  assert len(hypotheses) == 2
  assert len(anchors) == 2
  assert {node.content["run_id"] for node in hypotheses} == {"run-1", "run-2"}
  assert all(node.lifecycle == "raw" for node in hypotheses + anchors)
