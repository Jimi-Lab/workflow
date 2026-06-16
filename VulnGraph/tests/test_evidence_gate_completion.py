from __future__ import annotations

from pathlib import Path

import pytest

from vulngraph.schema import GraphDocument, GraphEdge, GraphNode, SourceRef
from vulngraph.services import VulnGraphClient
from vulngraph.builder.patch import build_patch_graph_from_text


def _src() -> SourceRef:
  return SourceRef(kind="test", ref="tests://evidence-gate-completion")


def _node(node_id: str, node_type: str, content: dict, *, scope: str = "cve", allowed_use: str = "root_cause_evidence") -> GraphNode:
  return GraphNode(
    id=node_id,
    type=node_type,
    scope=scope,
    source_refs=[_src()],
    allowed_use=allowed_use,
    confidence=0.9,
    lifecycle="raw",
    created_from="test",
    content=content,
  )


def _edge(source: str, edge_type: str, target: str) -> GraphEdge:
  return GraphEdge(
    id=f"edge:{source}:{edge_type}:{target}",
    type=edge_type,
    source=source,
    target=target,
    scope="cve",
    source_refs=[_src()],
    allowed_use="root_cause_evidence",
    confidence=0.9,
    lifecycle="raw",
    created_from="test",
  )


def _client(tmp_path: Path, fix_sets: list[list[str]] | None = None) -> tuple[VulnGraphClient, dict]:
  fix_sets = fix_sets or [["sha-1"]]
  nodes = [_node("cve:CVE-GATE", "CVE", {"cve_id": "CVE-GATE"}, allowed_use="context_only")]
  edges = []
  packet_ids: dict[str, dict[str, str]] = {}
  for group_index, commits in enumerate(fix_sets, start=1):
    fix_set_id = f"CVE-GATE:fix-set:{group_index}"
    for order, sha in enumerate(commits, start=1):
      fix_id = f"fix-commit:demo:{sha}"
      hunk_id = f"patch-hunk:demo:{sha}:src/{sha}.c:1"
      file_id = f"file:demo:src/{sha}.c"
      function_id = f"changed-function:demo:{sha}:src/{sha}.c:parse_{order}"
      nodes.extend(
        [
          _node(fix_id, "FixCommit", {"cve_id": "CVE-GATE", "repo": "demo", "commit_sha": sha, "fix_set_id": fix_set_id, "group_index": group_index, "order": order}),
          _node(hunk_id, "PatchHunk", {"cve_id": "CVE-GATE", "repo": "demo", "commit_sha": sha, "path": f"src/{sha}.c", "hunk_index": 1, "function_id": function_id, "function_symbol": f"parse_{order}"}),
          _node(file_id, "File", {"repo": "demo", "path": f"src/{sha}.c"}, scope="repo", allowed_use="navigation_only"),
          _node(function_id, "ChangedFunction", {"cve_id": "CVE-GATE", "repo": "demo", "commit_sha": sha, "path": f"src/{sha}.c", "symbol": f"parse_{order}"}),
        ]
      )
      edges.extend(
        [
          _edge("cve:CVE-GATE", "fixed_by", fix_id),
          _edge(fix_id, "has_patch_hunk", hunk_id),
          _edge(hunk_id, "touches_file", file_id),
          _edge(hunk_id, "touches_function", function_id),
        ]
      )
      packet_ids[sha] = {"fix": fix_id, "hunk": hunk_id, "file": file_id, "function": function_id, "fix_set": fix_set_id}
  client = VulnGraphClient(tmp_path / "graph")
  client.append_graph(GraphDocument(nodes=nodes, edges=edges), created_from="test")
  return client, packet_ids


def _trace(cve_id: str, scopes: list[dict], *, source: str = "wrapper_git_trace", valid: bool = True) -> dict:
  calls = []
  outputs = []
  observations = []
  for index, scope in enumerate(scopes, start=1):
    command_id = f"cmd-{index}"
    output_id = f"out-{index}"
    observation_id = f"obs-{index}"
    calls.append({"id": command_id, "source": source, "cve_id": cve_id, "trace_run_id": "trace-1", "command": "git show", "exit_code": 0})
    outputs.append({"id": output_id, "source": source, "cve_id": cve_id, "trace_run_id": "trace-1", "command_ref": command_id, "text": "commit and diff output"})
    observations.append(
      {
        "id": observation_id,
        "source": source,
        "valid_evidence": valid,
        "observation_kind": "patch_diff",
        "cve_id": cve_id,
        "trace_run_id": "trace-1",
        "command_ref": command_id,
        "tool_output_ref": output_id,
        "fix_commit_ids": list(scope.get("fix_commit_ids", [])),
        "patch_hunk_ids": list(scope.get("patch_hunk_ids", [])),
        "file_ids": list(scope.get("file_ids", [])),
        "function_ids": list(scope.get("function_ids", [])),
        "path": scope.get("path", ""),
        "claim": "wrapper observation",
        "snippet": "diff output",
      }
    )
  return {"source": source, "cve_id": cve_id, "trace_run_id": "trace-1", "tool_calls": calls, "tool_outputs": outputs, "git_observations": observations, "errors": []}


def _output(ids: dict[str, dict[str, str]], selected_shas: list[str] | None = None) -> dict:
  selected_shas = selected_shas or list(ids)
  anchors = []
  observation_refs = []
  for index, sha in enumerate(selected_shas, start=1):
    item = ids[sha]
    observation_id = f"obs-{index}"
    observation_refs.append(observation_id)
    anchors.append(
      {
        "anchor_id": f"a-{index}",
        "fix_commit_id": item["fix"],
        "patch_hunk_id": item["hunk"],
        "path": f"src/{sha}.c",
        "function_id": item["function"],
        "function": f"parse_{index}",
        "git_observation_refs": [observation_id],
      }
    )
  anchor_ids = [anchor["anchor_id"] for anchor in anchors]
  fix_ids = [ids[sha]["fix"] for sha in selected_shas]
  fix_set_ids = sorted({ids[sha]["fix_set"] for sha in selected_shas})
  return {
    "agent_run": {"run_id": "run-1", "cve_id": "CVE-GATE", "backend": "test"},
    "code_anchors": anchors,
    "vulnerable_predicates": [{"predicate_id": "vp-1", "description": "vulnerable", "anchor_ids": anchor_ids, "git_observation_refs": observation_refs}],
    "fix_predicates": [{"predicate_id": "fp-1", "description": "fixed", "anchor_ids": anchor_ids, "git_observation_refs": observation_refs}],
    "guard_conditions": [],
    "negative_conditions": [],
    "root_cause_hypotheses": [
      {
        "hypothesis_id": "hyp-1",
        "summary": "root cause",
        "fix_set_ids": fix_set_ids,
        "fix_commit_ids": fix_ids,
        "anchor_ids": anchor_ids,
        "vulnerable_predicate_ids": ["vp-1"],
        "fix_predicate_ids": ["fp-1"],
        "guard_condition_ids": [],
        "negative_condition_ids": [],
        "git_observation_refs": observation_refs,
      }
    ],
    "uncertainty_reasons": [],
    "risk_flags": [],
  }


def _scopes(ids: dict[str, dict[str, str]], selected_shas: list[str] | None = None) -> list[dict]:
  selected_shas = selected_shas or list(ids)
  return [
    {
      "fix_commit_ids": [ids[sha]["fix"]],
      "patch_hunk_ids": [ids[sha]["hunk"]],
      "file_ids": [ids[sha]["file"]],
      "function_ids": [ids[sha]["function"]],
      "path": f"src/{sha}.c",
    }
    for sha in selected_shas
  ]


@pytest.mark.parametrize(
  ("mutation", "expected_error"),
  [
    (lambda trace: trace["git_observations"][0].pop("source"), "source"),
    (lambda trace: trace["git_observations"][0].update(valid_evidence=False), "valid_evidence"),
    (lambda trace: trace["git_observations"][0].update(command_ref="missing"), "command_ref"),
    (lambda trace: trace["git_observations"][0].update(tool_output_ref="missing"), "tool_output_ref"),
    (lambda trace: trace["tool_outputs"][0].update(command_ref="other"), "does not belong"),
    (lambda trace: trace.update(source="agent_report"), "trace source"),
  ],
)
def test_untrusted_observation_cannot_create_supports(tmp_path: Path, mutation, expected_error: str):
  client, ids = _client(tmp_path)
  trace = _trace("CVE-GATE", _scopes(ids))
  mutation(trace)

  result = client.ingest_root_cause_output("CVE-GATE", _output(ids), trace=trace)
  graph = client.materialize()

  assert result.status == "rejected"
  assert expected_error in " ".join(result.errors)
  assert not any(edge.type == "supports" for edge in graph.edges if edge.created_from == "service_ingestion")


def test_agent_reported_observation_is_never_trusted(tmp_path: Path):
  client, ids = _client(tmp_path)
  output = _output(ids)
  output["git_observations"] = _trace("CVE-GATE", _scopes(ids))["git_observations"]

  result = client.ingest_root_cause_output("CVE-GATE", output, trace={"source": "wrapper_git_trace", "cve_id": "CVE-GATE", "trace_run_id": "trace-1", "tool_calls": [], "tool_outputs": [], "git_observations": []})

  assert result.status == "rejected"


@pytest.mark.parametrize("mismatch", ["unknown_hunk", "other_commit", "observation_scope"])
def test_anchor_scope_mismatch_is_rejected_for_single_fix(tmp_path: Path, mismatch: str):
  client, ids = _client(tmp_path, [["sha-1"], ["sha-2"]])
  output = _output(ids, ["sha-1"])
  trace = _trace("CVE-GATE", _scopes(ids, ["sha-1"]))
  if mismatch == "unknown_hunk":
    output["code_anchors"][0]["patch_hunk_id"] = "missing-hunk"
  elif mismatch == "other_commit":
    output["code_anchors"][0]["patch_hunk_id"] = ids["sha-2"]["hunk"]
  else:
    trace["git_observations"][0]["fix_commit_ids"] = [ids["sha-2"]["fix"]]

  result = client.ingest_root_cause_output("CVE-GATE", output, trace=trace)
  anchor = next(node for node in client.materialize().nodes if node.type == "CodeAnchor" and node.content.get("run_id") == "run-1")

  assert result.status == "rejected"
  assert anchor.lifecycle == "rejected"


@pytest.mark.parametrize("missing_field", ["anchor_ids", "vulnerable_predicate_ids", "fix_predicate_ids"])
def test_minimum_root_cause_contract_is_required(tmp_path: Path, missing_field: str):
  client, ids = _client(tmp_path)
  output = _output(ids)
  output["root_cause_hypotheses"][0][missing_field] = []

  result = client.ingest_root_cause_output("CVE-GATE", output, trace=_trace("CVE-GATE", _scopes(ids)))

  assert result.status == "rejected"
  assert missing_field in " ".join(result.errors)


def test_unused_semantic_node_is_not_raw_or_in_production_packet(tmp_path: Path):
  client, ids = _client(tmp_path)
  output = _output(ids)
  output["code_anchors"].append({"anchor_id": "unused", "fix_commit_id": ids["sha-1"]["fix"], "patch_hunk_id": ids["sha-1"]["hunk"], "path": "src/sha-1.c", "git_observation_refs": ["obs-1"]})

  result = client.ingest_root_cause_output("CVE-GATE", output, trace=_trace("CVE-GATE", _scopes(ids)))
  graph = client.materialize()
  unused = next(node for node in graph.nodes if node.type == "CodeAnchor" and node.content.get("anchor_id") == "unused")
  packet = client.build_judge_packet("CVE-GATE", "target")

  assert result.status == "ingested_raw"
  assert unused.lifecycle in {"candidate", "rejected"}
  assert unused.id not in {node["id"] for node in packet["code_anchors"]}


def test_single_fix_set_multiple_commits_requires_complete_coverage(tmp_path: Path):
  client, ids = _client(tmp_path, [["sha-1", "sha-2"]])

  complete = client.ingest_root_cause_output("CVE-GATE", _output(ids), trace=_trace("CVE-GATE", _scopes(ids)))

  assert complete.status == "ingested_raw"
  assert complete.details["fix_set_results"]["CVE-GATE:fix-set:1"]["complete"] is True


def test_single_fix_set_multiple_commits_rejects_missing_commit(tmp_path: Path):
  client, ids = _client(tmp_path, [["sha-1", "sha-2"]])

  result = client.ingest_root_cause_output("CVE-GATE", _output(ids, ["sha-1"]), trace=_trace("CVE-GATE", _scopes(ids, ["sha-1"])))

  assert result.status == "rejected"
  assert result.details["fix_set_results"]["CVE-GATE:fix-set:1"]["missing_fix_commits"] == [ids["sha-2"]["fix"]]


def test_multiple_fix_sets_are_evaluated_independently(tmp_path: Path):
  client, ids = _client(tmp_path, [["sha-1"], ["sha-2"]])

  result = client.ingest_root_cause_output("CVE-GATE", _output(ids, ["sha-1"]), trace=_trace("CVE-GATE", _scopes(ids, ["sha-1"])))

  assert result.status == "ingested_raw"
  assert result.details["fix_set_results"]["CVE-GATE:fix-set:1"]["complete"] is True
  assert result.details["fix_set_results"]["CVE-GATE:fix-set:2"]["complete"] is False


def test_fifteen_commit_fix_set_is_not_truncated(tmp_path: Path):
  commits = [f"sha-{index}" for index in range(1, 16)]
  client, ids = _client(tmp_path, [commits])

  result = client.ingest_root_cause_output("CVE-GATE", _output(ids), trace=_trace("CVE-GATE", _scopes(ids)))
  fix_set = result.details["fix_set_results"]["CVE-GATE:fix-set:1"]

  assert result.status == "ingested_raw"
  assert len(fix_set["expected_fix_commits"]) == 15
  assert len(fix_set["covered_fix_commits"]) == 15


def test_failure_cases_are_unique_across_runs(tmp_path: Path):
  client, ids = _client(tmp_path)
  first = _output(ids)
  second = _output(ids)
  first["agent_run"]["run_id"] = "run-1"
  second["agent_run"]["run_id"] = "run-2"
  first["root_cause_hypotheses"][0]["anchor_ids"] = []
  second["root_cause_hypotheses"][0]["anchor_ids"] = []

  client.ingest_root_cause_output("CVE-GATE", first, trace=_trace("CVE-GATE", _scopes(ids)))
  client.ingest_root_cause_output("CVE-GATE", second, trace=_trace("CVE-GATE", _scopes(ids)))
  failures = [node for node in client.materialize().nodes if node.type == "FailureCase"]

  assert len(failures) == 2
  assert len({node.id for node in failures}) == 2
  assert {node.content.get("run_id") for node in failures} == {"run-1", "run-2"}


def test_patch_import_preserves_dataset_fix_set_metadata():
  graph = build_patch_graph_from_text(
    cve_id="CVE-GATE",
    repo="demo",
    commit_sha="sha-1",
    patch_text="""diff --git a/a.c b/a.c
--- a/a.c
+++ b/a.c
@@ -1 +1 @@ parse
-old
+new
""",
    fix_commit_content={"fix_set_id": "CVE-GATE:fix-set:1", "group_index": 1, "order": 2},
  )
  fix = next(node for node in graph.nodes if node.type == "FixCommit")

  assert fix.content["fix_set_id"] == "CVE-GATE:fix-set:1"
  assert fix.content["group_index"] == 1
  assert fix.content["order"] == 2
