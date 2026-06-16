from __future__ import annotations

import json
import subprocess
from pathlib import Path

from vulngraph.agent_backends.fixture import FixtureRootCauseBackend
from vulngraph.builder.patch import build_patch_graph_from_repo
from vulngraph.schema import GraphDocument, GraphEdge, GraphNode, SourceRef
from vulngraph.services import VulnGraphClient
from vulngraph.workflows.git_evidence import adapt_legacy_evidence_trace, collect_git_evidence
from vulngraph.workflows.root_cause import RootCauseWorkflow, _prompt_template, run_root_cause_batch


def _src() -> SourceRef:
  return SourceRef(kind="test", ref="tests://root-cause-workflow-v2")


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


def _edge(source: str, edge_type: str, target: str, *, allowed_use: str = "context_only") -> GraphEdge:
  return GraphEdge(
    id=f"edge:{source}:{edge_type}:{target}",
    type=edge_type,
    source=source,
    target=target,
    scope="cve",
    source_refs=[_src()],
    allowed_use=allowed_use,
    confidence=0.8,
    lifecycle="raw",
    created_from="unit-test",
  )


def _run_git(repo: Path, args: list[str]) -> str:
  result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True)
  return result.stdout.strip()


def _seed_repo_and_client(tmp_path: Path) -> tuple[VulnGraphClient, Path, str]:
  repo_root = tmp_path / "repos"
  repo = repo_root / "demo"
  repo.mkdir(parents=True)
  _run_git(repo, ["init"])
  _run_git(repo, ["config", "user.email", "test@example.com"])
  _run_git(repo, ["config", "user.name", "Test User"])
  (repo / "src").mkdir()
  (repo / "src" / "parser.c").write_text(
    "int parse_record(int len) {\n  memcpy(dst, src, len);\n  return 0;\n}\n",
    encoding="utf-8",
  )
  _run_git(repo, ["add", "src/parser.c"])
  _run_git(repo, ["commit", "-m", "base"])
  (repo / "src" / "parser.c").write_text(
    "int parse_record(int len) {\n  if (len <= cap)\n    memcpy(dst, src, len);\n  return 0;\n}\n",
    encoding="utf-8",
  )
  _run_git(repo, ["add", "src/parser.c"])
  _run_git(repo, ["commit", "-m", "fix unchecked len"])
  commit_sha = _run_git(repo, ["rev-parse", "HEAD"])

  client = VulnGraphClient(tmp_path / "graph")
  base = GraphDocument(
    nodes=[
      _node("cve:CVE-TEST", "CVE", content={"cve_id": "CVE-TEST", "description": "unchecked copy length"}),
      _node("cwe:CWE-787", "CWE", scope="cwe", content={"cwe_id": "CWE-787"}),
      _node("repo:demo", "Repo", scope="repo", content={"repo": "demo"}),
      _node(
        f"fix-commit:demo:{commit_sha}",
        "FixCommit",
        allowed_use="root_cause_evidence",
        content={"cve_id": "CVE-TEST", "repo": "demo", "commit_sha": commit_sha},
      ),
      _node(
        "offline-affected:CVE-TEST:v1.0.0",
        "TargetVerdict",
        scope="experiment",
        allowed_use="offline_eval_only",
        lifecycle="validated",
        content={"cve_id": "CVE-TEST", "target": "v1.0.0"},
      ),
      _node(
        "memory:candidate",
        "ProcedureMemory",
        allowed_use="learning_candidate",
        lifecycle="candidate",
        content={"cve_id": "CVE-TEST", "hint": "must not enter production"},
      ),
    ],
    edges=[
      _edge("cve:CVE-TEST", "has_cwe", "cwe:CWE-787"),
      _edge("cve:CVE-TEST", "targets_repo", "repo:demo"),
      _edge("cve:CVE-TEST", "fixed_by", f"fix-commit:demo:{commit_sha}", allowed_use="root_cause_evidence"),
      _edge("cve:CVE-TEST", "has_offline_affected_version", "offline-affected:CVE-TEST:v1.0.0", allowed_use="offline_eval_only"),
    ],
  )
  client.append_graph(base, created_from="test-seed")
  client.append_graph(
    build_patch_graph_from_repo(cve_id="CVE-TEST", repo="demo", repo_path=repo, commit_sha=commit_sha),
    created_from="test-patch",
  )
  return client, repo_root, commit_sha


def test_evidence_collector_outputs_wrapper_trace(tmp_path: Path):
  client, repo_root, commit_sha = _seed_repo_and_client(tmp_path)
  packet = client.build_root_cause_packet("CVE-TEST")

  trace = collect_git_evidence("CVE-TEST", packet, repo_root=repo_root)

  assert trace["backend_trusted"] == "wrapper"
  assert trace["source"] == "wrapper_git_trace"
  assert trace["trace_run_id"]
  assert any("git show --stat" in call["command"] for call in trace["tool_calls"])
  assert any("git show --unified=80" in call["command"] for call in trace["tool_calls"])
  assert all("stdout_sha256" in call for call in trace["tool_calls"])
  assert trace["git_observations"]
  assert trace["git_observations"][0]["fix_commit_id"] == f"fix-commit:demo:{commit_sha}"
  assert trace["tool_outputs"]
  for observation in trace["git_observations"]:
    assert observation["source"] == "wrapper_git_trace"
    assert observation["valid_evidence"] is True
    assert observation["observation_kind"] in {"patch_stat", "patch_diff", "file_history"}
    assert observation["command_ref"] in {call["id"] for call in trace["tool_calls"]}
    assert observation["tool_output_ref"] in {output["id"] for output in trace["tool_outputs"]}
    assert observation["fix_commit_ids"]
    assert set(observation["patch_hunk_ids"]).issubset({node["id"] for node in packet["patch_evidence"] if node["type"] == "PatchHunk"})


def test_evidence_collector_assigns_unique_ids_to_similar_long_paths(tmp_path: Path):
  client, repo_root, _commit_sha = _seed_repo_and_client(tmp_path)
  packet = client.build_root_cause_packet("CVE-TEST")
  packet["patch_evidence"].extend(
    [
      {"id": "file-a", "type": "ChangedFile", "content": {"path": "src/very-long-common-prefix-for-collision-a.c"}},
      {"id": "file-b", "type": "ChangedFile", "content": {"path": "src/very-long-common-prefix-for-collision-b.c"}},
    ]
  )

  trace = collect_git_evidence("CVE-TEST", packet, repo_root=repo_root)
  tool_ids = [call["id"] for call in trace["tool_calls"]]

  assert len(tool_ids) == len(set(tool_ids))


def test_legacy_adapter_reconstructs_provenance_without_mutating_input(tmp_path: Path):
  client, repo_root, _commit_sha = _seed_repo_and_client(tmp_path)
  packet = client.build_root_cause_packet("CVE-TEST")
  native = collect_git_evidence("CVE-TEST", packet, repo_root=repo_root)
  legacy = {
    "cve_id": "CVE-TEST",
    "backend_trusted": "wrapper",
    "tool_calls": [
      {
        "id": call["id"],
        "command": call["command"],
        "exit_code": call["exit_code"],
        "output": next(output["text"] for output in native["tool_outputs"] if output["command_ref"] == call["id"]),
      }
      for call in native["tool_calls"]
    ],
    "git_observations": [{"id": "legacy", "command_ref": "invented"}],
  }

  adapted = adapt_legacy_evidence_trace("CVE-TEST", packet, legacy)

  assert "source" not in legacy
  assert adapted["source"] == "wrapper_git_trace"
  assert adapted["created_from"] == "legacy_replay_adapter"
  assert adapted["legacy_reconstructed"] is True
  assert adapted["git_observations"]
  assert all(observation["created_from"] == "legacy_replay_adapter" for observation in adapted["git_observations"])


def test_evidence_collector_marks_failed_commit_commands_invalid(tmp_path: Path):
  client, repo_root, _commit_sha = _seed_repo_and_client(tmp_path)
  packet = client.build_root_cause_packet("CVE-TEST")
  fix = next(node for node in packet["patch_evidence"] if node["type"] == "FixCommit")
  fix["content"]["commit_sha"] = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

  trace = collect_git_evidence("CVE-TEST", packet, repo_root=repo_root)

  assert trace["git_observations"]
  assert all(observation["valid_evidence"] is False for observation in trace["git_observations"])
  assert all(observation["invalid_reason"] for observation in trace["git_observations"])


def test_workflow_with_fixture_backend_writes_artifacts_and_ingests(tmp_path: Path):
  client, repo_root, _commit_sha = _seed_repo_and_client(tmp_path)
  workflow = RootCauseWorkflow(client=client, backend=FixtureRootCauseBackend(), repo_root=repo_root)

  result = workflow.run_root_cause_for_cve("CVE-TEST", out_dir=tmp_path / "runs")
  graph = client.materialize()

  assert result["status"] == "ingested_raw"
  assert result["backend_type"] == "fixture"
  assert result["valid_json"] is True
  assert result["json_parse_status"] == "json"
  assert result["raw_response_size_bytes"] > 0
  assert result["duration_s"] >= 0
  assert any(node.type == "RootCauseHypothesis" and node.lifecycle == "raw" for node in graph.nodes)
  run_dir = Path(result["run_dir"])
  assert (run_dir / "root_cause_packet.json").exists()
  assert (run_dir / "evidence_trace.json").exists()
  assert (run_dir / "prompt.txt").exists()
  assert (run_dir / "raw_response.txt").exists()
  assert (run_dir / "parsed_output.json").exists()


def test_workflow_does_not_write_agent_supports_into_wrapper_trace(tmp_path: Path):
  client, repo_root, _commit_sha = _seed_repo_and_client(tmp_path)
  workflow = RootCauseWorkflow(client=client, backend=FixtureRootCauseBackend(), repo_root=repo_root)

  result = workflow.run_root_cause_for_cve("CVE-TEST", out_dir=tmp_path / "runs")
  trace = json.loads((Path(result["run_dir"]) / "evidence_trace.json").read_text(encoding="utf-8"))

  assert result["status"] == "ingested_raw"
  assert all(not observation.get("supports") for observation in trace["git_observations"])


def test_malformed_json_generates_failure_case(tmp_path: Path):
  client, repo_root, _commit_sha = _seed_repo_and_client(tmp_path)
  workflow = RootCauseWorkflow(client=client, backend=FixtureRootCauseBackend(mode="malformed"), repo_root=repo_root)

  result = workflow.run_root_cause_for_cve("CVE-TEST", out_dir=tmp_path / "runs")

  assert result["status"] == "parse_error"
  assert result["json_parse_status"] == "malformed"
  assert result["valid_json"] is False
  assert (Path(result["run_dir"]) / "parse_error.json").exists()
  assert any(node.type == "FailureCase" and node.content.get("stage") == "root_cause" for node in client.materialize().nodes)


def test_empty_response_generates_failure_case(tmp_path: Path):
  client, repo_root, _commit_sha = _seed_repo_and_client(tmp_path)
  workflow = RootCauseWorkflow(client=client, backend=FixtureRootCauseBackend(mode="empty"), repo_root=repo_root)

  result = workflow.run_root_cause_for_cve("CVE-TEST", out_dir=tmp_path / "runs")

  assert result["status"] == "empty"
  assert result["json_parse_status"] == "empty"
  assert result["empty_message"] is True
  assert any(node.type == "FailureCase" and node.content.get("reason") == "empty assistant message" for node in client.materialize().nodes)


def test_missing_git_observation_refs_are_rejected(tmp_path: Path):
  client, repo_root, _commit_sha = _seed_repo_and_client(tmp_path)
  workflow = RootCauseWorkflow(client=client, backend=FixtureRootCauseBackend(mode="missing_refs"), repo_root=repo_root)

  result = workflow.run_root_cause_for_cve("CVE-TEST", out_dir=tmp_path / "runs")

  assert result["status"] == "rejected"
  assert result["ingestion_result"]["status"] == "rejected"
  assert any(node.type == "RootCauseHypothesis" and node.lifecycle == "rejected" for node in client.materialize().nodes)


def test_batch_report_marks_fixture_as_fixture_not_opencode(tmp_path: Path):
  client, repo_root, _commit_sha = _seed_repo_and_client(tmp_path)
  summary = run_root_cause_batch(
    ["CVE-TEST"],
    client=client,
    backend=FixtureRootCauseBackend(),
    repo_root=repo_root,
    out_dir=tmp_path / "batch",
  )
  report = (tmp_path / "batch" / "report.md").read_text(encoding="utf-8")

  assert summary["backend_type_counts"] == {"fixture": 1}
  assert summary["json_parse_status_counts"] == {"json": 1}
  assert summary["failure_case_count"] == 0
  assert summary["total_duration_s"] >= 0
  assert summary["avg_raw_response_size_bytes"] > 0
  assert "fixture" in report
  assert "OpenCode real results: 0" in report


def test_prompt_requires_per_fix_commit_anchor_mapping():
  prompt = _prompt_template()

  assert "one CodeAnchor for every FixCommit" in prompt
  assert "fix_commit_id" in prompt
  assert "patch_hunk_id" in prompt
