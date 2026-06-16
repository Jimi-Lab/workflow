import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnversion.agent_harness.base import AgentCapabilities
from vulnversion.stage1_semantic_aggregation.agent_refine_regions import refine_regions_with_agent
from vulnversion.stage1_semantic_aggregation.artifacts import _jsonl_write, step1_paths
from vulnversion.stage1_semantic_aggregation.schema import EvidenceRef, FixFamilySemantics, SemanticRegion
from vulnversion.utils.jsonschema import dump_json


class FakeAgent:
  backend = "fake"

  def __init__(self, response: dict[str, Any] | Exception):
    self.response = response
    self.sessions: list[str | None] = []
    self.calls: list[dict[str, Any]] = []

  def capabilities(self) -> AgentCapabilities:
    return AgentCapabilities(backend="fake", supports_session_reuse=True)

  def create_readonly_session(self, *, title: str | None = None) -> str:
    self.sessions.append(title)
    return f"session-{len(self.sessions)}"

  def run_json(
    self,
    *,
    session_id: str,
    prompt: str,
    system: str | None = None,
    tools: dict[str, bool] | None = None,
    timeout_s: float | None = None,
    metadata: dict[str, Any] | None = None,
  ) -> dict[str, Any]:
    self.calls.append({
      "session_id": session_id,
      "prompt": prompt,
      "system": system,
      "tools": tools or {},
      "metadata": metadata or {},
    })
    if isinstance(self.response, Exception):
      raise self.response
    return self.response


def _prepare_step1_artifacts(tmp_path: Path) -> dict[str, Path]:
  paths = step1_paths(result_root=tmp_path, repo="demo", cve_id="CVE-X")
  paths["output_dir"].mkdir(parents=True, exist_ok=True)
  paths["agent_calls_dir"].mkdir(parents=True, exist_ok=True)
  paths["fix_evidence_dir"].mkdir(parents=True, exist_ok=True)
  dump_json(paths["fix_family"], FixFamilySemantics(cve_id="CVE-X", repo="demo", primary_fix_commit="abc", fix_commits=["abc"]).model_dump())
  dump_json(
    paths["fix_evidence_manifest"],
    {
      "schema_version": "step1_fix_commit_evidence.v1",
      "cve_id": "CVE-X",
      "repo": "demo",
      "repo_path": str(tmp_path / "repo"),
      "commits": [
        {
          "commit": "abc",
          "directory": str(paths["fix_evidence_dir"] / "abc"),
          "files": {
            "show_full_patch": {
              "path": str(paths["fix_evidence_dir"] / "abc" / "show_full_patch.txt"),
              "sha256": "test",
              "bytes": 1,
              "lines": 1,
            }
          },
          "commands": {"show_full_patch": ["git", "show", "abc"]},
          "errors": {},
        }
      ],
    },
  )
  _jsonl_write(
    paths["semantic_regions"],
    [
      SemanticRegion(
        cve_id="CVE-X",
        repo="demo",
        region_id="region_0001",
        commits=["abc"],
        file_path="file.c",
        function_context="parse_len",
        chunk_ids=["chunk_0001"],
        patch_type="add_only",
        file_role="source",
        added_guard_sequence=["if (len < 0) return -1;"],
        root_cause_score=6,
        score_reasons=["source_file", "added_guard_check"],
        source_refs=[
          EvidenceRef(
            ref_id="src:CVE-X:abc:file.c:git_diff:1",
            kind="git_diff",
            change_type="added",
            commit="abc",
            file_path="file.c",
            function_context="parse_len",
            hunk_header="@@ -1,3 +1,5 @@",
            new_line_no=2,
            snippet="if (len < 0) return -1;",
            snippet_hash="sha256:test",
            strength_hint="medium",
          )
        ],
      ).model_dump()
    ],
  )
  return paths


def _jsonl(path: Path) -> list[dict[str, Any]]:
  text = path.read_text(encoding="utf-8").strip()
  if not text:
    return []
  return [json.loads(line) for line in text.splitlines()]


def test_agent_refinement_writes_region_results_and_call_artifacts(tmp_path: Path):
  paths = _prepare_step1_artifacts(tmp_path)
  agent = FakeAgent({
    "schema_version": "step1_agent_region_refinement.v1",
    "cve_id": "CVE-X",
    "repo": "demo",
    "region_results": [
      {
        "region_id": "region_0001",
        "region_role": "primary_root_cause_region",
        "evidence_strength": "medium",
        "allowed_downstream_use": ["prompt_context", "vet_candidate", "priority_signal"],
        "root_cause_relation": "missing_guard",
        "root_cause_likelihood": 0.8,
        "fix_guard_likelihood": 0.9,
        "vulnerable_sequence_likelihood": 0.3,
        "vulnerable_sequence": [],
        "fix_guard_sequence": ["if (len < 0) return -1;"],
        "evidence_refs_used": [],
        "reasoning_summary": "The region adds a missing bounds check.",
        "risk_flags": [],
      }
    ],
    "global_risk_flags": [],
  })

  result = refine_regions_with_agent(
    result_root=tmp_path,
    repo="demo",
    cve_id="CVE-X",
    cve_context={"description": "bounds check"},
    agent=agent,
    resume=True,
  )

  assert len(agent.sessions) == 1
  assert "CVE-X" in (agent.sessions[0] or "")
  assert len(agent.calls) == 1
  assert agent.calls[0]["metadata"]["stage"] == "stage1"
  assert agent.calls[0]["metadata"]["task_type"] == "region_refinement"

  parsed_path = Path(result["region_refinements"])
  rows = _jsonl(parsed_path)
  assert rows[0]["region_role"] == "primary_root_cause_region"
  assert rows[0]["allowed_downstream_use"] == ["prompt_context", "vet_candidate", "priority_signal"]
  assert (paths["agent_calls_dir"] / "stage1_region_refinement_CVE-X_packet_0001.prompt.txt").is_file()
  assert (paths["agent_calls_dir"] / "stage1_region_refinement_CVE-X_packet_0001.response.json").is_file()
  assert (paths["agent_calls_dir"] / "stage1_region_refinement_CVE-X_packet_0001.parsed.json").is_file()
  assert any(row["event"] == "packet_succeeded" for row in _jsonl(paths["trace"]))


def test_agent_refinement_resume_skips_existing_parsed_packet(tmp_path: Path):
  _prepare_step1_artifacts(tmp_path)
  response = {
    "schema_version": "step1_agent_region_refinement.v1",
    "cve_id": "CVE-X",
    "repo": "demo",
    "region_results": [
      {
        "region_id": "region_0001",
        "region_role": "context_region",
        "evidence_strength": "weak",
        "allowed_downstream_use": ["prompt_context"],
        "root_cause_relation": "unknown",
        "root_cause_likelihood": 0.1,
        "fix_guard_likelihood": 0.1,
        "vulnerable_sequence_likelihood": 0.1,
        "vulnerable_sequence": [],
        "fix_guard_sequence": [],
        "evidence_refs_used": [],
        "reasoning_summary": "context",
        "risk_flags": [],
      }
    ],
  }
  first_agent = FakeAgent(response)
  refine_regions_with_agent(result_root=tmp_path, repo="demo", cve_id="CVE-X", cve_context={}, agent=first_agent, resume=True)
  second_agent = FakeAgent(RuntimeError("should not run"))
  refine_regions_with_agent(result_root=tmp_path, repo="demo", cve_id="CVE-X", cve_context={}, agent=second_agent, resume=True)
  assert len(second_agent.calls) == 0


def test_agent_refinement_failure_outputs_unknown_agent_failed(tmp_path: Path):
  paths = _prepare_step1_artifacts(tmp_path)
  agent = FakeAgent(RuntimeError("backend down"))
  result = refine_regions_with_agent(
    result_root=tmp_path,
    repo="demo",
    cve_id="CVE-X",
    cve_context={},
    agent=agent,
    resume=True,
  )
  rows = _jsonl(Path(result["region_refinements"]))
  assert rows[0]["region_id"] == "region_0001"
  assert rows[0]["region_role"] == "unknown_agent_failed"
  assert "agent_error" in rows[0]["risk_flags"]
  assert any(row["event"] == "packet_failed" for row in _jsonl(paths["trace"]))


def test_agent_refinement_normalizes_invalid_downstream_use(tmp_path: Path):
  _prepare_step1_artifacts(tmp_path)
  agent = FakeAgent({
    "schema_version": "step1_agent_region_refinement.v1",
    "cve_id": "CVE-X",
    "repo": "demo",
    "region_results": [
      {
        "region_id": "region_0001",
        "region_role": "primary_root_cause_region",
        "evidence_strength": "strong",
        "allowed_downstream_use": ["prompt_context", "priority_signal", "step2_direct_input"],
        "root_cause_relation": "bounds_check",
        "root_cause_likelihood": 0.9,
        "fix_guard_likelihood": 0.9,
        "vulnerable_sequence_likelihood": 0.2,
        "vulnerable_sequence": [],
        "fix_guard_sequence": ["if (len < 0) return -1;"],
        "evidence_refs_used": [],
        "reasoning_summary": "root cause region",
        "risk_flags": [],
      }
    ],
  })

  result = refine_regions_with_agent(
    result_root=tmp_path,
    repo="demo",
    cve_id="CVE-X",
    cve_context={},
    agent=agent,
    resume=True,
  )

  rows = _jsonl(Path(result["region_refinements"]))
  assert rows[0]["region_role"] == "primary_root_cause_region"
  assert rows[0]["allowed_downstream_use"] == ["prompt_context", "priority_signal", "vet_candidate"]


def test_agent_refinement_prompt_uses_compressed_region_packet(tmp_path: Path):
  _prepare_step1_artifacts(tmp_path)
  agent = FakeAgent({
    "schema_version": "step1_agent_region_refinement.v1",
    "cve_id": "CVE-X",
    "repo": "demo",
    "region_results": [],
  })

  refine_regions_with_agent(
    result_root=tmp_path,
    repo="demo",
    cve_id="CVE-X",
    cve_context={},
    agent=agent,
    resume=True,
  )

  prompt = agent.calls[0]["prompt"]
  assert "source_refs_sample" in prompt
  assert "change_type" in prompt
  assert "fix_commit_evidence" in prompt
  assert "show_full_patch" in prompt
  assert '"schema_version": "semantic_region.v1"' not in prompt


def test_agent_refinement_can_enable_readonly_git_tools(tmp_path: Path):
  _prepare_step1_artifacts(tmp_path)
  agent = FakeAgent({
    "schema_version": "step1_agent_region_refinement.v1",
    "cve_id": "CVE-X",
    "repo": "demo",
    "region_results": [],
  })

  refine_regions_with_agent(
    result_root=tmp_path,
    repo="demo",
    cve_id="CVE-X",
    cve_context={},
    agent=agent,
    resume=True,
    enable_git_tools=True,
  )

  assert agent.calls[0]["tools"]["git_show"] is True
  assert agent.calls[0]["tools"]["git_grep"] is True
  assert agent.calls[0]["tools"]["git_log"] is True
  assert agent.calls[0]["tools"]["git_diff"] is True
  assert agent.calls[0]["tools"]["bash"] is True
  assert agent.calls[0]["metadata"]["enable_git_tools"] is True
  system = agent.calls[0]["system"] or ""
  assert "Read-only git and bash tools are enabled" in system
  assert "Forbidden actions" in system
