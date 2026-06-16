import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from vulnversion.agent_harness.base import AgentCapabilities
from vulnversion.stage3_verify.verify_tags import verify_tags


def _extract_prompt_tag_line(prompt: str) -> tuple[str, str]:
  """Parse both legacy and current Stage3 tag-judge prompt headers."""
  tag = ""
  release_line = ""
  for prompt_line in prompt.splitlines():
    if prompt_line.startswith("# Task: Verify whether tag `"):
      tag = prompt_line.split("`")[1]
    elif prompt_line.startswith("Target tag: `"):
      tag = prompt_line.split("`")[1]
    if prompt_line.startswith("Release line: `"):
      release_line = prompt_line.split("`")[1]
    elif prompt_line.startswith("Release line label: `"):
      release_line = prompt_line.split("`")[1]
  return tag, release_line


class _DummyAgent:
  """Fake agent implementing the AgentRuntime Protocol for unit testing."""

  def __init__(self, fail_tag: str):
    self._fail_tag = fail_tag
    self._calls: list[str] = []

  @property
  def backend(self) -> str:
    return "dummy"

  def capabilities(self) -> AgentCapabilities:
    return AgentCapabilities(backend="dummy")

  def create_readonly_session(self, *, title: str | None = None) -> str:
    return "dummy-session"

  def run_json(self, *, session_id: str, prompt: str, system=None, tools=None,
               timeout_s=None, metadata=None):
    tag, release_line = _extract_prompt_tag_line(prompt)
    self._calls.append(tag)
    if tag == self._fail_tag:
      raise ValueError("bad json from model")
    return {
      "tag": tag,
      "line": release_line,
      "verdict": "NOT_AFFECTED",
      "run_status": "OK",
      "confidence": 0.5,
      "reasoning_summary": "ok",
      "matched_predicates": [],
      "failed_predicates": [],
      "triggered_guards": [],
      "evidence_snippets": [],
    }


class TestStage3ErrorHandling(unittest.TestCase):
  def test_agent_error_does_not_abort(self):
    with tempfile.TemporaryDirectory() as tmp:
      repo_dir = Path(tmp) / "repo"
      out_dir = Path(tmp) / "out"
      repo_dir.mkdir(parents=True, exist_ok=True)
      out_dir.mkdir(parents=True, exist_ok=True)

      subprocess.run(["git", "-C", str(repo_dir), "init"], check=True, capture_output=True)
      (repo_dir / "a.txt").write_text("hello\n", encoding="utf-8")
      subprocess.run(["git", "-C", str(repo_dir), "add", "a.txt"], check=True, capture_output=True)
      subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", "init"], check=True, capture_output=True)
      subprocess.run(["git", "-C", str(repo_dir), "tag", "t1"], check=True, capture_output=True)
      subprocess.run(["git", "-C", str(repo_dir), "tag", "t2"], check=True, capture_output=True)

      rci_path = Path(tmp) / "rci.json"
      # Use an anchor with a file_path that exists in the test repo so that
      # the pre-filter (anchor absence check) does NOT short-circuit the tag
      # before the agent gets called.
      rci_path.write_text(json.dumps({
        "anchor": {"file_paths": ["a.txt"], "function_names": [], "stable_tokens": []},
        "vuln_predicates": [{"kind": "token_any", "args": {"tokens": ["hello"]}}],
        "fix_predicates": [{"kind": "token_any", "args": {"tokens": ["unlikely_fix_token_xyz"]}}],
        "guards": [],
      }, ensure_ascii=False, indent=2), encoding="utf-8")

      agent = _DummyAgent(fail_tag="t1")
      out = verify_tags(
        repo_path=str(repo_dir),
        cve_id="CVE-TEST",
        rci_path=str(rci_path),
        out_dir=str(out_dir),
        tags=["t1", "t2"],
        resume=False,
        agent=agent,  # type: ignore[arg-type]
        session_id="s",
        per_tag_session=False,
        log_progress=False,
      )

      results = list(out.get("results") or [])
      self.assertEqual(len(results), 2)
      by_tag = {r["tag"]: r for r in results}
      self.assertIsNone(by_tag["t1"]["verdict"])
      self.assertEqual(by_tag["t1"]["run_status"], "AGENT_ERROR")
      self.assertEqual(by_tag["t1"]["confidence"], 0.0)
      self.assertEqual(by_tag["t2"]["verdict"], "NOT_AFFECTED")


if __name__ == "__main__":
  unittest.main()
