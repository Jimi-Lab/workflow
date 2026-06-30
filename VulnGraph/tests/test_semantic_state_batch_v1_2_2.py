from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from vulngraph.workflows.semantic_state_batch_v1_2_2 import precompute_function_scope_semantic_states


def _git(repo: Path, *args: str) -> str:
  return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True, capture_output=True).stdout.strip()


def test_batch_function_scope_states_respect_semantic_context(tmp_path: Path) -> None:
  repo = tmp_path / "repo"
  repo.mkdir()
  _git(repo, "init", "-b", "main")
  _git(repo, "config", "user.email", "test@example.com")
  _git(repo, "config", "user.name", "Test")
  line = "if (len > capacity) return ERROR;"
  (repo / "parser.c").write_text("int parse(void) {\n  if ((len) > capacity) { return SAFE; }\n}\n", encoding="utf-8")
  _git(repo, "add", "parser.c")
  _git(repo, "commit", "-m", "release")
  _git(repo, "tag", "v1")
  (repo / "fix.txt").write_text("fix\n", encoding="utf-8")
  _git(repo, "add", "fix.txt")
  _git(repo, "commit", "-m", "fix")
  event = {
    "event_candidate_id": "event-1",
    "fix_commit_sha": _git(repo, "rev-parse", "HEAD"),
    "path_before": "parser.c",
    "old_line_start": 2,
    "old_line_text": line,
    "old_line_text_hash": hashlib.sha256(line.encode()).hexdigest(),
    "function_name": "parse",
    "semantic_context": ["ERROR"],
  }

  states = precompute_function_scope_semantic_states(repo, [event], ["v1"])

  assert states[("event-1", "v1")]["state"] == "absent"
  assert states[("event-1", "v1")]["failure_reason"] == "semantic_context_missing"
