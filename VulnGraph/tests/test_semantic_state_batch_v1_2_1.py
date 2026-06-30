from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from vulngraph.workflows.semantic_state_batch_v1_2_1 import precompute_git_semantic_states


def _git(repo: Path, *args: str) -> str:
  return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True, capture_output=True).stdout.strip()


def test_batch_semantic_states_use_wrapper_hash_and_tag_local_code(tmp_path: Path) -> None:
  repo = tmp_path / "repo"
  repo.mkdir()
  _git(repo, "init", "-b", "main")
  _git(repo, "config", "user.email", "test@example.com")
  _git(repo, "config", "user.name", "Test")
  raw = "    while (remaining > 0) {  /* old note */"
  (repo / "code.c").write_text(raw + "\n", encoding="utf-8")
  _git(repo, "add", "code.c")
  _git(repo, "commit", "-m", "introduce")
  _git(repo, "tag", "v1")
  (repo / "fix.txt").write_text("fix\n", encoding="utf-8")
  _git(repo, "add", "fix.txt")
  _git(repo, "commit", "-m", "fix wrapper")
  fix_sha = _git(repo, "rev-parse", "HEAD")
  event = {
    "event_candidate_id": "event-1", "fix_commit_sha": fix_sha,
    "path_before": "code.c", "old_line_start": 1,
    "old_line_text": raw.strip(), "old_line_text_hash": hashlib.sha256(raw.encode()).hexdigest(),
  }

  states = precompute_git_semantic_states(repo, [event], ["v1"])

  assert states[("event-1", "v1")]["state"] == "present_exact"
  assert states[("event-1", "v1")]["hash_resolution"] == "fix_parent_line"


def test_batch_semantic_states_skip_blob_over_explicit_byte_limit(tmp_path: Path) -> None:
  repo = tmp_path / "repo"
  repo.mkdir()
  _git(repo, "init", "-b", "main")
  _git(repo, "config", "user.email", "test@example.com")
  _git(repo, "config", "user.name", "Test")
  line = "int vulnerable = user_value;"
  (repo / "big.c").write_text(("x" * 256) + "\n" + line + "\n", encoding="utf-8")
  _git(repo, "add", "big.c")
  _git(repo, "commit", "-m", "introduce")
  _git(repo, "tag", "v1")
  (repo / "fix.txt").write_text("fix\n", encoding="utf-8")
  _git(repo, "add", "fix.txt")
  _git(repo, "commit", "-m", "fix wrapper")
  fix_sha = _git(repo, "rev-parse", "HEAD")
  event = {
    "event_candidate_id": "event-big", "fix_commit_sha": fix_sha,
    "path_before": "big.c", "old_line_start": 2,
    "old_line_text": line, "old_line_text_hash": hashlib.sha256(line.encode()).hexdigest(),
  }

  states = precompute_git_semantic_states(repo, [event], ["v1"], max_blob_bytes=64)

  assert states[("event-big", "v1")]["state"] == "unknown"
  assert states[("event-big", "v1")]["reason"] == "blob_too_large"
