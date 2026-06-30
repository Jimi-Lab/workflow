from __future__ import annotations

import hashlib

from vulngraph.workflows.semantic_state_v1_2_1 import SemanticStateVerifier


class HashRecoveryRunner:
  def read_file(self, commitish: str, path: str) -> str | None:
    return "    while (remaining > 0) { // current note\n"

  def related_paths(self, commitish: str, path: str) -> list[str]:
    return []

  def resolve_hashed_line(self, event: dict) -> dict:
    return {
      "line_text": "    while (remaining > 0) {  /* old note */",
      "line_number": 12,
      "parent_sha": "f" * 40,
      "path": "src/parser.c",
    }


def test_stripped_event_text_recovers_wrapper_hashed_parent_line() -> None:
  raw = "    while (remaining > 0) {  /* old note */"
  event = {
    "event_candidate_id": "event-1",
    "fix_commit_sha": "e" * 40,
    "path_before": "src/parser.c",
    "old_line_start": 12,
    "old_line_text": "while (remaining > 0) { /* old note */",
    "old_line_text_hash": hashlib.sha256(raw.encode()).hexdigest(),
  }

  result = SemanticStateVerifier(HashRecoveryRunner()).verify(event, "v1")

  assert result["state"] == "present_normalized"
  assert result["hash_resolution"] == "fix_parent_line"
  assert result["hash_source_line"] == 12
