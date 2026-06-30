from __future__ import annotations

import hashlib

from vulngraph.workflows.semantic_state_v1_2_2 import FunctionScopeSemanticVerifier


def _event(line: str, *, function_name: str = "parse", context: list[str] | None = None) -> dict:
  return {
    "event_candidate_id": "event-1",
    "path_before": "src/parser.c",
    "fix_commit_sha": "f" * 40,
    "old_line_text": line,
    "old_line_text_hash": hashlib.sha256(line.encode()).hexdigest(),
    "function_name": function_name,
    "semantic_context": context or [],
  }


class Runner:
  def __init__(self, files: dict[tuple[str, str], str]) -> None:
    self.files = files

  def read_file(self, commitish: str, path: str) -> str | None:
    return self.files.get((commitish, path))

  def related_paths(self, commitish: str, path: str) -> list[str]:
    return []


def test_function_scope_verifier_matches_normalized_statement_in_same_function() -> None:
  line = "if (len > capacity) return ERROR;"
  content = "int parse(void) {\n  if ((len) > capacity) { return ERROR; }\n}\n"
  result = FunctionScopeSemanticVerifier(Runner({("v1", "src/parser.c"): content})).verify(_event(line), "v1")

  assert result["state"] == "present_predicate_equivalent"
  assert result["match_level"] == "function_scope"
  assert result["function_name"] == "parse"


def test_function_scope_verifier_rejects_same_tokens_in_different_function() -> None:
  line = "if (len > capacity) return ERROR;"
  content = "int other(void) {\n  if ((len) > capacity) { return ERROR; }\n}\n"
  result = FunctionScopeSemanticVerifier(Runner({("v1", "src/parser.c"): content})).verify(_event(line), "v1")

  assert result["state"] in {"absent", "unknown"}
  assert result["state"] != "present_predicate_equivalent"


def test_function_scope_verifier_requires_semantic_context_for_equivalent_match() -> None:
  line = "if (len > capacity) return ERROR;"
  content = "int parse(void) {\n  if ((len) > capacity) { return SAFE; }\n}\n"
  result = FunctionScopeSemanticVerifier(Runner({("v1", "src/parser.c"): content})).verify(_event(line, context=["ERROR"]), "v1")

  assert result["state"] == "absent"
  assert result["failure_reason"] == "semantic_context_missing"


def test_common_identifier_alone_does_not_match() -> None:
  line = "if (status) return;"
  content = "int parse(void) {\n  status = 1;\n}\n"
  result = FunctionScopeSemanticVerifier(Runner({("v1", "src/parser.c"): content})).verify(_event(line), "v1")

  assert result["state"] != "present_predicate_equivalent"


def test_reordered_condition_returns_unknown_not_present() -> None:
  line = "if (a > b && c < d) return ERROR;"
  content = "int parse(void) {\n  if (c < d && a > b) return ERROR;\n}\n"
  result = FunctionScopeSemanticVerifier(Runner({("v1", "src/parser.c"): content})).verify(_event(line), "v1")

  assert result["state"] == "unknown"
  assert result["failure_reason"] == "predicate_tokens_reordered"



def test_weak_declaration_line_does_not_confirm_predicate_survival() -> None:
  line = "static int"
  content = "int parse(void) {\n  static int\n}\n"
  result = FunctionScopeSemanticVerifier(Runner({("v1", "src/parser.c"): content})).verify(_event(line), "v1")

  assert result["state"] == "absent"
  assert result["failure_reason"] == "weak_predicate_fingerprint"
