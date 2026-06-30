from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from vulngraph.workflows.semantic_state_v1_2_1 import GitSemanticStateRunner, normalize_semantic_line


_TOKEN_RE = re.compile(r"[A-Za-z_]\w*|==|!=|<=|>=|->|\+\+|--|&&|\|\||[<>+\-*/%=&|!]")
_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_ARRAY_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\[")
_MEMBER_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?:->|\.)\s*([A-Za-z_]\w*)")
_FUNCTION_HEADER_RE = re.compile(r"^\s*(?:[A-Za-z_][\w\s\*\(\),]*\s+)?(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:\{|$)")
_COMMON_TOKENS = {
  "if", "else", "while", "for", "return", "static", "const", "int", "void", "char",
  "long", "short", "unsigned", "signed", "struct", "enum", "sizeof", "NULL", "true",
  "false", "status", "value", "ret", "retval", "result", "error",
}
_PRESENT_STATES = {"present_exact", "present_normalized", "present_predicate_equivalent"}


@dataclass(frozen=True)
class FunctionScope:
  name: str
  start: int
  end: int
  lines: list[str]


class FunctionScopeSemanticVerifier:
  """Lightweight C-like function-scope verifier for vulnerable predicate survival."""

  def __init__(self, runner: Any) -> None:
    self.runner = runner

  def verify(self, event: dict[str, Any], commitish: str) -> dict[str, Any]:
    line, base = self._event_line(event, commitish)
    if not line:
      return base
    original = str(event.get("path_before") or "")
    lineage_ref = str(event.get("fix_commit_sha") or commitish)
    related = list(self.runner.related_paths(lineage_ref, original) or []) if hasattr(self.runner, "related_paths") else []
    paths = [original, *[path for path in related if path != original]]
    readable = 0
    context_missing = False
    reorder_seen = False
    function_missing = False
    weak_predicate = False
    for path in paths:
      content = self.runner.read_file(commitish, path)
      if content is None:
        continue
      readable += 1
      evidence = evaluate_predicate_in_content(event, line, content, path)
      if evidence["state"] in _PRESENT_STATES:
        return {**base, **evidence}
      context_missing = context_missing or evidence.get("failure_reason") == "semantic_context_missing"
      reorder_seen = reorder_seen or evidence.get("failure_reason") == "predicate_tokens_reordered"
      function_missing = function_missing or evidence.get("failure_reason") == "function_scope_missing"
      weak_predicate = weak_predicate or evidence.get("failure_reason") == "weak_predicate_fingerprint"
    if not readable:
      return {**base, **_unknown("path_unavailable")}
    if reorder_seen:
      return {**base, **_unknown("predicate_tokens_reordered")}
    if context_missing:
      return {**base, **_absent("semantic_context_missing")}
    if function_missing:
      return {**base, **_absent("function_scope_missing")}
    if weak_predicate:
      return {**base, **_absent("weak_predicate_fingerprint")}
    return {**base, **_absent("predicate_not_found_in_readable_paths")}

  def _event_line(self, event: dict[str, Any], commitish: str) -> tuple[str, dict[str, Any]]:
    line = str(event.get("old_line_text") or "")
    expected_hash = str(event.get("old_line_text_hash") or "")
    base = {
      "event_candidate_id": str(event.get("event_candidate_id") or ""),
      "commitish": commitish,
      "event_ancestry_required": False,
      "line_text_hash": expected_hash,
    }
    if not line:
      return "", {**base, **_unknown("missing_old_line_text")}
    if not expected_hash:
      return "", {**base, **_unknown("missing_old_line_text_hash")}
    if hashlib.sha256(line.encode()).hexdigest() != expected_hash:
      resolver = getattr(self.runner, "resolve_hashed_line", None)
      resolved = resolver(event) if callable(resolver) else None
      if not resolved:
        return "", {**base, **_unknown("old_line_text_hash_mismatch")}
      line = str(resolved["line_text"])
      base.update({
        "hash_resolution": "fix_parent_line",
        "hash_source_parent_sha": str(resolved.get("parent_sha") or ""),
        "hash_source_line": resolved.get("line_number"),
      })
    else:
      base["hash_resolution"] = "event_line_text"
    return line, base


def evaluate_predicate_in_content(event: dict[str, Any], line: str, content: str, path: str) -> dict[str, Any]:
  function_name = str(event.get("function_name") or _function_name_from_line(line) or "")
  scopes = _function_scopes(content)
  scope = _choose_scope(scopes, function_name)
  if function_name and scope is None:
    return _absent("function_scope_missing", path=path, function_name=function_name)
  search_lines = scope.lines if scope else _bounded_lines(content.splitlines(), int(event.get("old_line_start") or 0))
  match_level = "function_scope" if scope else "bounded_file_window"
  expected_norm = normalize_semantic_line(line)
  required_context = [str(value) for value in event.get("semantic_context", []) or [] if value]
  context_text = "\n".join(search_lines)
  exact_set = set(search_lines)
  normalized = {normalize_semantic_line(value): value for value in search_lines}
  fingerprint = predicate_fingerprint(line)
  if not _is_predicate_bearing(line, fingerprint):
    return _absent("weak_predicate_fingerprint", path=path, function_name=function_name, match_level=match_level, fingerprint=fingerprint)
  if line in exact_set:
    return _present("present_exact", line, required_context, context_text, fingerprint, path, function_name, match_level, "exact_line_and_hash")
  if expected_norm and expected_norm in normalized:
    return _present("present_normalized", normalized[expected_norm], required_context, context_text, fingerprint, path, function_name, match_level, "lexically_normalized_line")
  best_reorder = False
  for candidate in search_lines:
    candidate_fp = predicate_fingerprint(candidate)
    state, reason = _equivalent_state(fingerprint, candidate_fp, required_context, context_text)
    if state == "present_predicate_equivalent":
      return _present(state, candidate, required_context, context_text, fingerprint, path, function_name, match_level, reason)
    best_reorder = best_reorder or reason == "predicate_tokens_reordered"
  if required_context and not _context_present(required_context, context_text):
    return _absent("semantic_context_missing", path=path, function_name=function_name, match_level=match_level, fingerprint=fingerprint)
  if best_reorder:
    return _unknown("predicate_tokens_reordered", path=path, function_name=function_name, match_level=match_level, fingerprint=fingerprint)
  return _absent("predicate_not_found_in_scope", path=path, function_name=function_name, match_level=match_level, fingerprint=fingerprint)


def predicate_fingerprint(statement: str) -> dict[str, Any]:
  normalized = normalize_semantic_line(statement)
  tokens = _TOKEN_RE.findall(normalized)
  identifiers = [token for token in tokens if re.fullmatch(r"[A-Za-z_]\w*", token) and token not in _COMMON_TOKENS]
  calls = [name for name in _CALL_RE.findall(normalized) if name not in _COMMON_TOKENS]
  arrays = _ARRAY_RE.findall(normalized)
  members = [f"{left}.{right}" for left, right in _MEMBER_RE.findall(normalized)]
  operators = [token for token in tokens if not re.fullmatch(r"[A-Za-z_]\w*", token)]
  structural = sorted(set(calls + arrays + members + operators))
  return {
    "tokens": tokens,
    "identifiers": sorted(set(identifiers)),
    "calls": sorted(set(calls)),
    "array_accesses": sorted(set(arrays)),
    "member_accesses": sorted(set(members)),
    "operators": sorted(set(operators)),
    "structural": structural,
    "normalized": normalized,
  }


def _equivalent_state(expected: dict[str, Any], candidate: dict[str, Any], required_context: list[str], context: str) -> tuple[str, str]:
  if required_context and not _context_present(required_context, context):
    return "", "semantic_context_missing"
  if not _has_nontrivial_fingerprint(expected, candidate):
    return "", "weak_fingerprint"
  expected_tokens = list(expected["tokens"])
  candidate_tokens = list(candidate["tokens"])
  if len(expected_tokens) >= 3 and _is_subsequence(expected_tokens, candidate_tokens):
    return "present_predicate_equivalent", "function_scope_predicate_fingerprint"
  expected_struct = set(expected["structural"])
  candidate_struct = set(candidate["structural"])
  expected_ids = set(expected["identifiers"])
  candidate_ids = set(candidate["identifiers"])
  if len(expected_struct & candidate_struct) >= 2 and len(expected_ids & candidate_ids) >= 2:
    return "", "predicate_tokens_reordered"
  return "", "fingerprint_mismatch"


def _has_nontrivial_fingerprint(expected: dict[str, Any], candidate: dict[str, Any]) -> bool:
  structural_overlap = set(expected["structural"]) & set(candidate["structural"])
  identifier_overlap = set(expected["identifiers"]) & set(candidate["identifiers"])
  return len(structural_overlap) >= 1 and (len(identifier_overlap) >= 2 or len(structural_overlap) >= 2)


def _is_predicate_bearing(statement: str, fingerprint: dict[str, Any]) -> bool:
  stripped = statement.strip()
  if not stripped or stripped in {"{", "}", ";"}:
    return False
  if _FUNCTION_HEADER_RE.match(statement) and not stripped.startswith(("if", "while", "for", "switch")):
    return False
  if len(fingerprint["tokens"]) < 3:
    return False
  signal_count = (
    len(fingerprint["calls"]) + len(fingerprint["array_accesses"]) +
    len(fingerprint["member_accesses"]) + len(fingerprint["operators"])
  )
  if signal_count == 0:
    return False
  return len(fingerprint["identifiers"]) >= 1 or len(fingerprint["structural"]) >= 2


def _function_scopes(content: str) -> list[FunctionScope]:
  lines = content.splitlines()
  scopes: list[FunctionScope] = []
  index = 0
  while index < len(lines):
    match = _FUNCTION_HEADER_RE.match(lines[index])
    if not match or lines[index].strip().endswith(";"):
      index += 1
      continue
    name = match.group("name")
    start = index
    brace = lines[index].count("{") - lines[index].count("}")
    end = index
    while end + 1 < len(lines) and brace > 0:
      end += 1
      brace += lines[end].count("{") - lines[end].count("}")
    if brace == 0 and end > start:
      scopes.append(FunctionScope(name=name, start=start, end=end, lines=lines[start:end + 1]))
      index = end + 1
    else:
      index += 1
  return scopes


def _choose_scope(scopes: list[FunctionScope], function_name: str) -> FunctionScope | None:
  if not function_name:
    return None
  for scope in scopes:
    if scope.name == function_name:
      return scope
  return None


def _function_name_from_line(line: str) -> str:
  match = _FUNCTION_HEADER_RE.match(line)
  return match.group("name") if match else ""


def _bounded_lines(lines: list[str], line_number: int, radius: int = 40) -> list[str]:
  if line_number <= 0:
    return lines[: min(len(lines), radius * 2)]
  start = max(0, line_number - radius - 1)
  end = min(len(lines), line_number + radius)
  return lines[start:end]


def _context_present(required: list[str], context: str) -> bool:
  tokens = set(_TOKEN_RE.findall(context))
  return all(value in context or value in tokens for value in required)


def _is_subsequence(needle: list[str], haystack: list[str]) -> bool:
  iterator = iter(haystack)
  return all(any(value == candidate for candidate in iterator) for value in needle)


def _present(state: str, statement: str, required_context: list[str], context: str, fingerprint: dict[str, Any], path: str, function_name: str, match_level: str, reason: str) -> dict[str, Any]:
  if required_context and not _context_present(required_context, context):
    return _absent("semantic_context_missing", path=path, function_name=function_name, match_level=match_level, fingerprint=fingerprint)
  return {
    "state": state,
    "match_level": match_level,
    "path": path,
    "function_name": function_name,
    "function_id": "",
    "matched_statement": statement.strip(),
    "matched_context": "\n".join(context.splitlines()[:8]),
    "fingerprint": fingerprint,
    "confidence_reason": reason,
    "failure_reason": "",
    "reason": reason,
  }


def _absent(reason: str, *, path: str = "", function_name: str = "", match_level: str = "", fingerprint: dict[str, Any] | None = None) -> dict[str, Any]:
  return {
    "state": "absent",
    "match_level": match_level,
    "path": path,
    "function_name": function_name,
    "function_id": "",
    "matched_statement": "",
    "matched_context": "",
    "fingerprint": fingerprint or {},
    "confidence_reason": "",
    "failure_reason": reason,
    "reason": reason,
  }


def _unknown(reason: str, *, path: str = "", function_name: str = "", match_level: str = "", fingerprint: dict[str, Any] | None = None) -> dict[str, Any]:
  return {
    "state": "unknown",
    "match_level": match_level,
    "path": path,
    "function_name": function_name,
    "function_id": "",
    "matched_statement": "",
    "matched_context": "",
    "fingerprint": fingerprint or {},
    "confidence_reason": "",
    "failure_reason": reason,
    "reason": reason,
  }
