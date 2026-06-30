from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any


_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT_RE = re.compile(r"//.*$")
_TOKEN_RE = re.compile(r"[A-Za-z_]\w*|==|!=|<=|>=|->|\+\+|--|&&|\|\||[<>+\-*/%=&|!]")


class GitSemanticStateRunner:
  """Read-only Git adapter used by the deterministic semantic verifier."""

  def __init__(self, repo: str | Path) -> None:
    self.repo = Path(repo)
    self._file_cache: dict[tuple[str, str], str | None] = {}
    self._path_cache: dict[tuple[str, str], list[str]] = {}
    self._hash_cache: dict[tuple[str, str, str], dict[str, Any] | None] = {}

  def read_file(self, commitish: str, path: str) -> str | None:
    key = (commitish, path)
    if key not in self._file_cache:
      result = subprocess.run(
        ["git", "-C", str(self.repo), "show", f"{commitish}:{path}"],
        text=True, encoding="utf-8", errors="replace", capture_output=True, check=False,
      )
      self._file_cache[key] = result.stdout if result.returncode == 0 else None
    return self._file_cache[key]

  def related_paths(self, commitish: str, path: str) -> list[str]:
    key = (commitish, path)
    if key in self._path_cache:
      return self._path_cache[key]
    result = subprocess.run(
      ["git", "-C", str(self.repo), "log", "--follow", "--name-status", "--format=", commitish, "--", path],
      text=True, encoding="utf-8", errors="replace", capture_output=True, check=False,
    )
    output: set[str] = set()
    if result.returncode == 0:
      for row in result.stdout.splitlines():
        parts = row.split("\t")
        if len(parts) >= 3 and parts[0].startswith("R"):
          output.update(parts[1:3])
    output.discard(path)
    self._path_cache[key] = sorted(output)
    return self._path_cache[key]

  def resolve_hashed_line(self, event: dict[str, Any]) -> dict[str, Any] | None:
    fix_sha = str(event.get("fix_commit_sha") or "")
    path = str(event.get("path_before") or "")
    expected_hash = str(event.get("old_line_text_hash") or "")
    key = (fix_sha, path, expected_hash)
    if key in self._hash_cache:
      return self._hash_cache[key]
    parent_result = subprocess.run(
      ["git", "-C", str(self.repo), "rev-parse", f"{fix_sha}^1"],
      text=True, encoding="utf-8", errors="replace", capture_output=True, check=False,
    )
    parent = parent_result.stdout.strip() if parent_result.returncode == 0 else ""
    content = self.read_file(parent, path) if parent else None
    resolved = None
    if content is not None:
      lines = content.splitlines()
      preferred = int(event.get("old_line_start") or 0)
      indexes = ([preferred - 1] if 0 < preferred <= len(lines) else []) + list(range(len(lines)))
      seen: set[int] = set()
      for index in indexes:
        if index in seen:
          continue
        seen.add(index)
        if hashlib.sha256(lines[index].encode()).hexdigest() == expected_hash:
          resolved = {"line_text": lines[index], "line_number": index + 1, "parent_sha": parent, "path": path}
          break
    self._hash_cache[key] = resolved
    return resolved


class SemanticStateVerifier:
  """Verify vulnerable predicate survival without requiring candidate ancestry."""

  def __init__(self, runner: Any) -> None:
    self.runner = runner

  def verify(self, event: dict[str, Any], commitish: str) -> dict[str, Any]:
    line = str(event.get("old_line_text") or "")
    expected_hash = str(event.get("old_line_text_hash") or "")
    base = {
      "event_candidate_id": str(event.get("event_candidate_id") or ""),
      "commitish": commitish,
      "event_ancestry_required": False,
      "line_text_hash": expected_hash,
    }
    if not line:
      return {**base, "state": "unknown", "reason": "missing_old_line_text"}
    if not expected_hash:
      return {**base, "state": "unknown", "reason": "missing_old_line_text_hash"}
    hash_resolution = "event_line_text"
    if hashlib.sha256(line.encode()).hexdigest() != expected_hash:
      resolver = getattr(self.runner, "resolve_hashed_line", None)
      resolved = resolver(event) if callable(resolver) else None
      if not resolved:
        return {**base, "state": "unknown", "reason": "old_line_text_hash_mismatch"}
      line = str(resolved["line_text"])
      hash_resolution = "fix_parent_line"
      base["hash_resolution"] = hash_resolution
      base["hash_source_parent_sha"] = str(resolved.get("parent_sha") or "")
      base["hash_source_line"] = resolved.get("line_number")
    else:
      base["hash_resolution"] = hash_resolution
    original_path = str(event.get("path_before") or "")
    lineage_ref = str(event.get("fix_commit_sha") or commitish)
    related = list(self.runner.related_paths(lineage_ref, original_path) or []) if hasattr(self.runner, "related_paths") else []
    paths = [original_path, *[path for path in related if path != original_path]]
    readable = 0
    for path in paths:
      content = self.runner.read_file(commitish, path)
      if content is None:
        continue
      readable += 1
      lines = content.splitlines()
      if line in lines:
        return {**base, "state": "present_exact", "matched_path": path, "path_resolution": _path_resolution(path, original_path), "reason": "exact_line_and_hash"}
      normalized = normalize_semantic_line(line)
      if normalized and any(normalize_semantic_line(value) == normalized for value in lines):
        return {**base, "state": "present_normalized", "matched_path": path, "path_resolution": _path_resolution(path, original_path), "reason": "lexically_normalized_line"}
      if _predicate_equivalent(event, content):
        return {**base, "state": "present_predicate_equivalent", "matched_path": path, "path_resolution": _path_resolution(path, original_path), "reason": "bounded_predicate_fingerprint"}
    if not readable:
      return {**base, "state": "unknown", "reason": "path_unavailable"}
    return {**base, "state": "absent", "reason": "predicate_not_found_in_readable_paths"}


def normalize_semantic_line(value: str) -> str:
  value = _BLOCK_COMMENT_RE.sub("", value)
  value = _LINE_COMMENT_RE.sub("", value)
  return " ".join(value.strip().split())


def cluster_history_events(events: list[dict[str, Any]], judgments: list[dict[str, Any]]) -> list[dict[str, Any]]:
  judgment_by_id = {str(item.get("event_candidate_id") or ""): item for item in judgments}
  groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
  for event in events:
    key = (
      tuple(sorted(event.get("branch_context_ids") or [])),
      str(event.get("source_anchor_id") or event.get("old_line_text_hash") or ""),
      tuple(sorted(event.get("root_cause_binding_refs") or [])),
      tuple(sorted(event.get("vulnerable_predicate_refs") or [])),
    )
    groups.setdefault(key, []).append(event)
  output = []
  for key, members in sorted(groups.items(), key=lambda item: repr(item[0])):
    member_judgments = [judgment_by_id.get(str(item.get("event_candidate_id") or ""), {}) for item in members]
    selected_primary = [item for item in member_judgments if item.get("decision") == "selected" and item.get("boundary_role") == "primary_boundary"]
    selected_equivalent = [item for item in member_judgments if item.get("decision") == "selected" and item.get("boundary_role") == "branch_equivalent_boundary"]
    uncertain_primary = [item for item in member_judgments if item.get("decision") == "uncertain" and item.get("boundary_role") in {"primary_boundary", "branch_equivalent_boundary"}]
    resolution = "selected_primary" if selected_primary else "selected_equivalent" if selected_equivalent else "unresolved_primary" if uncertain_primary else "not_selected"
    ids = sorted(str(item.get("event_candidate_id") or "") for item in members)
    digest = hashlib.sha256("|".join(map(str, key)).encode()).hexdigest()[:20]
    output.append({
      "history_event_cluster_id": f"history-event-cluster:{digest}",
      "branch_context_ids": list(key[0]),
      "source_anchor_id": key[1],
      "root_cause_binding_refs": list(key[2]),
      "vulnerable_predicate_refs": list(key[3]),
      "alternative_event_candidate_ids": ids,
      "alternative_event_commit_shas": sorted({str(item.get("event_commit_sha") or "") for item in members}),
      "selected_event_candidate_ids": sorted(str(item.get("event_candidate_id") or "") for item in [*selected_primary, *selected_equivalent]),
      "resolution": resolution,
      "provenance": [{"event_candidate_id": str(item.get("event_candidate_id") or ""), "derivation_modes": list(item.get("derivation_modes") or []), "evidence_refs": list(item.get("evidence_refs") or [])} for item in members],
    })
  return output


def _predicate_equivalent(event: dict[str, Any], content: str) -> bool:
  expected = _semantic_tokens(str(event.get("old_line_text") or ""))
  if len(expected) < 3:
    return False
  target = _semantic_tokens(content)
  if not _is_subsequence(expected, target):
    return False
  required = [str(value) for value in event.get("semantic_context", []) or [] if value]
  return all(value in target for value in required)


def _semantic_tokens(value: str) -> list[str]:
  cleaned = _LINE_COMMENT_RE.sub("", _BLOCK_COMMENT_RE.sub("", value))
  return _TOKEN_RE.findall(cleaned)


def _is_subsequence(needle: list[str], haystack: list[str]) -> bool:
  iterator = iter(haystack)
  return all(any(value == candidate for candidate in iterator) for value in needle)


def _path_resolution(path: str, original: str) -> str:
  return "original" if path == original else "rename_or_move"
