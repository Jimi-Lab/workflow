from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any

from vulngraph.workflows.semantic_state_v1_2_1 import GitSemanticStateRunner, normalize_semantic_line


_TOKEN_RE = re.compile(r"[A-Za-z_]\w*|==|!=|<=|>=|->|\+\+|--|&&|\|\||[<>+\-*/%=&|!]")
_KEYWORD = {"if", "while", "for", "return", "static", "const", "int", "void", "struct"}


def precompute_git_semantic_states(
  repo: str | Path,
  events: list[dict[str, Any]],
  tags: list[str],
  *, chunk_size: int = 12, max_blob_bytes: int = 1_000_000,
) -> dict[tuple[str, str], dict[str, Any]]:
  """Read bounded tag:path blob batches and compare code state locally."""
  repo = Path(repo)
  runner = GitSemanticStateRunner(repo)
  output: dict[tuple[str, str], dict[str, Any]] = {}
  prepared: list[dict[str, Any]] = []
  for event in events:
    event_id = str(event.get("event_candidate_id") or "")
    expected_hash = str(event.get("old_line_text_hash") or "")
    line = str(event.get("old_line_text") or "")
    base = {"event_candidate_id": event_id, "event_ancestry_required": False, "line_text_hash": expected_hash}
    if not line or not expected_hash:
      reason = "missing_old_line_text" if not line else "missing_old_line_text_hash"
      for tag in tags:
        output[(event_id, tag)] = {**base, "commitish": tag, "state": "unknown", "reason": reason}
      continue
    if hashlib.sha256(line.encode()).hexdigest() != expected_hash:
      resolved = runner.resolve_hashed_line(event)
      if not resolved:
        for tag in tags:
          output[(event_id, tag)] = {**base, "commitish": tag, "state": "unknown", "reason": "old_line_text_hash_mismatch"}
        continue
      line = str(resolved["line_text"])
      base.update({"hash_resolution": "fix_parent_line", "hash_source_parent_sha": resolved.get("parent_sha"), "hash_source_line": resolved.get("line_number")})
    else:
      base["hash_resolution"] = "event_line_text"
    original = str(event.get("path_before") or "")
    lineage_ref = str(event.get("fix_commit_sha") or "")
    paths = [original, *[value for value in runner.related_paths(lineage_ref, original) if value != original]]
    prepared.append({"event_id": event_id, "base": base, "line": line, "original": original, "paths": paths, "needle": _grep_needle(line)})

  matches: dict[tuple[str, str], dict[str, Any]] = {}
  readable: set[tuple[str, str]] = set()
  oversized: set[tuple[str, str]] = set()
  all_paths = sorted({path for item in prepared for path in item["paths"]})
  for path in all_paths:
    path_events = [item for item in prepared if path in item["paths"]]
    for index in range(0, len(tags), chunk_size):
      blobs = _batch_read_blobs(repo, tags[index:index + chunk_size], path, max_blob_bytes=max_blob_bytes)
      for tag, blob in blobs.items():
        status = str(blob.get("status") or "")
        content = blob.get("content")
        if status == "too_large":
          oversized.add((tag, path))
          continue
        if not isinstance(content, str):
          continue
        readable.add((tag, path))
        lines = content.splitlines()
        exact_lines = set(lines)
        normalized_lines = {normalize_semantic_line(value) for value in lines}
        for item in path_events:
          state = ""
          if item["line"] in exact_lines:
            state = "present_exact"
          elif normalize_semantic_line(item["line"]) in normalized_lines:
            state = "present_normalized"
          elif item["needle"]:
            for candidate_line in lines:
              if item["needle"] in candidate_line:
                state = _line_state(item["line"], candidate_line)
                if state:
                  break
          if state:
            key = (item["event_id"], tag)
            current = matches.get(key)
            if current is None or _state_rank(state) > _state_rank(str(current["state"])):
              matches[key] = {"state": state, "matched_path": path, "path_resolution": "original" if path == item["original"] else "rename_or_move"}

  for item in prepared:
    for tag in tags:
      key = (item["event_id"], tag)
      matched = matches.get(key)
      if matched:
        output[key] = {**item["base"], "commitish": tag, **matched, "reason": _reason(str(matched["state"]))}
      elif any((tag, path) in readable for path in item["paths"]):
        output[key] = {**item["base"], "commitish": tag, "state": "absent", "reason": "predicate_not_found_in_readable_paths"}
      elif any((tag, path) in oversized for path in item["paths"]):
        output[key] = {**item["base"], "commitish": tag, "state": "unknown", "reason": "blob_too_large"}
      else:
        output[key] = {**item["base"], "commitish": tag, "state": "unknown", "reason": "path_unavailable"}
  return output


def _batch_read_blobs(repo: Path, tags: list[str], path: str, *, max_blob_bytes: int) -> dict[str, dict[str, Any]]:
  specs = [f"{tag}:{path}" for tag in tags]
  metadata = _batch_blob_metadata(repo, specs)
  output: dict[str, dict[str, Any]] = {}
  eligible: list[tuple[str, str]] = []
  for tag, spec in zip(tags, specs):
    meta = metadata.get(spec) or {}
    size = meta.get("size")
    if meta.get("status") == "missing":
      output[tag] = {"status": "missing", "content": None}
    elif not isinstance(size, int):
      output[tag] = {"status": "missing", "content": None}
    elif size > max_blob_bytes:
      output[tag] = {"status": "too_large", "content": None, "size": size, "max_blob_bytes": max_blob_bytes}
    else:
      eligible.append((tag, spec))
  if not eligible:
    return output
  payload = "".join(f"{spec}\n" for _, spec in eligible).encode()
  result = subprocess.run(
    ["git", "-C", str(repo), "cat-file", "--batch"],
    input=payload, capture_output=True, check=False, timeout=60,
  )
  data = result.stdout
  offset = 0
  for tag, _spec in eligible:
    end = data.find(b"\n", offset)
    if end < 0:
      output[tag] = {"status": "missing", "content": None}
      continue
    header = data[offset:end].decode("utf-8", errors="replace")
    offset = end + 1
    if header.endswith(" missing"):
      output[tag] = {"status": "missing", "content": None}
      continue
    parts = header.rsplit(" ", 2)
    if len(parts) != 3 or not parts[2].isdigit():
      output[tag] = {"status": "missing", "content": None}
      continue
    size = int(parts[2])
    blob = data[offset:offset + size]
    offset += size
    if offset < len(data) and data[offset:offset + 1] == b"\n":
      offset += 1
    output[tag] = {"status": "read", "content": blob.decode("utf-8", errors="replace"), "size": size}
  return output


def _batch_blob_metadata(repo: Path, specs: list[str]) -> dict[str, dict[str, Any]]:
  payload = "".join(f"{spec}\n" for spec in specs)
  result = subprocess.run(
    ["git", "-C", str(repo), "cat-file", "--batch-check"],
    input=payload, text=True, encoding="utf-8", errors="replace",
    capture_output=True, check=False, timeout=60,
  )
  rows = result.stdout.splitlines()
  output: dict[str, dict[str, Any]] = {}
  for spec, row in zip(specs, rows):
    if row.endswith(" missing"):
      output[spec] = {"status": "missing"}
      continue
    parts = row.rsplit(" ", 2)
    if len(parts) == 3 and parts[1] == "blob" and parts[2].isdigit():
      output[spec] = {"status": "ok", "size": int(parts[2])}
    else:
      output[spec] = {"status": "missing"}
  return output

def _batch_path_existence(repo: Path, tags: list[str], paths: list[str]) -> dict[tuple[str, str], bool]:
  specs = [(tag, path) for tag in tags for path in paths]
  payload = "".join(f"{tag}:{path}\n" for tag, path in specs)
  result = subprocess.run(
    ["git", "-C", str(repo), "cat-file", "--batch-check"], input=payload,
    text=True, encoding="utf-8", errors="replace", capture_output=True, check=False,
  )
  rows = result.stdout.splitlines()
  return {spec: index < len(rows) and not rows[index].endswith(" missing") for index, spec in enumerate(specs)}


def _grep_lines_multi(repo: Path, tags: list[str], path: str, needles: list[str]) -> list[tuple[str, str]]:
  if not needles:
    return []
  pattern_args = [value for needle in needles for value in ("-e", needle)]
  result = subprocess.run(
    ["git", "-C", str(repo), "grep", "-F", "-n", *pattern_args, *tags, "--", path],
    text=True, encoding="utf-8", errors="replace", capture_output=True, check=False,
  )
  if result.returncode not in {0, 1}:
    return []
  output = []
  for row in result.stdout.splitlines():
    parts = row.split(":", 3)
    if len(parts) == 4:
      output.append((parts[0], parts[3]))
  return output


def _grep_lines(repo: Path, tags: list[str], path: str, needle: str) -> list[tuple[str, str]]:
  result = subprocess.run(
    ["git", "-C", str(repo), "grep", "-F", "-n", "-e", needle, *tags, "--", path],
    text=True, encoding="utf-8", errors="replace", capture_output=True, check=False,
  )
  if result.returncode not in {0, 1}:
    return []
  output = []
  for row in result.stdout.splitlines():
    parts = row.split(":", 3)
    if len(parts) == 4:
      output.append((parts[0], parts[3]))
  return output


def _grep_needle(line: str) -> str:
  identifiers = [value for value in _TOKEN_RE.findall(line) if re.fullmatch(r"[A-Za-z_]\w*", value) and value not in _KEYWORD]
  return max(identifiers, key=len, default="")


def _line_state(expected: str, candidate: str) -> str:
  if candidate == expected:
    return "present_exact"
  if normalize_semantic_line(candidate) == normalize_semantic_line(expected):
    return "present_normalized"
  expected_tokens = _TOKEN_RE.findall(normalize_semantic_line(expected))
  candidate_tokens = _TOKEN_RE.findall(normalize_semantic_line(candidate))
  if len(expected_tokens) >= 3 and _is_subsequence(expected_tokens, candidate_tokens):
    return "present_predicate_equivalent"
  return ""


def _is_subsequence(needle: list[str], haystack: list[str]) -> bool:
  iterator = iter(haystack)
  return all(any(value == candidate for candidate in iterator) for value in needle)


def _state_rank(state: str) -> int:
  return {"present_exact": 3, "present_normalized": 2, "present_predicate_equivalent": 1}.get(state, 0)


def _reason(state: str) -> str:
  return {"present_exact": "exact_line_and_hash", "present_normalized": "lexically_normalized_line", "present_predicate_equivalent": "bounded_predicate_fingerprint"}[state]
