from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from vulngraph.workflows.semantic_state_batch_v1_2_1 import _batch_read_blobs
from vulngraph.workflows.semantic_state_v1_2_1 import GitSemanticStateRunner
from vulngraph.workflows.semantic_state_v1_2_2 import evaluate_predicate_in_content


_STATE_RANK = {"present_exact": 4, "present_normalized": 3, "present_predicate_equivalent": 2, "absent": 1, "unknown": 0}


def precompute_function_scope_semantic_states(
  repo: str | Path,
  events: list[dict[str, Any]],
  tags: list[str],
  *, chunk_size: int = 12, max_blob_bytes: int = 1_000_000,
) -> dict[tuple[str, str], dict[str, Any]]:
  repo = Path(repo)
  runner = GitSemanticStateRunner(repo)
  prepared: list[dict[str, Any]] = []
  output: dict[tuple[str, str], dict[str, Any]] = {}
  for event in events:
    event_id = str(event.get("event_candidate_id") or "")
    expected_hash = str(event.get("old_line_text_hash") or "")
    line = str(event.get("old_line_text") or "")
    base = {"event_candidate_id": event_id, "event_ancestry_required": False, "line_text_hash": expected_hash}
    if not line or not expected_hash:
      reason = "missing_old_line_text" if not line else "missing_old_line_text_hash"
      for tag in tags:
        output[(event_id, tag)] = {**base, "commitish": tag, "state": "unknown", "reason": reason, "failure_reason": reason}
      continue
    if hashlib.sha256(line.encode()).hexdigest() != expected_hash:
      resolved = runner.resolve_hashed_line(event)
      if not resolved:
        for tag in tags:
          output[(event_id, tag)] = {**base, "commitish": tag, "state": "unknown", "reason": "old_line_text_hash_mismatch", "failure_reason": "old_line_text_hash_mismatch"}
        continue
      line = str(resolved["line_text"])
      base.update({"hash_resolution": "fix_parent_line", "hash_source_parent_sha": resolved.get("parent_sha"), "hash_source_line": resolved.get("line_number")})
    else:
      base["hash_resolution"] = "event_line_text"
    original = str(event.get("path_before") or "")
    lineage_ref = str(event.get("fix_commit_sha") or "")
    paths = [original, *[value for value in runner.related_paths(lineage_ref, original) if value != original]]
    prepared.append({"event": event, "event_id": event_id, "base": base, "line": line, "original": original, "paths": paths})

  best: dict[tuple[str, str], dict[str, Any]] = {}
  readable: set[tuple[str, str]] = set()
  oversized: set[tuple[str, str]] = set()
  all_paths = sorted({path for item in prepared for path in item["paths"]})
  for path in all_paths:
    path_items = [item for item in prepared if path in item["paths"]]
    for index in range(0, len(tags), chunk_size):
      blobs = _batch_read_blobs(repo, tags[index:index + chunk_size], path, max_blob_bytes=max_blob_bytes)
      for tag, blob in blobs.items():
        if blob.get("status") == "too_large":
          oversized.add((tag, path))
          continue
        content = blob.get("content")
        if not isinstance(content, str):
          continue
        readable.add((tag, path))
        for item in path_items:
          evidence = evaluate_predicate_in_content(item["event"], item["line"], content, path)
          key = (item["event_id"], tag)
          current = best.get(key)
          if current is None or _STATE_RANK.get(str(evidence.get("state")), 0) > _STATE_RANK.get(str(current.get("state")), 0):
            best[key] = evidence

  for item in prepared:
    for tag in tags:
      key = (item["event_id"], tag)
      if key in best:
        output[key] = {**item["base"], "commitish": tag, **best[key]}
      elif any((tag, path) in readable for path in item["paths"]):
        output[key] = {**item["base"], "commitish": tag, "state": "absent", "reason": "predicate_not_found_in_readable_paths", "failure_reason": "predicate_not_found_in_readable_paths"}
      elif any((tag, path) in oversized for path in item["paths"]):
        output[key] = {**item["base"], "commitish": tag, "state": "unknown", "reason": "blob_too_large", "failure_reason": "blob_too_large"}
      else:
        output[key] = {**item["base"], "commitish": tag, "state": "unknown", "reason": "path_unavailable", "failure_reason": "path_unavailable"}
  return output
