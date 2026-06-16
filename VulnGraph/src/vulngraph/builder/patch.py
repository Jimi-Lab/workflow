from __future__ import annotations

import re
import subprocess
from pathlib import Path

from vulngraph.schema import GraphDocument, GraphEdge, GraphNode, SourceRef


def build_patch_graph_from_repo(
  *,
  cve_id: str,
  repo: str,
  repo_path: str | Path,
  commit_sha: str,
  max_chars: int | None = None,
  fix_commit_content: dict | None = None,
) -> GraphDocument:
  command = ["git", "-c", f"safe.directory={repo_path}", "-C", str(repo_path), "show", "--patch", "--no-color", "--format=fuller", commit_sha]
  result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="ignore", check=True)
  patch_text = result.stdout[:max_chars] if max_chars else result.stdout
  paths = {path for path, _ in _iter_hunks(patch_text)}
  new_sources = {path: text for path in paths if (text := _git_show_file(repo_path, commit_sha, path)) is not None}
  old_sources = {path: text for path in paths if (text := _git_show_file(repo_path, f"{commit_sha}^", path)) is not None}
  return build_patch_graph_from_text(
    cve_id=cve_id,
    repo=repo,
    commit_sha=commit_sha,
    patch_text=patch_text,
    fix_commit_content=fix_commit_content,
    new_sources=new_sources,
    old_sources=old_sources,
  )


def build_patch_graph_from_text(
  *,
  cve_id: str,
  repo: str,
  commit_sha: str,
  patch_text: str,
  fix_commit_content: dict | None = None,
  new_sources: dict[str, str] | None = None,
  old_sources: dict[str, str] | None = None,
) -> GraphDocument:
  source = [SourceRef(kind="git_patch", ref=f"patch:{repo}:{commit_sha}", snippet=patch_text[:500] or None)]
  nodes: dict[str, GraphNode] = {}
  edges: dict[str, GraphEdge] = {}
  fix_commit_id = f"fix-commit:{repo}:{commit_sha}"
  nodes[fix_commit_id] = _node(
    fix_commit_id,
    "FixCommit",
    "cve",
    "root_cause_evidence",
    source,
    {"cve_id": cve_id, "repo": repo, "commit_sha": commit_sha, **(fix_commit_content or {})},
    confidence=0.95,
  )

  hunk_index = 0
  for file_path, hunk_text in _iter_hunks(patch_text):
    hunk_index += 1
    parsed = _parse_hunk(hunk_text)
    hunk_id = f"patch-hunk:{repo}:{commit_sha}:{file_path}:{hunk_index}"
    anchor_id = f"code-anchor:{repo}:{commit_sha}:{file_path}:{hunk_index}"
    file_id = f"file:{repo}:{file_path}"
    function_name, function_declaration, function_resolution = _resolve_hunk_function(
      parsed,
      new_source=(new_sources or {}).get(file_path),
      old_source=(old_sources or {}).get(file_path),
    )
    function_id = f"changed-function:{repo}:{commit_sha}:{file_path}:{function_name}" if function_name else None

    nodes[hunk_id] = _node(
      hunk_id,
      "PatchHunk",
      "cve",
      "root_cause_evidence",
      source,
      {
        "cve_id": cve_id,
        "repo": repo,
        "commit_sha": commit_sha,
        "path": file_path,
        "hunk_index": hunk_index,
        "function_id": function_id,
        "function_symbol": function_name,
        "function_resolution": function_resolution,
        **parsed,
      },
      confidence=0.95,
    )
    nodes[anchor_id] = _node(
      anchor_id,
      "CodeAnchor",
      "cve",
      "root_cause_evidence",
      source,
      {
        "cve_id": cve_id,
        "repo": repo,
        "commit_sha": commit_sha,
        "path": file_path,
        "hunk_index": hunk_index,
        "old_start": parsed["old_start"],
        "new_start": parsed["new_start"],
        "function_context": parsed["function_context"],
        "function_id": function_id,
        "function_symbol": function_name,
        "function_resolution": function_resolution,
        "deleted_line_count": len(parsed["deleted_lines"]),
        "added_line_count": len(parsed["added_lines"]),
        "anchor_role": "patch_hunk",
      },
      confidence=0.85,
    )
    nodes.setdefault(
      file_id,
      _node(file_id, "File", "repo", "navigation_only", source, {"repo": repo, "path": file_path}, confidence=0.9),
    )
    _add_edge(edges, "has_patch_hunk", fix_commit_id, hunk_id, "cve", "root_cause_evidence", source, confidence=0.95)
    _add_edge(edges, "touches_file", hunk_id, file_id, "cve", "root_cause_evidence", source, confidence=0.95)
    _add_edge(edges, "yields_anchor", hunk_id, anchor_id, "cve", "root_cause_evidence", source, confidence=0.85)

    if function_name and function_id:
      nodes.setdefault(
        function_id,
        _node(
          function_id,
          "ChangedFunction",
          "cve",
          "root_cause_evidence",
          source,
          {
            "cve_id": cve_id,
            "repo": repo,
            "commit_sha": commit_sha,
            "path": file_path,
            "symbol": function_name,
            "function_context": function_declaration,
            "resolution": function_resolution,
          },
          confidence=0.9,
        ),
      )
      _add_edge(edges, "touches_function", hunk_id, function_id, "cve", "root_cause_evidence", source, confidence=0.9)

  return GraphDocument(nodes=list(nodes.values()), edges=list(edges.values()))


def _iter_hunks(patch_text: str) -> list[tuple[str, str]]:
  hunks: list[tuple[str, str]] = []
  blocks = re.split(r"(?=^diff --git )", patch_text, flags=re.MULTILINE)
  for block in blocks:
    file_path = _extract_file_path(block)
    if not file_path:
      continue
    hunk_starts = [match.start() for match in re.finditer(r"^@@ ", block, flags=re.MULTILINE)]
    for index, start in enumerate(hunk_starts):
      end = hunk_starts[index + 1] if index + 1 < len(hunk_starts) else len(block)
      hunks.append((file_path, block[start:end].strip()))
  return hunks


def _extract_file_path(block: str) -> str:
  match = re.search(r"^\+\+\+ b/(.+)$", block, re.MULTILINE)
  if match:
    return match.group(1).strip()
  match = re.search(r"^diff --git a/\S+ b/(\S+)", block, re.MULTILINE)
  if match:
    return match.group(1).strip()
  return ""


def _parse_hunk(hunk_text: str) -> dict:
  lines = hunk_text.splitlines()
  header = lines[0] if lines else ""
  match = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\s*(.*)", header)
  old_start = int(match.group(1)) if match else 1
  new_start = int(match.group(3)) if match else 1
  function_context = (match.group(5).strip() if match else "")
  old_line = old_start
  new_line = new_start
  deleted_lines: list[dict] = []
  added_lines: list[dict] = []
  context_lines: list[dict] = []

  for line in lines[1:]:
    if line.startswith("\\ No newline"):
      continue
    if line.startswith("-") and not line.startswith("---"):
      deleted_lines.append({"old_line": old_line, "text": line[1:]})
      old_line += 1
    elif line.startswith("+") and not line.startswith("+++"):
      added_lines.append({"new_line": new_line, "text": line[1:]})
      new_line += 1
    else:
      text = line[1:] if line.startswith(" ") else line
      context_lines.append({"old_line": old_line, "new_line": new_line, "text": text})
      old_line += 1
      new_line += 1

  return {
    "old_start": old_start,
    "new_start": new_start,
    "function_context": function_context,
    "deleted_lines": deleted_lines,
    "added_lines": added_lines,
    "context_lines": context_lines,
    "hunk_text": hunk_text,
  }


def _parse_function_name(context: str) -> str | None:
  if not context:
    return None
  py_match = re.search(r"\bdef\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", context)
  if py_match:
    return py_match.group(1)
  c_match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*(?:\{|$)", context)
  if c_match and c_match.group(1) not in {"if", "for", "while", "switch", "return", "sizeof"}:
    return c_match.group(1)
  class_match = re.search(r"\b(?:class|struct)\s+([A-Za-z_][A-Za-z0-9_]*)", context)
  if class_match:
    return class_match.group(1)
  return None


def _resolve_hunk_function(
  parsed: dict,
  *,
  new_source: str | None = None,
  old_source: str | None = None,
) -> tuple[str | None, str, str]:
  """Resolve the function containing changed lines without trusting @@ context."""
  source_results: list[tuple[str, str]] = []
  if new_source:
    new_lines = [int(item["new_line"]) for item in parsed["added_lines"] if item.get("new_line")]
    if new_lines:
      resolved = _function_for_source_lines(new_source, new_lines)
      if resolved:
        source_results.append(resolved)
  if old_source:
    old_lines = [int(item["old_line"]) for item in parsed["deleted_lines"] if item.get("old_line")]
    if old_lines:
      resolved = _function_for_source_lines(old_source, old_lines)
      if resolved:
        source_results.append(resolved)
  if source_results:
    names = {name for name, _ in source_results}
    if len(names) == 1:
      name, declaration = source_results[0]
      return name, declaration, "source_range"
    return None, "", "ambiguous_source_range"

  body_candidates: list[tuple[int, str, str]] = []
  changed_indexes: list[int] = []
  for index, raw_line in enumerate(parsed["hunk_text"].splitlines()[1:]):
    if raw_line.startswith("\\ No newline"):
      continue
    prefix = raw_line[:1]
    text = raw_line[1:] if prefix in {" ", "+", "-"} else raw_line
    function_name = _parse_function_name(text.strip())
    if function_name:
      body_candidates.append((index, function_name, text.strip()))
    if prefix in {"+", "-"} and not raw_line.startswith(("+++", "---")):
      changed_indexes.append(index)
  if not body_candidates or not changed_indexes:
    return None, "", "unresolved"
  resolved_candidates: list[tuple[str, str]] = []
  for changed_index in changed_indexes:
    preceding = [candidate for candidate in body_candidates if candidate[0] <= changed_index]
    if not preceding:
      return None, "", "unresolved"
    _, name, declaration = preceding[-1]
    resolved_candidates.append((name, declaration))
  names = {name for name, _ in resolved_candidates}
  if len(names) != 1:
    return None, "", "ambiguous_hunk_body"
  name, declaration = resolved_candidates[0]
  return name, declaration, "hunk_body_declaration"


def _function_for_source_lines(source: str, changed_lines: list[int]) -> tuple[str, str] | None:
  ranges = _source_function_ranges(source)
  matches = [item for item in ranges if all(item[0] <= line <= item[1] for line in changed_lines)]
  if len(matches) != 1:
    return None
  _, _, name, declaration = matches[0]
  return name, declaration


def _source_function_ranges(source: str) -> list[tuple[int, int, str, str]]:
  lines = source.splitlines()
  ranges: list[tuple[int, int, str, str]] = []
  top_level_depth = 0
  index = 0
  while index < len(lines):
    line = lines[index]
    stripped = line.strip()
    if top_level_depth != 0 or not stripped or stripped.startswith("#"):
      top_level_depth += line.count("{") - line.count("}")
      index += 1
      continue

    signature_lines = [stripped]
    opening_line = index
    while (
      "{" not in " ".join(signature_lines)
      and ";" not in " ".join(signature_lines)
      and opening_line + 1 < min(len(lines), index + 12)
    ):
      opening_line += 1
      signature_lines.append(lines[opening_line].strip())
    signature = " ".join(part for part in signature_lines if part)
    if ";" in signature.split("{", 1)[0] or "{" not in signature:
      top_level_depth += line.count("{") - line.count("}")
      index += 1
      continue

    resolved_name = _parse_function_name(signature)
    prefix = signature.split("(", 1)[0]
    if (
      not resolved_name
      or re.match(r"^(?:if|for|while|switch|return|sizeof)\b", signature)
      or "=" in prefix
    ):
      top_level_depth += line.count("{") - line.count("}")
      index += 1
      continue

    depth = 0
    seen_open = False
    end_index = opening_line
    for cursor in range(opening_line, len(lines)):
      code = lines[cursor]
      depth += code.count("{")
      if code.count("{"):
        seen_open = True
      depth -= code.count("}")
      end_index = cursor
      if seen_open and depth <= 0:
        break
    if seen_open and depth == 0:
      ranges.append((index + 1, end_index + 1, resolved_name, signature))
      index = end_index + 1
      top_level_depth = 0
      continue
    top_level_depth += line.count("{") - line.count("}")
    index += 1
  return ranges


def _git_show_file(repo_path: str | Path, revision: str, path: str) -> str | None:
  command = ["git", "-c", f"safe.directory={repo_path}", "-C", str(repo_path), "show", f"{revision}:{path}"]
  result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="ignore", check=False)
  return result.stdout if result.returncode == 0 else None


def _node(
  node_id: str,
  node_type: str,
  scope: str,
  allowed_use: str,
  source_refs: list[SourceRef],
  content: dict,
  *,
  confidence: float,
) -> GraphNode:
  return GraphNode(
    id=node_id,
    type=node_type,
    scope=scope,
    source_refs=source_refs,
    allowed_use=allowed_use,
    confidence=confidence,
    lifecycle="raw",
    created_from="patch_import",
    content=content,
  )


def _add_edge(
  edges: dict[str, GraphEdge],
  edge_type: str,
  source: str,
  target: str,
  scope: str,
  allowed_use: str,
  source_refs: list[SourceRef],
  *,
  confidence: float,
) -> None:
  edge_id = f"edge:{source}:{edge_type}:{target}"
  edges[edge_id] = GraphEdge(
    id=edge_id,
    type=edge_type,
    source=source,
    target=target,
    scope=scope,
    source_refs=source_refs,
    allowed_use=allowed_use,
    confidence=confidence,
    lifecycle="raw",
    created_from="patch_import",
  )
