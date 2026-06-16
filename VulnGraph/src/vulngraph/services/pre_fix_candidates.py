from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any, Protocol

from vulngraph.agent_io.szz_handoff_schema import (
  PreFixCandidateInventoryV1,
  PreFixLineCandidateV1,
)
from vulngraph.builder.patch import _parse_function_name


class PreFixSourceReader(Protocol):
  def resolve_parent(self, fix_sha: str) -> str: ...

  def inspect_hunk(self, fix_sha: str, patch_hunk: dict[str, Any]) -> dict[str, Any]: ...

  def read_file(self, revision: str, path: str) -> str | None: ...

  def read_function_body(
    self,
    revision: str,
    path: str,
    function_name: str | None,
  ) -> list[tuple[int, str]]: ...

  def patch_family_id(self, fix_sha: str) -> str: ...


class GitPreFixSourceReader:
  """Read-only Git adapter used to construct wrapper-owned parent-side lines."""

  def __init__(self, repo_path: str | Path):
    self.repo_path = Path(repo_path)
    self.trace: list[dict[str, Any]] = []

  def resolve_parent(self, fix_sha: str) -> str:
    return self._run(["rev-parse", f"{fix_sha}^"], operation="resolve_parent").strip()

  def inspect_hunk(self, fix_sha: str, patch_hunk: dict[str, Any]) -> dict[str, Any]:
    content = patch_hunk.get("content", {})
    packet_path = str(content.get("path") or "")
    output = self._run(
      ["diff-tree", "--no-commit-id", "--find-renames", "--name-status", "-r", fix_sha],
      operation="inspect_hunk",
      check=False,
    )
    path_before = packet_path
    path_after = packet_path
    new_file = False
    for raw_line in output.splitlines():
      parts = raw_line.split("\t")
      if len(parts) < 2:
        continue
      status = parts[0]
      if status.startswith("R") and len(parts) >= 3 and packet_path in {parts[1], parts[2]}:
        path_before, path_after = parts[1], parts[2]
        break
      if parts[-1] != packet_path:
        continue
      if status.startswith("A"):
        path_before = ""
        new_file = True
      elif status.startswith("D"):
        path_after = ""
      break
    deleted = list(content.get("deleted_lines") or [])
    added = list(content.get("added_lines") or [])
    if path_before and path_after and path_before != path_after:
      change_type = "rename"
    elif deleted and added:
      change_type = "modify"
    elif deleted:
      change_type = "delete"
    else:
      change_type = "add_only"
    return {
      "path_before": path_before or None,
      "path_after": path_after or None,
      "change_type": change_type,
      "new_file": new_file,
    }

  def read_file(self, revision: str, path: str) -> str | None:
    output = self._run(["show", f"{revision}:{path}"], operation="read_file", check=False)
    return output if self.trace[-1]["exit_code"] == 0 else None

  def read_function_body(
    self,
    revision: str,
    path: str,
    function_name: str | None,
  ) -> list[tuple[int, str]]:
    if not function_name:
      return []
    source = self.read_file(revision, path)
    if source is None:
      return []
    lines = _lf_lines(source)
    matches = [item for item in _source_function_ranges_robust(source) if item[2] == function_name]
    if len(matches) != 1:
      return []
    start, end, _, _ = matches[0]
    return [(line_no, lines[line_no - 1]) for line_no in range(start, end + 1)]

  def patch_family_id(self, fix_sha: str) -> str:
    show = self._run(
      ["show", "--pretty=format:", "--patch", "--no-color", fix_sha],
      operation="patch_family_source",
    )
    command = ["git", "patch-id", "--stable"]
    result = subprocess.run(
      command,
      input=show,
      capture_output=True,
      text=True,
      encoding="utf-8",
      errors="ignore",
      check=False,
    )
    self.trace.append(
      {
        "operation": "patch_family_id",
        "command": command,
        "cwd": str(self.repo_path),
        "exit_code": result.returncode,
        "stderr": result.stderr[-2000:],
      }
    )
    patch_id = result.stdout.split(maxsplit=1)[0] if result.returncode == 0 and result.stdout.strip() else ""
    return f"patch-family:{patch_id or hashlib.sha256(show.encode('utf-8')).hexdigest()}"

  def _run(self, args: list[str], *, operation: str, check: bool = True) -> str:
    command = ["git", "-c", f"safe.directory={self.repo_path}", "-C", str(self.repo_path), *args]
    result = subprocess.run(
      command,
      capture_output=True,
      text=True,
      encoding="utf-8",
      errors="ignore",
      check=False,
    )
    self.trace.append(
      {
        "operation": operation,
        "command": command,
        "cwd": str(self.repo_path),
        "exit_code": result.returncode,
        "stderr": result.stderr[-2000:],
      }
    )
    if check and result.returncode != 0:
      raise RuntimeError(f"git {operation} failed: {result.stderr.strip()}")
    return result.stdout


def build_pre_fix_candidate_inventory(
  *,
  packet: dict[str, Any],
  repo_path: Path,
  source_reader: PreFixSourceReader,
) -> PreFixCandidateInventoryV1:
  cve_id = str(packet.get("cve_id") or "")
  repo_id = _repo_id(packet)
  fix_commits = {
    str(item.get("content", {}).get("commit_sha") or ""): item
    for item in packet.get("patch_evidence", [])
    if item.get("type") == "FixCommit"
  }
  candidates: list[PreFixLineCandidateV1] = []
  issues: list[str] = []
  fix_families: dict[str, list[str]] = {}
  seen_ids: set[str] = set()

  for hunk in [item for item in packet.get("patch_evidence", []) if item.get("type") == "PatchHunk"]:
    content = hunk.get("content", {})
    fix_sha = str(content.get("commit_sha") or "")
    fix_commit = fix_commits.get(fix_sha)
    if not fix_commit:
      issues.append(f"missing_fix_commit:{hunk.get('id')}")
      continue
    parent_sha = source_reader.resolve_parent(fix_sha)
    metadata = source_reader.inspect_hunk(fix_sha, hunk)
    path_before = str(metadata.get("path_before") or "")
    path_after = str(metadata.get("path_after") or content.get("path") or "")
    if metadata.get("new_file") or not path_before:
      issues.append("new_file_without_parent_anchor")
      continue
    parent_source = source_reader.read_file(parent_sha, path_before)
    if parent_source is None:
      issues.append(f"missing_parent_file:{hunk.get('id')}")
      continue
    parent_lines = _lf_lines(parent_source)
    patch_family_id = source_reader.patch_family_id(fix_sha)
    fix_families.setdefault(patch_family_id, []).append(fix_sha)
    change_type = str(metadata.get("change_type") or _change_type(content))
    fix_content = fix_commit.get("content", {})
    function_name = content.get("function_symbol") or _resolve_parent_function_name(parent_source, content)
    function_id = content.get("function_id")
    if function_name and not function_id:
      function_id = f"pre-fix-function:{repo_id}:{parent_sha}:{path_before}:{function_name}"
    common = {
      "cve_id": cve_id,
      "repo_id": repo_id,
      "fix_set_id": str(fix_content.get("fix_set_id") or f"{cve_id}:fix-set:unknown"),
      "patch_family_id": patch_family_id,
      "fix_commit_id": str(fix_commit.get("id") or ""),
      "fix_commit_sha": fix_sha,
      "parent_sha": parent_sha,
      "patch_hunk_id": str(hunk.get("id") or ""),
      "path_before": path_before,
      "path_after": path_after or None,
      "function_id": function_id,
      "function_name": function_name,
      "change_type": change_type,
      "git_observation_refs": _source_observation_refs(hunk),
    }

    deleted = list(content.get("deleted_lines") or [])
    if deleted:
      mode = "modified_old_side" if change_type == "modify" else "direct_deleted_line"
      for line in deleted:
        _append_candidate(
          candidates,
          seen_ids,
          issues,
          common,
          parent_lines,
          line_no=int(line.get("old_line") or 0),
          expected_text=str(line.get("text") or ""),
          candidate_source="deleted_line",
          eligibility=[mode],
        )
      continue

    if change_type != "add_only":
      continue
    for line in content.get("context_lines") or []:
      _append_candidate(
        candidates,
        seen_ids,
        issues,
        common,
        parent_lines,
        line_no=int(line.get("old_line") or 0),
        expected_text=str(line.get("text") or ""),
        candidate_source="hunk_context",
        eligibility=["add_only_semantic_target", "context_fallback"],
      )
    for line_no, line_text in source_reader.read_function_body(
      parent_sha,
      path_before,
      function_name,
    ):
      _append_candidate(
        candidates,
        seen_ids,
        issues,
        common,
        parent_lines,
        line_no=int(line_no),
        expected_text=str(line_text),
        candidate_source="pre_fix_function_body",
        eligibility=["add_only_semantic_target"],
      )

  trace = list(getattr(source_reader, "trace", []))
  return PreFixCandidateInventoryV1(
    cve_id=cve_id,
    repo_id=repo_id,
    repo_path=str(repo_path),
    candidates=candidates,
    fix_families={key: sorted(set(value)) for key, value in fix_families.items()},
    issues=issues,
    git_trace=trace,
  )


def _append_candidate(
  candidates: list[PreFixLineCandidateV1],
  seen_ids: set[str],
  issues: list[str],
  common: dict[str, Any],
  parent_lines: list[str],
  *,
  line_no: int,
  expected_text: str,
  candidate_source: str,
  eligibility: list[str],
) -> None:
  if line_no < 1 or line_no > len(parent_lines):
    issues.append(f"parent_coordinate_mismatch:{common['patch_hunk_id']}:{line_no}")
    return
  exact_text = parent_lines[line_no - 1]
  if exact_text != expected_text:
    issues.append(f"parent_text_mismatch:{common['patch_hunk_id']}:{line_no}")
    return
  if not exact_text.strip():
    return
  text_hash = hashlib.sha256(exact_text.encode("utf-8")).hexdigest()
  candidate_id = "pre-fix-line:" + hashlib.sha256(
    "\0".join(
      [
        str(common["repo_id"]),
        str(common["fix_commit_sha"]),
        str(common["path_before"]),
        str(line_no),
        text_hash,
        candidate_source,
      ]
    ).encode("utf-8")
  ).hexdigest()
  if candidate_id in seen_ids:
    return
  seen_ids.add(candidate_id)
  flags = _line_flags(str(common["path_before"]), exact_text)
  candidates.append(
    PreFixLineCandidateV1(
      candidate_id=candidate_id,
      old_line_start=line_no,
      old_line_end=line_no,
      line_text=exact_text,
      line_text_sha256=text_hash,
      candidate_source=candidate_source,
      selection_mode_eligibility=eligibility,
      **common,
      **flags,
    )
  )


def _line_flags(path: str, line_text: str) -> dict[str, Any]:
  normalized = path.replace("\\", "/").lower()
  name = normalized.rsplit("/", 1)[-1]
  test_file = bool(re.search(r"(^|/)(tests?|testing|testdata|fixtures?)(/|$)", normalized))
  documentation_file = name.endswith((".md", ".rst", ".txt")) or "/docs/" in f"/{normalized}/"
  changelog_file = any(token in name for token in ("changelog", "changes", "news", "history"))
  generated_file = any(token in normalized for token in ("generated", "vendor/", "third_party/"))
  stripped = line_text.strip()
  comment_only = stripped.startswith(("//", "/*", "*", "#"))
  source_file = not (test_file or documentation_file or changelog_file or generated_file)
  reasons: list[str] = []
  if not source_file:
    reasons.append("non_source_file")
  if comment_only:
    reasons.append("comment_only")
  return {
    "generated_file": generated_file,
    "test_file": test_file,
    "documentation_file": documentation_file,
    "changelog_file": changelog_file,
    "comment_only": comment_only,
    "blank_line": not bool(stripped),
    "source_file": source_file,
    "exclusion_reasons": reasons,
  }


def _repo_id(packet: dict[str, Any]) -> str:
  for item in packet.get("repo_navigation", []) or []:
    if item.get("type") == "Repo":
      return str(item.get("content", {}).get("repo") or item.get("id") or "")
  for item in packet.get("patch_evidence", []) or []:
    repo = item.get("content", {}).get("repo")
    if repo:
      return str(repo)
  return "unknown-repo"


def _change_type(content: dict[str, Any]) -> str:
  deleted = bool(content.get("deleted_lines"))
  added = bool(content.get("added_lines"))
  if deleted and added:
    return "modify"
  if deleted:
    return "delete"
  return "add_only"


def _source_observation_refs(hunk: dict[str, Any]) -> list[str]:
  refs: list[str] = [
    str(ref) for ref in hunk.get("content", {}).get("git_observation_refs", []) or [] if ref
  ]
  for source in hunk.get("source_refs", []) or []:
    ref = source.get("ref")
    if ref:
      refs.append(str(ref))
  return sorted(set(refs))


def _resolve_parent_function_name(source: str, content: dict[str, Any]) -> str | None:
  line_numbers = [
    int(item.get("old_line") or 0)
    for key in ("deleted_lines", "context_lines")
    for item in content.get(key, []) or []
    if int(item.get("old_line") or 0) > 0
  ]
  if not line_numbers:
    old_start = int(content.get("old_start") or 0)
    if old_start > 0:
      line_numbers = [old_start]
  matches = [
    item for item in _source_function_ranges_robust(source)
    if all(item[0] <= line_no <= item[1] for line_no in line_numbers)
  ]
  return matches[0][2] if len(matches) == 1 else None


def _lf_lines(source: str) -> list[str]:
  return [line[:-1] if line.endswith("\r") else line for line in source.split("\n")]


def _source_function_ranges_robust(source: str) -> list[tuple[int, int, str, str]]:
  raw_lines = _lf_lines(source)
  code_lines = _strip_c_like_comments_and_literals(raw_lines)
  ranges: list[tuple[int, int, str, str]] = []
  index = 0
  while index < len(code_lines):
    stripped = code_lines[index].strip()
    if not stripped or stripped.startswith("#"):
      index += 1
      continue
    signature_parts = [stripped]
    opening_line = index
    while (
      "{" not in " ".join(signature_parts)
      and ";" not in " ".join(signature_parts)
      and opening_line + 1 < min(len(code_lines), index + 12)
    ):
      opening_line += 1
      signature_parts.append(code_lines[opening_line].strip())
    signature = " ".join(part for part in signature_parts if part)
    before_brace = signature.split("{", 1)[0]
    function_name = _parse_function_name(signature)
    if (
      not function_name
      or "{" not in signature
      or ";" in before_brace
      or "=" in before_brace.split("(", 1)[0]
    ):
      index += 1
      continue
    depth = 0
    seen_open = False
    end_index = opening_line
    for cursor in range(index, len(code_lines)):
      code = code_lines[cursor]
      opens = code.count("{")
      closes = code.count("}")
      if opens:
        seen_open = True
      depth += opens - closes
      end_index = cursor
      if seen_open and depth == 0:
        break
    if seen_open and depth == 0:
      declaration = " ".join(part.strip() for part in raw_lines[index : opening_line + 1] if part.strip())
      ranges.append((index + 1, end_index + 1, function_name, declaration))
      index = end_index + 1
      continue
    index += 1
  return ranges


def _strip_c_like_comments_and_literals(lines: list[str]) -> list[str]:
  output: list[str] = []
  in_block_comment = False
  for line in lines:
    cleaned: list[str] = []
    index = 0
    quote: str | None = None
    escaped = False
    while index < len(line):
      char = line[index]
      next_char = line[index + 1] if index + 1 < len(line) else ""
      if in_block_comment:
        if char == "*" and next_char == "/":
          in_block_comment = False
          cleaned.extend((" ", " "))
          index += 2
        else:
          cleaned.append(" ")
          index += 1
        continue
      if quote:
        cleaned.append(" ")
        if escaped:
          escaped = False
        elif char == "\\":
          escaped = True
        elif char == quote:
          quote = None
        index += 1
        continue
      if char == "/" and next_char == "*":
        in_block_comment = True
        cleaned.extend((" ", " "))
        index += 2
        continue
      if char == "/" and next_char == "/":
        cleaned.extend(" " * (len(line) - index))
        break
      if char in {'"', "'"}:
        quote = char
        cleaned.append(" ")
        index += 1
        continue
      cleaned.append(" " if char in {"\f", "\v"} else char)
      index += 1
    output.append("".join(cleaned))
  return output
