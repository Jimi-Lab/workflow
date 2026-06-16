from __future__ import annotations

import re
from typing import Any

from vulnversion.git_ops.repo import GitRepo


_HUNK_RE = re.compile(r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@")


def _hunk_starts(header: str) -> tuple[int | None, int | None]:
  m = _HUNK_RE.match(header)
  if not m:
    return None, None
  return int(m.group("old_start")), int(m.group("new_start"))


def _parse_patch(patch: str) -> list[dict[str, Any]]:
  lines = patch.replace("\r\n", "\n").replace("\r", "\n").split("\n")
  files: list[dict[str, Any]] = []
  current_file: dict[str, Any] | None = None
  current_hunk: dict[str, Any] | None = None
  old_line_no: int | None = None
  new_line_no: int | None = None

  def flush_hunk() -> None:
    nonlocal current_hunk
    if current_file is not None and current_hunk is not None:
      current_file["hunks"].append(current_hunk)
    current_hunk = None

  def flush_file() -> None:
    nonlocal current_file
    flush_hunk()
    current_file = None

  for line in lines:
    if line.startswith("diff --git "):
      flush_file()
      path = ""
      if " b/" in line:
        try:
          path = line.split(" b/", 1)[1]
        except Exception:
          path = ""
      current_file = {"path": path, "hunks": []}
      files.append(current_file)
      continue

    if current_file is None:
      continue

    if line.startswith("@@ "):
      flush_hunk()
      old_line_no, new_line_no = _hunk_starts(line)
      current_hunk = {"header": line, "removed": [], "added": [], "context": [], "lines": []}
      continue

    if current_hunk is None:
      continue

    if line.startswith("--- ") or line.startswith("+++ ") or line.startswith("\\ No newline at end of file"):
      continue

    if line.startswith("-") and not line.startswith("---"):
      content = line[1:]
      current_hunk["removed"].append(content)
      current_hunk["lines"].append({
        "change_type": "removed",
        "content": content,
        "old_line_no": old_line_no,
        "new_line_no": None,
      })
      if old_line_no is not None:
        old_line_no += 1
      continue
    if line.startswith("+") and not line.startswith("+++"):
      content = line[1:]
      current_hunk["added"].append(content)
      current_hunk["lines"].append({
        "change_type": "added",
        "content": content,
        "old_line_no": None,
        "new_line_no": new_line_no,
      })
      if new_line_no is not None:
        new_line_no += 1
      continue
    if line.startswith(" "):
      content = line[1:]
      current_hunk["context"].append(content)
      current_hunk["lines"].append({
        "change_type": "context",
        "content": content,
        "old_line_no": old_line_no,
        "new_line_no": new_line_no,
      })
      if old_line_no is not None:
        old_line_no += 1
      if new_line_no is not None:
        new_line_no += 1
      continue

  flush_file()
  return files


def git_diff(repo: GitRepo, *, commit: str, max_chars: int | None = None) -> dict[str, Any]:
  commit_resolved = repo.rev_parse(commit)
  patch = repo.show_patch(commit_resolved)
  limited = patch[:max_chars] if max_chars and max_chars > 0 else patch
  files = _parse_patch(limited)
  parents = repo.commit_parents(commit_resolved)
  return {
    "commit": commit_resolved,
    "files": files,
    "parent_count": len(parents),
    "diff_extraction_mode": "merge_first_parent" if len(parents) > 1 and files else "default",
  }
