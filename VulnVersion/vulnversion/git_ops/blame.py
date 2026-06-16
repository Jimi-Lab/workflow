from __future__ import annotations

from typing import Any

from vulnversion.git_ops.repo import GitRepo


def git_blame(
  repo: GitRepo,
  *,
  ref: str,
  path: str,
  start_line: int | None = None,
  end_line: int | None = None,
) -> dict[str, Any]:
  ref_resolved = repo.rev_parse(ref)
  entries = repo.blame(
    ref_resolved,
    path,
    start_line=start_line,
    end_line=end_line,
  )
  return {
    "ref_resolved": ref_resolved,
    "path": path,
    "start_line": start_line,
    "end_line": end_line,
    "entries": entries,
  }
