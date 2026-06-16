from __future__ import annotations

from typing import Any

from vulnversion.git_ops.repo import GitRepo


def git_grep(
  repo: GitRepo,
  *,
  ref: str,
  pattern: str,
  path_glob: str | None = None,
  max_matches: int | None = None,
) -> dict[str, Any]:
  ref_resolved = repo.rev_parse(ref)
  matches = repo.grep(ref_resolved, pattern, path_glob=path_glob)
  if max_matches and max_matches > 0:
    matches = matches[:max_matches]
  return {"ref_resolved": ref_resolved, "pattern": pattern, "matches": matches}

