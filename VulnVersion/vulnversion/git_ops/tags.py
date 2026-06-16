from __future__ import annotations

from typing import Any

from vulnversion.git_ops.repo import GitRepo


def list_tags(repo: GitRepo, *, tags_glob: str | None = None, max_tags: int | None = None) -> dict[str, Any]:
  return {"tags": repo.list_tags(tags_glob=tags_glob, max_tags=max_tags)}

