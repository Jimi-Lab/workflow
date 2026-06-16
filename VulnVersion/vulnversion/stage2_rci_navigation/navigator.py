from __future__ import annotations

from typing import Any

from vulnversion.utils.repomaster_bridge import build_repomaster_index


def build_navigation_hints(
  *,
  repo_path: str,
  repomaster_root: str | None,
  max_tokens: int = 8000,
) -> dict[str, Any] | None:
  if not repomaster_root:
    return None
  try:
    return build_repomaster_index(repomaster_root=repomaster_root, repo_path=repo_path, max_tokens=max_tokens)
  except Exception:
    return None

