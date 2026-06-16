from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def _hash_json(data: Any) -> str:
  raw = json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")
  return hashlib.sha256(raw).hexdigest()


def build_repomaster_index(
  *,
  repomaster_root: str | Path,
  repo_path: str | Path,
  max_tokens: int = 10000,
) -> dict[str, Any]:
  root = Path(repomaster_root).resolve()
  repo = Path(repo_path).resolve()
  src_root = root / "src"
  if not src_root.exists():
    raise FileNotFoundError(str(src_root))
  sys.path.insert(0, str(root))
  try:
    from src.core.tree_code import GlobalCodeTreeBuilder  # type: ignore
  finally:
    sys.path.pop(0)
  builder = GlobalCodeTreeBuilder(str(repo))
  builder.parse_repository()
  code_tree = getattr(builder, "code_tree", None)
  important = builder.generate_llm_important_modules(max_tokens=max_tokens, is_file_summary=False)
  data = {
    "repo_path": str(repo),
    "code_tree": code_tree,
    "important_modules": important,
  }
  data["index_hash"] = _hash_json(data)
  return data

