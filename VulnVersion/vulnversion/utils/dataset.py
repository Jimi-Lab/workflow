from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_dataset(path: str | Path) -> dict[str, Any]:
  return json.loads(Path(path).read_text(encoding="utf-8"))


def get_dataset_record(dataset: dict[str, Any], cve_id: str) -> dict[str, Any]:
  record = dataset.get(cve_id)
  if not isinstance(record, dict):
    raise KeyError(cve_id)
  return record


def list_fix_commits(record: dict[str, Any]) -> list[str]:
  fixing_commits = record.get("fixing_commits")
  if not isinstance(fixing_commits, list) or not fixing_commits:
    raise ValueError("missing fixing_commits")
  out: list[str] = []
  seen: set[str] = set()
  for path in fixing_commits:
    if not isinstance(path, list):
      continue
    for commit in path:
      if not isinstance(commit, str):
        continue
      c = commit.strip()
      if not c or c in seen:
        continue
      seen.add(c)
      out.append(c)
  if not out:
    raise ValueError("invalid fixing_commits")
  return out


def pick_default_fix_commit(record: dict[str, Any]) -> str:
  return list_fix_commits(record)[0]
