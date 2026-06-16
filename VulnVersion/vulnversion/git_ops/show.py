from __future__ import annotations

from typing import Any

from vulnversion.git_ops.repo import GitRepo


def git_show(
  repo: GitRepo,
  *,
  ref: str,
  path: str,
  start_line: int | None = None,
  end_line: int | None = None,
) -> dict[str, Any]:
  content = repo.show(ref, path)
  lines_raw = content.replace("\r\n", "\n").replace("\r", "\n").split("\n")
  if lines_raw and lines_raw[-1] == "":
    lines_raw = lines_raw[:-1]
  lines = [{"no": i + 1, "text": t} for i, t in enumerate(lines_raw)]
  start = start_line if start_line and start_line > 0 else 1
  end = end_line if end_line and end_line > 0 else len(lines)
  sliced = [l for l in lines if start <= int(l["no"]) <= end]
  ref_resolved = repo.rev_parse(ref)
  return {
    "ref_resolved": ref_resolved,
    "path": path,
    "start_line": start,
    "end_line": min(end, len(lines)),
    "lines": sliced,
  }

