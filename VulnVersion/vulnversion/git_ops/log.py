from __future__ import annotations

from typing import Any

from vulnversion.git_ops.repo import GitRepo
from vulnversion.utils.subprocess import run


def git_log(
  repo: GitRepo,
  *,
  range_or_ref: str,
  path_glob: str | None = None,
  max_commits: int | None = None,
) -> dict[str, Any]:
  max_count = max_commits if max_commits and max_commits > 0 else 50
  args = ["git", "-C", str(repo.repo_path), "log", "--oneline", "--decorate", f"--max-count={max_count}", range_or_ref]
  if path_glob:
    args.extend(["--", path_glob])
  out = run(args).stdout
  commits: list[dict[str, str]] = []
  for line in out.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
    t = line.strip()
    if not t:
      continue
    parts = t.split(maxsplit=1)
    if len(parts) != 2:
      continue
    commits.append({"hash": parts[0], "subject": parts[1]})
  return {"range_or_ref": range_or_ref, "commits": commits}


def git_log_pickaxe(
  repo: GitRepo,
  *,
  range_or_ref: str,
  needle: str,
  regex: bool = False,
  path_glob: str | None = None,
  max_commits: int | None = None,
  pickaxe_all: bool = False,
) -> dict[str, Any]:
  commits = repo.log_pickaxe(
    range_or_ref=range_or_ref,
    needle=needle,
    regex=regex,
    path_glob=path_glob,
    max_commits=max_commits,
    pickaxe_all=pickaxe_all,
  )
  return {
    "range_or_ref": range_or_ref,
    "needle": needle,
    "mode": "G" if regex else "S",
    "commits": commits,
  }


def git_line_history(
  repo: GitRepo,
  *,
  range_or_ref: str,
  path: str,
  function_name: str | None = None,
  start_line: int | None = None,
  end_line: int | None = None,
  max_commits: int | None = None,
  max_chars: int | None = None,
) -> dict[str, Any]:
  out = repo.log_line_history(
    range_or_ref=range_or_ref,
    path=path,
    function_name=function_name,
    start_line=start_line,
    end_line=end_line,
    max_commits=max_commits,
    max_chars=max_chars,
  )
  return out
