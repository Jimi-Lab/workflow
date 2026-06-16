from __future__ import annotations

from typing import Any

from vulnversion.git_ops.repo import GitRepo


def git_ls_tree(
  repo: GitRepo,
  *,
  ref: str,
  path: str | None = None,
  recursive: bool = False,
  max_entries: int | None = None,
) -> dict[str, Any]:
  ref_resolved = repo.rev_parse(ref)
  entries = repo.ls_tree(ref_resolved, path=path, recursive=recursive, max_entries=max_entries)
  return {"ref_resolved": ref_resolved, "entries": entries}


def git_cat_file(repo: GitRepo, *, object: str, pretty: bool = False, max_chars: int | None = None) -> dict[str, Any]:
  return repo.cat_file(object, pretty=pretty, max_chars=max_chars)


def git_rev_parse(repo: GitRepo, *, rev: str) -> dict[str, Any]:
  return {"rev": rev, "resolved": repo.rev_parse(rev)}


def git_merge_base(repo: GitRepo, *, ref_a: str, ref_b: str) -> dict[str, Any]:
  base = repo.merge_base(ref_a, ref_b)
  return {"ref_a_resolved": repo.rev_parse(ref_a), "ref_b_resolved": repo.rev_parse(ref_b), "merge_base": base}


def git_show_ref(repo: GitRepo, *, ref_glob: str | None = None, max_refs: int | None = None) -> dict[str, Any]:
  return {"refs": repo.show_ref(ref_glob=ref_glob, max_refs=max_refs)}


def git_rev_list_ancestry_path(
  repo: GitRepo,
  *,
  older: str,
  newer: str,
  max_count: int | None = None,
  reverse: bool = False,
) -> dict[str, Any]:
  older_resolved = repo.rev_parse(older)
  newer_resolved = repo.rev_parse(newer)
  commits = repo.rev_list_ancestry_path(
    older_resolved,
    newer_resolved,
    max_count=max_count,
    reverse=reverse,
  )
  return {
    "older_resolved": older_resolved,
    "newer_resolved": newer_resolved,
    "reverse": reverse,
    "commits": commits,
  }
