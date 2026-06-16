from __future__ import annotations

from vulnversion.git_ops.diff import git_diff
from vulnversion.git_ops.repo import GitRepo
from vulnversion.stage1_semantic_aggregation.schema import Chunk


def extract_chunks(*, repo: GitRepo, fix_commit: str) -> list[Chunk]:
  diff = git_diff(repo, commit=fix_commit)
  chunks: list[Chunk] = []
  idx = 0
  for f in diff.get("files", []):
    path = str(f.get("path") or "")
    for h in f.get("hunks", []):
      idx += 1
      chunks.append(
        Chunk(
          chunk_id=f"chunk_{idx:04d}",
          file_path=path,
          hunk_header=str(h.get("header") or ""),
          source_commit=fix_commit,
          removed=list(h.get("removed") or []),
          added=list(h.get("added") or []),
        )
      )
  return chunks


def extract_chunks_multi(*, repo: GitRepo, fix_commits: list[str]) -> list[Chunk]:
  chunks: list[Chunk] = []
  idx = 0
  for commit in fix_commits:
    diff = git_diff(repo, commit=commit)
    for f in diff.get("files", []):
      path = str(f.get("path") or "")
      for h in f.get("hunks", []):
        idx += 1
        chunks.append(
          Chunk(
            chunk_id=f"chunk_{idx:04d}",
            file_path=path,
            hunk_header=str(h.get("header") or ""),
            source_commit=commit,
            removed=list(h.get("removed") or []),
            added=list(h.get("added") or []),
          )
        )
  return chunks
