from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from vulnversion.git_ops.repo import GitRepo
from vulnversion.stage1_semantic_aggregation.artifacts import step1_paths


def _safe_commit_dir(commit: str) -> str:
  return commit[:12] if commit else "unknown"


def _write_text(path: Path, text: str) -> dict[str, Any]:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(text, encoding="utf-8", errors="replace")
  digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
  return {
    "path": str(path),
    "sha256": digest,
    "bytes": len(text.encode("utf-8", errors="replace")),
    "lines": len(text.splitlines()),
  }


def _git_or_error(repo: GitRepo, args: list[str]) -> tuple[str, str | None]:
  try:
    return repo._git(args), None
  except Exception as exc:
    return "", f"{type(exc).__name__}: {exc}"


def write_fix_commit_evidence(
  *,
  result_root: str | Path,
  repo_name: str,
  cve_id: str,
  repo: GitRepo,
  commits: list[str],
) -> dict[str, Any]:
  """Persist complete local read-only evidence for every fixing commit.

  The agent prompt may stay compressed, but Step1 must keep a full local
  evidence pack so the agent can inspect exact git data via read-only tools.
  """

  paths = step1_paths(result_root=result_root, repo=repo_name, cve_id=cve_id)
  evidence_root = paths["fix_evidence_dir"]
  evidence_root.mkdir(parents=True, exist_ok=True)

  commit_entries: list[dict[str, Any]] = []
  for commit in commits:
    resolved = repo.rev_parse(commit)
    commit_dir = evidence_root / _safe_commit_dir(resolved)
    files: dict[str, Any] = {}
    commands: dict[str, list[str]] = {}
    errors: dict[str, str] = {}

    command_specs = {
      "show_full_patch": ["show", "-m", "--first-parent", "--patch", "--no-color", "--find-renames", "--format=fuller", resolved],
      "show_patch_only": ["show", "-m", "--first-parent", "--patch", "--no-color", "--find-renames", "--format=", resolved],
      "show_numstat": ["show", "--numstat", "--find-renames", "--format=fuller", resolved],
      "show_name_status": ["show", "--name-status", "--find-renames", "--format=fuller", resolved],
      "show_summary": ["show", "--summary", "--stat", "--find-renames", "--format=fuller", resolved],
      "diff_tree": ["diff-tree", "--no-commit-id", "--name-status", "-r", resolved],
      "commit_message": ["show", "--no-patch", "--format=fuller", resolved],
    }

    for name, args in command_specs.items():
      out, err = _git_or_error(repo, args)
      commands[name] = ["git", "-C", str(repo.repo_path), *args]
      if err:
        errors[name] = err
      files[name] = _write_text(commit_dir / f"{name}.txt", out)

    commit_entries.append(
      {
        "commit": resolved,
        "short_commit": resolved[:12],
        "directory": str(commit_dir),
        "files": files,
        "commands": commands,
        "errors": errors,
      }
    )

  manifest = {
    "schema_version": "step1_fix_commit_evidence.v1",
    "cve_id": cve_id,
    "repo": repo_name,
    "repo_path": str(repo.repo_path),
    "policy": {
      "purpose": "complete local read-only evidence for Step1 agent verification",
      "ground_truth_used": False,
      "write_scope": "artifact_only",
    },
    "commits": commit_entries,
  }
  paths["fix_evidence_manifest"].write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
  return manifest
