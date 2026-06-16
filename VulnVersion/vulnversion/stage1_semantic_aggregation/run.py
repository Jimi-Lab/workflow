from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from vulnversion.agent_harness.base import AgentRuntime
from vulnversion.git_ops.diff import git_diff
from vulnversion.git_ops.repo import GitRepo
from vulnversion.stage1_semantic_aggregation.annotate_chunks import annotate_chunks
from vulnversion.stage1_semantic_aggregation.extract_chunks import extract_chunks_multi
from vulnversion.stage1_semantic_aggregation.schema import PatchSemantics
from vulnversion.utils.jsonschema import dump_json
from vulnversion.utils.paths import Paths


def _dedupe_commits_by_patch(repo: GitRepo, commits: list[str]) -> list[str]:
  kept: list[str] = []
  seen: set[str] = set()
  for c in commits:
    diff = git_diff(repo, commit=c)
    stable = json.dumps(diff.get("files") or [], ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    h = hashlib.sha256(stable.encode("utf-8")).hexdigest()
    if h in seen:
      continue
    seen.add(h)
    kept.append(c)
  return kept


def run_stage1(
  *,
  cve_id: str,
  repo_path: str,
  fix_commit: str,
  fix_commits: list[str] | None = None,
  cve_desc: str,
  cwe: list[str],
  artifacts_dir: str,
  dataset_record: dict[str, Any] | None = None,
  agent: AgentRuntime | None = None,
  session_id: str | None = None,
) -> dict[str, Any]:
  repo = GitRepo.open(repo_path)
  primary = repo.rev_parse(fix_commit)
  commits = fix_commits if fix_commits is not None else [fix_commit]
  resolved_commits: list[str] = []
  seen: set[str] = set()
  for c in commits:
    rc = repo.rev_parse(c)
    if rc in seen:
      continue
    seen.add(rc)
    resolved_commits.append(rc)
  if primary not in seen:
    resolved_commits.insert(0, primary)
  resolved_commits = _dedupe_commits_by_patch(repo, resolved_commits)
  chunks = extract_chunks_multi(repo=repo, fix_commits=resolved_commits)
  roles = annotate_chunks(
    agent=agent,
    session_id=session_id,
    cve_id=cve_id,
    repo_path=repo_path,
    fix_commit=primary,
    cve_desc=cve_desc,
    cwe=cwe,
    chunks=chunks,
    log_progress=True,
  )
  relevant = [r.chunk_id for r in roles if r.role in ("PRIMARY_FIX", "SUPPORTING_FIX")]
  excluded = [{"chunk_id": r.chunk_id, "reason": r.uncertainty or "role_unrelated"} for r in roles if r.role == "UNRELATED"]
  confidence = 0.0
  if roles:
    confidence = min(1.0, max(0.0, len(relevant) / max(1, len(roles))))

  semantics = PatchSemantics(
    cve_id=cve_id,
    repo_path=repo_path,
    fix_commit=primary,
    fix_commits=resolved_commits,
    all_chunks=chunks,
    chunk_roles=roles,
    rci_relevant_chunks=relevant,
    excluded_chunks=excluded,
    aggregation_confidence=confidence,
    dataset_record=dataset_record,
  )

  paths = Paths.from_root(Path.cwd(), artifacts_dir)
  out_dir = paths.ensure_dir(paths.cve_dir(cve_id))
  out_path = out_dir / "patch_semantics.json"
  dump_json(out_path, semantics.model_dump())
  return semantics.model_dump()
