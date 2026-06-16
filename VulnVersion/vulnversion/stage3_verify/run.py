from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnversion.agent_harness.base import AgentRuntime
from vulnversion.stage3_verify.verify_tags import verify_tags
from vulnversion.utils.paths import Paths


def run_stage3(
  *,
  cve_id: str,
  repo_path: str,
  artifacts_dir: str,
  rci_path: str | Path | None = None,
  evidence_path: str | Path | None = None,
  fix_commit: str | None = None,
  fixing_commits: list[list[str]] | None = None,
  tags: list[str] | None = None,
  tags_glob: str | None = None,
  tag_timeout_s: float = 300.0,
  resume: bool = False,
  gt_affected_tags: list[str] | None = None,
  gt_match_mode: str = "strict",
  agent: AgentRuntime | None = None,
  session_id: str | None = None,
  per_tag_session: bool = True,
  log_progress: bool = False,
  stage3_prompt_version: str = "v1",
) -> dict[str, Any]:
  paths = Paths.from_root(Path.cwd(), artifacts_dir)
  out_dir = paths.ensure_dir(paths.cve_dir(cve_id))
  return verify_tags(
    repo_path=repo_path,
    cve_id=cve_id,
    rci_path=rci_path,
    evidence_path=evidence_path,
    out_dir=out_dir,
    fix_commit=fix_commit,
    fixing_commits=fixing_commits,
    tags=tags,
    tags_glob=tags_glob,
    tag_timeout_s=tag_timeout_s,
    resume=resume,
    gt_affected_tags=gt_affected_tags,
    gt_match_mode=gt_match_mode,
    agent=agent,
    session_id=session_id,
    per_tag_session=per_tag_session,
    log_progress=log_progress,
    stage3_prompt_version=stage3_prompt_version,
  )
