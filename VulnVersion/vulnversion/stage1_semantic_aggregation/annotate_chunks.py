from __future__ import annotations

from typing import Any

from vulnversion.agent_harness.base import AgentRuntime
from vulnversion.agent_harness.task import AgentTask
from vulnversion.agent_harness.prompts import STAGE1_CHUNK_V0
from vulnversion.stage1_semantic_aggregation.schema import Chunk, ChunkRole


_ROLE_SET = {"PRIMARY_FIX", "SUPPORTING_FIX", "CONTEXTUAL_CHANGE", "UNRELATED"}


def _prompt_for_chunk(*, cve_id: str, repo_path: str, fix_commit: str, cve_desc: str, cwe: list[str], chunk: Chunk) -> str:
  return "\n".join(
    [
      "You are a vulnerability research agent operating under strict read-only evidence rules.",
      "Goal: label the diff chunk role for the given CVE fix commit.",
      "",
      f"cve_id: {cve_id}",
      f"repo_path: {repo_path}",
      f"fix_commit: {fix_commit}",
      f"chunk_fix_commit: {chunk.source_commit or fix_commit}",
      f"cwe: {cwe}",
      "",
      "CVE description (evidence):",
      cve_desc.strip(),
      "",
      "Diff chunk:",
      f"chunk_id: {chunk.chunk_id}",
      f"file_path: {chunk.file_path}",
      f"hunk_header: {chunk.hunk_header}",
      "removed_lines:",
      "\n".join([f"- {x}" for x in chunk.removed][:200]),
      "added_lines:",
      "\n".join([f"+ {x}" for x in chunk.added][:200]),
      "",
      "Required behavior:",
      "- Analyze this chunk's surrounding context before deciding role.",
      "- Use git_show on both parent ref (chunk_fix_commit^) and chunk_fix_commit to open necessary context windows.",
      "- If needed, use git_grep then git_show to locate symbol definitions and critical call sites.",
      "- Record evidence refs via concrete file snippets you opened.",
      "",
      "Output strictly as a single JSON object with keys:",
      '{ "chunk_id": "...", "role": "PRIMARY_FIX|SUPPORTING_FIX|CONTEXTUAL_CHANGE|UNRELATED", "uncertainty": "...|null", "reasoning_summary": "...", "evidence_refs": [{"ref":"...","source":"git_show|git_diff|git_grep","snippet":"..."}] }',
    ]
  )


def annotate_chunks(
  *,
  agent: AgentRuntime | None,
  session_id: str | None,
  cve_id: str,
  repo_path: str,
  fix_commit: str,
  cve_desc: str,
  cwe: list[str],
  chunks: list[Chunk],
  log_progress: bool = False,
) -> list[ChunkRole]:
  roles: list[ChunkRole] = []
  if agent is None or session_id is None:
    for ch in chunks:
      roles.append(ChunkRole(chunk_id=ch.chunk_id, role="UNRELATED", uncertainty="no_opencode_agent"))
    return roles

  total = len(chunks)
  for i, ch in enumerate(chunks, start=1):
    if log_progress:
      print(f"[VulnVersion] stage1 annotate {i}/{total} chunk={ch.chunk_id}", flush=True)
    prompt = _prompt_for_chunk(
      cve_id=cve_id,
      repo_path=repo_path,
      fix_commit=fix_commit,
      cve_desc=cve_desc,
      cwe=cwe,
      chunk=ch,
    )
    try:
      task = AgentTask(
        stage="stage1",
        task_type="chunk_role",
        cve_id=cve_id,
        repo_path=repo_path,
        session_id=session_id,
        prompt=prompt,
        prompt_name=STAGE1_CHUNK_V0.name,
        prompt_version=STAGE1_CHUNK_V0.version,
        schema_name=STAGE1_CHUNK_V0.schema_name,
        prompt_builder=STAGE1_CHUNK_V0.builder,
        judgement_only=True,
        forbidden_context=["tag_plan", "early_stop", "gt_affected_tags"],
        metadata={
          "fix_commit": fix_commit,
          "chunk_id": ch.chunk_id,
          "file_path": ch.file_path,
        },
      )
      run_task = getattr(agent, "run_task", None)
      if callable(run_task):
        raw = run_task(task).parsed
      else:
        raw = agent.run_json(
          session_id=task.session_id,
          prompt=task.prompt,
          timeout_s=task.timeout_s,
          tools=task.tools,
          metadata={
            "stage": task.stage,
            "task_type": task.task_type,
            "judgement_only": task.judgement_only,
            "forbidden_context": list(task.forbidden_context),
            **STAGE1_CHUNK_V0.trace_metadata(),
            "cve_id": task.cve_id,
            "repo_path": task.repo_path,
            **task.metadata,
          },
        )
      role = raw.get("role")
      if role not in _ROLE_SET:
        role = "UNRELATED"
      roles.append(
        ChunkRole(
          chunk_id=str(raw.get("chunk_id") or ch.chunk_id),
          role=role,
          uncertainty=raw.get("uncertainty"),
          reasoning_summary=raw.get("reasoning_summary"),
          evidence_refs=list(raw.get("evidence_refs") or []),
        )
      )
    except Exception as e:
      if log_progress:
        print(
          f"[VulnVersion] stage1 annotate {i}/{total} chunk={ch.chunk_id} error={type(e).__name__}",
          flush=True,
        )
      roles.append(
        ChunkRole(
          chunk_id=ch.chunk_id,
          role="UNRELATED",
          uncertainty=f"agent_error: {type(e).__name__}: {e}",
          reasoning_summary="chunk_annotation_failed",
          evidence_refs=[],
        )
      )
  return roles
