from __future__ import annotations

import re

from .schema import GraphNode, SourceRef


def _slug(value: str) -> str:
  value = value.strip() or "unknown"
  return re.sub(r"[^A-Za-z0-9_.-]+", "-", value)


def _failure_source(failure: GraphNode) -> list[SourceRef]:
  summary = str(failure.content.get("summary", ""))
  source = SourceRef(kind="failure_case", ref=failure.id, snippet=summary or None)
  return [source, *failure.source_refs]


def candidate_memories_from_failure(failure: GraphNode) -> list[GraphNode]:
  if failure.type != "FailureCase":
    raise ValueError("candidate memories can only be derived from FailureCase nodes")

  repo = str(failure.content.get("repo", "unknown-repo"))
  cwe_id = str(failure.content.get("cwe_id", "unknown-cwe"))
  target = str(failure.content.get("target", "unknown-target"))
  summary = str(failure.content.get("summary", ""))
  source_refs = _failure_source(failure)
  memories: list[GraphNode] = []

  repo_hint = failure.content.get("suggested_repo_memory")
  if repo_hint:
    memories.append(
      GraphNode(
        id=f"repo-memory:{_slug(repo)}:{_slug(failure.id)}",
        type="RepoMemory",
        scope="repo",
        source_refs=source_refs,
        allowed_use="navigation_only",
        confidence=0.3,
        lifecycle="candidate",
        created_from=failure.id,
        content={
          "repo": repo,
          "target": target,
          "summary": summary,
          "hint": str(repo_hint),
          "origin_failure_id": failure.id,
          "promotion_gate": "replay_pass_without_leakage",
        },
      )
    )

  cwe_hint = failure.content.get("suggested_cwe_memory")
  if cwe_hint:
    memories.append(
      GraphNode(
        id=f"cwe-memory:{_slug(cwe_id)}:{_slug(failure.id)}",
        type="CWEMemory",
        scope="cwe",
        source_refs=source_refs,
        allowed_use="procedure_only",
        confidence=0.3,
        lifecycle="candidate",
        created_from=failure.id,
        content={
          "cwe_id": cwe_id,
          "target": target,
          "summary": summary,
          "hint": str(cwe_hint),
          "origin_failure_id": failure.id,
          "promotion_gate": "multi_case_replay_pass_without_leakage",
        },
      )
    )

  return memories
