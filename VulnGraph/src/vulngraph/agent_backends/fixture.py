from __future__ import annotations

import json
from typing import Any, Literal

from .base import AgentResponse


FixtureMode = Literal["valid", "malformed", "empty", "missing_refs", "failed"]


class FixtureRootCauseBackend:
  backend_name = "fixture-root-cause"
  backend_type = "fixture"

  def __init__(self, mode: FixtureMode = "valid") -> None:
    self.mode = mode

  def generate(self, prompt: str, context: dict[str, Any]) -> AgentResponse:
    if self.mode == "empty":
      return AgentResponse(raw_text="", status="empty", backend_name=self.backend_name, backend_type=self.backend_type)
    if self.mode == "failed":
      return AgentResponse(raw_text="", status="failed", backend_name=self.backend_name, backend_type=self.backend_type, error="fixture backend failure")
    if self.mode == "malformed":
      return AgentResponse(raw_text="{not valid json", status="ok", backend_name=self.backend_name, backend_type=self.backend_type)

    payload = self._payload(context, include_refs=self.mode != "missing_refs")
    return AgentResponse(
      raw_text=json.dumps(payload, ensure_ascii=False, indent=2),
      status="ok",
      backend_name=self.backend_name,
      backend_type=self.backend_type,
      usage={"prompt_chars": len(prompt)},
    )

  def _payload(self, context: dict[str, Any], *, include_refs: bool) -> dict[str, Any]:
    cve_id = str(context.get("cve_id") or "CVE-UNKNOWN")
    packet = context.get("packet") if isinstance(context.get("packet"), dict) else {}
    trace = context.get("evidence_trace") if isinstance(context.get("evidence_trace"), dict) else {}
    fix_commits = [node for node in packet.get("patch_evidence", []) or [] if node.get("type") == "FixCommit"]
    selected_anchor_nodes = _select_anchor_per_fix_commit(packet, fix_commits)
    observations = trace.get("git_observations") or []
    git_refs = [str(item.get("id")) for item in observations if item.get("id")] if include_refs else []
    anchor_ids = [f"anchor-{index}" for index, _node in enumerate(selected_anchor_nodes, start=1)] or ["anchor-1"]
    fix_commit_ids = [str(item.get("id")) for item in fix_commits if item.get("id")]
    fix_set_ids = sorted(
      {
        str((item.get("content") or {}).get("fix_set_id") or f"single-fix:{item.get('id')}")
        for item in fix_commits
        if item.get("id")
      }
    )
    code_anchors = []
    for index, anchor_node in enumerate(selected_anchor_nodes or [{}], start=1):
      content = anchor_node.get("content") or {}
      commit_sha = str(content.get("commit_sha") or "")
      path = str(content.get("path") or "")
      repo = str(content.get("repo") or "")
      hunk_index = content.get("hunk_index")
      fix_commit_id = _fix_commit_id_for_sha(fix_commits, commit_sha)
      patch_hunk_id = f"patch-hunk:{repo}:{commit_sha}:{path}:{hunk_index}" if repo and commit_sha and path and hunk_index else str(anchor_node.get("id") or "")
      code_anchors.append(
        {
          "anchor_id": f"anchor-{index}",
          "fix_commit_id": fix_commit_id,
          "patch_hunk_id": patch_hunk_id,
          "path": path,
          "function": str(content.get("symbol") or content.get("function_context") or ""),
          "line_start": content.get("old_start"),
          "line_end": content.get("new_start"),
          "pattern": _observation_snippet_for_commit(observations, fix_commit_id),
          "git_observation_refs": git_refs,
          "confidence": 0.55,
        }
      )
    return {
      "agent_run": {
        "run_id": f"fixture-{cve_id}",
        "cve_id": cve_id,
        "backend": self.backend_name,
      },
      "root_cause_hypotheses": [
        {
          "hypothesis_id": "hyp-1",
          "summary": "Patch evidence indicates an unchecked value reaches a vulnerable operation before the fix.",
          "mechanism": "The pre-fix code lacks the guard introduced by the fix commit near the selected anchor.",
          "fix_commit_ids": fix_commit_ids,
          "fix_set_ids": fix_set_ids,
          "vulnerable_predicate_ids": ["vp-1"],
          "fix_predicate_ids": ["fp-1"],
          "guard_condition_ids": [],
          "negative_condition_ids": [],
          "anchor_ids": anchor_ids,
          "git_observation_refs": git_refs,
          "confidence": 0.55,
        }
      ],
      "vulnerable_predicates": [
        {
          "predicate_id": "vp-1",
          "description": "The vulnerable-side pattern is present in the removed/context lines of the fix patch.",
          "anchor_ids": anchor_ids,
          "git_observation_refs": git_refs,
          "confidence": 0.55,
        }
      ],
      "fix_predicates": [
        {
          "predicate_id": "fp-1",
          "description": "The fix-side pattern introduces or strengthens a guard around the risky operation.",
          "anchor_ids": anchor_ids,
          "git_observation_refs": git_refs,
          "confidence": 0.55,
        }
      ],
      "guard_conditions": [],
      "negative_conditions": [],
      "code_anchors": code_anchors,
      "git_observation_refs": git_refs,
      "uncertainty_reasons": [
        {
          "reason_id": "fixture-limited",
          "reason": "Fixture backend generated a deterministic smoke output; not a real OpenCode reasoning result.",
          "git_observation_refs": git_refs,
        }
      ],
      "learned_candidates": [],
      "risk_flags": [],
    }


def _first_node(nodes: list[dict[str, Any]], node_type: str) -> dict[str, Any]:
  for node in nodes:
    if node.get("type") == node_type:
      return node
  return {}


def _select_anchor_per_fix_commit(packet: dict[str, Any], fix_commits: list[dict[str, Any]]) -> list[dict[str, Any]]:
  anchors = [node for node in packet.get("patch_evidence", []) or [] if node.get("type") == "CodeAnchor"]
  by_sha: dict[str, dict[str, Any]] = {}
  for anchor in anchors:
    commit_sha = str((anchor.get("content") or {}).get("commit_sha") or "")
    by_sha.setdefault(commit_sha, anchor)
  selected = []
  for fix_commit in fix_commits:
    commit_sha = str((fix_commit.get("content") or {}).get("commit_sha") or "")
    if commit_sha in by_sha:
      selected.append(by_sha[commit_sha])
  return selected or anchors[:1]


def _fix_commit_id_for_sha(fix_commits: list[dict[str, Any]], commit_sha: str) -> str:
  for fix_commit in fix_commits:
    if str((fix_commit.get("content") or {}).get("commit_sha") or "") == commit_sha:
      return str(fix_commit.get("id") or "")
  return ""


def _observation_snippet_for_commit(observations: list[dict[str, Any]], fix_commit_id: str) -> str:
  for observation in observations:
    if str(observation.get("fix_commit_id") or "") == fix_commit_id:
      return str(observation.get("snippet") or "")[:160]
  return str((observations[0] if observations else {}).get("snippet") or "")[:160]
