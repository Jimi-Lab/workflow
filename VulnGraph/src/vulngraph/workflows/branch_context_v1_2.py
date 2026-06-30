from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any


class SubprocessGitGraph:
  def __init__(self, repo: str | Path) -> None:
    self.repo = Path(repo)

  def _run(self, *args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
      ["git", "-C", str(self.repo), *args], input=input_text, text=True,
      encoding="utf-8", errors="replace", capture_output=True, check=False,
    )

  def containing_branch_refs(self, sha: str) -> list[str]:
    result = self._run(
      "for-each-ref", "--format=%(refname:short)", f"--contains={sha}",
      "refs/heads", "refs/remotes",
    )
    return sorted(line for line in result.stdout.splitlines() if line)

  def is_ancestor(self, older: str, newer: str) -> bool:
    return self._run("merge-base", "--is-ancestor", older, newer).returncode == 0

  def merge_base(self, left: str, right: str) -> str:
    result = self._run("merge-base", left, right)
    return result.stdout.strip() if result.returncode == 0 else ""

  def patch_id(self, sha: str) -> str:
    diff = self._run("show", "--pretty=format:", "--binary", sha)
    if diff.returncode:
      return ""
    result = subprocess.run(
      ["git", "patch-id", "--stable"], input=diff.stdout, text=True,
      encoding="utf-8", errors="replace", capture_output=True, check=False,
    )
    return result.stdout.split()[0] if result.stdout.split() else ""

  def commit_metadata(self, sha: str) -> dict[str, Any]:
    result = self._run("show", "-s", "--format=%P%x00%s%x00%b", sha)
    values = (result.stdout.split("\x00") + ["", "", ""])[:3]
    return {"parents": values[0].split(), "subject": values[1], "body": values[2]}


def build_branch_scoped_groups(
  cve_id: str,
  repo: str,
  history_events: list[dict[str, Any]],
  graph: Any,
) -> dict[str, Any]:
  """Build branch contexts from Git DAG/ref facts, never from release-name parsing."""
  fix_shas = sorted({str(item.get("fix_commit_sha") or "") for item in history_events if item.get("fix_commit_sha")})
  fix_facts = {
    sha: {
      "sha": sha,
      "branch_refs": _meaningful_refs(graph.containing_branch_refs(sha)),
      "patch_id": str(graph.patch_id(sha) or ""),
      "metadata": dict(graph.commit_metadata(sha) or {}),
    }
    for sha in fix_shas
  }
  components: list[set[str]] = []
  for sha in fix_shas:
    matching = []
    for index, component in enumerate(components):
      if any(_same_lineage(sha, other, fix_facts, graph) for other in component):
        matching.append(index)
    if not matching:
      components.append({sha})
    else:
      merged = {sha}
      for index in reversed(matching):
        merged.update(components.pop(index))
      components.append(merged)

  branch_contexts = []
  fix_groups = []
  context_by_fix: dict[str, str] = {}
  for component in sorted(components, key=lambda value: sorted(value)):
    shas = sorted(component)
    refs = sorted({ref for sha in shas for ref in fix_facts[sha]["branch_refs"]})
    context_id = _stable_id("branch-context", cve_id, repo, *shas)
    for sha in shas:
      context_by_fix[sha] = context_id
    branch_contexts.append(
      {
        "branch_context_id": context_id,
        "repo": repo,
        "fix_commit_shas": shas,
        "branch_refs": refs,
        "lineage_evidence": _lineage_evidence(shas, fix_facts, graph),
        "event_candidate_ids": [],
        "source": "wrapper_git_dag",
      }
    )
    semantics = _fix_semantics(shas, fix_facts, graph)
    fix_groups.append(
      {
        "fix_group_id": _stable_id("fix-group-v1-2", cve_id, context_id),
        "branch_context_id": context_id,
        "fix_commit_shas": shas,
        "patch_ids": sorted({fix_facts[sha]["patch_id"] for sha in shas if fix_facts[sha]["patch_id"]}),
        "completion_semantics": semantics["completion_semantics"],
        "relation_semantics": semantics["relation_semantics"],
        "relation_evidence": semantics["evidence"],
        "fix_commit_facts": [
          {
            "fix_commit_sha": sha,
            "patch_id": fix_facts[sha]["patch_id"],
            "branch_refs": fix_facts[sha]["branch_refs"],
            "parent_count": len(fix_facts[sha]["metadata"].get("parents", []) or []),
            "is_merge": len(fix_facts[sha]["metadata"].get("parents", []) or []) > 1,
          }
          for sha in shas
        ],
        "source": "wrapper_git_dag_and_patch_id",
      }
    )

  annotated = []
  for raw in history_events:
    event = dict(raw)
    context_id = context_by_fix.get(str(event.get("fix_commit_sha") or ""), "")
    event["branch_context_ids"] = [context_id] if context_id else []
    annotated.append(event)
    if context_id:
      next(item for item in branch_contexts if item["branch_context_id"] == context_id)["event_candidate_ids"].append(event["event_candidate_id"])

  boundary_groups = []
  for context in branch_contexts:
    context_events = [item for item in annotated if context["branch_context_id"] in item["branch_context_ids"]]
    bindings = sorted({binding for item in context_events for binding in item.get("root_cause_binding_refs", []) or []}) or ["unbound"]
    for binding in bindings:
      event_ids = sorted(
        item["event_candidate_id"] for item in context_events
        if binding == "unbound" or binding in (item.get("root_cause_binding_refs") or [])
      )
      boundary_groups.append(
        {
          "boundary_group_id": _stable_id("boundary-group-v1-2", cve_id, context["branch_context_id"], binding),
          "branch_context_id": context["branch_context_id"],
          "root_cause_binding_refs": [] if binding == "unbound" else [binding],
          "event_candidate_ids": event_ids,
          "activation_semantics": "any_primary_and_explicit_conjunctive_prerequisites",
          "source": "wrapper_branch_context_and_root_cause_binding",
        }
      )
  equivalence_groups = []
  by_patch_id: dict[str, list[str]] = {}
  for sha, facts in fix_facts.items():
    if facts["patch_id"]:
      by_patch_id.setdefault(facts["patch_id"], []).append(sha)
  for patch_id, shas in sorted(by_patch_id.items()):
    contexts = sorted({context_by_fix[sha] for sha in shas})
    if len(shas) > 1:
      equivalence_groups.append({
        "fix_equivalence_group_id": _stable_id("fix-equivalence", cve_id, patch_id),
        "patch_id": patch_id,
        "fix_commit_shas": sorted(shas),
        "branch_context_ids": contexts,
        "member_semantics": "any_equivalent_fix_within_matching_branch_context",
        "source": "wrapper_stable_patch_id",
      })
  return {
    "history_event_candidates": annotated,
    "branch_contexts": branch_contexts,
    "boundary_groups": boundary_groups,
    "fix_groups": fix_groups,
    "fix_equivalence_groups": equivalence_groups,
  }


def _same_lineage(left: str, right: str, facts: dict[str, dict[str, Any]], graph: Any) -> bool:
  if graph.is_ancestor(left, right) or graph.is_ancestor(right, left):
    return True
  left_refs = set(facts[left]["branch_refs"])
  right_refs = set(facts[right]["branch_refs"])
  return bool(left_refs & right_refs and graph.merge_base(left, right))


def _meaningful_refs(refs: list[str]) -> list[str]:
  return sorted({ref for ref in refs if ref not in {"HEAD", "origin", "origin/HEAD"} and not ref.endswith("/HEAD")})


def _fix_semantics(shas: list[str], facts: dict[str, dict[str, Any]], graph: Any) -> dict[str, Any]:
  if len(shas) == 1:
    return {"completion_semantics": "any_equivalent_fix", "relation_semantics": "branch_local_single", "evidence": ["single_fix_commit"]}
  patch_ids = {facts[sha]["patch_id"] for sha in shas if facts[sha]["patch_id"]}
  if len(patch_ids) == 1:
    return {"completion_semantics": "any_equivalent_fix", "relation_semantics": "semantic_equivalent_fix", "evidence": ["identical_stable_patch_id"]}
  messages = " ".join(
    str(facts[sha]["metadata"].get("subject") or "") + " " + str(facts[sha]["metadata"].get("body") or "")
    for sha in shas
  )
  chain = all(
    graph.is_ancestor(shas[index], shas[index + 1]) or graph.is_ancestor(shas[index + 1], shas[index])
    for index in range(len(shas) - 1)
  )
  explicit_series = bool(re.search(r"\b(?:part|step)\s*[0-9]+|\b[0-9]+/[0-9]+\b|follow[- ]?up", messages, re.I))
  if chain and explicit_series:
    return {"completion_semantics": "all_conjunctive_fixes", "relation_semantics": "conjunctive_fix_series", "evidence": ["linear_dag", "explicit_series_metadata"]}
  return {"completion_semantics": "unknown", "relation_semantics": "unknown_fix_relation", "evidence": ["different_patch_id_without_explicit_conjunction"]}


def _lineage_evidence(shas: list[str], facts: dict[str, dict[str, Any]], graph: Any) -> list[dict[str, Any]]:
  output = []
  for index, left in enumerate(shas):
    for right in shas[index + 1:]:
      output.append({
        "left": left, "right": right,
        "left_ancestor_right": graph.is_ancestor(left, right),
        "right_ancestor_left": graph.is_ancestor(right, left),
        "merge_base": graph.merge_base(left, right),
        "shared_branch_refs": sorted(set(facts[left]["branch_refs"]) & set(facts[right]["branch_refs"])),
      })
  return output


def _stable_id(prefix: str, *parts: str) -> str:
  return f"{prefix}:{hashlib.sha256('|'.join(parts).encode()).hexdigest()[:20]}"
