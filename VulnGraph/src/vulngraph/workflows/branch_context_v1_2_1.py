from __future__ import annotations

import hashlib
import re
from typing import Any


_CHERRY_PICK_RE = re.compile(r"cherry picked from commit\s+([0-9a-f]{7,40})", re.I)


def build_complete_branch_scoped_groups(
  cve_id: str,
  repo: str,
  history_events: list[dict[str, Any]],
  declared_fix_shas: list[str],
  graph: Any,
) -> dict[str, Any]:
  """Build branch/fix groups from the declared fix universe, independent of candidates."""
  declared = sorted({str(value) for value in declared_fix_shas if value})
  event_fix_shas = sorted({str(item.get("fix_commit_sha") or "") for item in history_events if item.get("fix_commit_sha")})
  all_shas = sorted(set(declared) | set(event_fix_shas))
  fix_facts = {sha: _fix_fact(sha, declared, event_fix_shas, graph) for sha in all_shas}
  aliases = _fix_aliases(declared, event_fix_shas, fix_facts)

  components: list[set[str]] = []
  for sha in all_shas:
    matching = [index for index, component in enumerate(components) if any(_same_lineage(sha, other, fix_facts, graph) for other in component)]
    if not matching:
      components.append({sha})
      continue
    merged = {sha}
    for index in reversed(matching):
      merged.update(components.pop(index))
    components.append(merged)

  branch_contexts: list[dict[str, Any]] = []
  fix_groups: list[dict[str, Any]] = []
  context_by_fix: dict[str, str] = {}
  for component in sorted(components, key=lambda value: sorted(value)):
    shas = sorted(component)
    context_id = _stable_id("branch-context-v1-2-1", cve_id, repo, *shas)
    for sha in shas:
      context_by_fix[sha] = context_id
    component_aliases = [item for item in aliases if item["declared_fix_sha"] in component or item["equivalent_fix_sha"] in component]
    branch_contexts.append({
      "branch_context_id": context_id,
      "repo": repo,
      "fix_commit_shas": shas,
      "declared_fix_shas": sorted(set(shas) & set(declared)),
      "alias_fix_shas": sorted(set(shas) - set(declared)),
      "branch_refs": sorted({ref for sha in shas for ref in fix_facts[sha]["branch_refs"]}),
      "lineage_evidence": _lineage_evidence(shas, fix_facts, graph),
      "event_candidate_ids": [],
      "source": "wrapper_git_dag_complete_fix_universe",
    })
    semantics = _fix_semantics(shas, fix_facts, component_aliases, graph)
    fix_groups.append({
      "fix_group_id": _stable_id("fix-group-v1-2-1", cve_id, context_id),
      "branch_context_id": context_id,
      "fix_commit_shas": shas,
      "declared_fix_shas": sorted(set(shas) & set(declared)),
      "alias_fix_shas": sorted(set(shas) - set(declared)),
      "patch_ids": sorted({fix_facts[sha]["patch_id"] for sha in shas if fix_facts[sha]["patch_id"]}),
      "completion_semantics": semantics["completion_semantics"],
      "relation_semantics": semantics["relation_semantics"],
      "relation_evidence": semantics["evidence"],
      "fix_commit_facts": [fix_facts[sha] for sha in shas],
      "source": "wrapper_dataset_git_dag_patch_id",
    })

  annotated: list[dict[str, Any]] = []
  for raw in history_events:
    event = dict(raw)
    context_id = context_by_fix.get(str(event.get("fix_commit_sha") or ""), "")
    event["branch_context_ids"] = [context_id] if context_id else []
    annotated.append(event)
    if context_id:
      next(item for item in branch_contexts if item["branch_context_id"] == context_id)["event_candidate_ids"].append(str(event.get("event_candidate_id") or ""))

  boundary_groups = _boundary_groups(cve_id, annotated, branch_contexts)
  equivalence_groups = _equivalence_groups(cve_id, fix_facts, aliases, context_by_fix)
  represented = sorted({sha for group in fix_groups for sha in group["fix_commit_shas"] if sha in declared})
  missing = sorted(set(declared) - set(represented))
  return {
    "history_event_candidates": annotated,
    "branch_contexts": branch_contexts,
    "boundary_groups": boundary_groups,
    "fix_groups": fix_groups,
    "fix_equivalence_groups": equivalence_groups,
    "fix_aliases": aliases,
    "fix_universe_audit": {
      "declared_fix_count": len(declared),
      "represented_declared_fix_count": len(represented),
      "alias_fix_count": len(set(event_fix_shas) - set(declared)),
      "missing_declared_fix_count": len(missing),
      "declared_fix_shas": declared,
      "represented_declared_fix_shas": represented,
      "missing_declared_fix_shas": missing,
      "coverage": (len(represented) / len(declared)) if declared else 1.0,
    },
  }


def _fix_fact(sha: str, declared: list[str], event_fixes: list[str], graph: Any) -> dict[str, Any]:
  metadata = dict(graph.commit_metadata(sha) or {})
  refs = _meaningful_refs(graph.containing_branch_refs(sha))
  patch_id = str(graph.patch_id(sha) or "")
  # A ref or patch-id cannot substitute for a readable commit object.
  resolved = bool(metadata.get("subject") or metadata.get("body") or metadata.get("parents"))
  return {
    "fix_commit_sha": sha,
    "declared_in_dataset": sha in declared,
    "event_referenced": sha in event_fixes,
    "resolution_status": "resolved" if resolved else "missing_commit",
    "parents": list(metadata.get("parents") or []),
    "parent_count": len(metadata.get("parents") or []),
    "is_merge": len(metadata.get("parents") or []) > 1,
    "subject": str(metadata.get("subject") or ""),
    "body": str(metadata.get("body") or ""),
    "branch_refs": refs,
    "patch_id": patch_id,
  }


def _fix_aliases(declared: list[str], event_fixes: list[str], facts: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
  output: list[dict[str, Any]] = []
  for sha in declared:
    for parent in facts.get(sha, {}).get("parents", []):
      if parent in event_fixes and parent not in declared:
        output.append({"declared_fix_sha": sha, "equivalent_fix_sha": parent, "alias_evidence": "declared_merge_parent", "confidence": "strong"})
    message = f"{facts.get(sha, {}).get('subject', '')} {facts.get(sha, {}).get('body', '')}"
    for match in _CHERRY_PICK_RE.finditer(message):
      original = match.group(1)
      candidates = [value for value in facts if value.startswith(original)]
      for candidate in candidates:
        if candidate != sha:
          output.append({"declared_fix_sha": sha, "equivalent_fix_sha": candidate, "alias_evidence": "explicit_cherry_pick_metadata", "confidence": "strong"})
  unique = {(item["declared_fix_sha"], item["equivalent_fix_sha"], item["alias_evidence"]): item for item in output}
  return sorted(unique.values(), key=lambda item: (item["declared_fix_sha"], item["equivalent_fix_sha"]))


def _fix_semantics(shas: list[str], facts: dict[str, dict[str, Any]], aliases: list[dict[str, Any]], graph: Any) -> dict[str, Any]:
  if len(shas) == 1:
    return {"completion_semantics": "any_equivalent_fix", "relation_semantics": "branch_local_single", "evidence": ["single_fix_commit"]}
  if aliases:
    return {"completion_semantics": "any_equivalent_fix", "relation_semantics": "explicit_fix_alias", "evidence": sorted({item["alias_evidence"] for item in aliases})}
  patch_ids = {facts[sha]["patch_id"] for sha in shas if facts[sha]["patch_id"]}
  if len(patch_ids) == 1:
    return {"completion_semantics": "any_equivalent_fix", "relation_semantics": "semantic_equivalent_fix", "evidence": ["identical_stable_patch_id"]}
  messages = " ".join(f"{facts[sha]['subject']} {facts[sha]['body']}" for sha in shas)
  chain = all(graph.is_ancestor(shas[index], shas[index + 1]) or graph.is_ancestor(shas[index + 1], shas[index]) for index in range(len(shas) - 1))
  explicit_series = bool(re.search(r"\b(?:part|step)\s*[0-9]+|\b[0-9]+/[0-9]+\b|follow[- ]?up", messages, re.I))
  if chain and explicit_series:
    return {"completion_semantics": "all_conjunctive_fixes", "relation_semantics": "conjunctive_fix_series", "evidence": ["linear_dag", "explicit_series_metadata"]}
  return {"completion_semantics": "unknown", "relation_semantics": "unknown_fix_relation", "evidence": ["different_patch_id_without_explicit_conjunction"]}


def _same_lineage(left: str, right: str, facts: dict[str, dict[str, Any]], graph: Any) -> bool:
  if graph.is_ancestor(left, right) or graph.is_ancestor(right, left):
    return True
  left_refs, right_refs = set(facts[left]["branch_refs"]), set(facts[right]["branch_refs"])
  return bool(left_refs & right_refs and graph.merge_base(left, right))


def _boundary_groups(cve_id: str, events: list[dict[str, Any]], contexts: list[dict[str, Any]]) -> list[dict[str, Any]]:
  output = []
  for context in contexts:
    context_events = [item for item in events if context["branch_context_id"] in item.get("branch_context_ids", [])]
    bindings = sorted({binding for item in context_events for binding in item.get("root_cause_binding_refs", []) or []}) or ["unbound"]
    for binding in bindings:
      ids = sorted(item["event_candidate_id"] for item in context_events if binding == "unbound" or binding in (item.get("root_cause_binding_refs") or []))
      output.append({
        "boundary_group_id": _stable_id("boundary-group-v1-2-1", cve_id, context["branch_context_id"], binding),
        "branch_context_id": context["branch_context_id"],
        "root_cause_binding_refs": [] if binding == "unbound" else [binding],
        "event_candidate_ids": ids,
        "activation_semantics": "any_primary_and_explicit_conjunctive_prerequisites",
        "source": "wrapper_branch_context_and_root_cause_binding",
      })
  return output


def _equivalence_groups(cve_id: str, facts: dict[str, dict[str, Any]], aliases: list[dict[str, Any]], contexts: dict[str, str]) -> list[dict[str, Any]]:
  groups: list[dict[str, Any]] = []
  by_patch: dict[str, list[str]] = {}
  for sha, fact in facts.items():
    if fact["patch_id"]:
      by_patch.setdefault(fact["patch_id"], []).append(sha)
  for patch_id, shas in sorted(by_patch.items()):
    if len(shas) > 1:
      groups.append({
        "fix_equivalence_group_id": _stable_id("fix-equivalence-v1-2-1", cve_id, patch_id),
        "fix_commit_shas": sorted(shas), "branch_context_ids": sorted({contexts[sha] for sha in shas}),
        "equivalence_evidence": "identical_stable_patch_id", "completion_semantics": "any_equivalent_fix",
      })
  for alias in aliases:
    shas = [alias["declared_fix_sha"], alias["equivalent_fix_sha"]]
    groups.append({
      "fix_equivalence_group_id": _stable_id("fix-alias-v1-2-1", cve_id, *shas),
      "fix_commit_shas": shas, "branch_context_ids": sorted({contexts[sha] for sha in shas}),
      "equivalence_evidence": alias["alias_evidence"], "completion_semantics": "any_equivalent_fix",
    })
  return groups


def _lineage_evidence(shas: list[str], facts: dict[str, dict[str, Any]], graph: Any) -> list[dict[str, Any]]:
  return [{
    "left": left, "right": right,
    "left_ancestor_right": graph.is_ancestor(left, right),
    "right_ancestor_left": graph.is_ancestor(right, left),
    "merge_base": graph.merge_base(left, right),
    "shared_branch_refs": sorted(set(facts[left]["branch_refs"]) & set(facts[right]["branch_refs"])),
  } for index, left in enumerate(shas) for right in shas[index + 1:]]


def _meaningful_refs(refs: list[str]) -> list[str]:
  return sorted({ref for ref in refs if ref not in {"HEAD", "origin", "origin/HEAD"} and not ref.endswith("/HEAD")})


def _stable_id(prefix: str, *parts: str) -> str:
  return f"{prefix}:{hashlib.sha256('|'.join(parts).encode()).hexdigest()[:20]}"
