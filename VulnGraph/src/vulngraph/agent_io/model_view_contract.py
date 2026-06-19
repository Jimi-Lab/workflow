from __future__ import annotations

import json
from typing import Any


WRAPPER_OWNED_FACTS = {
  "repo",
  "fix_commit_sha",
  "parent_sha",
  "patch_family_id",
  "patch_hunk_id",
  "candidate_id",
  "path_before",
  "old_line_start",
  "old_line_end",
  "line_text_hash",
  "function_id",
  "evidence_observation_id",
  "blame_result",
  "release_tag_universe",
}

MODEL_OWNED_JUDGMENTS = {
  "root_cause_interpretation",
  "attacker_trigger",
  "exploit_precondition",
  "vulnerable_predicate_decision",
  "anchor_selection",
  "uncertainty_rationale",
  "bic_likelihood_interface_only",
}

FORBIDDEN_MODEL_INPUT_KEYS = {
  "gt_release_tags",
  "ground_truth_affected_versions",
  "overlap_release_tags",
  "release_metrics",
  "false_positive_taxonomy",
  "diagnostic_gt_overlap",
  "precision",
  "recall",
  "f1",
  "exact_match",
  "validated_bic",
  "correct_bic",
  "affected_versions",
}


def build_root_cause_model_view(
  cve_id: str,
  packet: dict[str, Any],
  evidence_trace: dict[str, Any],
  *,
  line_text_limit: int = 220,
  observation_snippet_limit: int = 360,
  root_cause_packet_ref: str = "root_cause_packet.json",
  evidence_trace_ref: str = "evidence_trace.json",
) -> dict[str, Any]:
  return {
    "schema_version": "root_cause_model_view_v1",
    "ownership_contract": _ownership_contract(),
    "cve_id": cve_id,
    "context": _root_context(packet),
    "patch_evidence": {
      "artifact_ref": root_cause_packet_ref,
      "fix_commits": _compact_fix_commits(packet),
      "patch_hunks": _compact_patch_hunks(packet, line_text_limit=line_text_limit),
    },
    "evidence_inventory": {
      "artifact_ref": evidence_trace_ref,
      "backend_trusted": evidence_trace.get("backend_trusted"),
      "repo": evidence_trace.get("repo"),
      "observations": _compact_observations(
        evidence_trace,
        snippet_limit=observation_snippet_limit,
      ),
      "tool_call_refs": [
        {
          "id": call.get("id"),
          "command": call.get("command"),
          "exit_code": call.get("exit_code"),
          "stdout_artifact_ref": call.get("tool_output_ref") or call.get("id"),
          "stderr_excerpt": _truncate(str(call.get("stderr_excerpt") or ""), 240),
        }
        for call in evidence_trace.get("tool_calls", []) or []
      ],
    },
    "output_instruction": {
      "model_should_reference_ids": ["git_observation_refs", "patch_hunk_id", "function_id", "fix_commit_id"],
      "wrapper_owned_fields_are_alias_only": ["path", "line_start", "line_end", "commit_sha"],
    },
  }


def build_szz_anchor_model_view(
  root_cause: dict[str, Any],
  inventory: dict[str, Any],
  *,
  top_k_per_patch_family: int = 40,
  line_text_limit: int = 180,
) -> dict[str, Any]:
  selected, metrics = _compact_szz_candidates(
    root_cause=root_cause,
    inventory=inventory,
    top_k_per_patch_family=top_k_per_patch_family,
    line_text_limit=line_text_limit,
  )
  return {
    "schema_version": "szz_anchor_model_view_v1",
    "ownership_contract": _ownership_contract(),
    "root_cause_summary": _compact_root_cause_for_szz(root_cause),
    "candidate_inventory": {
      "artifact_ref": "candidate_inventory.json",
      "cve_id": inventory.get("cve_id"),
      "repo_id": inventory.get("repo_id"),
      "fix_families": inventory.get("fix_families", {}),
      "issues": inventory.get("issues", []),
      **metrics,
      "candidates": selected,
    },
    "output_instruction": {
      "select_only_candidate_id": True,
      "do_not_generate_wrapper_facts": ["path", "line", "commit_sha", "observation_id"],
    },
  }


def build_judge_blind_model_view(
  packet: dict[str, Any],
  *,
  release_tag_inline_limit: int = 40,
  old_line_text_limit: int = 180,
) -> dict[str, Any]:
  candidates = []
  for candidate in packet.get("candidates", []) or []:
    compact = dict(candidate)
    tags = list(compact.pop("predicted_release_tags_from_version_probe", []) or [])
    if len(tags) > release_tag_inline_limit:
      compact["release_tag_summary"] = {
        "count": len(tags),
        "first": tags[:5],
        "last": tags[-5:],
        "truncated": True,
      }
      compact["release_tag_artifact_ref"] = f"judge_audit_packet.json#candidate:{candidate.get('candidate_commit_sha')}"
    else:
      compact["release_tag_summary"] = {
        "count": len(tags),
        "tags": tags,
        "truncated": False,
      }
      compact["release_tag_artifact_ref"] = ""
    if "old_line_text" in compact:
      compact["old_line_text"] = _truncate(str(compact.get("old_line_text") or ""), old_line_text_limit)
    compact["blame_trace"] = _compact_blame_trace(compact.get("blame_trace") or {})
    candidates.append(_drop_forbidden_keys(compact))
  return {
    "schema_version": "judge_blind_model_view_v1",
    "ownership_contract": _ownership_contract(),
    "cve_id": packet.get("cve_id"),
    "repo": packet.get("repo"),
    "case_status": packet.get("case_status"),
    "lifecycle": packet.get("lifecycle", "raw_candidate"),
    "candidate_count": len(candidates),
    "candidates": candidates,
    "audit_artifact_ref": "judge_audit_packet.json",
    "output_instruction": {
      "judge_may_use_only_raw_candidates": True,
      "do_not_claim_validated_bic": True,
      "gt_diagnostics_absent": True,
    },
  }


def scan_forbidden_model_input(data: Any) -> dict[str, Any]:
  violations: list[dict[str, str]] = []
  for token in sorted(FORBIDDEN_MODEL_INPUT_KEYS):
    for location in _find_forbidden(data, token):
      violations.append({"token": token, "location": location})
  return {
    "ok": not violations,
    "forbidden_tokens": sorted(FORBIDDEN_MODEL_INPUT_KEYS),
    "violation_count": len(violations),
    "violations": violations,
  }


def field_deprecation_map() -> dict[str, Any]:
  return {
    "deprecated_backward_compat": {
      "id": "use typed primary IDs such as hypothesis_id, predicate_id, anchor_id, candidate_id",
      "code_anchor_ids": "use anchor_ids",
      "function_name": "use function as model alias only; wrapper resolves function_id",
      "line_range": "use wrapper-owned old_line_start/old_line_end or line_start/line_end aliases only for backward compatibility",
      "statement": "use description",
      "all_anchor_ids": "use provenance refs; do not duplicate selected/fallback anchor fields",
      "selected_anchor_id": "use anchor_id in model-owned selection outputs where applicable",
      "fallback_anchor_id": "use anchor_id plus candidate_source=fallback where applicable",
    },
    "wrapper_owned_not_model_output": sorted(WRAPPER_OWNED_FACTS),
    "model_owned_judgments": sorted(MODEL_OWNED_JUDGMENTS),
  }


def _root_context(packet: dict[str, Any]) -> dict[str, Any]:
  context = packet.get("context", {})
  if isinstance(context, dict):
    return _drop_forbidden_keys(context)
  return {"raw_context_summary": _truncate(json.dumps(context, ensure_ascii=False), 1000)}


def _compact_fix_commits(packet: dict[str, Any]) -> list[dict[str, Any]]:
  output = []
  for item in packet.get("patch_evidence", []) or []:
    if item.get("type") != "FixCommit":
      continue
    content = item.get("content", {}) or {}
    output.append(
      {
        "id": item.get("id"),
        "repo": content.get("repo"),
        "fix_commit_id": item.get("id"),
        "fix_commit_sha": content.get("commit_sha"),
        "fix_set_id": content.get("fix_set_id"),
        "message_summary": _truncate(str(content.get("message") or content.get("subject") or ""), 320),
      }
    )
  return output


def _compact_patch_hunks(packet: dict[str, Any], *, line_text_limit: int) -> list[dict[str, Any]]:
  output = []
  for item in packet.get("patch_evidence", []) or []:
    if item.get("type") != "PatchHunk":
      continue
    content = item.get("content", {}) or {}
    deleted = [_compact_line(line, "old_line", line_text_limit) for line in content.get("deleted_lines", [])[:6]]
    added = [_compact_line(line, "new_line", line_text_limit) for line in content.get("added_lines", [])[:6]]
    context = [_compact_line(line, "old_line", line_text_limit) for line in content.get("context_lines", [])[:4]]
    output.append(
      {
        "patch_hunk_id": item.get("id"),
        "fix_commit_id": content.get("fix_commit_id") or f"fix-commit:{content.get('repo')}:{content.get('commit_sha')}",
        "fix_commit_sha": content.get("commit_sha"),
        "path": content.get("path"),
        "function_id": content.get("function_id"),
        "function": content.get("function_symbol"),
        "change_type": content.get("change_type") or _infer_change_type(content),
        "old_start": content.get("old_start"),
        "new_start": content.get("new_start"),
        "deleted_line_count": len(content.get("deleted_lines", []) or []),
        "added_line_count": len(content.get("added_lines", []) or []),
        "semantic_summary": _hunk_semantic_summary(content),
        "key_deleted_lines": deleted,
        "key_added_lines": added,
        "context_lines": context,
        "git_observation_refs": content.get("git_observation_refs", []),
        "full_hunk_artifact_ref": f"root_cause_packet.json#patch_hunk:{item.get('id')}",
      }
    )
  return output


def _compact_observations(evidence_trace: dict[str, Any], *, snippet_limit: int) -> list[dict[str, Any]]:
  observations = []
  for observation in evidence_trace.get("git_observations", []) or []:
    observations.append(
      {
        "id": observation.get("id") or observation.get("observation_id"),
        "source": observation.get("source"),
        "valid_evidence": observation.get("valid_evidence"),
        "observation_kind": observation.get("observation_kind"),
        "claim": _truncate(str(observation.get("claim") or ""), 280),
        "fix_commit_ids": observation.get("fix_commit_ids", []),
        "patch_hunk_ids": observation.get("patch_hunk_ids", []),
        "file_ids": observation.get("file_ids", []),
        "function_ids": observation.get("function_ids", []),
        "snippet_excerpt": _truncate(str(observation.get("snippet") or ""), snippet_limit),
        "artifact_ref": observation.get("tool_output_ref") or observation.get("id"),
      }
    )
  return observations


def _compact_szz_candidates(
  *,
  root_cause: dict[str, Any],
  inventory: dict[str, Any],
  top_k_per_patch_family: int,
  line_text_limit: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
  candidates = list(inventory.get("candidates", []) or [])
  by_family: dict[str, list[dict[str, Any]]] = {}
  for candidate in candidates:
    family = str(candidate.get("patch_family_id") or "")
    by_family.setdefault(family, []).append(candidate)
  selected = []
  selected_ids: set[str] = set()
  for family, group in by_family.items():
    if not family:
      continue
    for candidate in sorted(group, key=lambda item: _szz_candidate_rank(item, root_cause))[: max(1, top_k_per_patch_family)]:
      candidate_id = str(candidate.get("candidate_id") or "")
      if candidate_id not in selected_ids:
        selected.append(_compact_szz_candidate(candidate, line_text_limit=line_text_limit))
        selected_ids.add(candidate_id)
  isolated = [item for item in candidates if not item.get("patch_family_id")]
  fix_commit_ids = {str(item.get("fix_commit_id") or "") for item in candidates if item.get("fix_commit_id")}
  prompt_fix_commits = {str(item.get("fix_commit_id") or "") for item in selected if item.get("fix_commit_id")}
  return selected, {
    "original_candidate_count": len(candidates),
    "compacted_candidate_count": len(selected),
    "candidate_without_patch_family": len(isolated),
    "fix_commits_total": len(fix_commit_ids),
    "fix_commits_prompt_covered": len(prompt_fix_commits & fix_commit_ids),
    "top_k_per_patch_family": top_k_per_patch_family,
    "line_text_limit": line_text_limit,
  }


def _compact_szz_candidate(candidate: dict[str, Any], *, line_text_limit: int) -> dict[str, Any]:
  line_text = str(candidate.get("line_text") or "")
  return {
    "candidate_id": candidate.get("candidate_id"),
    "fix_set_id": candidate.get("fix_set_id"),
    "patch_family_id": candidate.get("patch_family_id"),
    "fix_commit_id": candidate.get("fix_commit_id"),
    "patch_hunk_id": candidate.get("patch_hunk_id"),
    "path_before": candidate.get("path_before"),
    "old_line_start": candidate.get("old_line_start"),
    "old_line_end": candidate.get("old_line_end"),
    "line_text": _truncate(line_text, line_text_limit),
    "line_text_hash": candidate.get("line_text_sha256") or candidate.get("line_text_hash"),
    "function_id": candidate.get("function_id"),
    "function": candidate.get("function_name"),
    "candidate_source": candidate.get("candidate_source"),
    "change_type": candidate.get("change_type"),
    "selection_mode_eligibility": candidate.get("selection_mode_eligibility", []),
    "role_hint": _role_hint(candidate),
    "risk_flags": _candidate_risk_flags(candidate),
    "git_observation_refs": candidate.get("git_observation_refs", []),
    "source_file": candidate.get("source_file"),
    "exclusion_reasons": candidate.get("exclusion_reasons", []),
  }


def _compact_root_cause_for_szz(root_cause: dict[str, Any]) -> dict[str, Any]:
  return {
    "root_cause_hypotheses": [
      {
        "hypothesis_id": item.get("hypothesis_id"),
        "summary": _truncate(str(item.get("summary") or item.get("mechanism") or ""), 360),
        "anchor_ids": item.get("anchor_ids", []),
        "vulnerable_predicate_ids": item.get("vulnerable_predicate_ids", []),
        "fix_predicate_ids": item.get("fix_predicate_ids", []),
        "git_observation_refs": item.get("git_observation_refs", []),
      }
      for item in root_cause.get("root_cause_hypotheses", []) or []
    ],
    "vulnerable_predicates": [
      {
        "predicate_id": item.get("predicate_id"),
        "description": _truncate(str(item.get("description") or ""), 320),
        "anchor_ids": item.get("anchor_ids", []),
        "git_observation_refs": item.get("git_observation_refs", []),
      }
      for item in root_cause.get("vulnerable_predicates", []) or []
    ],
    "fix_predicates": [
      {
        "predicate_id": item.get("predicate_id"),
        "description": _truncate(str(item.get("description") or ""), 320),
        "anchor_ids": item.get("anchor_ids", []),
        "git_observation_refs": item.get("git_observation_refs", []),
      }
      for item in root_cause.get("fix_predicates", []) or []
    ],
    "code_anchors": [
      {
        "anchor_id": item.get("anchor_id"),
        "patch_hunk_id": item.get("patch_hunk_id"),
        "function_id": item.get("function_id"),
        "git_observation_refs": item.get("git_observation_refs", []),
      }
      for item in root_cause.get("code_anchors", []) or []
    ],
  }


def _compact_blame_trace(blame_trace: dict[str, Any]) -> dict[str, Any]:
  provenance = []
  for item in blame_trace.get("line_provenance", []) or []:
    provenance.append(
      {
        "anchor_id": item.get("anchor_id"),
        "candidate_id": item.get("candidate_id"),
        "role": item.get("role"),
        "selection_mode": item.get("selection_mode"),
        "boundary_marker": item.get("boundary_marker"),
        "status": item.get("status"),
      }
    )
  return {
    "status": blame_trace.get("status"),
    "line_provenance": provenance[:12],
    "line_provenance_count": len(blame_trace.get("line_provenance", []) or []),
    "errors": blame_trace.get("errors", [])[:5],
  }


def _drop_forbidden_keys(value: Any) -> Any:
  if isinstance(value, dict):
    return {key: _drop_forbidden_keys(child) for key, child in value.items() if key not in FORBIDDEN_MODEL_INPUT_KEYS}
  if isinstance(value, list):
    return [_drop_forbidden_keys(child) for child in value]
  return value


def _find_forbidden(value: Any, token: str, path: str = "$") -> list[str]:
  matches: list[str] = []
  if isinstance(value, dict):
    for key, child in value.items():
      child_path = f"{path}.{key}"
      if key == token:
        matches.append(child_path)
      matches.extend(_find_forbidden(child, token, child_path))
  elif isinstance(value, list):
    for index, child in enumerate(value):
      matches.extend(_find_forbidden(child, token, f"{path}[{index}]"))
  elif isinstance(value, str) and value == token:
    matches.append(path)
  return matches


def _compact_line(line: dict[str, Any], line_key: str, limit: int) -> dict[str, Any]:
  return {
    "line": line.get(line_key),
    "text": _truncate(str(line.get("text") or ""), limit),
  }


def _infer_change_type(content: dict[str, Any]) -> str:
  deleted = bool(content.get("deleted_lines"))
  added = bool(content.get("added_lines"))
  if deleted and added:
    return "modify"
  if deleted:
    return "delete"
  return "add_only"


def _hunk_semantic_summary(content: dict[str, Any]) -> str:
  change_type = content.get("change_type") or _infer_change_type(content)
  function = content.get("function_symbol") or content.get("function_name") or ""
  return f"{change_type} hunk in {content.get('path', '')}" + (f"::{function}" if function else "")


def _szz_candidate_rank(candidate: dict[str, Any], root_cause: dict[str, Any]) -> tuple[Any, ...]:
  source_rank = {"deleted_line": 0, "pre_fix_function_body": 1, "hunk_context": 2}
  noise = 1 if any(candidate.get(key) for key in ("comment_only", "blank_line", "test_file", "documentation_file", "generated_file", "changelog_file")) else 0
  shared = 0 if _candidate_shares_root_cause_evidence(candidate, root_cause) else 1
  return (
    source_rank.get(str(candidate.get("candidate_source") or ""), 9),
    0 if candidate.get("source_file") is True else 1,
    noise,
    shared,
    int(candidate.get("old_line_start") or 0),
    str(candidate.get("candidate_id") or ""),
  )


def _candidate_shares_root_cause_evidence(candidate: dict[str, Any], root_cause: dict[str, Any]) -> bool:
  refs = set(candidate.get("git_observation_refs") or [])
  if not refs:
    return False
  for key in ("root_cause_hypotheses", "vulnerable_predicates", "fix_predicates", "code_anchors"):
    for item in root_cause.get(key, []) or []:
      if refs & set(item.get("git_observation_refs") or []):
        return True
  return False


def _role_hint(candidate: dict[str, Any]) -> str:
  source = str(candidate.get("candidate_source") or "")
  if source == "deleted_line":
    return "dangerous_use"
  if source == "pre_fix_function_body":
    return "missing_guard_target"
  return "control_predecessor"


def _candidate_risk_flags(candidate: dict[str, Any]) -> list[str]:
  flags = []
  for key in ("generated_file", "test_file", "documentation_file", "changelog_file", "comment_only", "blank_line"):
    if candidate.get(key) is True:
      flags.append(key)
  if candidate.get("candidate_source") == "hunk_context":
    flags.append("context_only_candidate")
  return flags


def _ownership_contract() -> dict[str, Any]:
  return {
    "wrapper_owned_facts": sorted(WRAPPER_OWNED_FACTS),
    "model_owned_judgments": sorted(MODEL_OWNED_JUDGMENTS),
    "model_output_rule": "model selects IDs and writes rationale; wrapper resolves path, line, SHA, and evidence facts",
  }


def _truncate(value: str, limit: int) -> str:
  if len(value) <= limit:
    return value
  return value[: max(0, limit - 14)] + "...[truncated]"
