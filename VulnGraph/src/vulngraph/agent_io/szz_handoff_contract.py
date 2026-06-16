from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from typing import Any

from vulngraph.agent_io.szz_handoff_schema import (
  PreFixCandidateInventoryV1,
  ResolvedPreFixAnchorV1,
  RootCauseSzzHandoffV1,
)


TAXONOMY_KEYS = (
  "unknown_candidate_id",
  "candidate_scope_mismatch",
  "added_line_not_blameable",
  "parent_coordinate_mismatch",
  "non_source_anchor",
  "comment_or_blank_anchor",
  "weak_root_cause_binding",
  "add_only_context_only",
  "fix_family_incomplete",
  "fix_commit_incomplete",
  "unknown_uncertainty_patch_family",
  "unknown_uncertainty_fix_commit",
  "uncertainty_commit_family_mismatch",
  "duplicate_anchor_selection",
  "no_blameable_anchor_selected",
)


@dataclass(frozen=True)
class SzzHandoffValidationResult:
  accepted_anchor_ids: list[str]
  rejected_anchor_ids: list[str]
  resolved_anchors: list[ResolvedPreFixAnchorV1]
  errors: list[str]
  taxonomy: dict[str, int]
  invented_ids: list[str]
  patch_family_coverage: dict[str, dict[str, bool]]
  fix_commit_coverage: dict[str, dict[str, Any]]
  ok: bool

  def to_dict(self) -> dict[str, Any]:
    return {
      "accepted_anchor_ids": self.accepted_anchor_ids,
      "rejected_anchor_ids": self.rejected_anchor_ids,
      "resolved_anchors": [item.model_dump(mode="json") for item in self.resolved_anchors],
      "errors": self.errors,
      "taxonomy": self.taxonomy,
      "invented_ids": self.invented_ids,
      "patch_family_coverage": self.patch_family_coverage,
      "fix_commit_coverage": self.fix_commit_coverage,
      "ok": self.ok,
    }


def validate_szz_handoff(
  selection: dict[str, Any] | RootCauseSzzHandoffV1,
  inventory: PreFixCandidateInventoryV1,
  root_cause_output: dict[str, Any],
) -> SzzHandoffValidationResult:
  handoff = selection if isinstance(selection, RootCauseSzzHandoffV1) else RootCauseSzzHandoffV1.model_validate(selection)
  candidates = {item.candidate_id: item for item in inventory.candidates}
  hypothesis_refs = _semantic_refs(root_cause_output.get("root_cause_hypotheses", []), "hypothesis_id")
  predicate_refs: dict[str, set[str]] = {}
  for key in ("vulnerable_predicates", "fix_predicates", "guard_conditions", "negative_conditions"):
    predicate_refs.update(_semantic_refs(root_cause_output.get(key, []), "predicate_id"))

  taxonomy: Counter[str] = Counter()
  errors: list[str] = []
  invented_ids: set[str] = set()
  accepted: list[str] = []
  rejected: list[str] = []
  resolved: list[ResolvedPreFixAnchorV1] = []
  selected_counts = Counter(item.candidate_id for item in handoff.selected_anchors)

  for selected in handoff.selected_anchors:
    candidate = candidates.get(selected.candidate_id)
    candidate_errors: list[str] = []
    if selected_counts[selected.candidate_id] > 1:
      _reject(candidate_errors, taxonomy, "duplicate_anchor_selection", selected.candidate_id)
    if candidate is None:
      invented_ids.add(selected.candidate_id)
      _reject(candidate_errors, taxonomy, "unknown_candidate_id", selected.candidate_id)
    else:
      if handoff.agent_run.cve_id != inventory.cve_id or candidate.cve_id != inventory.cve_id:
        _reject(candidate_errors, taxonomy, "candidate_scope_mismatch", selected.candidate_id)
      if candidate.old_line_start < 1 or candidate.old_line_end < candidate.old_line_start:
        _reject(candidate_errors, taxonomy, "parent_coordinate_mismatch", selected.candidate_id)
      if not candidate.source_file:
        _reject(candidate_errors, taxonomy, "non_source_anchor", selected.candidate_id)
      if candidate.comment_only or candidate.blank_line:
        _reject(candidate_errors, taxonomy, "comment_or_blank_anchor", selected.candidate_id)
      if not _has_strong_root_cause_binding(
        selected.root_cause_hypothesis_ids,
        selected.predicate_ids,
        candidate.git_observation_refs,
        hypothesis_refs,
        predicate_refs,
      ):
        _reject(candidate_errors, taxonomy, "weak_root_cause_binding", selected.candidate_id)
      if candidate.change_type == "add_only" and candidate.candidate_source == "hunk_context":
        taxonomy["add_only_context_only"] += 1
        stronger = any(
          candidates.get(item.candidate_id)
          and candidates[item.candidate_id].patch_family_id == candidate.patch_family_id
          and candidates[item.candidate_id].candidate_source == "pre_fix_function_body"
          for item in handoff.selected_anchors
        )
        if not stronger:
          candidate_errors.append(f"add_only_context_only:{selected.candidate_id}")

    if candidate_errors or candidate is None:
      rejected.append(selected.candidate_id)
      errors.extend(candidate_errors)
      continue
    accepted.append(selected.candidate_id)
    selection_mode = _selection_mode(candidate.candidate_source, candidate.change_type)
    anchor_id = "pre-fix-anchor:" + hashlib.sha256(
      f"{handoff.agent_run.run_id}\0{selected.candidate_id}".encode("utf-8")
    ).hexdigest()
    resolved.append(
      ResolvedPreFixAnchorV1(
        anchor_id=anchor_id,
        candidate_id=candidate.candidate_id,
        cve_id=candidate.cve_id,
        fix_set_id=candidate.fix_set_id,
        patch_family_id=candidate.patch_family_id,
        fix_commit_id=candidate.fix_commit_id,
        fix_commit_sha=candidate.fix_commit_sha,
        parent_sha=candidate.parent_sha,
        patch_hunk_id=candidate.patch_hunk_id,
        path_before=candidate.path_before,
        path_after=candidate.path_after,
        old_line_start=candidate.old_line_start,
        old_line_end=candidate.old_line_end,
        line_text=candidate.line_text,
        line_text_sha256=candidate.line_text_sha256,
        function_id=candidate.function_id,
        function_name=candidate.function_name,
        candidate_source=candidate.candidate_source,
        role=selected.role,
        selection_mode=selection_mode,
        root_cause_hypothesis_ids=selected.root_cause_hypothesis_ids,
        predicate_ids=selected.predicate_ids,
        git_observation_refs=candidate.git_observation_refs,
        rationale=selected.rationale,
        confidence=selected.confidence,
        lifecycle="raw_candidate",
        exclusion_reasons=candidate.exclusion_reasons,
      )
    )

  expected_families = set(inventory.fix_families)
  family_commits: dict[str, set[str]] = {family_id: set() for family_id in expected_families}
  commit_family: dict[str, str] = {}
  for candidate in inventory.candidates:
    if candidate.patch_family_id not in expected_families:
      continue
    family_commits[candidate.patch_family_id].add(candidate.fix_commit_id)
    commit_family[candidate.fix_commit_id] = candidate.patch_family_id

  uncertain_pairs: set[tuple[str, str]] = set()
  for item in handoff.uncertainty_items:
    family_known = item.patch_family_id in expected_families
    commit_known = item.fix_commit_id in commit_family
    if not family_known:
      taxonomy["unknown_uncertainty_patch_family"] += 1
      errors.append(f"unknown_uncertainty_patch_family:{item.patch_family_id}")
    if not commit_known:
      taxonomy["unknown_uncertainty_fix_commit"] += 1
      errors.append(f"unknown_uncertainty_fix_commit:{item.fix_commit_id}")
    if family_known and commit_known and commit_family[item.fix_commit_id] != item.patch_family_id:
      taxonomy["uncertainty_commit_family_mismatch"] += 1
      errors.append(f"uncertainty_commit_family_mismatch:{item.patch_family_id}:{item.fix_commit_id}")
    if family_known and commit_known and commit_family[item.fix_commit_id] == item.patch_family_id:
      uncertain_pairs.add((item.patch_family_id, item.fix_commit_id))

  anchored_pairs = {(item.patch_family_id, item.fix_commit_id) for item in resolved}
  fix_commit_coverage: dict[str, dict[str, Any]] = {}
  for family_id, fix_commit_ids in family_commits.items():
    for fix_commit_id in sorted(fix_commit_ids):
      anchored = (family_id, fix_commit_id) in anchored_pairs
      uncertain = (family_id, fix_commit_id) in uncertain_pairs
      accounted = anchored or uncertain
      fix_commit_coverage[fix_commit_id] = {
        "patch_family_id": family_id,
        "anchored": anchored,
        "accounted": accounted,
        "uncertain": uncertain,
      }
      if not accounted:
        taxonomy["fix_commit_incomplete"] += 1
        errors.append(f"fix_commit_incomplete:{family_id}:{fix_commit_id}")

  patch_family_coverage: dict[str, dict[str, bool]] = {}
  for family_id, fix_commit_ids in family_commits.items():
    statuses = [fix_commit_coverage[fix_commit_id] for fix_commit_id in fix_commit_ids]
    anchored = bool(statuses) and all(status["anchored"] for status in statuses)
    accounted = bool(statuses) and all(status["accounted"] for status in statuses)
    uncertain = any(status["uncertain"] for status in statuses)
    patch_family_coverage[family_id] = {
      "anchored": anchored,
      "accounted": accounted,
      "uncertain": uncertain,
    }
    if not accounted:
      taxonomy["fix_family_incomplete"] += 1
      errors.append(f"fix_family_incomplete:{family_id}")

  if not resolved:
    taxonomy["no_blameable_anchor_selected"] += 1
    errors.append("no_blameable_anchor_selected")

  return SzzHandoffValidationResult(
    accepted_anchor_ids=accepted,
    rejected_anchor_ids=rejected,
    resolved_anchors=resolved,
    errors=errors,
    taxonomy={key: taxonomy.get(key, 0) for key in TAXONOMY_KEYS if taxonomy.get(key, 0)},
    invented_ids=sorted(invented_ids),
    patch_family_coverage=patch_family_coverage,
    fix_commit_coverage=fix_commit_coverage,
    ok=not errors,
  )


def lint_szz_handoff(
  selection: dict[str, Any] | RootCauseSzzHandoffV1,
  inventory: PreFixCandidateInventoryV1,
  root_cause_output: dict[str, Any],
) -> SzzHandoffValidationResult:
  return validate_szz_handoff(selection, inventory, root_cause_output)


def resolve_szz_handoff(
  selection: dict[str, Any] | RootCauseSzzHandoffV1,
  inventory: PreFixCandidateInventoryV1,
  root_cause_output: dict[str, Any],
) -> SzzHandoffValidationResult:
  return validate_szz_handoff(selection, inventory, root_cause_output)


def _semantic_refs(items: list[dict[str, Any]], id_field: str) -> dict[str, set[str]]:
  return {
    str(item.get(id_field) or item.get("id") or ""): set(item.get("git_observation_refs") or [])
    for item in items
    if item.get(id_field) or item.get("id")
  }


def _has_strong_root_cause_binding(
  hypothesis_ids: list[str],
  predicate_ids: list[str],
  candidate_refs: list[str],
  hypothesis_refs: dict[str, set[str]],
  predicate_refs: dict[str, set[str]],
) -> bool:
  candidate_set = set(candidate_refs)
  if not candidate_set or not hypothesis_ids or not predicate_ids:
    return False
  for hypothesis_id in hypothesis_ids:
    refs = hypothesis_refs.get(hypothesis_id)
    if not refs or not (refs & candidate_set):
      return False
  for predicate_id in predicate_ids:
    refs = predicate_refs.get(predicate_id)
    if not refs or not (refs & candidate_set):
      return False
  return True


def _selection_mode(candidate_source: str, change_type: str) -> str:
  if candidate_source == "pre_fix_function_body":
    return "add_only_semantic_target"
  if candidate_source == "hunk_context":
    return "context_fallback"
  if change_type == "modify":
    return "modified_old_side"
  return "direct_deleted_line"


def _reject(errors: list[str], taxonomy: Counter[str], key: str, candidate_id: str) -> None:
  taxonomy[key] += 1
  errors.append(f"{key}:{candidate_id}")
