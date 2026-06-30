from __future__ import annotations

import hashlib
import json
from pathlib import Path

from vulngraph.workflows.affected_version_converter_v1_2_1 import (
  convert_affected_versions_for_cve_v1_2_1,
  _reachability,
  ranked_raw_top1_metrics,
)


def _sha(char: str) -> str:
  return char * 40


def _write(path: Path, value: object) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(value), encoding="utf-8")


def _input(cve: str, fixes: list[str]) -> dict:
  line = "if (len > capacity) return ERROR;"
  return {
    "schema_version": "judge_boundary_input_v1_2",
    "cve_id": cve,
    "history_event_candidates": [{
      "event_candidate_id": "event-1", "source_anchor_id": "anchor-1",
      "event_commit_sha": _sha("a"), "fix_commit_sha": fixes[0],
      "patch_family_id": "family-1", "path_before": "src/parser.c",
      "old_line_start": 3, "old_line_end": 3, "old_line_text": line,
      "old_line_text_hash": hashlib.sha256(line.encode()).hexdigest(),
      "root_cause_binding_refs": ["rc-1"], "vulnerable_predicate_refs": ["vp-1"],
      "fix_predicate_refs": ["fp-1"], "evidence_refs": ["history_event:event-1"],
      "candidate_source": "strong", "lifecycle": "raw_candidate",
    }],
    "branch_contexts": [], "boundary_groups": [], "fix_groups": [],
  }


def _output(cve: str, decision: str = "selected") -> dict:
  return {
    "schema_version": "judge_boundary_output_v1_2", "cve_id": cve,
    "candidate_judgments": [{
      "event_candidate_id": "event-1", "event_commit_sha": _sha("a"),
      "boundary_role": "primary_boundary", "decision": decision,
      "confidence": "medium", "evidence_refs": ["history_event:event-1"],
      "reasoning_short": "wrapper evidence supports this branch-local predicate boundary",
    }],
  }


class ReconstructionRunner:
  def __init__(self, fixes: list[str], *, same_patch: bool = True, missing: set[str] | None = None) -> None:
    self.fixes = fixes
    self.same_patch = same_patch
    self.missing = missing or set()
    self.current_repo: Path | None = None

  def set_repo(self, repo: Path) -> None:
    self.current_repo = repo

  def list_tags(self, repo: Path) -> list[str]:
    return ["v1.0", "v1.1"]

  def is_ancestor(self, older: str, newer: str) -> str | bool:
    if older == self.fixes[-1] and newer == "v1.1":
      return "yes"
    return "no"

  def containing_branch_refs(self, sha: str) -> list[str]:
    return ["origin/trunk"] if sha == self.fixes[0] else ["origin/maintenance"]

  def merge_base(self, left: str, right: str) -> str:
    return _sha("0")

  def patch_id(self, sha: str) -> str:
    return "patch-equivalent" if self.same_patch else f"patch-{sha}"

  def commit_metadata(self, sha: str) -> dict:
    if sha in self.missing:
      return {"parents": [], "subject": "", "body": ""}
    return {"parents": [_sha("0")], "subject": "security fix", "body": ""}

  def read_file(self, commitish: str, path: str) -> str | None:
    if commitish == "v1.0":
      return "void parse(void) {\n  if ((len) > capacity) { return ERROR; }\n}\n"
    return "void parse(void) {\n  return SAFE;\n}\n"

  def related_paths(self, commitish: str, path: str) -> list[str]:
    return []

  def fix_predicate_state(self, fix_group: dict, tag: str) -> str:
    return "absent"


def _case(tmp_path: Path, cve: str, fixes: list[str], decision: str = "selected") -> tuple[Path, Path, Path]:
  boundary = tmp_path / "boundary"
  dataset = tmp_path / "dataset.json"
  repo_root = tmp_path / "repos"
  _write(dataset, {cve: {"repo": "repo", "fixing_commits": [fixes], "affected_version": []}})
  _write(boundary / cve / "judge_boundary_input_v1_2.json", _input(cve, fixes))
  _write(boundary / cve / "parsed_boundary_output_v1_2.json", _output(cve, decision))
  _write(boundary / cve / "judge_boundary_result_v1_2.json", {"contract_ok": True})
  return boundary, dataset, repo_root


def test_converter_uses_semantic_state_without_candidate_ancestry_and_equivalent_fix_or(tmp_path: Path) -> None:
  cve, fixes = "CVE-CROSS-BRANCH", [_sha("f"), _sha("e")]
  boundary, dataset, repo_root = _case(tmp_path, cve, fixes)

  prediction = convert_affected_versions_for_cve_v1_2_1(
    cve_id=cve, boundary_run=boundary, dataset=dataset, repo_root=repo_root,
    git_runner=ReconstructionRunner(fixes), graph=ReconstructionRunner(fixes),
  )

  assert prediction["affected_versions"] == ["v1.0"]
  assert prediction["prediction_status"] == "converted"
  assert prediction["fix_universe_audit"]["coverage"] == 1.0
  assert prediction["semantic_state_counts"]["present_predicate_equivalent"] >= 1


def test_converter_blocks_before_replay_when_declared_fix_is_missing(tmp_path: Path) -> None:
  cve, fixes = "CVE-MISSING-FIX", [_sha("f"), _sha("e")]
  boundary, dataset, repo_root = _case(tmp_path, cve, fixes)
  runner = ReconstructionRunner(fixes, missing={fixes[-1]})

  prediction = convert_affected_versions_for_cve_v1_2_1(
    cve_id=cve, boundary_run=boundary, dataset=dataset, repo_root=repo_root,
    git_runner=runner, graph=runner,
  )

  assert prediction["prediction_status"] == "blocked"
  assert prediction["blocked_reason"] == "incomplete_declared_fix_universe"
  assert prediction["affected_versions"] == []


def test_converter_preserves_uncertain_primary_as_unresolved(tmp_path: Path) -> None:
  cve, fixes = "CVE-UNCERTAIN", [_sha("f")]
  boundary, dataset, repo_root = _case(tmp_path, cve, fixes, decision="uncertain")
  runner = ReconstructionRunner(fixes)

  prediction = convert_affected_versions_for_cve_v1_2_1(
    cve_id=cve, boundary_run=boundary, dataset=dataset, repo_root=repo_root,
    git_runner=runner, graph=runner,
  )

  assert prediction["prediction_status"] == "unresolved_boundary"
  assert prediction["affected_versions"] == []


def test_ranked_raw_top1_metrics_uses_ranking_diagnostics_not_array_order() -> None:
  dataset = {"CVE-X": {"affected_version": ["v2"]}}
  diagnostics = {"CVE-X": {"release_tag_universe": {"top1": {"predicted_tags": ["v2"]}}}}
  per_candidate = {"CVE-X": {"release_tag_universe": [{"predicted_tags": ["v1"]}, {"predicted_tags": ["v2"]}]}}

  metrics = ranked_raw_top1_metrics(dataset, diagnostics, per_candidate)

  assert metrics["exact_match_count"] == 1
  assert metrics["micro_f1"] == 1.0
  assert metrics["ordering_mismatch_count"] == 1


def test_reachability_prefers_tag_contains_over_per_tag_merge_base() -> None:
  class Runner:
    def __init__(self) -> None:
      self.is_ancestor_calls = 0
      self.tags_containing_calls = 0

    def tags_containing(self, sha: str) -> set[str]:
      self.tags_containing_calls += 1
      assert sha == "fix-a"
      return {"v1", "v2"}

    def is_ancestor(self, sha: str, tag: str) -> str:
      self.is_ancestor_calls += 1
      return "unknown"

  runner = Runner()
  cache: dict[tuple[str, str], str] = {}

  assert _reachability(runner, "fix-a", "v1", cache) == "yes"
  assert _reachability(runner, "fix-a", "v3", cache) == "no"
  assert runner.is_ancestor_calls == 0
