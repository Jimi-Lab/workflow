from __future__ import annotations

from vulngraph.workflows.affected_version_converter_v1_2_2 import (
  classify_version_state_v1_2_2,
  evaluate_fix_state_v1_2_2,
)


class FixRunner:
  def __init__(self, containing: dict[str, set[str]], semantic: str = "absent") -> None:
    self.containing = containing
    self.semantic = semantic

  def tags_containing(self, sha: str) -> set[str] | None:
    return self.containing.get(sha, set())

  def is_ancestor(self, sha: str, tag: str) -> str:
    return "unknown"

  def fix_predicate_state(self, group: dict, tag: str) -> str:
    return self.semantic


def test_fix_predicate_present_marks_fix_state_present() -> None:
  group = {"completion_semantics": "branch_local_single", "fix_commit_shas": ["fix-a"]}
  evidence = evaluate_fix_state_v1_2_2(FixRunner({"fix-a": set()}, semantic="present"), group, [], "v1", {})

  assert evidence["state"] == "fix_predicate_present"
  assert evidence["fix_presence"] == "present"


def test_equivalent_fix_reachable_marks_patch_id_equivalent() -> None:
  group = {"completion_semantics": "any_equivalent_fix", "fix_commit_shas": ["fix-a"]}
  equivalence = [{"fix_commit_shas": ["fix-a", "fix-b"], "equivalence_evidence": "identical_stable_patch_id"}]
  evidence = evaluate_fix_state_v1_2_2(FixRunner({"fix-b": {"v1"}}), group, equivalence, "v1", {})

  assert evidence["state"] == "patch_id_equivalent"
  assert evidence["fix_presence"] == "present"


def test_unknown_versions_are_not_confirmed_affected() -> None:
  outcome = classify_version_state_v1_2_2("unknown", "complete", {"fix_presence": "absent"})

  assert outcome["bucket"] == "unknown"
  assert outcome["confirmed_affected"] is False
  assert outcome["metric_predicted_affected"] is True
  assert outcome["metric_policy"] == "optimistic_unknown_activation_fix_absent"


def test_fix_present_always_confirms_unaffected() -> None:
  outcome = classify_version_state_v1_2_2("active", "complete", {"fix_presence": "present"})

  assert outcome["bucket"] == "confirmed_unaffected"
  assert outcome["confirmed_unaffected"] is True
  assert outcome["metric_predicted_affected"] is False
