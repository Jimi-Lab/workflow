from __future__ import annotations

from vulngraph.workflows.branch_context_v1_2_1 import build_complete_branch_scoped_groups


def _sha(char: str) -> str:
  return char * 40


def _event(event_id: str, event_sha: str, fix_sha: str) -> dict:
  return {
    "event_candidate_id": event_id,
    "event_commit_sha": event_sha,
    "fix_commit_sha": fix_sha,
    "patch_family_id": "family-1",
    "root_cause_binding_refs": ["rc-1"],
    "vulnerable_predicate_refs": ["vp-1"],
  }


class FixGraph:
  def __init__(self) -> None:
    self.refs = {_sha("f"): ["origin/trunk"], _sha("e"): ["origin/maintenance"]}
    self.parents = {_sha("f"): [_sha("0")], _sha("e"): [_sha("0")]}
    self.patch_ids = {_sha("f"): "patch-trunk", _sha("e"): "patch-maint"}

  def containing_branch_refs(self, sha: str) -> list[str]:
    return self.refs.get(sha, [])

  def is_ancestor(self, older: str, newer: str) -> bool:
    return older in self.parents.get(newer, [])

  def merge_base(self, left: str, right: str) -> str:
    return _sha("0")

  def patch_id(self, sha: str) -> str:
    return self.patch_ids.get(sha, "")

  def commit_metadata(self, sha: str) -> dict:
    return {"parents": self.parents.get(sha, []), "subject": "fix", "body": ""}


def test_declared_fix_universe_is_independent_from_history_events() -> None:
  graph = FixGraph()
  grouped = build_complete_branch_scoped_groups(
    "CVE-FIX-UNIVERSE", "repo", [_event("event-1", _sha("a"), _sha("f"))],
    [_sha("f"), _sha("e")], graph,
  )

  assert grouped["fix_universe_audit"]["declared_fix_count"] == 2
  assert grouped["fix_universe_audit"]["represented_declared_fix_count"] == 2
  assert grouped["fix_universe_audit"]["missing_declared_fix_shas"] == []
  represented = {sha for group in grouped["fix_groups"] for sha in group["fix_commit_shas"]}
  assert represented == {_sha("f"), _sha("e")}


def test_declared_merge_fix_is_preserved_with_content_commit_alias() -> None:
  graph = FixGraph()
  merge_sha, content_sha = _sha("d"), _sha("f")
  graph.refs[merge_sha] = ["origin/trunk"]
  graph.parents[merge_sha] = [_sha("0"), content_sha]
  graph.patch_ids[merge_sha] = ""

  grouped = build_complete_branch_scoped_groups(
    "CVE-MERGE-ALIAS", "repo", [_event("event-1", _sha("a"), content_sha)],
    [merge_sha], graph,
  )

  assert merge_sha in grouped["fix_universe_audit"]["represented_declared_fix_shas"]
  assert any(
    alias["declared_fix_sha"] == merge_sha
    and alias["equivalent_fix_sha"] == content_sha
    and alias["alias_evidence"] == "declared_merge_parent"
    for alias in grouped["fix_aliases"]
  )


def test_fix_universe_preserves_fifteen_declared_commits() -> None:
  graph = FixGraph()
  declared = [f"{index:040x}" for index in range(1, 16)]
  for sha in declared:
    graph.refs[sha] = [f"origin/release-{sha[-1]}"]
    graph.parents[sha] = [_sha("0")]
    graph.patch_ids[sha] = f"patch-{sha}"

  grouped = build_complete_branch_scoped_groups(
    "CVE-2020-13904", "repo", [_event("event-1", _sha("a"), declared[0])],
    declared, graph,
  )

  assert grouped["fix_universe_audit"]["declared_fix_count"] == 15
  assert grouped["fix_universe_audit"]["represented_declared_fix_count"] == 15
