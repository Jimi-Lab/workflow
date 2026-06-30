from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from vulngraph.agent_io.judge_boundary_v1_2_contract import (
  derive_boundary_views_v1_2,
  lint_judge_boundary_output_v1_2,
)
from vulngraph.workflows.affected_version_converter_v1_2 import (
  convert_affected_versions_for_cve_v1_2,
)
from vulngraph.workflows.branch_context_v1_2 import build_branch_scoped_groups
from vulngraph.workflows.history_event_candidates import (
  materialize_history_event_candidates,
)


def _sha(char: str) -> str:
  return char * 40


def _write_json(path: Path, value: object) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def _candidate(candidate_id: str = "line-1", source: str = "strong") -> dict:
  return {
    "candidate_id": candidate_id,
    "candidate_commit_sha": _sha("a"),
    "candidate_source": source,
    "candidate_selection_mode": "modified_old_side",
    "path_before": "src/parser.c",
    "old_line_start": 12,
    "old_line_end": 12,
    "old_line_text": "dangerous_copy(dst, src);",
    "line_text_hash": "hash-1",
    "fix_commit_id": f"fix-commit:repo:{_sha('f')}",
    "patch_family_id": "family-1",
    "root_cause_binding_refs": ["rc-1"],
    "vulnerable_predicate_refs": ["vp-1"],
    "fix_predicate_refs": ["fp-1"],
    "evidence_refs": ["candidate:line-1", "szz:line-1"],
    "risk_flags": [],
  }


def _evidence() -> dict:
  return {
    "candidate_identity": {
      "candidate_id": "line-1",
      "fix_commit_sha": _sha("f"),
      "fix_commit_id": f"fix-commit:repo:{_sha('f')}",
      "patch_family_id": "family-1",
      "path_before": "src/parser.c",
      "old_line_start": 12,
      "old_line_end": 12,
      "old_line_text_hash": "hash-1",
    },
    "blame_variants": {
      "variants": [
        {"variant": "normal", "exit_code": 0, "blamed_commit_sha": _sha("a")},
        {"variant": "w", "exit_code": 0, "blamed_commit_sha": _sha("b")},
        {"variant": "M", "exit_code": 0, "blamed_commit_sha": _sha("b")},
        {"variant": "C", "exit_code": 0, "blamed_commit_sha": _sha("c")},
      ]
    },
    "line_survival_evidence": {"line_survival_status": "survives_to_fix_parent"},
    "risk_flags": ["whitespace_sensitive_blame"],
    "confidence_features": ["root_cause_predicate_bound"],
  }


def test_materializes_each_distinct_blame_sha_as_history_event_candidate() -> None:
  events = materialize_history_event_candidates([_candidate()], [_evidence()])

  assert {item["event_commit_sha"] for item in events} == {_sha("a"), _sha("b"), _sha("c")}
  assert next(item for item in events if item["event_commit_sha"] == _sha("b"))["derivation_modes"] == ["M", "w"]
  assert all(item["event_candidate_id"].startswith("history-event:") for item in events)
  assert all(item["source_anchor_id"] == "line-1" for item in events)
  assert all(item["lifecycle"] == "raw_candidate" for item in events)


def test_add_only_protected_old_code_statement_remains_blameable() -> None:
  candidate = _candidate(source="fallback")
  candidate["candidate_selection_mode"] = "add_only_semantic_target"
  candidate["risk_flags"] = ["add_only_semantic_anchor"]

  events = materialize_history_event_candidates([candidate], [_evidence()])

  assert events
  assert all("add_only_semantic_anchor" in item["risk_flags"] for item in events)


def test_history_events_exclude_converter_release_breadth_risk_flags() -> None:
  candidate = _candidate()
  candidate["risk_flags"] = ["release_reachability_too_broad", "release_line_overreach", "non_release_tag_noise"]

  events = materialize_history_event_candidates([candidate], [_evidence()])

  assert all(not set(item["risk_flags"]) & {"release_reachability_too_broad", "release_line_overreach", "non_release_tag_noise"} for item in events)


@pytest.mark.parametrize(
  "line",
  [
    "", "{", "}", "} else {", "// context only", "int value;",
    "static const int count = 2;",
    "int parse_layer(Context *ctx, int size);",
    "int parse_layer(Context *ctx, int size)",
  ],
)
def test_fallback_noise_is_not_materialized(line: str) -> None:
  candidate = _candidate(source="fallback")
  candidate["old_line_text"] = line

  assert materialize_history_event_candidates([candidate], [_evidence()]) == []


class GraphFixture:
  def __init__(self) -> None:
    self.refs = {
      _sha("a"): ["origin/maintenance"],
      _sha("f"): ["origin/maintenance"],
      _sha("b"): ["origin/trunk"],
      _sha("e"): ["origin/trunk"],
    }
    self.ancestors = {
      (_sha("a"), _sha("f")): True,
      (_sha("b"), _sha("e")): True,
    }
    self.patch_ids = {_sha("f"): "patch-maint", _sha("e"): "patch-trunk"}

  def containing_branch_refs(self, sha: str) -> list[str]:
    return self.refs.get(sha, [])

  def is_ancestor(self, older: str, newer: str) -> bool:
    return self.ancestors.get((older, newer), False)

  def merge_base(self, left: str, right: str) -> str:
    return _sha("0")

  def patch_id(self, sha: str) -> str:
    return self.patch_ids.get(sha, "")

  def commit_metadata(self, sha: str) -> dict:
    return {"subject": "maintenance backport" if sha == _sha("f") else "trunk fix", "parents": [_sha("0")]}


def _event(event_id: str, event_sha: str, fix_sha: str, family: str) -> dict:
  return {
    "event_candidate_id": event_id,
    "source_anchor_id": "line-1",
    "event_commit_sha": event_sha,
    "derivation_modes": ["normal"],
    "path_before": "src/parser.c",
    "old_line_start": 12,
    "old_line_end": 12,
    "old_line_text": "dangerous_copy(dst, src);",
    "old_line_text_hash": "hash-1",
    "fix_commit_id": f"fix-commit:repo:{fix_sha}",
    "fix_commit_sha": fix_sha,
    "patch_family_id": family,
    "root_cause_binding_refs": ["rc-1"],
    "vulnerable_predicate_refs": ["vp-1"],
    "fix_predicate_refs": ["fp-1"],
    "evidence_refs": [f"event:{event_id}"],
    "candidate_source": "strong",
    "risk_flags": [],
    "lifecycle": "raw_candidate",
  }


def test_branch_groups_do_not_global_and_divergent_fixes() -> None:
  graph = GraphFixture()
  events = [
    _event("event-maint", _sha("a"), _sha("f"), "family-maint"),
    _event("event-trunk", _sha("b"), _sha("e"), "family-trunk"),
  ]

  grouped = build_branch_scoped_groups("CVE-BRANCH", "repo", events, graph)

  assert len(grouped["branch_contexts"]) == 2
  assert all(len(item["fix_commit_shas"]) == 1 for item in grouped["fix_groups"])
  assert {item["relation_semantics"] for item in grouped["fix_groups"]} == {"branch_local_single"}
  assert all(len(item["branch_context_ids"]) == 1 for item in grouped["history_event_candidates"])


def test_same_patch_id_members_are_equivalent_or_not_conjunctive() -> None:
  graph = GraphFixture()
  graph.refs[_sha("e")] = ["origin/maintenance"]
  graph.refs[_sha("b")] = ["origin/maintenance"]
  graph.patch_ids[_sha("e")] = "patch-maint"
  events = [
    _event("event-a", _sha("a"), _sha("f"), "family-a"),
    _event("event-b", _sha("b"), _sha("e"), "family-b"),
  ]

  grouped = build_branch_scoped_groups("CVE-EQUIV", "repo", events, graph)

  assert len(grouped["branch_contexts"]) == 1
  assert grouped["fix_groups"][0]["completion_semantics"] == "any_equivalent_fix"
  assert set(grouped["fix_groups"][0]["fix_commit_shas"]) == {_sha("f"), _sha("e")}


def test_cross_branch_same_patch_id_is_audited_as_branch_equivalent() -> None:
  graph = GraphFixture()
  graph.patch_ids[_sha("e")] = "patch-maint"
  grouped = build_branch_scoped_groups(
    "CVE-BACKPORT", "repo",
    [_event("event-a", _sha("a"), _sha("f"), "family-a"), _event("event-b", _sha("b"), _sha("e"), "family-b")],
    graph,
  )

  assert len(grouped["branch_contexts"]) == 2
  assert grouped["fix_equivalence_groups"][0]["member_semantics"] == "any_equivalent_fix_within_matching_branch_context"
  assert len(grouped["fix_equivalence_groups"][0]["branch_context_ids"]) == 2


def test_explicit_linear_two_commit_series_is_conjunctive() -> None:
  graph = GraphFixture()
  graph.refs[_sha("e")] = ["origin/maintenance"]
  graph.refs[_sha("b")] = ["origin/maintenance"]
  graph.ancestors[(_sha("f"), _sha("e"))] = True
  graph.patch_ids[_sha("e")] = "patch-second"
  graph.commit_metadata = lambda sha: {
    "subject": "security fix part 1/2" if sha == _sha("f") else "security fix part 2/2",
    "parents": [_sha("0")],
  }
  grouped = build_branch_scoped_groups(
    "CVE-SERIES", "repo",
    [_event("event-a", _sha("a"), _sha("f"), "family-a"), _event("event-b", _sha("b"), _sha("e"), "family-b")],
    graph,
  )

  assert len(grouped["fix_groups"]) == 1
  assert grouped["fix_groups"][0]["completion_semantics"] == "all_conjunctive_fixes"
  assert grouped["fix_groups"][0]["relation_semantics"] == "conjunctive_fix_series"


def test_different_patch_ids_without_series_evidence_remain_unknown() -> None:
  graph = GraphFixture()
  graph.refs[_sha("e")] = ["origin/maintenance"]
  graph.refs[_sha("b")] = ["origin/maintenance"]
  graph.ancestors[(_sha("f"), _sha("e"))] = True
  graph.patch_ids[_sha("e")] = "patch-second"
  grouped = build_branch_scoped_groups(
    "CVE-UNKNOWN", "repo",
    [_event("event-a", _sha("a"), _sha("f"), "family-a"), _event("event-b", _sha("b"), _sha("e"), "family-b")],
    graph,
  )

  assert grouped["fix_groups"][0]["completion_semantics"] == "unknown"
  assert grouped["fix_groups"][0]["relation_semantics"] == "unknown_fix_relation"


def test_merge_fix_is_preserved_as_wrapper_fact() -> None:
  graph = GraphFixture()
  graph.commit_metadata = lambda sha: {"subject": "merge security fix", "parents": [_sha("1"), _sha("2")]}

  grouped = build_branch_scoped_groups("CVE-MERGE", "repo", [_event("event-a", _sha("a"), _sha("f"), "family-a")], graph)

  assert grouped["fix_groups"][0]["fix_commit_facts"][0]["is_merge"] is True
  assert grouped["fix_groups"][0]["fix_commit_facts"][0]["parent_count"] == 2


def _boundary_input() -> dict:
  events = [_event("event-a", _sha("a"), _sha("f"), "family-a")]
  events[0]["branch_context_ids"] = ["branch-1"]
  return {
    "schema_version": "judge_boundary_input_v1_2",
    "cve_id": "CVE-BRANCH",
    "history_event_candidates": events,
    "branch_contexts": [{"branch_context_id": "branch-1", "event_candidate_ids": ["event-a"]}],
    "boundary_groups": [{"boundary_group_id": "group-1", "branch_context_id": "branch-1", "event_candidate_ids": ["event-a"]}],
    "fix_groups": [{"fix_group_id": "fix-1", "branch_context_id": "branch-1", "completion_semantics": "branch_local_single", "fix_commit_shas": [_sha("f")]}],
  }


def _boundary_output() -> dict:
  return {
    "schema_version": "judge_boundary_output_v1_2",
    "cve_id": "CVE-BRANCH",
    "candidate_judgments": [
      {
        "event_candidate_id": "event-a",
        "event_commit_sha": _sha("a"),
        "boundary_role": "primary_boundary",
        "decision": "selected",
        "confidence": "medium",
        "evidence_refs": ["event:event-a"],
        "reasoning_short": "direct old-side predicate evidence supports the branch-local boundary",
      }
    ],
  }


def test_v1_2_contract_accounts_every_event_exactly_once() -> None:
  boundary_input = _boundary_input()
  output = _boundary_output()
  output["candidate_judgments"].append(dict(output["candidate_judgments"][0]))

  result = lint_judge_boundary_output_v1_2(output, boundary_input)

  assert result.ok is False
  assert result.taxonomy["candidate_accounted_multiple_times"] == 1


def test_supporting_evidence_is_not_a_converter_prerequisite() -> None:
  boundary_input = _boundary_input()
  supporting = _event("event-support", _sha("b"), _sha("f"), "family-a")
  supporting["branch_context_ids"] = ["branch-1"]
  boundary_input["history_event_candidates"].append(supporting)
  boundary_input["branch_contexts"][0]["event_candidate_ids"].append("event-support")
  boundary_input["boundary_groups"][0]["event_candidate_ids"].append("event-support")
  output = _boundary_output()
  output["candidate_judgments"].append(
    {
      "event_candidate_id": "event-support",
      "event_commit_sha": _sha("b"),
      "boundary_role": "supporting_evidence_only",
      "decision": "selected",
      "confidence": "low",
      "evidence_refs": ["event:event-support"],
      "reasoning_short": "corroborating context only",
    }
  )

  views = derive_boundary_views_v1_2(output, boundary_input)

  assert [item["event_candidate_id"] for item in views["activation_events"]] == ["event-a"]
  assert views["conjunctive_prerequisites"] == []


class ConverterRunner:
  def list_tags(self, repo_path: Path) -> list[str]:
    return ["v1.0", "v1.1"]

  def set_repo(self, repo_path: Path) -> None:
    return None

  def is_ancestor(self, older: str, newer: str) -> str:
    table = {
      (_sha("a"), "v1.0"): "yes",
      (_sha("a"), "v1.1"): "yes",
      (_sha("f"), "v1.0"): "no",
      (_sha("f"), "v1.1"): "yes",
    }
    return table.get((older, newer), "no")

  def line_state(self, commitish: str, path: str, line_text: str, line_hash: str) -> str:
    return "present" if commitish == "v1.0" else "absent"


class ReintroductionRunner(ConverterRunner):
  def list_tags(self, repo_path: Path) -> list[str]:
    return ["v1.0", "v1.1", "v1.2"]

  def is_ancestor(self, older: str, newer: str) -> str:
    if older == _sha("a"):
      return "yes"
    if older == _sha("f"):
      return "no"
    return "no"

  def line_state(self, commitish: str, path: str, line_text: str, line_hash: str) -> str:
    return "absent" if commitish == "v1.1" else "present"


def test_converter_v1_2_uses_branch_local_state_and_line_survival(tmp_path: Path) -> None:
  boundary_root = tmp_path / "boundary"
  dataset = tmp_path / "dataset.json"
  repo_root = tmp_path / "repos"
  cve = "CVE-BRANCH"
  _write_json(dataset, {cve: {"repo": "repo", "fixing_commits": [[_sha("f")]]}})
  _write_json(boundary_root / cve / "judge_boundary_input_v1_2.json", _boundary_input())
  _write_json(boundary_root / cve / "parsed_boundary_output_v1_2.json", _boundary_output())
  _write_json(boundary_root / cve / "judge_boundary_result_v1_2.json", {"contract_ok": True})

  prediction = convert_affected_versions_for_cve_v1_2(
    cve_id=cve,
    boundary_run=boundary_root,
    dataset=dataset,
    repo_root=repo_root,
    git_runner=ConverterRunner(),
  )

  assert prediction["affected_versions"] == ["v1.0"]
  assert prediction["prediction_status"] == "converted"
  assert prediction["lifecycle"] == "deterministic_converter_v1_2_prediction"


def test_converter_v1_2_preserves_uncertain_as_unresolved(tmp_path: Path) -> None:
  boundary_root = tmp_path / "boundary"
  dataset = tmp_path / "dataset.json"
  repo_root = tmp_path / "repos"
  cve = "CVE-BRANCH"
  output = _boundary_output()
  output["candidate_judgments"][0]["decision"] = "uncertain"
  _write_json(dataset, {cve: {"repo": "repo", "fixing_commits": [[_sha("f")]]}})
  _write_json(boundary_root / cve / "judge_boundary_input_v1_2.json", _boundary_input())
  _write_json(boundary_root / cve / "parsed_boundary_output_v1_2.json", output)
  _write_json(boundary_root / cve / "judge_boundary_result_v1_2.json", {"contract_ok": True})

  prediction = convert_affected_versions_for_cve_v1_2(
    cve_id=cve,
    boundary_run=boundary_root,
    dataset=dataset,
    repo_root=repo_root,
    git_runner=ConverterRunner(),
  )

  assert prediction["affected_versions"] == []
  assert prediction["prediction_status"] == "unresolved_boundary"
  assert prediction["unknown_version_count"] == 2


def test_converter_tracks_revert_and_reintroduction_by_code_state(tmp_path: Path) -> None:
  boundary_root = tmp_path / "boundary"
  dataset = tmp_path / "dataset.json"
  repo_root = tmp_path / "repos"
  cve = "CVE-BRANCH"
  _write_json(dataset, {cve: {"repo": "repo", "fixing_commits": [[_sha("f")]]}})
  _write_json(boundary_root / cve / "judge_boundary_input_v1_2.json", _boundary_input())
  _write_json(boundary_root / cve / "parsed_boundary_output_v1_2.json", _boundary_output())
  _write_json(boundary_root / cve / "judge_boundary_result_v1_2.json", {"contract_ok": True})

  prediction = convert_affected_versions_for_cve_v1_2(
    cve_id=cve, boundary_run=boundary_root, dataset=dataset,
    repo_root=repo_root, git_runner=ReintroductionRunner(),
  )

  assert prediction["affected_versions"] == ["v1.0", "v1.2"]


def _git(repo: Path, *args: str) -> str:
  return subprocess.run(
    ["git", "-C", str(repo), *args],
    check=True,
    text=True,
    encoding="utf-8",
    capture_output=True,
  ).stdout.strip()


def test_temporary_git_dag_trunk_and_maintenance_are_separate(tmp_path: Path) -> None:
  repo = tmp_path / "repo"
  repo.mkdir()
  _git(repo, "init", "-b", "trunk")
  _git(repo, "config", "user.email", "test@example.com")
  _git(repo, "config", "user.name", "VulnGraph Test")
  (repo / "code.c").write_text("int vulnerable = 1;\n", encoding="utf-8")
  _git(repo, "add", "code.c")
  _git(repo, "commit", "-m", "base")
  base = _git(repo, "rev-parse", "HEAD")
  _git(repo, "branch", "maintenance", base)
  (repo / "code.c").write_text("int vulnerable = 1;\nint trunk = 1;\n", encoding="utf-8")
  _git(repo, "commit", "-am", "trunk event")
  trunk_event = _git(repo, "rev-parse", "HEAD")
  (repo / "code.c").write_text("int vulnerable = 0;\nint trunk = 1;\n", encoding="utf-8")
  _git(repo, "commit", "-am", "trunk fix")
  trunk_fix = _git(repo, "rev-parse", "HEAD")
  _git(repo, "checkout", "maintenance")
  (repo / "code.c").write_text("int vulnerable = 1;\nint maintenance = 1;\n", encoding="utf-8")
  _git(repo, "commit", "-am", "maintenance event")
  maintenance_event = _git(repo, "rev-parse", "HEAD")
  (repo / "code.c").write_text("int vulnerable = 0;\nint maintenance = 1;\n", encoding="utf-8")
  _git(repo, "commit", "-am", "maintenance backport fix")
  maintenance_fix = _git(repo, "rev-parse", "HEAD")

  from vulngraph.workflows.branch_context_v1_2 import SubprocessGitGraph

  grouped = build_branch_scoped_groups(
    "CVE-DAG",
    "repo",
    [
      _event("trunk-event", trunk_event, trunk_fix, "trunk-family"),
      _event("maintenance-event", maintenance_event, maintenance_fix, "maintenance-family"),
    ],
    SubprocessGitGraph(repo),
  )

  assert len(grouped["branch_contexts"]) == 2
  assert all(group["completion_semantics"] == "any_equivalent_fix" for group in grouped["fix_groups"])
  assert all(group["relation_semantics"] == "branch_local_single" for group in grouped["fix_groups"])


def test_temporary_git_dag_cherry_pick_equivalence_and_merge_fact(tmp_path: Path) -> None:
  repo = tmp_path / "repo"
  repo.mkdir()
  _git(repo, "init", "-b", "trunk")
  _git(repo, "config", "user.email", "test@example.com")
  _git(repo, "config", "user.name", "VulnGraph Test")
  (repo / "code.c").write_text("int vulnerable = 1;\n", encoding="utf-8")
  _git(repo, "add", "code.c")
  _git(repo, "commit", "-m", "base")
  base = _git(repo, "rev-parse", "HEAD")
  _git(repo, "branch", "maintenance", base)
  (repo / "code.c").write_text("int vulnerable = 0;\n", encoding="utf-8")
  _git(repo, "commit", "-am", "security fix")
  trunk_fix = _git(repo, "rev-parse", "HEAD")
  _git(repo, "checkout", "maintenance")
  (repo / "maintenance.txt").write_text("branch divergence\n", encoding="utf-8")
  _git(repo, "add", "maintenance.txt")
  _git(repo, "commit", "-m", "maintenance branch setup")
  _git(repo, "cherry-pick", trunk_fix)
  maintenance_fix = _git(repo, "rev-parse", "HEAD")
  _git(repo, "checkout", "trunk")
  _git(repo, "checkout", "-b", "merge-fix")
  (repo / "extra.c").write_text("int fixed = 1;\n", encoding="utf-8")
  _git(repo, "add", "extra.c")
  _git(repo, "commit", "-m", "feature fix")
  _git(repo, "checkout", "trunk")
  _git(repo, "merge", "--no-ff", "merge-fix", "-m", "merge fix")
  merge_fix = _git(repo, "rev-parse", "HEAD")

  from vulngraph.workflows.branch_context_v1_2 import SubprocessGitGraph

  graph = SubprocessGitGraph(repo)
  grouped = build_branch_scoped_groups(
    "CVE-CHERRY", "repo",
    [_event("trunk", base, trunk_fix, "family-trunk"), _event("maintenance", base, maintenance_fix, "family-maint")],
    graph,
  )

  assert len(grouped["branch_contexts"]) == 2
  assert len(grouped["fix_equivalence_groups"]) == 1
  assert graph.patch_id(trunk_fix) == graph.patch_id(maintenance_fix)
  assert len(graph.commit_metadata(merge_fix)["parents"]) == 2


def test_temporary_git_dag_whitespace_blame_materializes_alternatives(tmp_path: Path) -> None:
  repo = tmp_path / "repo"
  repo.mkdir()
  _git(repo, "init", "-b", "trunk")
  _git(repo, "config", "user.email", "test@example.com")
  _git(repo, "config", "user.name", "VulnGraph Test")
  (repo / "code.c").write_text("int value = 1;\n", encoding="utf-8")
  _git(repo, "add", "code.c")
  _git(repo, "commit", "-m", "introduce line")
  original = _git(repo, "rev-parse", "HEAD")
  (repo / "code.c").write_text("int  value = 1;\n", encoding="utf-8")
  _git(repo, "commit", "-am", "whitespace only")
  whitespace = _git(repo, "rev-parse", "HEAD")
  normal = _git(repo, "blame", "--line-porcelain", "-L", "1,1", "HEAD", "--", "code.c").splitlines()[0].split()[0].lstrip("^")
  ignored = _git(repo, "blame", "-w", "--line-porcelain", "-L", "1,1", "HEAD", "--", "code.c").splitlines()[0].split()[0].lstrip("^")
  evidence = _evidence()
  evidence["blame_variants"]["variants"] = [
    {"variant": "normal", "exit_code": 0, "blamed_commit_sha": normal},
    {"variant": "w", "exit_code": 0, "blamed_commit_sha": ignored},
  ]
  candidate = _candidate()
  candidate["candidate_commit_sha"] = whitespace

  events = materialize_history_event_candidates([candidate], [evidence])

  assert {item["event_commit_sha"] for item in events} == {original, whitespace}


def test_temporary_git_dag_converter_tracks_real_revert_reintroduction(tmp_path: Path) -> None:
  repo = tmp_path / "repos" / "repo"
  repo.mkdir(parents=True)
  _git(repo, "init", "-b", "trunk")
  _git(repo, "config", "user.email", "test@example.com")
  _git(repo, "config", "user.name", "VulnGraph Test")
  line = "int vulnerable = 1;"
  (repo / "code.c").write_text(line + "\n", encoding="utf-8")
  _git(repo, "add", "code.c")
  _git(repo, "commit", "-m", "introduce vulnerable state")
  event_sha = _git(repo, "rev-parse", "HEAD")
  _git(repo, "tag", "v1.0")
  (repo / "code.c").write_text("int safe = 1;\n", encoding="utf-8")
  _git(repo, "commit", "-am", "remove vulnerable state")
  removal = _git(repo, "rev-parse", "HEAD")
  _git(repo, "tag", "v1.1")
  _git(repo, "revert", "--no-edit", removal)
  _git(repo, "tag", "v1.2")
  (repo / "fix.c").write_text("int final_fix = 1;\n", encoding="utf-8")
  _git(repo, "add", "fix.c")
  _git(repo, "commit", "-m", "future fix")
  fix_sha = _git(repo, "rev-parse", "HEAD")
  boundary_root = tmp_path / "boundary"
  dataset = tmp_path / "dataset.json"
  cve = "CVE-REINTRO"
  boundary_input = _boundary_input()
  boundary_input["cve_id"] = cve
  boundary_input["history_event_candidates"][0].update({
    "event_commit_sha": event_sha, "path_before": "code.c", "old_line_text": line,
    "old_line_text_hash": "", "fix_commit_sha": fix_sha,
  })
  boundary_input["fix_groups"][0]["fix_commit_shas"] = [fix_sha]
  output = _boundary_output()
  output["cve_id"] = cve
  output["candidate_judgments"][0]["event_commit_sha"] = event_sha
  _write_json(dataset, {cve: {"repo": "repo", "fixing_commits": [[fix_sha]]}})
  _write_json(boundary_root / cve / "judge_boundary_input_v1_2.json", boundary_input)
  _write_json(boundary_root / cve / "parsed_boundary_output_v1_2.json", output)
  _write_json(boundary_root / cve / "judge_boundary_result_v1_2.json", {"contract_ok": True})

  prediction = convert_affected_versions_for_cve_v1_2(
    cve_id=cve, boundary_run=boundary_root, dataset=dataset,
    repo_root=tmp_path / "repos",
  )

  assert prediction["affected_versions"] == ["v1.0", "v1.2"]
