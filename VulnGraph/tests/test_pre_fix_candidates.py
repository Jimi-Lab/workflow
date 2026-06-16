from __future__ import annotations

from pathlib import Path

from vulngraph.services.pre_fix_candidates import build_pre_fix_candidate_inventory


class FakeSourceReader:
  def __init__(self, *, metadata=None, files=None, functions=None, family_ids=None):
    self.metadata = metadata or {}
    self.files = files or {}
    self.functions = functions or {}
    self.family_ids = family_ids or {}

  def resolve_parent(self, fix_sha: str) -> str:
    return "a" * 40

  def inspect_hunk(self, fix_sha: str, patch_hunk: dict) -> dict:
    return self.metadata.get(patch_hunk["id"], {})

  def read_file(self, revision: str, path: str) -> str | None:
    return self.files.get((revision, path))

  def read_function_body(self, revision: str, path: str, function_name: str | None):
    return self.functions.get((revision, path, function_name), [])

  def patch_family_id(self, fix_sha: str) -> str:
    return self.family_ids.get(fix_sha, f"patch-family:{fix_sha[:8]}")


def _packet(*hunks: dict, fix_shas: tuple[str, ...] = ("b" * 40,)) -> dict:
  patch_evidence = []
  for index, sha in enumerate(fix_shas, start=1):
    patch_evidence.append(
      {
        "id": f"fix-commit:repo:{sha}",
        "type": "FixCommit",
        "content": {
          "cve_id": "CVE-TEST-1",
          "repo": "repo",
          "commit_sha": sha,
          "fix_set_id": "CVE-TEST-1:fix-set:1",
          "order": index,
        },
      }
    )
  patch_evidence.extend(hunks)
  return {
    "cve_id": "CVE-TEST-1",
    "patch_evidence": patch_evidence,
    "repo_navigation": [{"id": "repo:repo", "type": "Repo", "content": {"repo": "repo"}}],
  }


def _hunk(
  *,
  hunk_id: str = "patch-hunk:repo:" + "b" * 40 + ":src/a.c:1",
  sha: str = "b" * 40,
  path: str = "src/a.c",
  deleted=None,
  added=None,
  context=None,
  function_id: str | None = "changed-function:repo:sha:src/a.c:target",
  function_symbol: str | None = "target",
) -> dict:
  return {
    "id": hunk_id,
    "type": "PatchHunk",
    "content": {
      "cve_id": "CVE-TEST-1",
      "repo": "repo",
      "commit_sha": sha,
      "path": path,
      "hunk_index": 1,
      "old_start": 10,
      "new_start": 10,
      "deleted_lines": deleted or [],
      "added_lines": added or [],
      "context_lines": context or [],
      "function_id": function_id,
      "function_symbol": function_symbol,
    },
  }


def test_delete_only_emits_each_nonblank_deleted_old_line(tmp_path: Path):
  hunk = _hunk(deleted=[{"old_line": 11, "text": "danger();"}, {"old_line": 12, "text": ""}])
  reader = FakeSourceReader(
    metadata={hunk["id"]: {"path_before": "src/a.c", "path_after": "src/a.c", "change_type": "delete"}},
    files={("a" * 40, "src/a.c"): "\n" * 10 + "danger();\n"},
  )

  inventory = build_pre_fix_candidate_inventory(packet=_packet(hunk), repo_path=tmp_path, source_reader=reader)

  assert len(inventory.candidates) == 1
  assert inventory.candidates[0].candidate_source == "deleted_line"
  assert inventory.candidates[0].old_line_start == 11
  assert inventory.candidates[0].line_text == "danger();"


def test_modify_emits_old_side_not_added_replacement(tmp_path: Path):
  hunk = _hunk(
    deleted=[{"old_line": 11, "text": "unsafe(ptr);"}],
    added=[{"new_line": 11, "text": "safe(ptr);"}],
  )
  reader = FakeSourceReader(
    metadata={hunk["id"]: {"path_before": "src/a.c", "path_after": "src/a.c", "change_type": "modify"}},
    files={("a" * 40, "src/a.c"): "\n" * 10 + "unsafe(ptr);\n"},
  )

  inventory = build_pre_fix_candidate_inventory(packet=_packet(hunk), repo_path=tmp_path, source_reader=reader)

  assert [item.line_text for item in inventory.candidates] == ["unsafe(ptr);"]
  assert inventory.candidates[0].selection_mode_eligibility == ["modified_old_side"]


def test_add_only_emits_context_and_complete_pre_fix_function_body(tmp_path: Path):
  hunk = _hunk(
    added=[{"new_line": 12, "text": "if (idx >= count) return ERR;"}],
    context=[{"old_line": 11, "new_line": 11, "text": "value = items[idx];"}],
  )
  reader = FakeSourceReader(
    metadata={hunk["id"]: {"path_before": "src/a.c", "path_after": "src/a.c", "change_type": "add_only"}},
    files={("a" * 40, "src/a.c"): "\n" * 10 + "value = items[idx];\nreturn value;\n"},
    functions={("a" * 40, "src/a.c", "target"): [(10, "int target(void) {"), (11, "value = items[idx];"), (12, "return value;"), (13, "}")]},
  )

  inventory = build_pre_fix_candidate_inventory(packet=_packet(hunk), repo_path=tmp_path, source_reader=reader)

  assert any(item.candidate_source == "hunk_context" for item in inventory.candidates)
  assert any(item.candidate_source == "pre_fix_function_body" and item.old_line_start == 12 for item in inventory.candidates)
  assert all("add_only_semantic_target" in item.selection_mode_eligibility for item in inventory.candidates)


def test_new_file_add_only_has_no_parent_candidate(tmp_path: Path):
  hunk = _hunk(path="src/new.c", added=[{"new_line": 1, "text": "guard();"}], context=[])
  reader = FakeSourceReader(
    metadata={hunk["id"]: {"path_before": None, "path_after": "src/new.c", "change_type": "add_only", "new_file": True}},
  )

  inventory = build_pre_fix_candidate_inventory(packet=_packet(hunk), repo_path=tmp_path, source_reader=reader)

  assert inventory.candidates == []
  assert "new_file_without_parent_anchor" in inventory.issues


def test_rename_uses_path_before_and_preserves_path_after(tmp_path: Path):
  hunk = _hunk(path="src/new.c", deleted=[{"old_line": 3, "text": "danger();"}])
  reader = FakeSourceReader(
    metadata={hunk["id"]: {"path_before": "src/old.c", "path_after": "src/new.c", "change_type": "rename"}},
    files={("a" * 40, "src/old.c"): "\n\ndanger();\n"},
  )

  inventory = build_pre_fix_candidate_inventory(packet=_packet(hunk), repo_path=tmp_path, source_reader=reader)

  assert inventory.candidates[0].path_before == "src/old.c"
  assert inventory.candidates[0].path_after == "src/new.c"


def test_noise_lines_receive_exclusion_flags(tmp_path: Path):
  hunk = _hunk(path="tests/CHANGELOG.md", deleted=[{"old_line": 1, "text": "# fixed issue"}])
  reader = FakeSourceReader(
    metadata={hunk["id"]: {"path_before": "tests/CHANGELOG.md", "path_after": "tests/CHANGELOG.md", "change_type": "delete"}},
    files={("a" * 40, "tests/CHANGELOG.md"): "# fixed issue\n"},
  )

  inventory = build_pre_fix_candidate_inventory(packet=_packet(hunk), repo_path=tmp_path, source_reader=reader)

  candidate = inventory.candidates[0]
  assert candidate.test_file
  assert candidate.documentation_file
  assert candidate.changelog_file
  assert candidate.comment_only
  assert "non_source_file" in candidate.exclusion_reasons


def test_multi_fix_keeps_coordinates_but_shares_patch_family(tmp_path: Path):
  first_sha = "b" * 40
  second_sha = "c" * 40
  first = _hunk(sha=first_sha, deleted=[{"old_line": 11, "text": "danger();"}])
  second = _hunk(
    hunk_id=f"patch-hunk:repo:{second_sha}:src/a.c:1",
    sha=second_sha,
    deleted=[{"old_line": 21, "text": "danger();"}],
  )
  reader = FakeSourceReader(
    metadata={
      first["id"]: {"path_before": "src/a.c", "path_after": "src/a.c", "change_type": "delete"},
      second["id"]: {"path_before": "src/a.c", "path_after": "src/a.c", "change_type": "delete"},
    },
    files={
      ("a" * 40, "src/a.c"): "\n" * 10 + "danger();\n" + "\n" * 9 + "danger();\n",
    },
    family_ids={first_sha: "patch-family:shared", second_sha: "patch-family:shared"},
  )

  inventory = build_pre_fix_candidate_inventory(
    packet=_packet(first, second, fix_shas=(first_sha, second_sha)),
    repo_path=tmp_path,
    source_reader=reader,
  )

  assert {item.patch_family_id for item in inventory.candidates} == {"patch-family:shared"}
  assert {item.fix_commit_sha for item in inventory.candidates} == {first_sha, second_sha}
  assert {item.old_line_start for item in inventory.candidates} == {11, 21}


def test_parent_coordinates_count_only_lf_not_form_feed(tmp_path: Path):
  hunk = _hunk(deleted=[{"old_line": 2, "text": "danger();"}])
  reader = FakeSourceReader(
    metadata={hunk["id"]: {"path_before": "src/a.c", "path_after": "src/a.c", "change_type": "delete"}},
    files={("a" * 40, "src/a.c"): "header\fmarker\ndanger();\n"},
  )

  inventory = build_pre_fix_candidate_inventory(packet=_packet(hunk), repo_path=tmp_path, source_reader=reader)

  assert len(inventory.candidates) == 1
  assert inventory.candidates[0].old_line_start == 2
  assert inventory.candidates[0].line_text == "danger();"


def test_add_only_resolves_parent_function_when_packet_function_is_unresolved(tmp_path: Path):
  hunk = _hunk(
    added=[{"new_line": 12, "text": "guard();"}],
    context=[{"old_line": 11, "new_line": 11, "text": "danger();"}],
    function_id=None,
    function_symbol=None,
  )
  source = "\n" * 8 + "int target(void) {\n  int x = 0;\n  danger();\n  return x;\n}\n"
  reader = FakeSourceReader(
    metadata={hunk["id"]: {"path_before": "src/a.c", "path_after": "src/a.c", "change_type": "add_only"}},
    files={("a" * 40, "src/a.c"): source},
    functions={("a" * 40, "src/a.c", "target"): [(9, "int target(void) {"), (10, "  int x = 0;"), (11, "  danger();"), (12, "  return x;"), (13, "}")]},
  )

  inventory = build_pre_fix_candidate_inventory(packet=_packet(hunk), repo_path=tmp_path, source_reader=reader)

  semantic = [item for item in inventory.candidates if item.candidate_source == "pre_fix_function_body"]
  assert semantic
  assert {item.function_name for item in semantic} == {"target"}
  assert all(item.function_id for item in semantic)


def test_parent_function_resolution_ignores_braces_inside_comments(tmp_path: Path):
  hunk = _hunk(
    added=[{"new_line": 7, "text": "guard();"}],
    context=[{"old_line": 6, "new_line": 6, "text": "  danger();"}],
    function_id=None,
    function_symbol=None,
  )
  source = "int target(void) {\n  /* misleading } brace */\n  if (ready) {\n    prepare();\n  }\n  danger();\n  return 0;\n}\n"
  reader = FakeSourceReader(
    metadata={hunk["id"]: {"path_before": "src/a.c", "path_after": "src/a.c", "change_type": "add_only"}},
    files={("a" * 40, "src/a.c"): source},
    functions={("a" * 40, "src/a.c", "target"): [(1, "int target(void) {"), (2, "  /* misleading } brace */"), (3, "  if (ready) {"), (4, "    prepare();"), (5, "  }"), (6, "  danger();"), (7, "  return 0;"), (8, "}")]},
  )

  inventory = build_pre_fix_candidate_inventory(packet=_packet(hunk), repo_path=tmp_path, source_reader=reader)

  assert any(item.candidate_source == "pre_fix_function_body" for item in inventory.candidates)
  assert {item.function_name for item in inventory.candidates} == {"target"}
