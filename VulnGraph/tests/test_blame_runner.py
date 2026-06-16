from __future__ import annotations

import hashlib
from pathlib import Path

from vulngraph.agent_io.szz_handoff_schema import ResolvedPreFixAnchorV1
from vulngraph.services.blame_runner import (
  CommandResult,
  build_blame_command,
  parse_blame_porcelain,
  run_blame_for_anchors,
)


def _anchor(*, start: int = 17, end: int = 17, text: str = "dangerous_use(ptr);") -> ResolvedPreFixAnchorV1:
  return ResolvedPreFixAnchorV1(
    anchor_id="pre-fix-anchor:1",
    candidate_id="pre-fix-line:1",
    cve_id="CVE-TEST-1",
    fix_set_id="fix-set:1",
    patch_family_id="patch-family:1",
    fix_commit_id="fix-commit:1",
    fix_commit_sha="b" * 40,
    parent_sha="a" * 40,
    patch_hunk_id="patch-hunk:1",
    path_before="src/old.c",
    path_after="src/new.c",
    old_line_start=start,
    old_line_end=end,
    line_text=text,
    line_text_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
    function_id="function:1",
    function_name="target",
    candidate_source="deleted_line",
    role="dangerous_use",
    selection_mode="direct_deleted_line",
    root_cause_hypothesis_ids=["hypothesis:1"],
    predicate_ids=["predicate:1"],
    git_observation_refs=["obs:1"],
    rationale="Parent-side use.",
    confidence=0.9,
  )


def test_blame_command_uses_parent_path_before_and_old_side_range(tmp_path: Path):
  command = build_blame_command(tmp_path, _anchor(start=17, end=19))

  assert command[-5:] == ["-L", "17,19", "a" * 40, "--", "src/old.c"]
  assert "-w" in command
  assert "--line-porcelain" in command
  assert "src/new.c" not in command


def test_porcelain_output_is_normalized_per_line():
  output = "\n".join(
    [
      f"{'c' * 40} 7 17 1",
      "author Alice",
      "author-time 100",
      "committer-time 120",
      "filename src/original.c",
      "\tdangerous_use(ptr);",
    ]
  )

  records = parse_blame_porcelain(output)

  assert len(records) == 1
  assert records[0]["blamed_commit_sha"] == "c" * 40
  assert records[0]["blamed_original_line"] == 7
  assert records[0]["old_line"] == 17
  assert records[0]["blamed_original_path"] == "src/original.c"
  assert records[0]["author_time"] == 100


def test_boundary_porcelain_commit_with_caret_is_preserved_as_raw_candidate():
  output = "\n".join(
    [
      f"^{'c' * 40} 7 17 1",
      "boundary",
      "author-time 100",
      "committer-time 120",
      "filename src/original.c",
      "\tdangerous_use(ptr);",
    ]
  )

  records = parse_blame_porcelain(output)

  assert len(records) == 1
  assert records[0]["blamed_commit_sha"] == "c" * 40
  assert records[0]["boundary_marker"] is True


def test_multiple_lines_aggregate_commit_but_preserve_line_provenance(tmp_path: Path):
  anchor = _anchor(start=17, end=18, text="dangerous_use(ptr);")
  file_text = "\n" * 16 + "dangerous_use(ptr);\nnext_line();\n"
  blame = "\n".join(
    [
      f"{'c' * 40} 7 17 1", "author-time 100", "committer-time 120", "filename src/old.c", "\tdangerous_use(ptr);",
      f"{'c' * 40} 8 18 1", "author-time 100", "committer-time 120", "filename src/old.c", "\tnext_line();",
    ]
  )

  def runner(command: list[str], cwd: Path) -> CommandResult:
    if "--is-shallow-repository" in command:
      return CommandResult(command, 0, "false\n", "")
    if "cat-file" in command:
      return CommandResult(command, 0, "", "")
    if "show" in command:
      return CommandResult(command, 0, file_text, "")
    return CommandResult(command, 0, blame, "")

  result = run_blame_for_anchors(tmp_path, [anchor], command_runner=runner)

  assert result.status == "success"
  assert len(result.line_records) == 2
  assert result.candidate_commits[0]["vote_count"] == 2
  assert result.candidate_commits[0]["anchor_ids"] == ["pre-fix-anchor:1"]


def test_blame_failure_returns_typed_status(tmp_path: Path):
  anchor = _anchor()
  file_text = "\n" * 16 + "dangerous_use(ptr);\n"

  def runner(command: list[str], cwd: Path) -> CommandResult:
    if "--is-shallow-repository" in command:
      return CommandResult(command, 0, "false\n", "")
    if "cat-file" in command:
      return CommandResult(command, 0, "", "")
    if "show" in command:
      return CommandResult(command, 0, file_text, "")
    return CommandResult(command, 128, "", "fatal: no such path")

  result = run_blame_for_anchors(tmp_path, [anchor], command_runner=runner)

  assert result.status == "failed"
  assert result.line_records[0]["status"] == "blame_failed"
  assert "no such path" in result.line_records[0]["stderr"]


def test_shallow_repository_produces_shallow_history(tmp_path: Path):
  def runner(command: list[str], cwd: Path) -> CommandResult:
    return CommandResult(command, 0, "true\n", "")

  result = run_blame_for_anchors(tmp_path, [_anchor()], command_runner=runner)

  assert result.status == "shallow_history"
  assert result.candidate_commits == []


def test_parent_line_hash_mismatch_prevents_blame(tmp_path: Path):
  anchor = _anchor()
  commands: list[list[str]] = []

  def runner(command: list[str], cwd: Path) -> CommandResult:
    commands.append(command)
    if "--is-shallow-repository" in command:
      return CommandResult(command, 0, "false\n", "")
    if "cat-file" in command:
      return CommandResult(command, 0, "", "")
    if "show" in command:
      return CommandResult(command, 0, "\n" * 16 + "different();\n", "")
    raise AssertionError("blame must not run after parent-line validation failure")

  result = run_blame_for_anchors(tmp_path, [anchor], command_runner=runner)

  assert result.status == "failed"
  assert result.line_records[0]["status"] == "parent_line_mismatch"
  assert not any("blame" in command for command in commands)


def test_parent_validation_counts_only_lf_not_form_feed(tmp_path: Path):
  anchor = _anchor(start=2, end=2, text="dangerous_use(ptr);")
  blame = "\n".join(
    [
      f"{'c' * 40} 2 2 1",
      "author-time 100",
      "committer-time 120",
      "filename src/old.c",
      "\tdangerous_use(ptr);",
    ]
  )

  def runner(command: list[str], cwd: Path) -> CommandResult:
    if "--is-shallow-repository" in command:
      return CommandResult(command, 0, "false\n", "")
    if "cat-file" in command:
      return CommandResult(command, 0, "", "")
    if "show" in command:
      return CommandResult(command, 0, "header\fmarker\ndangerous_use(ptr);\n", "")
    return CommandResult(command, 0, blame, "")

  result = run_blame_for_anchors(tmp_path, [anchor], command_runner=runner)

  assert result.status == "success"
