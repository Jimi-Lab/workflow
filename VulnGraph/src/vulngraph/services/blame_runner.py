from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from vulngraph.agent_io.szz_handoff_schema import ResolvedPreFixAnchorV1


@dataclass(frozen=True)
class CommandResult:
  command: list[str]
  exit_code: int
  stdout: str
  stderr: str


@dataclass(frozen=True)
class BlameAuditResult:
  status: str
  line_records: list[dict[str, Any]] = field(default_factory=list)
  candidate_commits: list[dict[str, Any]] = field(default_factory=list)
  git_trace: list[dict[str, Any]] = field(default_factory=list)
  errors: list[str] = field(default_factory=list)

  def to_dict(self) -> dict[str, Any]:
    return {
      "status": self.status,
      "line_records": self.line_records,
      "candidate_commits": self.candidate_commits,
      "git_trace": self.git_trace,
      "errors": self.errors,
    }


CommandRunner = Callable[[list[str], Path], CommandResult]


def build_blame_command(repo_path: str | Path, anchor: ResolvedPreFixAnchorV1) -> list[str]:
  repo = Path(repo_path)
  return [
    "git",
    "-c",
    f"safe.directory={repo}",
    "-C",
    str(repo),
    "blame",
    "-w",
    "--line-porcelain",
    "-L",
    f"{anchor.old_line_start},{anchor.old_line_end}",
    anchor.parent_sha,
    "--",
    anchor.path_before,
  ]


def parse_blame_porcelain(output: str) -> list[dict[str, Any]]:
  records: list[dict[str, Any]] = []
  current: dict[str, Any] | None = None
  for raw_line in output.splitlines():
    if raw_line.startswith("\t"):
      if current is not None:
        current["line_text"] = raw_line[1:]
        records.append(current)
        current = None
      continue
    parts = raw_line.split()
    if len(parts) >= 3 and re.fullmatch(r"\^?[0-9a-fA-F]{40}", parts[0] or ""):
      current = {
        "blamed_commit_sha": parts[0].lstrip("^"),
        "blamed_original_line": int(parts[1]),
        "old_line": int(parts[2]),
        "boundary_marker": parts[0].startswith("^"),
      }
      continue
    if current is None:
      continue
    if raw_line == "boundary":
      current["boundary_marker"] = True
    elif raw_line.startswith("author-time "):
      current["author_time"] = int(raw_line.split(" ", 1)[1])
    elif raw_line.startswith("committer-time "):
      current["committer_time"] = int(raw_line.split(" ", 1)[1])
    elif raw_line.startswith("filename "):
      current["blamed_original_path"] = raw_line.split(" ", 1)[1]
  return records


def run_blame_for_anchors(
  repo_path: str | Path,
  anchors: list[ResolvedPreFixAnchorV1],
  *,
  command_runner: CommandRunner | None = None,
) -> BlameAuditResult:
  repo = Path(repo_path)
  runner = command_runner or _subprocess_runner
  trace: list[dict[str, Any]] = []
  errors: list[str] = []
  line_records: list[dict[str, Any]] = []

  shallow_command = _git_command(repo, ["rev-parse", "--is-shallow-repository"])
  shallow_result = runner(shallow_command, repo)
  trace.append(_trace_entry("shallow_check", shallow_result))
  if shallow_result.exit_code != 0:
    return BlameAuditResult(
      status="failed",
      git_trace=trace,
      errors=[f"shallow_check_failed:{shallow_result.stderr.strip()}"],
    )
  if shallow_result.stdout.strip().lower() == "true":
    return BlameAuditResult(status="shallow_history", git_trace=trace, errors=["shallow_history"])

  for anchor in anchors:
    anchor_records, anchor_errors = _blame_anchor(repo, anchor, runner, trace)
    line_records.extend(anchor_records)
    errors.extend(anchor_errors)

  successes = [item for item in line_records if item.get("status") == "success"]
  if successes and errors:
    status = "partial"
  elif successes:
    status = "success"
  else:
    status = "failed"
  return BlameAuditResult(
    status=status,
    line_records=line_records,
    candidate_commits=_aggregate_candidate_commits(successes),
    git_trace=trace,
    errors=errors,
  )


def _blame_anchor(
  repo: Path,
  anchor: ResolvedPreFixAnchorV1,
  runner: CommandRunner,
  trace: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
  commit_command = _git_command(repo, ["cat-file", "-e", f"{anchor.parent_sha}^{{commit}}"])
  commit_result = runner(commit_command, repo)
  trace.append(_trace_entry("validate_parent", commit_result, anchor.anchor_id))
  if commit_result.exit_code != 0:
    return [_failure_record(anchor, "parent_missing", commit_result.stderr)], [f"parent_missing:{anchor.anchor_id}"]

  show_command = _git_command(repo, ["show", f"{anchor.parent_sha}:{anchor.path_before}"])
  show_result = runner(show_command, repo)
  trace.append(_trace_entry("validate_parent_line", show_result, anchor.anchor_id))
  if show_result.exit_code != 0:
    return [_failure_record(anchor, "parent_path_missing", show_result.stderr)], [f"parent_path_missing:{anchor.anchor_id}"]
  source_lines = _lf_lines(show_result.stdout)
  if anchor.old_line_start > len(source_lines):
    return [_failure_record(anchor, "parent_line_mismatch", "line outside parent file")], [f"parent_line_mismatch:{anchor.anchor_id}"]
  exact_text = source_lines[anchor.old_line_start - 1]
  exact_hash = hashlib.sha256(exact_text.encode("utf-8")).hexdigest()
  if exact_text != anchor.line_text or exact_hash != anchor.line_text_sha256:
    return [_failure_record(anchor, "parent_line_mismatch", "text/hash mismatch")], [f"parent_line_mismatch:{anchor.anchor_id}"]

  blame_command = build_blame_command(repo, anchor)
  blame_result = runner(blame_command, repo)
  trace.append(_trace_entry("blame", blame_result, anchor.anchor_id))
  if blame_result.exit_code != 0:
    return [_failure_record(anchor, "blame_failed", blame_result.stderr)], [f"blame_failed:{anchor.anchor_id}"]
  parsed = parse_blame_porcelain(blame_result.stdout)
  if not parsed:
    return [_failure_record(anchor, "blame_failed", "empty porcelain output")], [f"blame_failed:{anchor.anchor_id}"]

  records: list[dict[str, Any]] = []
  for item in parsed:
    records.append(
      {
        "anchor_id": anchor.anchor_id,
        "candidate_id": anchor.candidate_id,
        "fix_commit_sha": anchor.fix_commit_sha,
        "parent_sha": anchor.parent_sha,
        "path_before": anchor.path_before,
        "old_line": item.get("old_line"),
        "line_text_sha256": hashlib.sha256(str(item.get("line_text") or "").encode("utf-8")).hexdigest(),
        "blamed_commit_sha": item.get("blamed_commit_sha"),
        "blamed_original_path": item.get("blamed_original_path", anchor.path_before),
        "blamed_original_line": item.get("blamed_original_line"),
        "author_time": item.get("author_time"),
        "committer_time": item.get("committer_time"),
        "boundary_marker": bool(item.get("boundary_marker")),
        "role": anchor.role,
        "selection_mode": anchor.selection_mode,
        "status": "success",
        "stderr": "",
        "lifecycle": "raw_candidate",
      }
    )
  return records, []


def _aggregate_candidate_commits(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
  aggregate: dict[str, dict[str, Any]] = {}
  for record in records:
    sha = str(record.get("blamed_commit_sha") or "")
    if not sha:
      continue
    item = aggregate.setdefault(
      sha,
      {
        "commit_sha": sha,
        "anchor_ids": set(),
        "candidate_ids": set(),
        "roles": set(),
        "selection_modes": set(),
        "vote_count": 0,
        "line_provenance": [],
        "lifecycle": "raw_candidate",
      },
    )
    item["anchor_ids"].add(record["anchor_id"])
    item["candidate_ids"].add(record["candidate_id"])
    item["roles"].add(record["role"])
    item["selection_modes"].add(record["selection_mode"])
    item["vote_count"] += 1
    item["line_provenance"].append(record)
  output: list[dict[str, Any]] = []
  for item in aggregate.values():
    output.append(
      {
        **item,
        "anchor_ids": sorted(item["anchor_ids"]),
        "candidate_ids": sorted(item["candidate_ids"]),
        "roles": sorted(item["roles"]),
        "selection_modes": sorted(item["selection_modes"]),
      }
    )
  return sorted(output, key=lambda item: (-item["vote_count"], item["commit_sha"]))


def _failure_record(anchor: ResolvedPreFixAnchorV1, status: str, stderr: str) -> dict[str, Any]:
  return {
    "anchor_id": anchor.anchor_id,
    "candidate_id": anchor.candidate_id,
    "fix_commit_sha": anchor.fix_commit_sha,
    "parent_sha": anchor.parent_sha,
    "path_before": anchor.path_before,
    "old_line": anchor.old_line_start,
    "line_text_sha256": anchor.line_text_sha256,
    "blamed_commit_sha": None,
    "blamed_original_path": None,
    "blamed_original_line": None,
    "author_time": None,
    "committer_time": None,
    "boundary_marker": False,
    "role": anchor.role,
    "selection_mode": anchor.selection_mode,
    "status": status,
    "stderr": stderr,
    "lifecycle": "raw_candidate",
  }


def _git_command(repo: Path, args: list[str]) -> list[str]:
  return ["git", "-c", f"safe.directory={repo}", "-C", str(repo), *args]


def _subprocess_runner(command: list[str], cwd: Path) -> CommandResult:
  result = subprocess.run(
    command,
    cwd=cwd,
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="ignore",
    check=False,
  )
  return CommandResult(command=command, exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)


def _trace_entry(operation: str, result: CommandResult, anchor_id: str | None = None) -> dict[str, Any]:
  return {
    "operation": operation,
    "anchor_id": anchor_id,
    "command": result.command,
    "exit_code": result.exit_code,
    "stderr": result.stderr[-2000:],
  }


def _lf_lines(source: str) -> list[str]:
  return [line[:-1] if line.endswith("\r") else line for line in source.split("\n")]
