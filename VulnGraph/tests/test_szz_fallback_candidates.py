from __future__ import annotations

import hashlib
import json
from pathlib import Path

from vulngraph.services.blame_runner import CommandResult
from vulngraph.workflows.szz_fallback_candidates import (
  build_fallback_enhanced_artifact,
  select_fallback_inventory_candidates,
)


def _candidate(
  candidate_id: str,
  *,
  fix_commit_id: str = "fix-commit:repo:fix1",
  fix_commit_sha: str = "f" * 40,
  parent_sha: str = "p" * 40,
  patch_family_id: str = "patch-family:one",
  patch_hunk_id: str = "patch-hunk:one",
  line_text: str = "dangerous_use(ptr);",
  candidate_source: str = "deleted_line",
  selection_mode: str = "modified_old_side",
  source_file: bool = True,
  comment_only: bool = False,
) -> dict:
  return {
    "candidate_id": candidate_id,
    "cve_id": "CVE-FALLBACK",
    "repo_id": "repo",
    "fix_set_id": "fix-set:one",
    "patch_family_id": patch_family_id,
    "fix_commit_id": fix_commit_id,
    "fix_commit_sha": fix_commit_sha,
    "parent_sha": parent_sha,
    "patch_hunk_id": patch_hunk_id,
    "path_before": "src/a.c",
    "path_after": "src/a.c",
    "old_line_start": 7,
    "old_line_end": 7,
    "line_text": line_text,
    "line_text_sha256": hashlib.sha256(line_text.encode("utf-8")).hexdigest(),
    "function_id": "function:dangerous_use",
    "function_name": "dangerous_use",
    "candidate_source": candidate_source,
    "change_type": "modify",
    "selection_mode_eligibility": [selection_mode],
    "git_observation_refs": ["obs:patch-diff"],
    "source_file": source_file,
    "comment_only": comment_only,
    "blank_line": False,
    "test_file": False,
    "documentation_file": False,
    "generated_file": False,
    "changelog_file": False,
    "exclusion_reasons": [],
  }


def test_select_fallback_candidates_prioritizes_old_side_and_tracks_unfamilied() -> None:
  candidates = [
    _candidate("context", candidate_source="hunk_context", selection_mode="context_fallback", source_file=False),
    _candidate("deleted", candidate_source="deleted_line", selection_mode="modified_old_side"),
    _candidate(
      "prefunc",
      fix_commit_id="fix-commit:repo:fix2",
      fix_commit_sha="e" * 40,
      parent_sha="q" * 40,
      patch_family_id="patch-family:two",
      patch_hunk_id="patch-hunk:two",
      candidate_source="pre_fix_function_body",
      selection_mode="add_only_semantic_target",
    ),
    _candidate("no-family", patch_family_id=""),
  ]

  selection = select_fallback_inventory_candidates(
    candidates,
    top_k_per_fix_commit=1,
    mandatory_candidate_ids={"context"},
  )

  selected_ids = [item["candidate_id"] for item in selection["candidates"]]
  assert "deleted" in selected_ids
  assert "prefunc" in selected_ids
  assert "context" in selected_ids
  assert "no-family" not in selected_ids
  assert selection["candidate_without_patch_family"] == 1
  assert selection["selected_by_fix_commit"]["fix-commit:repo:fix1"] >= 1
  assert selection["selected_by_fix_commit"]["fix-commit:repo:fix2"] == 1


def test_build_fallback_artifact_preserves_strong_and_adds_raw_fallback(tmp_path: Path) -> None:
  anchor_run = tmp_path / "anchor-run"
  root_cause_run = tmp_path / "root-cause"
  out_dir = tmp_path / "out"
  repo_root = tmp_path / "repos"
  anchor_run.mkdir()
  root_cause_run.mkdir()
  repo_root.mkdir()
  (repo_root / "repo").mkdir()
  (anchor_run / "summary.json").write_text(
    json.dumps(
      {
        "results": [
          {"cve_id": "CVE-STRONG", "status": "ingested_raw_candidate", "candidate_commit_count": 1},
          {"cve_id": "CVE-FALLBACK", "status": "contract_rejected", "candidate_commit_count": 0},
        ]
      }
    ),
    encoding="utf-8",
  )

  strong_dir = anchor_run / "CVE-STRONG"
  strong_dir.mkdir()
  strong_dir.joinpath("candidate_commits.json").write_text(
    json.dumps([{"commit_sha": "s" * 40, "lifecycle": "raw_candidate"}]),
    encoding="utf-8",
  )
  strong_dir.joinpath("resolved_pre_fix_anchors.json").write_text("[]", encoding="utf-8")
  strong_dir.joinpath("ingestion_result.json").write_text(json.dumps({"status": "ingested_raw_candidate"}), encoding="utf-8")

  fallback_dir = anchor_run / "CVE-FALLBACK"
  fallback_dir.mkdir()
  fallback_dir.joinpath("candidate_inventory.json").write_text(
    json.dumps(
      {
        "cve_id": "CVE-FALLBACK",
        "repo_id": "repo",
        "repo_path": str(repo_root / "repo"),
        "candidates": [_candidate("fallback-candidate")],
        "fix_families": {"patch-family:one": ["fix-commit:repo:fix1"]},
        "issues": [],
        "git_trace": [],
      }
    ),
    encoding="utf-8",
  )
  fallback_dir.joinpath("compact_candidate_inventory.json").write_text(
    json.dumps({"mandatory_candidate_ids": ["fallback-candidate"]}),
    encoding="utf-8",
  )
  fallback_dir.joinpath("ingestion_result.json").write_text(json.dumps({"status": "contract_rejected"}), encoding="utf-8")

  file_text = "\n" * 6 + "dangerous_use(ptr);\n"
  blame = "\n".join(
    [
      f"{'c' * 40} 7 7 1",
      "author-time 100",
      "committer-time 120",
      "filename src/a.c",
      "\tdangerous_use(ptr);",
    ]
  )

  def command_runner(command: list[str], cwd: Path) -> CommandResult:
    if "--is-shallow-repository" in command:
      return CommandResult(command, 0, "false\n", "")
    if "cat-file" in command:
      return CommandResult(command, 0, "", "")
    if "show" in command:
      return CommandResult(command, 0, file_text, "")
    return CommandResult(command, 0, blame, "")

  summary = build_fallback_enhanced_artifact(
    anchor_run=anchor_run,
    root_cause_run=root_cause_run,
    repo_root=repo_root,
    out_dir=out_dir,
    top_k_per_fix_commit=1,
    command_runner=command_runner,
  )

  assert summary["cases_total"] == 2
  assert summary["strong_candidate_ready_count"] == 1
  assert summary["fallback_candidate_ready_count"] == 1
  assert summary["judge_input_ready_count"] == 2
  strong_candidate = json.loads((out_dir / "CVE-STRONG" / "candidate_commits.json").read_text(encoding="utf-8"))[0]
  fallback_candidate = json.loads((out_dir / "CVE-FALLBACK" / "candidate_commits.json").read_text(encoding="utf-8"))[0]
  assert strong_candidate["candidate_generation_mode"] == "strong_model_anchor"
  assert strong_candidate["evidence_level"] == "strong"
  assert fallback_candidate["candidate_generation_mode"] == "fallback_inventory_anchor"
  assert fallback_candidate["evidence_level"] == "fallback"
  assert fallback_candidate["lifecycle"] == "raw_candidate"
  serialized = json.dumps(summary) + "".join(path.read_text(encoding="utf-8") for path in out_dir.rglob("*.json"))
  assert "validated_bic" not in serialized
  assert "correct_bic" not in serialized
  assert '"affected_versions"' not in serialized
