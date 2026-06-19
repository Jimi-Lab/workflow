from __future__ import annotations

import json
from pathlib import Path

from vulngraph.services.blame_runner import CommandResult
from vulngraph.workflows.detailed_szz_evidence import (
  build_detailed_szz_evidence_v0,
  build_szz_evidence_for_candidate,
  scan_forbidden_evidence_fields,
)


def _write_json(path: Path, data: object) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _read_json(path: Path) -> dict:
  return json.loads(path.read_text(encoding="utf-8"))


def _candidate() -> dict:
  return {
    "cve_id": "CVE-X",
    "repo": "repo",
    "fix_commit_id": "fix-commit:repo:" + "f" * 40,
    "patch_family_id": "patch-family:x",
    "candidate_commit_sha": "c" * 40,
    "candidate_source": "strong",
    "candidate_generation_mode": "strong_model_anchor",
    "evidence_level": "strong",
    "lifecycle": "raw_candidate",
    "selected_anchor_id": "anchor-1",
    "fallback_anchor_id": "",
    "candidate_ids": ["cand-1"],
    "path_before": "src/a.c",
    "old_line_start": 10,
    "old_line_end": 10,
    "old_line_text_hash": "h" * 64,
    "old_line_text": "dangerous_use(ptr);",
    "blame_trace": {
      "status": "success",
      "line_provenance": [
        {
          "anchor_id": "anchor-1",
          "candidate_id": "cand-1",
          "fix_commit_sha": "f" * 40,
          "parent_sha": "p" * 40,
          "path_before": "src/a.c",
          "old_line": 10,
          "line_text_sha256": "h" * 64,
          "blamed_commit_sha": "c" * 40,
          "blamed_original_path": "src/a.c",
          "blamed_original_line": 9,
          "author_time": 100,
          "committer_time": 100,
          "boundary_marker": False,
          "role": "dangerous_use",
          "selection_mode": "modified_old_side",
          "status": "success",
          "lifecycle": "raw_candidate",
          "old_text": "dangerous_use(ptr);",
        }
      ],
      "errors": [],
    },
    "root_cause_hypothesis_bindings": ["hyp-1"],
    "vulnerable_predicate_bindings": ["vp-1"],
    "fix_predicate_bindings": ["fp-1"],
    "predicate_bindings": ["vp-1", "fp-1"],
    "predicted_release_tags_from_version_probe": ["v1.0", "v1.1"],
    "risk_flags": [],
    "uncertainty_flags": [],
  }


class FakeGit:
  def __init__(self) -> None:
    self.commands: list[list[str]] = []

  def __call__(self, command: list[str], cwd: Path) -> CommandResult:
    del cwd
    self.commands.append(command)
    text = "dangerous_use(ptr);\n"
    if "show" in command and command[-1].endswith(":src/a.c"):
      return CommandResult(command, 0, text * 20, "")
    if "blame" in command:
      prefix = "^" if "-C" in command and "-M" in command and "-w" in command else ""
      output = (
        f"{prefix}{'c' * 40} 9 10 1\n"
        "author Alice\n"
        "author-time 100\n"
        "committer-time 101\n"
        "filename src/a.c\n"
        "\tdangerous_use(ptr);\n"
      )
      if prefix:
        output = output.replace("filename src/a.c", "boundary\nfilename src/a.c")
      return CommandResult(command, 0, output, "")
    if command[-3:] == ["rev-parse", "--is-shallow-repository"]:
      return CommandResult(command, 0, "false\n", "")
    if "merge-base" in command:
      return CommandResult(command, 0, "", "")
    if "rev-list" in command and "--count" in command:
      return CommandResult(command, 0, "7\n", "")
    if "rev-list" in command and "--parents" in command:
      return CommandResult(command, 0, f"{command[-1]} {'p' * 40}\n", "")
    if "diff-tree" in command:
      return CommandResult(command, 0, "src/a.c\n", "")
    if "log" in command:
      return CommandResult(command, 0, "src/a.c\n", "")
    if "show" in command and "--format=%at:%ct:%s" in command:
      return CommandResult(command, 0, "100:101:initial dangerous use\n", "")
    if "show" in command and "--format=%P" in command:
      return CommandResult(command, 0, "p\n", "")
    return CommandResult(command, 0, "", "")


def test_candidate_szz_evidence_has_variants_and_no_forbidden_keys(tmp_path: Path) -> None:
  fake = FakeGit()

  evidence = build_szz_evidence_for_candidate(
    candidate=_candidate(),
    dataset_record={"repo": "repo", "fixing_commits": [["f" * 40]]},
    repo_path=tmp_path,
    release_tags=["v1.0", "v1.1"],
    command_runner=fake,
  )

  assert evidence["candidate_identity"]["lifecycle"] == "raw_candidate"
  assert {item["variant"] for item in evidence["blame_variants"]["variants"]} == {"normal", "w", "M", "C", "w_M_C"}
  assert evidence["blame_variants"]["canonical_blame_commit_sha"] == "c" * 40
  assert evidence["blame_variants"]["variant_agreement"] in {"all_same", "move_copy_differs"}
  assert evidence["line_survival_evidence"]["line_survives_to_fix_parent"] is True
  assert evidence["commit_relation_evidence"]["candidate_is_ancestor_of_fix"] is True
  assert "stable_blame_variants" in evidence["confidence_features"]
  assert scan_forbidden_evidence_fields(evidence)["ok"] is True


def test_batch_writes_judge_and_audit_packets_without_forbidden_keys(tmp_path: Path) -> None:
  judge_root = tmp_path / "judge"
  dataset = tmp_path / "dataset.json"
  repo_root = tmp_path / "repo-root"
  repo = repo_root / "repo"
  repo.mkdir(parents=True)
  out_dir = tmp_path / "out"
  _write_json(dataset, {"CVE-X": {"repo": "repo", "fixing_commits": [["f" * 40]]}})
  _write_json(
    judge_root / "CVE-X" / "judge_blind_input_packet.json",
    {
      "schema_version": "judge_blind_input_packet_v0",
      "cve_id": "CVE-X",
      "repo": "repo",
      "candidate_count": 1,
      "lifecycle": "raw_candidate",
      "candidates": [_candidate()],
    },
  )
  _write_json(
    judge_root / "CVE-X" / "judge_audit_packet.json",
    {
      "schema_version": "judge_audit_packet_v0",
      "cve_id": "CVE-X",
      "repo": "repo",
      "candidate_count": 1,
      "lifecycle": "raw_candidate",
      "candidates": [_candidate()],
    },
  )

  summary = build_detailed_szz_evidence_v0(
    slimming_root=tmp_path / "slim",
    judge_packet_root=judge_root,
    dataset=dataset,
    repo_root=repo_root,
    out_dir=out_dir,
    command_runner=FakeGit(),
  )

  assert summary["model_invocation_count"] == 0
  assert summary["judge_invocation_count"] == 0
  assert summary["lifecycle"] == "raw_candidate"
  assert summary["cases_total"] == 1
  assert summary["candidates_total"] == 1
  assert (out_dir / "CVE-X" / "judge_szz_evidence_packet.json").exists()
  assert (out_dir / "CVE-X" / "szz_evidence_audit_packet.json").exists()
  assert _read_json(out_dir / "forbidden_field_scan.json")["ok"] is True
  assert scan_forbidden_evidence_fields(_read_json(out_dir / "CVE-X" / "judge_szz_evidence_packet.json"))["ok"] is True
