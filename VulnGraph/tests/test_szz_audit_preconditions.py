from __future__ import annotations

import csv
import json
import subprocess
from pathlib import Path

from vulngraph.agent_backends.szz_fixture import FixtureSzzAnchorBackend
from vulngraph.workflows.szz_anchor_audit import verify_szz_audit_preconditions
from vulngraph.workflows.szz_anchor_audit import SEMANTIC_LABEL_FIELDS


def test_fixture_backend_selects_only_inventory_candidate_ids():
  backend = FixtureSzzAnchorBackend()
  context = {
    "cve_id": "CVE-TEST-1",
    "root_cause": {
      "root_cause_hypotheses": [{"hypothesis_id": "hyp:1", "git_observation_refs": ["obs:1"]}],
      "vulnerable_predicates": [{"predicate_id": "pred:1", "git_observation_refs": ["obs:1"]}],
    },
    "candidate_inventory": {
      "fix_families": {"family:1": ["b" * 40]},
      "candidates": [
        {
            "candidate_id": "candidate:1",
            "patch_family_id": "family:1",
            "fix_commit_id": "fix:1",
          "candidate_source": "deleted_line",
          "source_file": True,
          "comment_only": False,
          "blank_line": False,
          "git_observation_refs": ["obs:1"],
        }
      ],
    },
  }

  response = backend.generate("prompt", context)
  payload = json.loads(response.raw_text)

  assert response.backend_type == "fixture"
  assert [item["candidate_id"] for item in payload["selected_anchors"]] == ["candidate:1"]
  assert "validated_bic" not in response.raw_text


def test_preconditions_fail_closed_when_independent_semantic_labels_are_incomplete(tmp_path: Path):
  repo_root = tmp_path / "repo-root"
  repo = repo_root / "repo"
  repo.mkdir(parents=True)
  _git(repo, "init")
  _git(repo, "config", "user.email", "test@example.com")
  _git(repo, "config", "user.name", "Test")
  (repo / "a.c").write_text("int a;\n", encoding="utf-8")
  _git(repo, "add", "a.c")
  _git(repo, "commit", "-m", "initial")
  (repo / "a.c").write_text("int a;\nint b;\n", encoding="utf-8")
  _git(repo, "commit", "-am", "fix")
  fix_sha = _git(repo, "rev-parse", "HEAD").strip()

  root_run = tmp_path / "root-run"
  case = root_run / "CVE-TEST-1"
  case.mkdir(parents=True)
  (case / "contract_lint.json").write_text(json.dumps({"ok": True}), encoding="utf-8")
  (case / "structural_validation.json").write_text(json.dumps({"ok": True}), encoding="utf-8")
  (case / "ingestion_result.json").write_text(json.dumps({"status": "ingested_raw"}), encoding="utf-8")
  with (root_run / "evaluation.csv").open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=["cve_id", "overall_root_cause_correct", "anchor_hunk_correct", "evidence_link_precise"])
    writer.writeheader()
    writer.writerow({"cve_id": "CVE-TEST-1", "overall_root_cause_correct": "", "anchor_hunk_correct": "1", "evidence_link_precise": "1"})
  dataset = tmp_path / "dataset.json"
  dataset.write_text(
    json.dumps({"CVE-TEST-1": {"repo": "repo", "fixing_commits": [[fix_sha]]}}),
    encoding="utf-8",
  )

  result = verify_szz_audit_preconditions(
    ["CVE-TEST-1"],
    root_cause_run=root_run,
    dataset=dataset,
    repo_root=repo_root,
    opencode_health={"healthy": True},
    provider_id="deepseek",
    model_id="deepseek-v4-pro",
  )

  assert not result["ready"]
  assert result["structurally_accepted"] == 1
  assert result["fix_commits_with_parents"] == 1
  assert result["semantic_labels_complete"] is False
  assert "optimized_semantic_labels_incomplete" in result["blocking_reasons"]


def test_engineering_smoke_preconditions_can_skip_semantic_labels_but_report_mode(tmp_path: Path):
  repo_root = tmp_path / "repo-root"
  repo = repo_root / "repo"
  repo.mkdir(parents=True)
  _git(repo, "init")
  _git(repo, "config", "user.email", "test@example.com")
  _git(repo, "config", "user.name", "Test")
  (repo / "a.c").write_text("int a;\n", encoding="utf-8")
  _git(repo, "add", "a.c")
  _git(repo, "commit", "-m", "initial")
  (repo / "a.c").write_text("int a;\nint b;\n", encoding="utf-8")
  _git(repo, "commit", "-am", "fix")
  fix_sha = _git(repo, "rev-parse", "HEAD").strip()

  root_run = tmp_path / "root-run"
  case = root_run / "CVE-TEST-1"
  case.mkdir(parents=True)
  (case / "contract_lint.json").write_text(json.dumps({"ok": True}), encoding="utf-8")
  (case / "structural_validation.json").write_text(json.dumps({"ok": True}), encoding="utf-8")
  (case / "ingestion_result.json").write_text(json.dumps({"status": "ingested_raw"}), encoding="utf-8")
  (root_run / "evaluation.csv").write_text("cve_id,overall_root_cause_correct\nCVE-TEST-1,\n", encoding="utf-8")
  dataset = tmp_path / "dataset.json"
  dataset.write_text(json.dumps({"CVE-TEST-1": {"repo": "repo", "fixing_commits": [[fix_sha]]}}), encoding="utf-8")

  result = verify_szz_audit_preconditions(
    ["CVE-TEST-1"],
    root_cause_run=root_run,
    dataset=dataset,
    repo_root=repo_root,
    opencode_health={"healthy": True},
    provider_id="deepseek",
    model_id="deepseek-v4-pro",
    require_semantic_labels=False,
    mode="engineering_smoke",
  )

  assert result["ready"]
  assert result["mode"] == "engineering_smoke"
  assert result["semantic_labels_complete"] is False
  assert "optimized_semantic_labels_incomplete" not in result["blocking_reasons"]


def test_formal_preconditions_block_shallow_history_by_default(tmp_path: Path, monkeypatch):
  root_run = tmp_path / "root-run"
  case = root_run / "CVE-TEST-1"
  case.mkdir(parents=True)
  (case / "contract_lint.json").write_text(json.dumps({"ok": True}), encoding="utf-8")
  (case / "structural_validation.json").write_text(json.dumps({"ok": True}), encoding="utf-8")
  (case / "ingestion_result.json").write_text(json.dumps({"status": "ingested_raw"}), encoding="utf-8")
  with (root_run / "evaluation.csv").open("w", newline="", encoding="utf-8") as handle:
    fields = ["cve_id", *SEMANTIC_LABEL_FIELDS]
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerow({"cve_id": "CVE-TEST-1", **{field: "1" for field in SEMANTIC_LABEL_FIELDS}})
  repo_root = tmp_path / "repos"
  (repo_root / "repo").mkdir(parents=True)
  dataset = tmp_path / "dataset.json"
  dataset.write_text(json.dumps({"CVE-TEST-1": {"repo": "repo", "fixing_commits": [["b" * 40]]}}), encoding="utf-8")

  def fake_run_git(repo_path: Path, args: list[str]) -> dict:
    if "--is-shallow-repository" in args:
      return {"exit_code": 0, "stdout": "true\n", "stderr": ""}
    if "rev-parse" in args:
      return {"exit_code": 0, "stdout": "a" * 40 + "\n", "stderr": ""}
    return {"exit_code": 0, "stdout": "", "stderr": ""}

  monkeypatch.setattr("vulngraph.workflows.szz_anchor_audit._run_git", fake_run_git)

  result = verify_szz_audit_preconditions(
    ["CVE-TEST-1"],
    root_cause_run=root_run,
    dataset=dataset,
    repo_root=repo_root,
    opencode_health={"healthy": True},
    provider_id="deepseek",
    model_id="deepseek-v4-pro",
  )

  assert not result["ready"]
  assert result["shallow_history_cases"] == ["CVE-TEST-1"]
  assert "shallow_history_in_formal_run" in result["blocking_reasons"]


def _git(repo: Path, *args: str) -> str:
  result = subprocess.run(
    ["git", "-c", f"safe.directory={repo}", "-C", str(repo), *args],
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="ignore",
    check=True,
  )
  return result.stdout
