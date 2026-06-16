from __future__ import annotations

import hashlib
import json
from pathlib import Path

from vulngraph.agent_backends.base import AgentResponse
from vulngraph.services.blame_runner import CommandResult
from vulngraph.workflows.szz_anchor_audit import (
  _aggregate_summary,
  _render_batch_report,
  _render_handoff_prompt,
  _selection_inventory,
  replay_szz_anchor_audit_case,
  run_szz_anchor_audit_case,
)


FIXTURE_ROOT = Path("tests/fixtures/szz_compaction")


def _load_compaction_fixture(cve_id: str) -> tuple[dict, dict]:
  payload = json.loads((FIXTURE_ROOT / f"{cve_id}.json").read_text(encoding="utf-8"))
  return payload["inventory"], payload["root_cause"]


class FixtureSzzBackend:
  backend_name = "fixture-szz"
  backend_type = "fixture"

  def generate(self, prompt: str, context: dict) -> AgentResponse:
    candidate_id = context["candidate_inventory"]["candidates"][0]["candidate_id"]
    payload = {
      "agent_run": {"run_id": "szz-run:fixture", "cve_id": "CVE-TEST-1", "backend": self.backend_name},
      "failure_mode": "Out-of-bounds access",
      "trigger": "Untrusted index",
      "violated_invariant": "Index must be in range",
      "vulnerable_state": "Unchecked index reaches a lookup",
      "propagation": ["index", "lookup"],
      "sink": "array dereference",
      "fix_mechanism": "Bounds guard",
      "selected_anchors": [
        {
          "candidate_id": candidate_id,
          "role": "dangerous_use",
          "root_cause_hypothesis_ids": ["hypothesis:1"],
          "predicate_ids": ["predicate:1"],
          "rationale": "This parent-side lookup violates the invariant.",
          "confidence": 0.9,
        }
      ],
      "excluded_hunk_ids": [],
      "uncertainty_items": [],
    }
    return AgentResponse(
      raw_text=json.dumps(payload),
      status="ok",
      backend_name=self.backend_name,
      backend_type=self.backend_type,
      usage={"tokens": 10},
    )


class MalformedSzzBackend:
  backend_name = "malformed-szz"
  backend_type = "fixture"

  def generate(self, prompt: str, context: dict) -> AgentResponse:
    return AgentResponse(raw_text="{bad json", status="ok", backend_name=self.backend_name, backend_type=self.backend_type)


class InventedCandidateSzzBackend(FixtureSzzBackend):
  def generate(self, prompt: str, context: dict) -> AgentResponse:
    response = super().generate(prompt, context)
    payload = json.loads(response.raw_text)
    payload["selected_anchors"][0]["candidate_id"] = "candidate:invented"
    return AgentResponse(raw_text=json.dumps(payload), status="ok", backend_name=self.backend_name, backend_type=self.backend_type)


class FixtureSourceReader:
  def __init__(self):
    self.trace = []

  def resolve_parent(self, fix_sha: str) -> str:
    return "a" * 40

  def inspect_hunk(self, fix_sha: str, patch_hunk: dict) -> dict:
    return {"path_before": "src/a.c", "path_after": "src/a.c", "change_type": "delete"}

  def read_file(self, revision: str, path: str) -> str | None:
    return "\n" * 16 + "dangerous_use(ptr);\n"

  def read_function_body(self, revision: str, path: str, function_name: str | None):
    return []

  def patch_family_id(self, fix_sha: str) -> str:
    return "patch-family:1"


def _write_root_cause_case(case_dir: Path) -> None:
  case_dir.mkdir(parents=True)
  fix_sha = "b" * 40
  hunk_id = f"patch-hunk:repo:{fix_sha}:src/a.c:1"
  packet = {
    "cve_id": "CVE-TEST-1",
    "patch_evidence": [
      {
        "id": f"fix-commit:repo:{fix_sha}",
        "type": "FixCommit",
        "content": {"cve_id": "CVE-TEST-1", "repo": "repo", "commit_sha": fix_sha, "fix_set_id": "fix-set:1"},
      },
      {
        "id": hunk_id,
        "type": "PatchHunk",
        "content": {
          "cve_id": "CVE-TEST-1",
          "repo": "repo",
          "commit_sha": fix_sha,
          "path": "src/a.c",
          "hunk_index": 1,
          "deleted_lines": [{"old_line": 17, "text": "dangerous_use(ptr);"}],
          "added_lines": [],
          "context_lines": [],
          "function_id": "function:1",
          "function_symbol": "target",
        },
      },
    ],
    "repo_navigation": [{"id": "repo:repo", "type": "Repo", "content": {"repo": "repo"}}],
  }
  parsed = {
    "agent_run": {"run_id": "root-run:1", "cve_id": "CVE-TEST-1", "backend": "opencode"},
    "root_cause_hypotheses": [
      {"hypothesis_id": "hypothesis:1", "summary": "Unchecked use", "git_observation_refs": ["obs:patch-diff"]}
    ],
    "vulnerable_predicates": [
      {"predicate_id": "predicate:1", "description": "Index is unchecked", "git_observation_refs": ["obs:patch-diff"]}
    ],
    "fix_predicates": [],
    "guard_conditions": [],
    "negative_conditions": [],
    "code_anchors": [],
    "git_observation_refs": ["obs:patch-diff"],
    "uncertainty_reasons": [],
    "learned_candidates": [],
    "risk_flags": [],
  }
  trace = {
    "git_observations": [
      {
        "id": "obs:patch-diff",
        "source": "wrapper_git_trace",
        "valid_evidence": True,
        "observation_kind": "patch_diff",
        "patch_hunk_ids": [hunk_id],
        "fix_commit_ids": [f"fix-commit:repo:{fix_sha}"],
      }
    ]
  }
  (case_dir / "root_cause_packet.json").write_text(json.dumps(packet), encoding="utf-8")
  (case_dir / "parsed_output.json").write_text(json.dumps(parsed), encoding="utf-8")
  (case_dir / "evidence_trace.json").write_text(json.dumps(trace), encoding="utf-8")
  (case_dir / "contract_lint.json").write_text(json.dumps({"ok": True}), encoding="utf-8")
  (case_dir / "structural_validation.json").write_text(json.dumps({"ok": True}), encoding="utf-8")
  (case_dir / "ingestion_result.json").write_text(json.dumps({"status": "ingested_raw"}), encoding="utf-8")


def test_fixture_audit_writes_raw_candidate_artifacts(tmp_path: Path):
  case_dir = tmp_path / "root-cause" / "CVE-TEST-1"
  out_dir = tmp_path / "audit" / "CVE-TEST-1"
  _write_root_cause_case(case_dir)

  file_text = "\n" * 16 + "dangerous_use(ptr);\n"
  blame = "\n".join(
    [
      f"{'c' * 40} 7 17 1",
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

  result = run_szz_anchor_audit_case(
    cve_id="CVE-TEST-1",
    root_cause_case_dir=case_dir,
    repo_path=tmp_path / "repo",
    out_dir=out_dir,
    backend=FixtureSzzBackend(),
    source_reader=FixtureSourceReader(),
    command_runner=command_runner,
  )

  required = {
    "candidate_inventory.json",
    "pre_fix_candidate_inventory.json",
    "szz_handoff_prompt.txt",
    "raw_response.txt",
    "raw_szz_handoff_response.txt",
    "parsed_selection.json",
    "parsed_szz_handoff.json",
    "contract_lint.json",
    "resolved_anchors.json",
    "resolved_pre_fix_anchors.json",
    "blame_trace.json",
    "candidate_commits.json",
    "ingestion_result.json",
    "manual_anchor_review_template.csv",
  }
  assert required <= {path.name for path in out_dir.iterdir()}
  assert result["status"] == "ingested_raw_candidate"
  assert result["direct_old_side_anchor_count"] == 1
  assert result["add_only_semantic_anchor_count"] == 0
  assert result["context_only_anchor_count"] == 0
  assert result["blame_success_anchor_count"] == 1
  assert result["git_query_count"] >= 4
  assert result["original_candidate_count"] == 1
  assert result["compacted_candidate_count"] == 1
  assert result["prompt_bytes"] > 0
  prompt_text = (out_dir / "szz_handoff_prompt.txt").read_text(encoding="utf-8")
  assert '"git_trace"' not in prompt_text

  combined = "\n".join(path.read_text(encoding="utf-8") for path in out_dir.iterdir() if path.suffix in {".json", ".csv"})
  assert "validated_bic" not in combined
  assert "correct_bic" not in combined
  assert "affected_versions" not in combined
  resolved = json.loads((out_dir / "resolved_anchors.json").read_text(encoding="utf-8"))
  assert resolved[0]["lifecycle"] == "raw_candidate"
  commits = json.loads((out_dir / "candidate_commits.json").read_text(encoding="utf-8"))
  assert commits[0]["lifecycle"] == "raw_candidate"


def test_replay_szz_anchor_audit_case_reuses_existing_handoff_without_backend(tmp_path: Path):
  case_dir = tmp_path / "root-cause" / "CVE-TEST-1"
  previous_dir = tmp_path / "previous" / "CVE-TEST-1"
  out_dir = tmp_path / "replay" / "CVE-TEST-1"
  _write_root_cause_case(case_dir)
  previous_dir.mkdir(parents=True)

  inventory = {
    "cve_id": "CVE-TEST-1",
    "repo_id": "repo:repo",
    "repo_path": str(tmp_path / "repo"),
    "fix_families": {"patch-family:1": ["b" * 40]},
    "issues": [],
    "git_trace": [],
    "candidates": [
      {
        "candidate_id": "pre-fix-line:1",
        "cve_id": "CVE-TEST-1",
        "repo_id": "repo:repo",
        "fix_set_id": "fix-set:1",
        "patch_family_id": "patch-family:1",
        "fix_commit_id": "fix-commit:1",
        "fix_commit_sha": "b" * 40,
        "parent_sha": "a" * 40,
        "patch_hunk_id": f"patch-hunk:repo:{'b' * 40}:src/a.c:1",
        "path_before": "src/a.c",
        "path_after": "src/a.c",
        "old_line_start": 17,
        "old_line_end": 17,
        "line_text": "dangerous_use(ptr);",
        "line_text_sha256": hashlib.sha256("dangerous_use(ptr);".encode("utf-8")).hexdigest(),
        "function_id": "function:1",
        "function_name": "target",
        "candidate_source": "deleted_line",
        "change_type": "delete",
        "selection_mode_eligibility": ["direct_deleted_line"],
        "git_observation_refs": ["obs:patch-diff"],
        "source_file": True,
        "comment_only": False,
        "blank_line": False,
        "test_file": False,
        "documentation_file": False,
        "generated_file": False,
        "changelog_file": False,
        "exclusion_reasons": [],
      }
    ],
  }
  handoff = {
    "agent_run": {"run_id": "szz-run:previous", "cve_id": "CVE-TEST-1", "backend": "opencode"},
    "failure_mode": "Out-of-bounds access",
    "trigger": "Untrusted index",
    "violated_invariant": "Index must be in range",
    "vulnerable_state": "Unchecked index reaches a lookup",
    "propagation": ["index", "lookup"],
    "sink": "array dereference",
    "fix_mechanism": "Bounds guard",
    "selected_anchors": [
      {
        "candidate_id": "pre-fix-line:1",
        "role": "dangerous_use",
        "root_cause_hypothesis_ids": ["hypothesis:1"],
        "predicate_ids": ["predicate:1"],
        "rationale": "Previous model-selected parent-side line.",
        "confidence": 0.9,
      }
    ],
    "excluded_hunk_ids": [],
    "uncertainty_items": [],
  }
  (previous_dir / "candidate_inventory.json").write_text(json.dumps(inventory), encoding="utf-8")
  (previous_dir / "raw_szz_handoff_response.txt").write_text(json.dumps(handoff), encoding="utf-8")

  file_text = "\n" * 16 + "dangerous_use(ptr);\n"
  blame = "\n".join(
    [
      f"{'c' * 40} 7 17 1",
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

  result = replay_szz_anchor_audit_case(
    cve_id="CVE-TEST-1",
    root_cause_case_dir=case_dir,
    previous_case_dir=previous_dir,
    repo_path=tmp_path / "repo",
    out_dir=out_dir,
    source_reader=FixtureSourceReader(),
    command_runner=command_runner,
  )

  assert result["status"] == "ingested_raw_candidate"
  assert result["backend_type"] == "replay_existing_handoff"
  assert result["parse_status"] == "json"
  assert result["contract_ok"] is True
  assert result["candidate_commit_count"] == 1
  assert result["blame_status"] == "success"
  assert (out_dir / "raw_szz_handoff_response.txt").read_text(encoding="utf-8") == json.dumps(handoff)
  assert not (out_dir / "szz_handoff_prompt.txt").exists()
  commits = json.loads((out_dir / "candidate_commits.json").read_text(encoding="utf-8"))
  assert commits[0]["lifecycle"] == "raw_candidate"


def test_parse_error_retains_compaction_metrics(tmp_path: Path):
  case_dir = tmp_path / "root-cause" / "CVE-TEST-1"
  out_dir = tmp_path / "audit" / "CVE-TEST-1"
  _write_root_cause_case(case_dir)

  result = run_szz_anchor_audit_case(
    cve_id="CVE-TEST-1",
    root_cause_case_dir=case_dir,
    repo_path=tmp_path / "repo",
    out_dir=out_dir,
    backend=MalformedSzzBackend(),
    source_reader=FixtureSourceReader(),
  )

  assert result["status"] == "handoff_parse_error"
  assert result["original_candidate_count"] == 1
  assert result["compacted_candidate_count"] == 1
  assert result["prompt_bytes"] > 0


def test_contract_rejection_retains_compaction_metrics(tmp_path: Path):
  case_dir = tmp_path / "root-cause" / "CVE-TEST-1"
  out_dir = tmp_path / "audit" / "CVE-TEST-1"
  _write_root_cause_case(case_dir)

  result = run_szz_anchor_audit_case(
    cve_id="CVE-TEST-1",
    root_cause_case_dir=case_dir,
    repo_path=tmp_path / "repo",
    out_dir=out_dir,
    backend=InventedCandidateSzzBackend(),
    source_reader=FixtureSourceReader(),
  )

  assert result["status"] == "contract_rejected"
  assert result["original_candidate_count"] == 1
  assert result["compacted_candidate_count"] == 1
  assert result["prompt_bytes"] > 0


def test_batch_report_names_anchor_and_candidate_quality_metrics():
  summary = {
    "cases_total": 1,
    "candidate_inventory_coverage": 1.0,
    "statement_localization_precision": None,
    "statement_localization_precision_status": "requires_manual_anchor_review",
    "handoff_parse_success": 1,
    "handoff_contract_acceptance": 1,
    "resolved_anchor_count": 1,
    "direct_old_side_anchor_count": 1,
    "add_only_semantic_anchor_count": 0,
    "context_only_noise_rate": 0.0,
    "blame_worthy_anchor_rate": 1.0,
    "blame_success_rate": 1.0,
    "candidate_recall_diagnostic": 1.0,
    "candidates_per_anchor": 2.0,
    "fix_family_anchor_coverage": {"anchored": 1, "total": 1, "rate": 1.0},
    "fix_family_accounted_coverage": {"accounted": 1, "total": 1, "rate": 1.0},
    "fix_family_uncertain_coverage": {"uncertain": 0, "total": 1, "rate": 0.0},
    "multi_anchor_coverage": 0,
    "shallow_history_cases": [],
    "fix_series_candidates_excluded": 0,
    "invented_ids": [],
    "git_query_count": 4,
    "total_duration_s": 1.2,
    "total_raw_response_chars": 100,
  }

  report = _render_batch_report(summary, [])

  for term in (
    "Fixture mode only proves pipeline integrity",
    "Candidate inventory coverage",
    "Statement localization precision",
    "Direct old-side anchors",
    "Add-only semantic anchors",
    "Context-only noise rate",
    "Blame-worthy anchor rate",
    "Candidate recall diagnostic",
    "Candidates per anchor",
    "Fix-family coverage",
    "Fix-series candidates excluded",
    "Git query count",
  ):
    assert term in report
  assert "Statement localization coverage" not in report


def test_cve_2020_13164_preserves_every_root_cause_hunk_before_truncation():
  inventory, root_cause = _load_compaction_fixture("CVE-2020-13164")
  compact = _selection_inventory(inventory, root_cause, top_k_per_patch_family=40)
  retained_hunks = {item["patch_hunk_id"] for item in compact["candidates"]}

  assert retained_hunks >= {"hunk:nfs:1", "hunk:nfs:8"}
  assert compact["root_cause_hunks_total"] == 2
  assert compact["root_cause_hunks_preserved"] == 2
  assert compact["root_cause_hunks_dropped"] == 0
  assert compact["root_cause_hunk_retention_rate"] == 1.0


def test_cve_2020_14212_preserves_each_equivalent_fix_commit_even_over_budget():
  inventory, root_cause = _load_compaction_fixture("CVE-2020-14212")

  compact = _selection_inventory(inventory, root_cause, top_k_per_patch_family=1)
  retained_commits = {item["fix_commit_id"] for item in compact["candidates"]}

  assert retained_commits == {"fix:ffmpeg:upstream", "fix:ffmpeg:backport"}
  assert compact["fix_commits_total"] == 2
  assert compact["fix_commits_prompt_covered"] == 2
  assert compact["mandatory_candidate_count"] == 2
  assert compact["budget_overflow_count"] == 1


def test_cve_2022_0171_preserves_add_only_function_body_for_root_cause_hunk():
  inventory, root_cause = _load_compaction_fixture("CVE-2022-0171")

  compact = _selection_inventory(inventory, root_cause, top_k_per_patch_family=1)
  by_hunk = {item["patch_hunk_id"]: item for item in compact["candidates"]}

  assert by_hunk["hunk:sev:3"]["candidate_source"] == "pre_fix_function_body"
  assert compact["root_cause_hunks_total"] == 2
  assert compact["root_cause_hunks_preserved"] == 2


def test_candidates_without_patch_family_are_isolated_not_appended():
  inventory, root_cause = _load_compaction_fixture("CVE-2020-13164")
  inventory["candidates"].append(
    {
      "candidate_id": "candidate:orphan",
      "patch_family_id": "",
      "fix_commit_id": "fix:nfs",
      "patch_hunk_id": "hunk:orphan",
      "candidate_source": "deleted_line",
      "change_type": "delete",
      "line_text": "orphan();",
      "source_file": True,
      "git_observation_refs": ["obs:nfs"],
    }
  )

  compact = _selection_inventory(inventory, root_cause, top_k_per_patch_family=1)

  assert "candidate:orphan" not in {item["candidate_id"] for item in compact["candidates"]}
  assert compact["candidate_without_patch_family"] == 1


def test_censored_cases_do_not_enter_blame_success_denominator(tmp_path: Path):
  results = [
    {
      "cve_id": "CVE-EVAL",
      "status": "ingested_raw_candidate",
      "contract_ok": True,
      "parse_status": "json",
      "original_candidate_count": 2,
      "compacted_candidate_count": 2,
      "prompt_bytes": 100,
      "resolved_anchor_count": 2,
      "blame_success_anchor_count": 1,
      "blame_status": "partial",
      "patch_family_coverage": {},
      "fix_commit_coverage": {},
    },
    {
      "cve_id": "CVE-SHALLOW",
      "status": "raw_candidate_censored",
      "contract_ok": True,
      "parse_status": "json",
      "original_candidate_count": 3,
      "compacted_candidate_count": 2,
      "prompt_bytes": 120,
      "resolved_anchor_count": 3,
      "blame_success_anchor_count": 0,
      "blame_status": "shallow_history",
      "patch_family_coverage": {},
      "fix_commit_coverage": {},
    },
  ]

  summary = _aggregate_summary(results, tmp_path)

  assert summary["requested_count"] == 2
  assert summary["inventory_built_count"] == 2
  assert summary["agent_accepted_count"] == 2
  assert summary["blame_evaluable_count"] == 1
  assert summary["censored_count"] == 1
  assert summary["blame_success_rate"] == 0.5
