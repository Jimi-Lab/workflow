from __future__ import annotations

import csv
import json
from pathlib import Path

from vulngraph.agent_backends.fixture import FixtureRootCauseBackend
from vulngraph.workflows.semantic_baseline import (
  FAILURE_CATEGORIES,
  SEMANTIC_EVALUATION_COLUMNS,
  aggregate_evaluation_metrics,
  build_compact_review_packet,
  ensure_semantic_artifacts,
  seed_baseline_graph,
)
from vulngraph.services import VulnGraphClient


def _write_dataset(path: Path) -> None:
  data = {
    "CVE-KEEP": {
      "repo": "demo",
      "CWE": ["CWE-787"],
      "fixing_commits": [["abc123"]],
      "affected_version": ["v1"],
    },
    "CVE-DROP": {
      "repo": "other",
      "CWE": ["CWE-20"],
      "fixing_commits": [["def456"]],
      "affected_version": ["v2"],
    },
  }
  path.write_text(json.dumps(data), encoding="utf-8")


def test_seed_baseline_graph_imports_only_requested_cves(tmp_path: Path):
  dataset = tmp_path / "dataset.json"
  _write_dataset(dataset)
  client = VulnGraphClient(tmp_path / "graph")

  result = seed_baseline_graph(
    client,
    ["CVE-KEEP"],
    dataset=dataset,
    repo_root=tmp_path / "repos",
  )
  materialized = client.materialize()

  cve_ids = {node.content.get("cve_id") for node in materialized.nodes if node.type == "CVE"}
  assert cve_ids == {"CVE-KEEP"}
  assert result["missing_cves"] == []
  assert all(item["cve_id"] == "CVE-KEEP" for item in result["patch_results"])


def test_ensure_semantic_artifacts_writes_evaluation_review_and_taxonomy(tmp_path: Path):
  dataset = tmp_path / "dataset.json"
  _write_dataset(dataset)
  cve_dir = tmp_path / "out" / "CVE-KEEP"
  cve_dir.mkdir(parents=True)
  (cve_dir / "root_cause_packet.json").write_text("{}", encoding="utf-8")
  summary = {
    "total": 1,
    "real_opencode_invocation_count": 1,
    "ingested_raw_count": 1,
    "structurally_rejected_count": 0,
    "parse_error_count": 0,
    "backend_failed_count": 0,
    "valid_json_count": 1,
    "json_parse_status_counts": {"json": 1},
    "empty_message_count": 0,
    "evidence_backed_hypothesis_count": 1,
    "invented_id_cases": [],
    "lint_ingestion_parity_count": 1,
    "avg_packet_size_bytes": 10,
    "avg_evidence_trace_size_bytes": 20,
    "avg_raw_response_size_bytes": 30,
    "total_duration_s": 1.2,
    "results": [
      {
        "cve_id": "CVE-KEEP",
        "status": "ingested_raw",
        "json_parse_status": "json",
        "contract_ok": True,
        "hypothesis_count": 1,
        "evidence_backed_hypothesis_count": 1,
        "fix_commit_count": 1,
        "run_dir": str(cve_dir),
      }
    ],
  }
  seed_result = {"patch_results": [{"cve_id": "CVE-KEEP", "status": "skipped", "error": "repo path not found"}]}

  artifacts = ensure_semantic_artifacts(
    tmp_path / "out",
    summary=summary,
    dataset=dataset,
    cve_ids=["CVE-KEEP"],
    provider_id="google",
    model_id="gemini-2.5-flash",
    command="python scripts/run_root_cause_semantic_baseline.py ...",
    seed_result=seed_result,
  )

  assert artifacts["evaluation_csv"].exists()
  rows = list(csv.DictReader(artifacts["evaluation_csv"].open(newline="", encoding="utf-8")))
  assert rows[0]["cve_id"] == "CVE-KEEP"
  assert rows[0]["mechanism_correct"] == ""
  assert list(rows[0].keys()) == SEMANTIC_EVALUATION_COLUMNS

  taxonomy = json.loads(artifacts["failure_taxonomy"].read_text(encoding="utf-8"))
  assert set(taxonomy["categories"]) == set(FAILURE_CATEGORIES)
  assert taxonomy["categories"]["data_import"]["count"] == 1

  review = artifacts["semantic_review_template"].read_text(encoding="utf-8")
  assert "CVE-KEEP" in review
  assert "VulnerablePredicate" in review

  per_cve_report = cve_dir / "report.md"
  assert per_cve_report.exists()
  assert "Manual Semantic Review" in per_cve_report.read_text(encoding="utf-8")


def test_fixture_backend_is_not_reported_as_real_opencode_by_semantic_artifacts(tmp_path: Path):
  dataset = tmp_path / "dataset.json"
  _write_dataset(dataset)
  cve_dir = tmp_path / "out" / "CVE-KEEP"
  cve_dir.mkdir(parents=True)
  summary = {
    "total": 1,
    "real_opencode_invocation_count": 0,
    "ingested_raw_count": 1,
    "structurally_rejected_count": 0,
    "parse_error_count": 0,
    "backend_failed_count": 0,
    "valid_json_count": 1,
    "json_parse_status_counts": {"json": 1},
    "empty_message_count": 0,
    "evidence_backed_hypothesis_count": 1,
    "invented_id_cases": [],
    "lint_ingestion_parity_count": 1,
    "avg_packet_size_bytes": 10,
    "avg_evidence_trace_size_bytes": 20,
    "avg_raw_response_size_bytes": 30,
    "total_duration_s": 1.2,
    "results": [
      {
        "cve_id": "CVE-KEEP",
        "backend_type": FixtureRootCauseBackend.backend_type,
        "status": "ingested_raw",
        "json_parse_status": "json",
        "run_dir": str(cve_dir),
      }
    ],
  }

  artifacts = ensure_semantic_artifacts(
    tmp_path / "out",
    summary=summary,
    dataset=dataset,
    cve_ids=["CVE-KEEP"],
    provider_id="fixture",
    model_id="fixture",
    command="fixture command",
    seed_result={"patch_results": []},
  )

  report = artifacts["report"].read_text(encoding="utf-8")
  assert "Real OpenCode invocation count: 0" in report
  assert "fixture" in report


def test_build_compact_review_packet_summarizes_evidence_and_failure_classes(tmp_path: Path):
  out = tmp_path / "run"
  cve = out / "CVE-2020-19667"
  cve.mkdir(parents=True)
  (out / "summary.json").write_text(
    json.dumps(
      {
        "selected_cves": ["CVE-2020-19667"],
        "results": [
          {
            "cve_id": "CVE-2020-19667",
            "status": "rejected",
            "json_parse_status": "fenced_json",
            "contract_ok": False,
            "run_dir": str(cve),
          }
        ],
      }
    ),
    encoding="utf-8",
  )
  (cve / "root_cause_packet.json").write_text("{}", encoding="utf-8")
  (cve / "evidence_trace.json").write_text(
    json.dumps(
      {
        "git_observations": [
          {
            "id": "obs-1",
            "observation_kind": "patch_diff",
            "valid_evidence": True,
            "command_ref": "cmd-1",
            "tool_output_ref": "out-1",
            "claim": "diff supports memset",
            "fix_commit_ids": ["fix-1"],
            "patch_hunk_ids": ["hunk-1"],
            "file_ids": ["file-1"],
            "function_ids": [],
            "snippet": "memset(target,0,sizeof(target));",
          }
        ]
      }
    ),
    encoding="utf-8",
  )
  (cve / "parsed_output.json").write_text(
    json.dumps(
      {
        "root_cause_hypotheses": [
          {
            "hypothesis_id": "hyp-1",
            "summary": "uninitialized buffers",
            "mechanism": "missing initialization",
            "vulnerable_predicate_ids": ["vp-1"],
            "fix_predicate_ids": ["fp-1"],
            "anchor_ids": ["anchor-1"],
            "git_observation_refs": ["obs-1"],
          }
        ],
        "vulnerable_predicates": [{"predicate_id": "vp-1", "description": "target buffer may contain stale data", "anchor_ids": ["anchor-1"], "git_observation_refs": ["obs-1"]}],
        "fix_predicates": [{"predicate_id": "fp-1", "description": "target buffer is zeroed", "anchor_ids": ["anchor-1"], "git_observation_refs": ["obs-1"]}],
        "code_anchors": [
          {
            "anchor_id": "anchor-1",
            "path": "coders/xpm.c",
            "function": "ReadXPMImage",
            "function_id": None,
            "patch_hunk_id": "hunk-1",
            "fix_commit_id": "fix-1",
            "git_observation_refs": ["obs-1"],
          }
        ],
      }
    ),
    encoding="utf-8",
  )
  (cve / "contract_lint.json").write_text(
    json.dumps({"ok": False, "errors": ["anchor anchor-1 names a function without function_id"], "taxonomy": {"unknown_function_id": 1}}),
    encoding="utf-8",
  )
  (cve / "structural_validation.json").write_text(
    json.dumps({"ok": False, "accepted_hypothesis_ids": [], "errors": ["anchor anchor-1 names a function without function_id"], "anchor_results": {"anchor-1": {"gate_valid": False, "gate_errors": ["missing function_id"]}}}),
    encoding="utf-8",
  )
  (cve / "ingestion_result.json").write_text(json.dumps({"status": "rejected", "errors": ["missing function binding"]}), encoding="utf-8")

  packet = build_compact_review_packet(out)

  item = packet["cves"][0]
  assert item["failure_class"] == "structural_gate / function_binding failure"
  assert item["agent_hypotheses"][0]["summary"] == "uninitialized buffers"
  assert item["anchors"][0]["function"] == "ReadXPMImage"
  assert item["anchors"][0]["gate_valid"] is False
  assert item["supporting_git_observations"][0]["id"] == "obs-1"
  assert item["manual_judgement_basis"]["overall_root_cause_correct"]["value"] == ""


def test_compact_review_packet_classifies_missing_anchor_path_parse_error(tmp_path: Path):
  out = tmp_path / "run"
  cve = out / "CVE-2022-0171"
  cve.mkdir(parents=True)
  (out / "summary.json").write_text(json.dumps({"selected_cves": ["CVE-2022-0171"], "results": [{"cve_id": "CVE-2022-0171", "status": "parse_error", "run_dir": str(cve)}]}), encoding="utf-8")
  for name, payload in {
    "root_cause_packet.json": {},
    "evidence_trace.json": {"git_observations": []},
    "contract_lint.json": {"ok": False, "errors": []},
    "structural_validation.json": {"ok": False, "errors": []},
    "ingestion_result.json": {"status": "parse_error"},
  }.items():
    (cve / name).write_text(json.dumps(payload), encoding="utf-8")
  (cve / "parse_error.json").write_text(json.dumps({"error": "code_anchors.1.path\n  Field required"}), encoding="utf-8")

  packet = build_compact_review_packet(out)

  assert packet["cves"][0]["failure_class"] == "schema_validation_missing_path"


def test_aggregate_evaluation_metrics_uses_only_filled_manual_labels(tmp_path: Path):
  path = tmp_path / "evaluation.csv"
  rows = [
    {
      "cve_id": "CVE-1",
      "fix_commit_count": "2",
      "ingested_raw": "1",
      "overall_root_cause_correct": "1",
      "anchor_hunk_correct": "1",
      "evidence_link_precise": "1",
      "unsupported_inference": "0",
      "fix_set_complete": "1",
    },
    {
      "cve_id": "CVE-2",
      "fix_commit_count": "1",
      "ingested_raw": "1",
      "overall_root_cause_correct": "0",
      "anchor_hunk_correct": "0",
      "evidence_link_precise": "1",
      "unsupported_inference": "1",
      "fix_set_complete": "",
    },
    {
      "cve_id": "CVE-3",
      "fix_commit_count": "1",
      "ingested_raw": "0",
      "overall_root_cause_correct": "",
      "anchor_hunk_correct": "",
      "evidence_link_precise": "",
      "unsupported_inference": "",
      "fix_set_complete": "",
    },
  ]
  with path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=SEMANTIC_EVALUATION_COLUMNS)
    writer.writeheader()
    for row in rows:
      full = {key: "" for key in SEMANTIC_EVALUATION_COLUMNS}
      full.update(row)
      writer.writerow(full)

  metrics = aggregate_evaluation_metrics(path)

  assert metrics["schema_acceptance_rate"]["value"] == 2 / 3
  assert metrics["semantic_correct_rate_among_accepted_cases"]["value"] == 0.5
  assert metrics["overall_correct_rate_among_all_cases"]["value"] is None
  assert metrics["overall_correct_rate_among_all_cases"]["ready"] is False
  assert metrics["anchor_hunk_precision"]["value"] == 0.5
  assert metrics["evidence_link_precision"]["value"] == 1.0
  assert metrics["unsupported_inference_rate"]["value"] == 0.5
  assert metrics["multi_fix_semantic_coverage"]["value"] == 1.0
