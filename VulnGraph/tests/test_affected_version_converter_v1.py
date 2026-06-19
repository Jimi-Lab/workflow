from __future__ import annotations

import json
from pathlib import Path

from vulngraph.workflows.affected_version_converter_v1 import (
  convert_affected_versions_for_cve,
  discover_boundary_cves,
  p01_metrics,
  run_affected_version_converter_v1,
)


def _write_json(path: Path, data: object) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


class FakeRunner:
  def __init__(self) -> None:
    self.tags = ["v1.0", "v1.1", "v1.2rc1", "test-tag"]
    self.ancestor = {
      ("a" * 40, "v1.0"): "yes",
      ("a" * 40, "v1.1"): "yes",
      ("f" * 40, "v1.0"): "no",
      ("f" * 40, "v1.1"): "yes",
    }
    self.trace = []

  def list_tags(self, repo_path: Path) -> list[str]:
    return list(self.tags)

  def set_repo(self, repo_path: Path) -> None:
    return None

  def is_ancestor(self, ancestor: str, descendant: str) -> str:
    return self.ancestor.get((ancestor, descendant), "no")

  def tags_containing(self, commit_sha: str):
    return None


def _make_boundary_case(tmp_path: Path) -> tuple[Path, Path, Path]:
  boundary = tmp_path / "boundary"
  dataset = tmp_path / "dataset.json"
  repo_root = tmp_path / "repo"
  cve_id = "CVE-CONVERT-1"
  _write_json(
    dataset,
    {
      cve_id: {
        "repo": "repo",
        "fixing_commits": [["f" * 40]],
        "affected_version": ["v1.0"],
      }
    },
  )
  _write_json(
    boundary / cve_id / "judge_boundary_result.json",
    {"cve_id": cve_id, "contract_ok": True, "lifecycle": "raw_boundary_event_accepted"},
  )
  _write_json(
    boundary / cve_id / "parsed_boundary_output.json",
    {
      "schema_version": "judge_boundary_output_v1",
      "cve_id": cve_id,
      "candidate_judgments": [],
      "selected_boundary_events": [
        {"candidate_id": "cand-1", "candidate_commit_sha": "a" * 40, "boundary_role": "introduction", "evidence_refs": ["candidate:cand-1"]}
      ],
      "uncertainty": [],
      "rejected_candidates": [],
    },
  )
  _write_json(
    boundary / cve_id / "judge_boundary_input_v1.json",
    {
      "schema_version": "judge_boundary_input_v1",
      "cve_id": cve_id,
      "candidate_set": [
        {
          "candidate_id": "cand-1",
          "candidate_commit_sha": "a" * 40,
          "candidate_source": "strong",
          "risk_flags": [],
          "evidence_refs": ["candidate:cand-1"],
        }
      ],
    },
  )
  return boundary, dataset, repo_root


def test_converter_uses_release_tags_and_excludes_fixed_tags(tmp_path: Path) -> None:
  boundary, dataset, repo_root = _make_boundary_case(tmp_path)

  prediction = convert_affected_versions_for_cve(
    cve_id="CVE-CONVERT-1",
    boundary_run=boundary,
    dataset=dataset,
    repo_root=repo_root,
    git_runner=FakeRunner(),
  )

  assert prediction["affected_versions"] == ["v1.0"]
  assert "v1.2rc1" not in prediction["affected_versions"]
  assert prediction["lifecycle"] == "deterministic_converter_v1_prediction"
  assert prediction["evidence"][0]["candidate_reachable_to_tag"] == "yes"
  assert prediction["evidence"][0]["fix_reachable_to_tag"] == "no"


def test_p01_metrics_exact_nmr_and_micro_scores() -> None:
  rows = [
    {"cve_id": "A", "predicted": {"v1"}, "ground_truth": {"v1"}},
    {"cve_id": "B", "predicted": {"v1"}, "ground_truth": {"v1", "v2"}},
  ]

  metrics = p01_metrics(rows)

  assert metrics["exact_accuracy"] == 0.5
  assert metrics["nmr"] == 0.5
  assert metrics["version_micro_precision"] == 1.0
  assert metrics["version_micro_recall"] == 2 / 3


def test_converter_batch_writes_public_predictions_and_metrics(tmp_path: Path) -> None:
  boundary, dataset, repo_root = _make_boundary_case(tmp_path)
  out_dir = tmp_path / "out"

  summary = run_affected_version_converter_v1(
    cve_ids=["CVE-CONVERT-1"],
    boundary_run=boundary,
    dataset=dataset,
    repo_root=repo_root,
    out_dir=out_dir,
    git_runner=FakeRunner(),
  )

  assert summary["cases_total"] == 1
  assert (out_dir / "per_cve_predictions.jsonl").exists()
  assert (out_dir / "paper_metrics.json").exists()
  prediction = json.loads((out_dir / "per_cve_predictions.jsonl").read_text(encoding="utf-8").splitlines()[0])
  assert prediction["affected_versions"] == ["v1.0"]
  assert prediction["lifecycle"] == "deterministic_converter_v1_prediction"


def test_discover_boundary_cves_supports_flat_judge_boundary_layout(tmp_path: Path) -> None:
  _write_json(tmp_path / "CVE-A" / "judge_boundary_result.json", {"contract_ok": True})
  _write_json(tmp_path / "CVE-B" / "judge_boundary_result.json", {"contract_ok": False})
  _write_json(tmp_path / "not-a-case" / "other.json", {})

  assert discover_boundary_cves(tmp_path) == ["CVE-A", "CVE-B"]
