from __future__ import annotations

import json
from pathlib import Path

from vulngraph.workflows.szz_release_line_conversion_probe import (
  apply_conversion_strategies,
  build_release_line_groups,
  parse_release_version,
  run_release_line_conversion_probe,
)


def test_parse_release_version_extracts_last_semantic_token() -> None:
  assert parse_release_version("v5.10").major_minor == "5.10"
  assert parse_release_version("qemu-4.2.1").major_minor == "4.2"
  assert parse_release_version("wireshark-3.2.10").major_minor == "3.2"
  assert parse_release_version("release-1-2-3").major_minor == "1.2"
  assert parse_release_version("wg1n6848") is None


def test_release_line_groups_report_line_level_metrics() -> None:
  groups = build_release_line_groups(
    ground_truth_tags={"v5.10.1", "v5.10.2"},
    predicted_tags={"v5.10.1", "v5.10.3", "v5.11.1"},
  )

  by_line = {item["line_id"]: item for item in groups}
  assert by_line["5.10"]["ground_truth_tags"] == ["v5.10.1", "v5.10.2"]
  assert by_line["5.10"]["false_positive_tags"] == ["v5.10.3"]
  assert by_line["5.10"]["false_negative_tags"] == ["v5.10.2"]
  assert by_line["5.11"]["ground_truth_tags"] == []
  assert by_line["5.11"]["false_positive_tags"] == ["v5.11.1"]


def test_conversion_strategies_keep_baseline_and_mark_gt_line_upper_bound() -> None:
  tag_diagnostics = [
    {
      "tag": "v5.10.3",
      "known_fix_reachable": "yes",
      "tag_after_fix": True,
      "line_id": "5.10",
    },
    {
      "tag": "v5.11.1",
      "known_fix_reachable": "no",
      "tag_after_fix": True,
      "line_id": "5.11",
    },
  ]

  strategies = apply_conversion_strategies(
    predicted_tags={"v5.10.1", "v5.10.3", "v5.11.1"},
    ground_truth_tags={"v5.10.1"},
    tag_diagnostics=tag_diagnostics,
  )

  assert strategies["direct_release_reachability"]["predicted_tags"] == ["v5.10.1", "v5.10.3", "v5.11.1"]
  assert strategies["same_line_trim"]["diagnostic_uses_ground_truth_line"] is True
  assert strategies["same_line_trim"]["predicted_tags"] == ["v5.10.1", "v5.10.3"]
  assert strategies["fix_reachable_exclusion"]["predicted_tags"] == ["v5.10.1", "v5.11.1"]
  assert strategies["time_after_fix_exclusion"]["uncertainty"]


def test_run_release_line_conversion_probe_writes_required_artifacts_without_forbidden_fields(tmp_path: Path) -> None:
  dataset = tmp_path / "dataset.json"
  repo_root = tmp_path / "repos"
  anchor_run = tmp_path / "anchor"
  version_run = tmp_path / "version"
  out_dir = tmp_path / "out"
  (repo_root / "repo").mkdir(parents=True)
  (anchor_run / "CVE-X").mkdir(parents=True)
  version_run.mkdir()

  dataset.write_text(
    json.dumps(
      {
        "CVE-X": {
          "repo": "repo",
          "fixing_commits": [["fix"]],
          "affected_version": ["v1.2.1"],
        }
      }
    ),
    encoding="utf-8",
  )
  (version_run / "ranking_diagnostics.json").write_text(
    json.dumps(
      {
        "CVE-X": {
          "top1_candidate_commit": "candidate",
          "release_tag_universe": {
            "top1": {"predicted_tags": ["v1.2.1", "v1.2.2"]},
            "oracle": {"oracle_best_candidate_commit": "candidate", "predicted_tags": ["v1.2.1"]},
          },
        }
      }
    ),
    encoding="utf-8",
  )
  (anchor_run / "CVE-X" / "candidate_commits.json").write_text(
    json.dumps(
      [
        {
          "commit_sha": "candidate",
          "lifecycle": "raw_candidate",
          "anchor_ids": ["anchor-1"],
          "roles": ["sink"],
          "line_provenance": [
            {
              "anchor_id": "anchor-1",
              "old_line": 7,
              "line_text": "danger();",
              "path_before": "src/a.c",
              "blamed_commit_sha": "candidate",
            }
          ],
        }
      ]
    ),
    encoding="utf-8",
  )
  (anchor_run / "CVE-X" / "resolved_pre_fix_anchors.json").write_text(
    json.dumps(
      [
        {
          "anchor_id": "anchor-1",
          "role": "sink",
          "path_before": "src/a.c",
          "old_line_start": 7,
          "line_text": "danger();",
        }
      ]
    ),
    encoding="utf-8",
  )

  class FakeRunner:
    def is_ancestor(self, ancestor: str, descendant: str) -> str:
      if ancestor == "candidate":
        return "yes"
      return "no"

    def commit_time(self, repo_path: Path, commit_sha: str) -> int | None:
      del repo_path
      if commit_sha == "fix":
        return 200
      if commit_sha.startswith("v"):
        return 300
      return 100

  summary = run_release_line_conversion_probe(
    anchor_audit_run=anchor_run,
    version_probe_run=version_run,
    dataset=dataset,
    repo_root=repo_root,
    out_dir=out_dir,
    cve_ids=["CVE-X"],
    git_runner=FakeRunner(),
  )

  assert summary["cases_total"] == 1
  assert (out_dir / "per_cve_release_line_diagnostic.json").exists()
  assert (out_dir / "per_tag_false_positive_diagnostic.csv").exists()
  assert (out_dir / "per_strategy_metrics.csv").exists()
  assert (out_dir / "manual_anchor_review_residual_3.csv").exists()
  serialized = "".join(path.read_text(encoding="utf-8") for path in out_dir.glob("*"))
  assert '"validated_bic"' not in serialized
  assert '"correct_bic"' not in serialized
  assert '"affected_versions"' not in serialized
