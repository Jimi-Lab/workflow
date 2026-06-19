from __future__ import annotations

import json
from pathlib import Path

from vulngraph.workflows.szz_anchor_version_probe import (
  CandidateVersionResult,
  DirectReachabilityRunner,
  build_tag_universe,
  classify_false_positive_tags,
  choose_oracle_candidate,
  direct_reachability_prediction,
  inspect_dataset_schema,
  rank_candidate_commits,
  run_szz_anchor_version_probe,
  set_metrics,
)


def test_set_metrics_precision_recall_f1_exact_match() -> None:
  metrics = set_metrics({"v1", "v2"}, {"v2", "v3"})

  assert metrics["precision"] == 0.5
  assert metrics["recall"] == 0.5
  assert metrics["f1"] == 0.5
  assert metrics["exact_match"] is False
  assert metrics["true_positive_count"] == 1
  assert metrics["false_positive_count"] == 1
  assert metrics["false_negative_count"] == 1


def test_candidate_ranking_does_not_use_ground_truth() -> None:
  candidates = [
    {
      "commit_sha": "bad",
      "excluded": False,
      "vote_count": 1,
      "roles": ["data_source"],
      "selection_modes": ["add_only_semantic_target"],
      "line_provenance": [{"boundary_marker": False, "author_time": 10}],
    },
    {
      "commit_sha": "good",
      "excluded": False,
      "vote_count": 1,
      "roles": ["dangerous_use"],
      "selection_modes": ["modified_old_side"],
      "line_provenance": [{"boundary_marker": False, "author_time": 1}],
    },
  ]

  ranked = rank_candidate_commits(candidates, fix_times=[100], ground_truth_affected_versions={"bad"})

  assert [item["commit_sha"] for item in ranked] == ["good", "bad"]
  assert all("ground_truth" not in json.dumps(item) for item in ranked)


def test_oracle_upper_bound_is_marked_diagnostic() -> None:
  results = [
    CandidateVersionResult(
      commit_sha="c1",
      universe_name="release_tag_universe",
      predicted_tags={"v1"},
      metrics={"precision": 0.0, "recall": 0.0, "f1": 0.0, "exact_match": False},
      unknown_tags=[],
      false_positive_taxonomy={},
    ),
    CandidateVersionResult(
      commit_sha="c2",
      universe_name="release_tag_universe",
      predicted_tags={"v2"},
      metrics={"precision": 1.0, "recall": 1.0, "f1": 1.0, "exact_match": True},
      unknown_tags=[],
      false_positive_taxonomy={},
    ),
  ]

  oracle = choose_oracle_candidate(results)

  assert oracle["oracle_best_candidate_commit"] == "c2"
  assert oracle["diagnostic_only"] is True
  assert "validated_bic" not in oracle
  assert "correct_bic" not in oracle
  assert "affected_versions" not in oracle
  assert oracle["predicted_tags"] == ["v2"]


def test_empty_oracle_candidate_scores_zero_against_non_empty_ground_truth() -> None:
  oracle = choose_oracle_candidate([], ground_truth={"v1"})

  assert oracle["oracle_best_candidate_commit"] == ""
  assert oracle["predicted_tags"] == []
  assert oracle["metrics"]["precision"] == 0.0
  assert oracle["metrics"]["recall"] == 0.0
  assert oracle["metrics"]["f1"] == 0.0
  assert oracle["metrics"]["exact_match"] is False


def test_direct_reachability_conversion_uses_candidate_and_direct_fix_reachability() -> None:
  class FakeRunner(DirectReachabilityRunner):
    def is_ancestor(self, ancestor: str, descendant: str) -> str:
      reachable = {
        ("candidate", "v1"): True,
        ("candidate", "v2"): True,
        ("fix", "v1"): False,
        ("fix", "v2"): True,
      }
      return "yes" if reachable.get((ancestor, descendant), False) else "no"

  result = direct_reachability_prediction(
    repo_path=Path("repo"),
    candidate_commit="candidate",
    fixing_commits=["fix"],
    tags=["v1", "v2"],
    runner=FakeRunner(),
  )

  assert result.predicted_tags == {"v1"}
  assert result.unknown_tags == []


def test_release_tag_universe_filters_non_release_noise() -> None:
  diagnostics = build_tag_universe(
    "repo",
    [
      "v1.0.0",
      "v1.0.1-rc1",
      "v1.0.1rc1",
      "wireshark-2.2.0rc1",
      "ssv0.9.0rc0",
      "v2.0.0-beta",
      "v2.0.0beta1",
      "backup/v3.0.0",
      "dev-snapshot-4.0",
      "wg1n6848",
      "OpenSSL_1_1_1",
      "OpenSSL_1_1_1f",
      "curl-7_68_0",
      "wireshark-3.2.1",
      "internal-test-v5",
    ],
  )

  assert set(diagnostics["release_tag_universe"]) == {
    "OpenSSL_1_1_1",
    "OpenSSL_1_1_1f",
    "curl-7_68_0",
    "v1.0.0",
    "wireshark-3.2.1",
  }
  assert diagnostics["all_tag_count"] == 15
  assert diagnostics["release_tag_count"] == 5
  assert "v1.0.1-rc1" in diagnostics["filtered_non_release_tags"]
  assert "v1.0.1rc1" in diagnostics["filtered_non_release_tags"]
  assert "wireshark-2.2.0rc1" in diagnostics["filtered_non_release_tags"]
  assert "ssv0.9.0rc0" in diagnostics["filtered_non_release_tags"]
  assert "wg1n6848" in diagnostics["filtered_non_release_tags"]
  assert "backup/v3.0.0" in diagnostics["filtered_non_release_tags"]


def test_top1_tie_breaker_uses_fixing_commit_time_not_candidate_pool_time() -> None:
  candidates = [
    {
      "commit_sha": "a-old",
      "excluded": False,
      "vote_count": 1,
      "roles": ["dangerous_use"],
      "selection_modes": ["modified_old_side"],
      "line_provenance": [{"fix_commit_sha": "fix", "committer_time": 10}],
    },
    {
      "commit_sha": "z-near-fix",
      "excluded": False,
      "vote_count": 1,
      "roles": ["dangerous_use"],
      "selection_modes": ["modified_old_side"],
      "line_provenance": [{"fix_commit_sha": "fix", "committer_time": 900}],
    },
  ]

  ranked = rank_candidate_commits(candidates, fix_times_by_commit={"fix": 1000})

  assert [item["commit_sha"] for item in ranked] == ["z-near-fix", "a-old"]


def test_false_positive_predicted_tags_are_not_auto_branch_or_backport() -> None:
  buckets = classify_false_positive_tags(
    predicted_tags={"v1.0.0", "v1.0.1-rc1"},
    ground_truth_tags={"v1.0.2"},
    all_tags={"v1.0.0", "v1.0.1-rc1", "v1.0.2"},
    release_tags={"v1.0.0", "v1.0.2"},
  )

  assert buckets["false_positive_predicted_tags"] == ["v1.0.0", "v1.0.1-rc1"]
  assert buckets["non_release_tag_noise"] == ["v1.0.1-rc1"]
  assert buckets["release_line_overreach"] == ["v1.0.0"]
  assert buckets["branch_or_backport_limit"] == []


def test_schema_inspect_missing_affected_version_fails_closed(tmp_path: Path) -> None:
  dataset = tmp_path / "dataset.json"
  dataset.write_text(json.dumps({"CVE-X": {"repo": "repo", "fixing_commits": [["a" * 40]]}}), encoding="utf-8")

  diagnostics = inspect_dataset_schema(dataset, ["CVE-X"], repo_root=tmp_path)

  assert diagnostics["cases"]["CVE-X"]["ok"] is False
  assert "missing_affected_version_field" in diagnostics["cases"]["CVE-X"]["problems"]


def test_probe_outputs_release_and_all_tag_metrics_without_forbidden_prediction_names(tmp_path: Path) -> None:
  dataset = tmp_path / "dataset.json"
  repo_root = tmp_path / "repos"
  anchor_run = tmp_path / "anchor-run"
  out_dir = tmp_path / "out"
  repo_root.mkdir()
  (repo_root / "repo").mkdir()
  anchor_run.mkdir()
  (anchor_run / "summary.json").write_text(json.dumps({"results": [{"cve_id": "CVE-X"}]}), encoding="utf-8")
  (anchor_run / "CVE-X").mkdir()
  (anchor_run / "CVE-X" / "candidate_commits.json").write_text("[]", encoding="utf-8")
  (anchor_run / "CVE-X" / "resolved_pre_fix_anchors.json").write_text("[]", encoding="utf-8")
  (anchor_run / "CVE-X" / "blame_trace.json").write_text(json.dumps({"line_records": []}), encoding="utf-8")
  (anchor_run / "CVE-X" / "ingestion_result.json").write_text(
    json.dumps({"status": "ingested_raw_candidate", "lifecycle": "raw_candidate"}), encoding="utf-8"
  )
  dataset.write_text(
    json.dumps({"CVE-X": {"repo": "repo", "fixing_commits": [["a" * 40]], "affected_version": ["v1"]}}),
    encoding="utf-8",
  )

  summary = run_szz_anchor_version_probe(
    anchor_run=anchor_run,
    dataset=dataset,
    repo_root=repo_root,
    out_dir=out_dir,
    git_runner=DirectReachabilityRunner(tags_by_repo={repo_root / "repo": ["v1"]}),
  )

  serialized = json.dumps(summary) + "".join(path.read_text(encoding="utf-8") for path in out_dir.glob("*"))
  assert "validated_bic" not in serialized
  assert "correct_bic" not in serialized
  assert '"affected_versions"' not in serialized
  assert '"predicted_affected_versions"' not in serialized
  assert '"predicted_tags"' in serialized
  assert '"diagnostic_all_tags_metrics"' in serialized
  assert '"release_evaluation_universe_metrics"' in serialized
  assert '"any_candidate_non_release_tag_noise_cases"' in serialized
  assert '"dominant_non_release_tag_noise_cases"' in serialized
  assert '"manual_anchor_review_required_cases"' in serialized
  assert '"dominant_requires_manual_review_cases"' in serialized
  assert '"non_release_tag_noise_cases"' not in serialized
  assert '"ground_truth_affected_versions"' in serialized
  per_cve_rows = (out_dir / "per_cve_version_probe.csv").read_text(encoding="utf-8")
  assert ",0.0,0.0,0.0,False," in per_cve_rows
  assert summary["release_evaluation_universe_metrics"]["top1"]["f1"] == 0.0
  assert summary["release_evaluation_universe_metrics"]["oracle"]["f1"] == 0.0
  assert summary["release_evaluation_universe_metrics"]["top1_exact_match_count"] == 0
  assert summary["release_evaluation_universe_metrics"]["oracle_exact_match_count"] == 0


def test_all_tags_and_release_universe_metrics_are_reported_separately(tmp_path: Path) -> None:
  class FakeRunner(DirectReachabilityRunner):
    def tags_containing(self, commit_sha: str) -> set[str] | None:
      if commit_sha == "candidate":
        return {"v1.0.0", "v1.0.1-rc1"}
      if commit_sha == "fix":
        return set()
      return set()

  dataset = tmp_path / "dataset.json"
  repo_root = tmp_path / "repos"
  anchor_run = tmp_path / "anchor-run"
  out_dir = tmp_path / "out"
  repo_root.mkdir()
  (repo_root / "repo").mkdir()
  case_dir = anchor_run / "CVE-X"
  case_dir.mkdir(parents=True)
  anchor_run.joinpath("summary.json").write_text(json.dumps({"results": [{"cve_id": "CVE-X"}]}), encoding="utf-8")
  case_dir.joinpath("candidate_commits.json").write_text(
    json.dumps(
      [
        {
          "commit_sha": "candidate",
          "lifecycle": "raw_candidate",
          "roles": ["dangerous_use"],
          "selection_modes": ["modified_old_side"],
          "line_provenance": [{"fix_commit_sha": "fix", "committer_time": 10}],
        }
      ]
    ),
    encoding="utf-8",
  )
  case_dir.joinpath("resolved_pre_fix_anchors.json").write_text("[]", encoding="utf-8")
  case_dir.joinpath("blame_trace.json").write_text(json.dumps({}), encoding="utf-8")
  case_dir.joinpath("ingestion_result.json").write_text(json.dumps({}), encoding="utf-8")
  dataset.write_text(
    json.dumps({"CVE-X": {"repo": "repo", "fixing_commits": [["fix"]], "affected_version": ["v1.0.0"]}}),
    encoding="utf-8",
  )

  summary = run_szz_anchor_version_probe(
    anchor_run=anchor_run,
    dataset=dataset,
    repo_root=repo_root,
    out_dir=out_dir,
    git_runner=FakeRunner(tags_by_repo={repo_root / "repo": ["v1.0.0", "v1.0.1-rc1"]}),
  )

  assert summary["diagnostic_all_tags_metrics"]["top1"]["precision"] == 0.5
  assert summary["release_evaluation_universe_metrics"]["top1"]["precision"] == 1.0
  tag_diagnostics = json.loads((out_dir / "tag_universe_diagnostics.json").read_text(encoding="utf-8"))
  assert tag_diagnostics["repos"]["repo"]["universe_used_for_primary_metrics"] == "release_tag_universe"


def test_probe_reports_strong_and_fallback_metric_groups(tmp_path: Path) -> None:
  class FakeRunner(DirectReachabilityRunner):
    def tags_containing(self, commit_sha: str) -> set[str] | None:
      if commit_sha == "strong":
        return {"v1.0.0"}
      if commit_sha == "fallback":
        return {"v2.0.0"}
      if commit_sha == "fix":
        return set()
      return set()

  dataset = tmp_path / "dataset.json"
  repo_root = tmp_path / "repos"
  anchor_run = tmp_path / "anchor-run"
  out_dir = tmp_path / "out"
  repo_root.mkdir()
  (repo_root / "repo").mkdir()
  anchor_run.mkdir()
  anchor_run.joinpath("summary.json").write_text(
    json.dumps({"results": [{"cve_id": "CVE-S"}, {"cve_id": "CVE-F"}]}),
    encoding="utf-8",
  )
  dataset.write_text(
    json.dumps(
      {
        "CVE-S": {"repo": "repo", "fixing_commits": [["fix"]], "affected_version": ["v1.0.0"]},
        "CVE-F": {"repo": "repo", "fixing_commits": [["fix"]], "affected_version": ["v2.0.0"]},
      }
    ),
    encoding="utf-8",
  )
  for cve_id, commit, mode, evidence in [
    ("CVE-S", "strong", "strong_model_anchor", "strong"),
    ("CVE-F", "fallback", "fallback_inventory_anchor", "fallback"),
  ]:
    case_dir = anchor_run / cve_id
    case_dir.mkdir()
    case_dir.joinpath("candidate_commits.json").write_text(
      json.dumps(
        [
          {
            "commit_sha": commit,
            "lifecycle": "raw_candidate",
            "candidate_generation_mode": mode,
            "evidence_level": evidence,
            "roles": ["dangerous_use"],
            "selection_modes": ["modified_old_side"],
            "line_provenance": [{"fix_commit_sha": "fix", "committer_time": 10}],
          }
        ]
      ),
      encoding="utf-8",
    )
    case_dir.joinpath("resolved_pre_fix_anchors.json").write_text("[]", encoding="utf-8")
    case_dir.joinpath("blame_trace.json").write_text(json.dumps({}), encoding="utf-8")
    case_dir.joinpath("ingestion_result.json").write_text(json.dumps({}), encoding="utf-8")

  summary = run_szz_anchor_version_probe(
    anchor_run=anchor_run,
    dataset=dataset,
    repo_root=repo_root,
    out_dir=out_dir,
    git_runner=FakeRunner(tags_by_repo={repo_root / "repo": ["v1.0.0", "v2.0.0"]}),
  )

  assert summary["candidate_generation_mode_distribution"] == {
    "fallback_inventory_anchor": 1,
    "strong_model_anchor": 1,
  }
  assert summary["evidence_level_distribution"] == {"fallback": 1, "strong": 1}
  assert summary["candidate_lane_distribution"] == {"fallback_only": 1, "strong_only": 1}
  assert summary["release_metric_groups"]["strong_only"]["cases_total"] == 1
  assert summary["release_metric_groups"]["fallback_only"]["cases_total"] == 1
  assert summary["release_metric_groups"]["strong_plus_fallback"]["cases_total"] == 2
  rows = (out_dir / "per_cve_version_probe.csv").read_text(encoding="utf-8")
  assert "candidate_generation_modes" in rows
  assert "fallback_inventory_anchor" in rows
