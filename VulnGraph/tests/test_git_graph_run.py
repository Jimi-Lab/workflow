from __future__ import annotations

import json

from vulngraph.git_graph.run import build_index_run

from git_graph_helpers import make_linear_repo


def test_run_writes_required_artifacts_without_ground_truth(tmp_path):
    repo, commits = make_linear_repo(tmp_path)
    repo_root = tmp_path / "repos"
    repo_root.mkdir()
    repo.rename(repo_root / "openjpeg")
    dataset = tmp_path / "dataset.json"
    dataset.write_text(
        json.dumps(
            {
                "CVE-X": {
                    "repo": "openjpeg",
                    "fixing_commits": [[commits[1]]],
                    "affected_version": ["must-not-leak"],
                }
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "run"
    summary = build_index_run(
        dataset_path=dataset,
        repo_root=repo_root,
        out_dir=output,
        repo_ids=["openjpeg"],
        reset=True,
    )
    assert summary["repositories_built"] == 1
    assert summary["fix_sha_resolved"] == 1
    for name in (
        "summary.json", "report.md", "repository_snapshot_manifest.json",
        "dataset_fix_coverage.csv", "build_performance.csv",
        "validation_summary.json", "provenance_manifest.json",
        "schema.sql", "query_api_report.md",
    ):
        assert (output / name).exists()
    query_api_report = (output / "query_api_report.md").read_text(encoding="utf-8")
    for api_name in ("get_changed_paths", "get_commit_diff", "stable_patch_id", "blame"):
        assert api_name in query_api_report
    artifact_text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in output.rglob("*")
        if path.is_file() and path.suffix != ".sqlite"
    )
    assert "must-not-leak" not in artifact_text
    assert "affected_version" not in artifact_text

