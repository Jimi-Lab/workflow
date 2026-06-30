from __future__ import annotations

from collections.abc import Mapping

from vulngraph.git_graph.builder import GitGraphBuilder
from vulngraph.git_graph.validation import (
    _has_cycle,
    audit_dataset_fix_coverage,
    extract_dataset_fix_records,
    validate_graph_index,
)

from git_graph_helpers import make_linear_repo


class GroundTruthTrap(Mapping):
    def __init__(self, values):
        self.values = values

    def __getitem__(self, key):
        if key == "affected_version":
            raise AssertionError("ground truth was read")
        return self.values[key]

    def __iter__(self):
        return iter(self.values)

    def __len__(self):
        return len(self.values)

    def get(self, key, default=None):
        if key == "affected_version":
            raise AssertionError("ground truth was read")
        return self.values.get(key, default)


def test_fix_preflight_never_reads_affected_version():
    dataset = {
        "CVE-X": GroundTruthTrap(
            {
                "repo": "openjpeg",
                "fixing_commits": [["a" * 40]],
                "affected_version": ["forbidden"],
            }
        )
    }
    rows = extract_dataset_fix_records(dataset)
    assert rows == [{"cve_id": "CVE-X", "repo_id": "openjpeg", "fix_commit_sha": "a" * 40}]


def test_validation_matches_native_git_on_synthetic_repo(tmp_path):
    repo, _ = make_linear_repo(tmp_path)
    output = tmp_path / "index"
    GitGraphBuilder().build(repo, output, repo_id="openjpeg", reset=True)
    report = validate_graph_index(output / "graph.sqlite", repo)
    assert report["ok"] is True
    assert report["commit_count_matches"] is True
    assert report["parent_foreign_keys_ok"] is True
    assert report["release_edges_acyclic"] is True
    assert report["release_edges_follow_ancestry"] is True
    assert report["release_ancestry_total_edge_count"] >= report["release_ancestry_sample_count"]
    assert report["release_ancestry_sample_count"] <= 8


def test_fix_coverage_uses_indexed_dag_reachability_without_ref_enumeration(tmp_path):
    repo, commits = make_linear_repo(tmp_path)
    repo_root = tmp_path / "repos"
    repo_root.mkdir()
    repo.rename(repo_root / "openjpeg")
    index_root = tmp_path / "index"
    GitGraphBuilder().build(repo_root / "openjpeg", index_root / "openjpeg", repo_id="openjpeg", reset=True)
    dataset = tmp_path / "dataset.json"
    dataset.write_text(
        '{"CVE-X":{"repo":"openjpeg","fixing_commits":[["' + commits[1] + '"]],"affected_version":["forbidden"]}}',
        encoding="utf-8",
    )

    rows = audit_dataset_fix_coverage(dataset, index_root, repo_root)

    assert rows[0]["status"] == "resolved"
    assert rows[0]["reachable_from_indexed_refs"] is True
    assert rows[0]["reachability_basis"] == "commit_node_from_git_log_all"
    assert rows[0]["containing_ref_count"] is None


def test_cycle_detection_handles_deep_release_chains_without_recursion():
    adjacency = {f"v{i}": [f"v{i + 1}"] for i in range(1500)}
    adjacency["v1500"] = []
    assert _has_cycle(adjacency) is False

    adjacency["v1500"] = ["v1499"]
    assert _has_cycle(adjacency) is True
