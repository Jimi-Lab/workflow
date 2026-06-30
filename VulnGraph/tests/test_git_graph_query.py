from __future__ import annotations

from vulngraph.git_graph.builder import GitGraphBuilder
from vulngraph.git_graph.query import GitGraphQuery
from vulngraph.git_graph.schema import QueryStatus
from vulngraph.git_graph.sqlite_store import SQLiteGraphStore

from git_graph_helpers import make_linear_repo


def test_query_statuses_and_native_git_parity(tmp_path):
    repo, commits = make_linear_repo(tmp_path)
    output = tmp_path / "index"
    GitGraphBuilder().build(repo, output, repo_id="openjpeg", reset=True)
    query = GitGraphQuery(output / "graph.sqlite", repo)

    assert query.get_commit(commits[0]).status is QueryStatus.FOUND
    assert query.get_commit("f" * 40).status is QueryStatus.NOT_FOUND
    assert query.get_commit("bad").status is QueryStatus.INVALID_INPUT
    assert query.is_ancestor(commits[0], commits[2]).value is True
    assert query.is_ancestor(commits[2], commits[0]).value is False
    assert query.merge_base(commits[1], commits[2]).value == commits[1]


def test_snapshot_mismatch_is_explicit(tmp_path):
    repo, commits = make_linear_repo(tmp_path)
    output = tmp_path / "index"
    GitGraphBuilder().build(repo, output, repo_id="openjpeg", reset=True)
    query = GitGraphQuery(output / "graph.sqlite", repo, expected_snapshot_id="wrong")
    assert query.get_commit(commits[0]).status is QueryStatus.REPOSITORY_SNAPSHOT_MISMATCH


def test_evidence_cache_key_is_argument_order_stable(tmp_path):
    repo, _ = make_linear_repo(tmp_path)
    output = tmp_path / "index"
    GitGraphBuilder().build(repo, output, repo_id="openjpeg", reset=True)
    query = GitGraphQuery(output / "graph.sqlite", repo)
    left = query.evidence_cache_key("merge-base", {"right": "b", "left": "a"})
    right = query.evidence_cache_key("merge-base", {"left": "a", "right": "b"})
    assert left == right


def test_on_demand_evidence_cache_for_diff_patch_id_and_blame(tmp_path):
    repo, commits = make_linear_repo(tmp_path)
    output = tmp_path / "index"
    GitGraphBuilder().build(repo, output, repo_id="openjpeg", reset=True)
    query = GitGraphQuery(output / "graph.sqlite", repo)

    changed_paths = query.get_changed_paths(commits[1])
    assert changed_paths.status is QueryStatus.FOUND
    assert changed_paths.value == ["second.txt"]

    diff = query.get_commit_diff(commits[1])
    assert diff.status is QueryStatus.FOUND
    assert "second.txt" in diff.value

    patch_id = query.stable_patch_id(commits[1])
    assert patch_id.status is QueryStatus.FOUND
    assert len(patch_id.value) == 40

    blame = query.blame("second.txt", "HEAD", 1, 1)
    assert blame.status is QueryStatus.FOUND
    assert commits[1][:12] in blame.value

    with SQLiteGraphStore(output / "graph.sqlite").connect() as connection:
        operations = {
            row[0]
            for row in connection.execute(
                "SELECT operation FROM evidence_cache WHERE repo_id = ?",
                ("openjpeg",),
            )
        }
    assert {"changed_paths", "commit_diff", "stable_patch_id", "blame"}.issubset(operations)


def test_query_api_exposes_cached_blame_variants_and_log_history(tmp_path):
    repo, commits = make_linear_repo(tmp_path)
    output = tmp_path / "index"
    GitGraphBuilder().build(repo, output, repo_id="openjpeg", reset=True)
    query = GitGraphQuery(output / "graph.sqlite", repo)

    normal = query.blame("second.txt", "HEAD", 1, 1)
    blame_w = query.blame("second.txt", "HEAD", 1, 1, options=["-w"])
    blame_m = query.blame("second.txt", "HEAD", 1, 1, options=["-M"])
    blame_c = query.blame("second.txt", "HEAD", 1, 1, options=["-C"])
    log_l = query.log_l("second.txt", "HEAD", 1, 1, max_count=5)
    log_s = query.log_pickaxe("second", revision="HEAD", mode="S", path="second.txt", max_count=5)
    log_g = query.log_pickaxe("second", revision="HEAD", mode="G", path="second.txt", max_count=5)
    log_follow = query.log_follow("second.txt", revision="HEAD", max_count=5)
    per_parent_diff = query.per_parent_diff(commits[1], commits[0])

    assert normal.status is QueryStatus.FOUND
    assert blame_w.status is QueryStatus.FOUND
    assert blame_m.status is QueryStatus.FOUND
    assert blame_c.status is QueryStatus.FOUND
    assert log_l.status is QueryStatus.FOUND
    assert commits[1] in log_l.value
    assert log_s.status is QueryStatus.FOUND
    assert log_g.status is QueryStatus.FOUND
    assert log_follow.status is QueryStatus.FOUND
    assert per_parent_diff.status is QueryStatus.FOUND
    assert "second.txt" in per_parent_diff.value

    with SQLiteGraphStore(output / "graph.sqlite").connect() as connection:
        operations = {
            row[0]
            for row in connection.execute(
                "SELECT operation FROM evidence_cache WHERE repo_id = ?",
                ("openjpeg",),
            )
        }
    assert {
        "blame",
        "blame_w",
        "blame_M",
        "blame_C",
        "log_L",
        "log_S",
        "log_G",
        "log_follow",
        "per_parent_diff",
    }.issubset(operations)
