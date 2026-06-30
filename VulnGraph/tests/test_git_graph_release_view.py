from __future__ import annotations

from vulngraph.git_graph.builder import GitGraphBuilder
from vulngraph.git_graph.query import GitGraphQuery

from git_graph_helpers import commit, git, make_linear_repo


def test_release_view_groups_aliases_and_uses_dag_ancestry(tmp_path):
    repo, commits = make_linear_repo(tmp_path)
    output = tmp_path / "index"
    GitGraphBuilder().build(repo, output, repo_id="openjpeg", reset=True)
    query = GitGraphQuery(output / "graph.sqlite", repo)

    assert set(query.tags_at_commit(commits[1]).value) == {"v1.1.0", "v1.1.0-alias"}
    assert query.release_predecessors("v1.1.0").value == ["v1.0.0"]
    assert query.release_successors("v1.0.0").value == ["v1.1.0"]


def test_release_view_preserves_incomparable_orphan_history(tmp_path):
    repo, _ = make_linear_repo(tmp_path)
    git(repo, "checkout", "--orphan", "other")
    for path in repo.glob("*.txt"):
        path.unlink()
    git(repo, "rm", "-rf", ".")
    orphan = commit(repo, "orphan")
    git(repo, "tag", "v9.0.0", orphan)
    output = tmp_path / "index"
    GitGraphBuilder().build(repo, output, repo_id="openjpeg", reset=True)
    query = GitGraphQuery(output / "graph.sqlite", repo)

    assert query.release_predecessors("v9.0.0").value == []
    assert query.release_successors("v1.1.0").value == []


def test_release_filter_rejects_non_release_tags(tmp_path):
    repo, _ = make_linear_repo(tmp_path)
    output = tmp_path / "index"
    GitGraphBuilder().build(repo, output, repo_id="openjpeg", reset=True)
    query = GitGraphQuery(output / "graph.sqlite", repo)
    inventory = query.list_tags(release_only=False)
    by_name = {row["raw_tag_name"]: row for row in inventory}
    assert by_name["test-internal"]["is_release_tag"] == 0
    assert by_name["test-internal"]["filter_reason"]
