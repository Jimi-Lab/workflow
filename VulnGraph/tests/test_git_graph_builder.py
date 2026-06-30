from __future__ import annotations

import os
import subprocess

from vulngraph.git_graph.builder import GitGraphBuilder
from vulngraph.git_graph.query import GitGraphQuery

from git_graph_helpers import git, make_linear_repo


def test_streaming_builder_indexes_commits_parents_refs_and_tags(tmp_path):
    repo, commits = make_linear_repo(tmp_path)
    output = tmp_path / "index"
    result = GitGraphBuilder(batch_size=2).build(repo, output, repo_id="openjpeg", reset=True)

    assert result.commit_count == 3
    assert result.parent_edge_count == 2
    assert result.root_count == 1
    assert result.merge_count == 0
    assert result.raw_tag_count == 4
    assert result.max_pending_batch <= 2

    query = GitGraphQuery(output / "graph.sqlite", repo)
    assert query.get_parents(commits[2]).value == [commits[1]]
    assert query.peel_tag("v1.1.0").value["peeled_commit_sha"] == commits[1]


def test_reset_rebuild_has_same_semantic_hash(tmp_path):
    repo, _ = make_linear_repo(tmp_path)
    output = tmp_path / "index"
    first = GitGraphBuilder().build(repo, output, repo_id="openjpeg", reset=True)
    second = GitGraphBuilder().build(repo, output, repo_id="openjpeg", reset=True)
    assert first.semantic_hash == second.semantic_hash
    assert first.snapshot_id == second.snapshot_id


def test_update_removes_deleted_ref_and_stale_release_rows(tmp_path):
    repo, commits = make_linear_repo(tmp_path)
    output = tmp_path / "index"
    builder = GitGraphBuilder()
    builder.build(repo, output, repo_id="openjpeg", reset=True)
    git(repo, "tag", "-d", "v1.0.0")
    updated = builder.build(repo, output, repo_id="openjpeg", update=True)

    query = GitGraphQuery(output / "graph.sqlite", repo)
    assert query.peel_tag("v1.0.0").status.value == "not_found"
    assert updated.raw_tag_count == 3
    assert commits[0] in {row["commit_sha"] for row in query.iter_commits()}


def test_builder_preserves_duplicate_parent_slots(tmp_path):
    repo, commits = make_linear_repo(tmp_path)
    tree = git(repo, "rev-parse", f"{commits[-1]}^{{tree}}")
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "VulnGraph Test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "VulnGraph Test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
        }
    )
    raw_commit = (
        f"tree {tree}\n"
        f"parent {commits[-1]}\n"
        f"parent {commits[-1]}\n"
        "author VulnGraph Test <test@example.invalid> 1 +0000\n"
        "committer VulnGraph Test <test@example.invalid> 1 +0000\n"
        "\n"
        "duplicate parent slots\n"
    )
    duplicate_parent_commit = subprocess.run(
        ["git", "-C", str(repo), "hash-object", "-t", "commit", "-w", "--stdin"],
        input=raw_commit.encode("utf-8"),
        check=True,
        capture_output=True,
        env=env,
    ).stdout.decode("utf-8").strip()
    git(repo, "update-ref", "refs/heads/main", duplicate_parent_commit)

    output = tmp_path / "index"
    GitGraphBuilder(batch_size=2).build(repo, output, repo_id="openjpeg", reset=True)

    query = GitGraphQuery(output / "graph.sqlite", repo)
    assert query.get_parents(duplicate_parent_commit).value == [commits[-1], commits[-1]]
    assert query.get_children(commits[-1]).value.count(duplicate_parent_commit) == 1
