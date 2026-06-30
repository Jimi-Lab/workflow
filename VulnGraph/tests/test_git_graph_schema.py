from __future__ import annotations

import sqlite3

from vulngraph.git_graph.schema import QueryStatus, SCHEMA_SQL
from vulngraph.git_graph.sqlite_store import SQLiteGraphStore


def test_schema_creates_required_tables_and_enables_foreign_keys(tmp_path):
    store = SQLiteGraphStore(tmp_path / "graph.sqlite")
    with store.connect() as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert {
        "repository_snapshot",
        "commit_node",
        "parent_edge",
        "git_ref",
        "git_tag",
        "release_edge",
        "evidence_cache",
    } <= tables
    assert "affected_version" not in SCHEMA_SQL


def test_parent_edges_reject_missing_commits(tmp_path):
    store = SQLiteGraphStore(tmp_path / "graph.sqlite")
    with store.connect() as connection:
        connection.execute(
            "INSERT INTO repository_snapshot "
            "(repo_id, snapshot_id, canonical_repo_path, head_sha, object_format, shallow, refs_hash, tags_hash, build_tool_version, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("r", "s", "x", "a" * 40, "sha1", 0, "r", "t", "v", "now"),
        )
        connection.execute(
            "INSERT INTO commit_node VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("r", "a" * 40, 1, 1, 0, 1, 0, 0),
        )
        try:
            connection.execute(
                "INSERT INTO parent_edge VALUES (?, ?, ?, ?)",
                ("r", "a" * 40, "b" * 40, 0),
            )
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError("missing parent must violate a foreign key")

    assert QueryStatus.FOUND.value == "found"
