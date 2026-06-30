from __future__ import annotations

import json
import sqlite3
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .query import GitGraphQuery
from .schema import QueryStatus


def extract_dataset_fix_records(dataset: Mapping[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for cve_id, record in dataset.items():
        if not isinstance(record, Mapping):
            continue
        repo_value = str(record.get("repo") or "").strip()
        repo_id = Path(repo_value).name if repo_value else ""
        fixing = record.get("fixing_commits")
        if not isinstance(fixing, list):
            continue
        for group in fixing:
            commits = group if isinstance(group, list) else [group]
            for value in commits:
                sha = str(value or "").strip()
                if sha:
                    rows.append({"cve_id": str(cve_id), "repo_id": repo_id, "fix_commit_sha": sha})
    return rows


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _fixed_sample(rows: list[Any], limit: int) -> list[Any]:
    if len(rows) <= limit:
        return rows
    if limit <= 1:
        return rows[:1]
    indexes = {
        round(i * (len(rows) - 1) / (limit - 1))
        for i in range(limit)
    }
    return [rows[index] for index in sorted(indexes)]


def _has_cycle(adjacency: dict[str, list[str]]) -> bool:
    permanent: set[str] = set()
    temporary: set[str] = set()
    for start in list(adjacency):
        if start in permanent:
            continue
        stack: list[tuple[str, bool]] = [(start, False)]
        while stack:
            node, exiting = stack.pop()
            if exiting:
                temporary.discard(node)
                permanent.add(node)
                continue
            if node in permanent:
                continue
            if node in temporary:
                return True
            temporary.add(node)
            stack.append((node, True))
            for child in adjacency.get(node, []):
                if child in temporary:
                    return True
                if child not in permanent:
                    stack.append((child, False))
    return False


def validate_graph_index(database: str | Path, repo_path: str | Path, *, ancestry_sample_limit: int = 8) -> dict[str, Any]:
    database_path = Path(database)
    repo = Path(repo_path).resolve()
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    try:
        snapshot = connection.execute("SELECT * FROM repository_snapshot").fetchone()
        if snapshot is None:
            return {"ok": False, "errors": ["missing_repository_snapshot"]}
        repo_id = snapshot["repo_id"]
        indexed_commits = connection.execute(
            "SELECT COUNT(*) FROM commit_node WHERE repo_id = ?", (repo_id,)
        ).fetchone()[0]
        native_result = _git(repo, "rev-list", "--all", "--count")
        native_commits = int(native_result.stdout.strip()) if native_result.returncode == 0 else None
        dangling = connection.execute(
            """
            SELECT COUNT(*) FROM parent_edge p
            LEFT JOIN commit_node c ON c.repo_id=p.repo_id AND c.commit_sha=p.child_sha
            LEFT JOIN commit_node a ON a.repo_id=p.repo_id AND a.commit_sha=p.parent_sha
            WHERE p.repo_id=? AND (c.commit_sha IS NULL OR a.commit_sha IS NULL)
            """,
            (repo_id,),
        ).fetchone()[0]
        unresolved_release_tags = connection.execute(
            "SELECT COUNT(*) FROM git_tag WHERE repo_id=? AND is_release_tag=1 AND peeled_commit_sha IS NULL",
            (repo_id,),
        ).fetchone()[0]
        edge_rows = connection.execute(
            """
            SELECT e.predecessor_tag, e.successor_tag,
                   p.peeled_commit_sha AS predecessor_sha,
                   s.peeled_commit_sha AS successor_sha
            FROM release_edge e
            JOIN git_tag p ON p.repo_id=e.repo_id AND p.raw_tag_name=e.predecessor_tag
            JOIN git_tag s ON s.repo_id=e.repo_id AND s.raw_tag_name=e.successor_tag
            WHERE e.repo_id=?
            """,
            (repo_id,),
        ).fetchall()
    finally:
        connection.close()

    adjacency: dict[str, list[str]] = {}
    for row in edge_rows:
        adjacency.setdefault(row["predecessor_tag"], []).append(row["successor_tag"])
    release_cycle = _has_cycle(adjacency)
    ancestry_failures: list[dict[str, str]] = []
    ancestry_sample = _fixed_sample(edge_rows, ancestry_sample_limit)
    for row in ancestry_sample:
        completed = _git(repo, "merge-base", "--is-ancestor", row["predecessor_sha"], row["successor_sha"])
        if completed.returncode != 0:
            ancestry_failures.append(
                {
                    "predecessor_tag": row["predecessor_tag"],
                    "successor_tag": row["successor_tag"],
                    "stderr": completed.stderr.strip(),
                }
            )
    report = {
        "repo_id": repo_id,
        "snapshot_id": snapshot["snapshot_id"],
        "shallow": bool(snapshot["shallow"]),
        "indexed_commit_count": indexed_commits,
        "native_commit_count": native_commits,
        "commit_count_matches": indexed_commits == native_commits,
        "parent_foreign_keys_ok": dangling == 0,
        "dangling_parent_edge_count": dangling,
        "unresolved_release_tag_count": unresolved_release_tags,
        "release_edges_acyclic": not release_cycle,
        "release_edges_follow_ancestry": not ancestry_failures,
        "release_edges_native_check_mode": "fixed_seed_sample",
        "release_ancestry_total_edge_count": len(edge_rows),
        "release_ancestry_sample_count": len(ancestry_sample),
        "release_ancestry_sample_limit": ancestry_sample_limit,
        "release_ancestry_failures": ancestry_failures,
    }
    report["ok"] = all(
        [
            report["commit_count_matches"],
            report["parent_foreign_keys_ok"],
            report["release_edges_acyclic"],
            report["release_edges_follow_ancestry"],
            unresolved_release_tags == 0,
        ]
    )
    return report


def audit_dataset_fix_coverage(
    dataset_path: str | Path,
    index_root: str | Path,
    repo_root: str | Path,
) -> list[dict[str, Any]]:
    dataset = json.loads(Path(dataset_path).read_text(encoding="utf-8"))
    if not isinstance(dataset, Mapping):
        raise ValueError("dataset must be an object keyed by CVE")
    rows: list[dict[str, Any]] = []
    queries: dict[str, GitGraphQuery] = {}
    for record in extract_dataset_fix_records(dataset):
        repo_id = record["repo_id"]
        database = Path(index_root) / repo_id / "graph.sqlite"
        repo_path = Path(repo_root) / repo_id
        result = dict(record)
        if not database.exists() or not repo_path.exists():
            result.update({"status": "censored", "reason": "repository_or_index_missing"})
            rows.append(result)
            continue
        query = queries.setdefault(repo_id, GitGraphQuery(database, repo_path))
        commit = query.get_commit(record["fix_commit_sha"])
        if commit.status is QueryStatus.FOUND:
            parents = query.get_parents(record["fix_commit_sha"])
            result.update(
                {
                    "status": "resolved",
                    "reason": "",
                    "parent_count": commit.value["parent_count"],
                    "all_parents_resolve": parents.status is QueryStatus.FOUND
                    and all(query.get_commit(parent).status is QueryStatus.FOUND for parent in parents.value or []),
                    "is_merge": bool(commit.value["is_merge"]),
                    "reachable_from_indexed_refs": True,
                    "reachability_basis": "commit_node_from_git_log_all",
                    "containing_ref_count": None,
                }
            )
        else:
            exists = _git(repo_path, "cat-file", "-e", f"{record['fix_commit_sha']}^{{commit}}")
            result.update(
                {
                    "status": "censored",
                    "reason": "object_exists_but_unreachable" if exists.returncode == 0 else "fix_commit_missing",
                    "parent_count": None,
                    "all_parents_resolve": False,
                    "is_merge": None,
                    "reachable_from_indexed_refs": False,
                    "reachability_basis": "cat_file_commit_probe",
                    "containing_ref_count": 0,
                }
            )
        rows.append(result)
    return rows

