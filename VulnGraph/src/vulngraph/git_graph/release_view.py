from __future__ import annotations

import hashlib
import re
import sqlite3
from collections import defaultdict


POLICY_SOURCE = "VulnVersion/vulnversion/stage3_verify/version_registry.py"

_EXCLUDE = re.compile(
    r"(?:rc\d*|pre\d*|alpha\d*|beta\d*|candidate|dev|snapshot|test|internal|backup|bak|nightly|experimental)",
    re.IGNORECASE,
)
_INTERNAL_EXCLUDE = re.compile(
    r"(?:backups/|reformat|CLANG|FIPS_TEST|BEN_FIPS|STATE_|LEVITTE_|BEFORE_|AFTER_|master-)",
    re.IGNORECASE,
)
_FILTERS = {
    "ImageMagick": re.compile(r"^\d+\.\d+\.\d+[\.-]\d+$"),
    "FFmpeg": re.compile(r"^(?:n\d+\.\d+(?:\.\d+)?|v\d+\.\d+(?:\.\d+)?|ffmpeg-\d+(?:\.\d+)*)$"),
    "curl": re.compile(r"^curl-\d+_\d+(?:_\d+)?$"),
    "openssl": re.compile(
        r"^(?:OpenSSL_\d+_\d+_\d+\w*|openssl-\d+\.\d+\.\d+|OpenSSL-fips-\d+_\d+[\w-]*|OpenSSL-engine-\d+_\d+_\d+\w*|OpenSSL_FIPS_\d+_\d+)$"
    ),
    "wireshark": re.compile(r"^(?:v\d+\.\d+\.\d+|wireshark-\d+\.\d+\.\d+|NCP_sync.*)$"),
    "httpd": re.compile(r"^\d+\.\d+\.\d+$"),
    "qemu": re.compile(r"^v\d+\.\d+(?:\.\d+(?:\.\d+)?)?$"),
    "openjpeg": re.compile(r"^(?:v\d+\.\d+\.\d+|version\.\d+\.\d+(?:\.\d+)?)$"),
    "linux": re.compile(r"^v\d+\.\d+(?:\.\d+)?$"),
}


def classify_release_tag(repo_id: str, tag: str) -> tuple[bool, str | None, str | None]:
    if _EXCLUDE.search(tag) or _INTERNAL_EXCLUDE.search(tag):
        return False, "non_release_name", None
    pattern = _FILTERS.get(repo_id)
    if pattern is None or pattern.fullmatch(tag) is None:
        return False, "repo_release_pattern_mismatch", None
    return True, None, tag


def rebuild_release_view(connection: sqlite3.Connection, repo_id: str) -> dict[str, int]:
    connection.execute("DELETE FROM release_edge WHERE repo_id = ?", (repo_id,))
    connection.execute("DELETE FROM tag_alias_group WHERE repo_id = ?", (repo_id,))

    releases_by_commit: dict[str, list[str]] = defaultdict(list)
    for row in connection.execute(
        "SELECT raw_tag_name, peeled_commit_sha FROM git_tag "
        "WHERE repo_id = ? AND is_release_tag = 1 AND peeled_commit_sha IS NOT NULL "
        "ORDER BY raw_tag_name",
        (repo_id,),
    ):
        releases_by_commit[row["peeled_commit_sha"]].append(row["raw_tag_name"])

    canonical_by_commit: dict[str, str] = {}
    for commit_sha, tags in releases_by_commit.items():
        canonical = sorted(tags)[0]
        canonical_by_commit[commit_sha] = canonical
        alias_group_id = hashlib.sha256(f"{repo_id}\0{commit_sha}".encode()).hexdigest()
        connection.executemany(
            "INSERT INTO tag_alias_group VALUES (?, ?, ?, ?, ?)",
            [(repo_id, alias_group_id, canonical, tag, commit_sha) for tag in tags],
        )

    pending: dict[str, set[str]] = defaultdict(set)
    edges: set[tuple[str, str]] = set()
    cursor = connection.execute(
        "SELECT c.topo_order, c.commit_sha, p.parent_sha "
        "FROM commit_node c LEFT JOIN parent_edge p "
        "ON p.repo_id = c.repo_id AND p.child_sha = c.commit_sha "
        "WHERE c.repo_id = ? ORDER BY c.topo_order, p.parent_order",
        (repo_id,),
    )
    current_sha: str | None = None
    parents: list[str] = []

    def propagate(commit_sha: str, commit_parents: list[str]) -> None:
        frontier = pending.pop(commit_sha, set())
        release = canonical_by_commit.get(commit_sha)
        if release is not None:
            for successor in frontier:
                if release != successor:
                    edges.add((release, successor))
            frontier = {release}
        for parent_sha in commit_parents:
            pending[parent_sha].update(frontier)

    for row in cursor:
        sha = row["commit_sha"]
        if current_sha is not None and sha != current_sha:
            propagate(current_sha, parents)
            parents = []
        current_sha = sha
        if row["parent_sha"] is not None:
            parents.append(row["parent_sha"])
    if current_sha is not None:
        propagate(current_sha, parents)

    connection.executemany(
        "INSERT INTO release_edge(repo_id, predecessor_tag, successor_tag, derivation) VALUES (?, ?, ?, ?)",
        [(repo_id, left, right, "git_dag_frontier") for left, right in sorted(edges)],
    )
    return {
        "release_tag_count": sum(len(tags) for tags in releases_by_commit.values()),
        "alias_group_count": len(releases_by_commit),
        "release_edge_count": len(edges),
        "pending_frontier_count": len(pending),
    }
