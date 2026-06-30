from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from .release_view import POLICY_SOURCE, classify_release_tag, rebuild_release_view
from .snapshot import SnapshotFacts, collect_snapshot
from .sqlite_store import SQLiteGraphStore

BUILD_TOOL_VERSION = "git-graph-index-v1"


@dataclass(frozen=True)
class BuildResult:
    repo_id: str
    repo_path: str
    index_path: str
    snapshot_id: str
    semantic_hash: str
    shallow: bool
    commit_count: int
    parent_edge_count: int
    root_count: int
    merge_count: int
    ref_count: int
    raw_tag_count: int
    release_tag_count: int
    unresolved_tag_count: int
    release_edge_count: int
    max_pending_batch: int
    duration_seconds: float
    index_size_bytes: int
    mode: str


class GitGraphBuilder:
    def __init__(self, *, batch_size: int = 5_000):
        if batch_size < 1:
            raise ValueError("batch_size must be positive")
        self.batch_size = batch_size

    def build(
        self,
        repo: str | Path,
        output_dir: str | Path,
        *,
        repo_id: str | None = None,
        reset: bool = False,
        update: bool = False,
    ) -> BuildResult:
        started = time.perf_counter()
        repo_path = Path(repo).resolve()
        resolved_repo_id = repo_id or repo_path.name
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        destination = output / "graph.sqlite"
        snapshot = collect_snapshot(repo_path, resolved_repo_id)
        if destination.exists() and not reset and not update:
            raise FileExistsError(f"index exists; pass reset or update: {destination}")
        if destination.exists() and update:
            existing = self._existing_result_if_unchanged(destination, output, snapshot)
            if existing is not None:
                return existing

        temporary = output / "graph.sqlite.building"
        for path in (temporary, Path(f"{temporary}-wal"), Path(f"{temporary}-shm")):
            if path.exists():
                path.unlink()
        store = SQLiteGraphStore(temporary)
        counts = self._materialize(store, repo_path, snapshot)
        store.checkpoint()
        semantic_hash = self._semantic_hash(temporary, snapshot, counts)
        with store.connect() as connection:
            connection.execute(
                "UPDATE repository_snapshot SET semantic_hash = ? WHERE repo_id = ?",
                (semantic_hash, resolved_repo_id),
            )
        store.checkpoint()
        if destination.exists():
            destination.unlink()
        os.replace(temporary, destination)
        duration = time.perf_counter() - started
        result = BuildResult(
            repo_id=resolved_repo_id,
            repo_path=str(repo_path),
            index_path=str(destination),
            snapshot_id=snapshot.snapshot_id,
            semantic_hash=semantic_hash,
            shallow=snapshot.shallow,
            commit_count=counts["commit_count"],
            parent_edge_count=counts["parent_edge_count"],
            root_count=counts["root_count"],
            merge_count=counts["merge_count"],
            ref_count=counts["ref_count"],
            raw_tag_count=counts["raw_tag_count"],
            release_tag_count=counts["release_tag_count"],
            unresolved_tag_count=counts["unresolved_tag_count"],
            release_edge_count=counts["release_edge_count"],
            max_pending_batch=counts["max_pending_batch"],
            duration_seconds=duration,
            index_size_bytes=destination.stat().st_size,
            mode="reset" if reset else ("update_rebuild" if update else "build"),
        )
        self._write_repo_artifacts(output, result, snapshot)
        return result

    def _materialize(self, store: SQLiteGraphStore, repo: Path, snapshot: SnapshotFacts) -> dict[str, int]:
        created_at = datetime.now(UTC).isoformat()
        with store.connect() as connection:
            connection.execute(
                "INSERT INTO repository_snapshot "
                "(repo_id, snapshot_id, canonical_repo_path, head_sha, object_format, shallow, refs_hash, tags_hash, build_tool_version, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    snapshot.repo_id, snapshot.snapshot_id, snapshot.canonical_repo_path,
                    snapshot.head_sha, snapshot.object_format, int(snapshot.shallow),
                    snapshot.refs_hash, snapshot.tags_hash, BUILD_TOOL_VERSION, created_at,
                ),
            )
            counts = self._stream_commits(connection, repo, snapshot.repo_id)
            counts["parent_edge_count"] = self._stream_parent_edges(connection, repo, snapshot.repo_id)
            counts.update(self._insert_refs_and_tags(connection, snapshot))
            release_counts = rebuild_release_view(connection, snapshot.repo_id)
            counts["release_tag_count"] = release_counts["release_tag_count"]
            counts["release_edge_count"] = release_counts["release_edge_count"]
        return counts

    def _stream_commits(self, connection: sqlite3.Connection, repo: Path, repo_id: str) -> dict[str, int]:
        process = subprocess.Popen(
            ["git", "-C", str(repo), "log", "--all", "--topo-order", "--no-show-signature", "--format=%H%x00%at%x00%ct%x00%P"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace", bufsize=1024 * 1024,
        )
        assert process.stdout is not None
        batch: list[tuple[object, ...]] = []
        commit_count = root_count = merge_count = max_batch = 0
        for line in process.stdout:
            parts = line.rstrip("\r\n").split("\x00")
            if len(parts) != 4:
                process.kill()
                raise ValueError(f"malformed git log record with {len(parts)} fields")
            sha, author_time, committer_time, parent_text = parts
            parents = parent_text.split() if parent_text else []
            batch.append((repo_id, sha, int(author_time), int(committer_time), len(parents), int(not parents), int(len(parents) > 1), commit_count))
            commit_count += 1
            root_count += int(not parents)
            merge_count += int(len(parents) > 1)
            max_batch = max(max_batch, len(batch))
            if len(batch) >= self.batch_size:
                connection.executemany("INSERT INTO commit_node VALUES (?, ?, ?, ?, ?, ?, ?, ?)", batch)
                connection.commit()
                batch.clear()
        if batch:
            connection.executemany("INSERT INTO commit_node VALUES (?, ?, ?, ?, ?, ?, ?, ?)", batch)
            connection.commit()
        stderr = process.stderr.read() if process.stderr is not None else ""
        if process.wait() != 0:
            raise RuntimeError(f"git log failed: {stderr.strip()}")
        return {"commit_count": commit_count, "root_count": root_count, "merge_count": merge_count, "max_pending_batch": max_batch}

    def _stream_parent_edges(self, connection: sqlite3.Connection, repo: Path, repo_id: str) -> int:
        process = subprocess.Popen(
            ["git", "-C", str(repo), "rev-list", "--all", "--parents", "--topo-order"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="ascii", errors="strict", bufsize=1024 * 1024,
        )
        assert process.stdout is not None
        batch: list[tuple[str, str, str, int]] = []
        edge_count = 0
        for line in process.stdout:
            values = line.split()
            child = values[0]
            for order, parent in enumerate(values[1:]):
                batch.append((repo_id, child, parent, order))
                edge_count += 1
                if len(batch) >= self.batch_size:
                    connection.executemany("INSERT INTO parent_edge VALUES (?, ?, ?, ?)", batch)
                    connection.commit()
                    batch.clear()
        if batch:
            connection.executemany("INSERT INTO parent_edge VALUES (?, ?, ?, ?)", batch)
            connection.commit()
        stderr = process.stderr.read() if process.stderr is not None else ""
        if process.wait() != 0:
            raise RuntimeError(f"git rev-list failed: {stderr.strip()}")
        return edge_count

    def _insert_refs_and_tags(self, connection: sqlite3.Connection, snapshot: SnapshotFacts) -> dict[str, int]:
        refs: list[tuple[object, ...]] = []
        tags: list[tuple[object, ...]] = []
        unresolved_count = 0
        for ref in snapshot.refs:
            ref_type = (
                "tag" if ref.ref_name.startswith("refs/tags/") else
                "branch" if ref.ref_name.startswith("refs/heads/") else
                "remote" if ref.ref_name.startswith("refs/remotes/") else "other"
            )
            refs.append((snapshot.repo_id, ref.ref_name, ref_type, ref.target_object_sha, ref.peeled_commit_sha, ref.symbolic_target))
            if ref_type != "tag":
                continue
            raw_name = ref.ref_name.removeprefix("refs/tags/")
            is_release, reason, normalized = classify_release_tag(snapshot.repo_id, raw_name)
            tag_type = "annotated" if ref.object_type == "tag" else "lightweight"
            peel_status = "peeled" if ref.peeled_commit_sha else "unresolved_non_commit_target"
            if not ref.peeled_commit_sha:
                tag_type = "unresolved"
                reason = peel_status
                unresolved_count += 1
            tags.append((
                snapshot.repo_id, raw_name,
                ref.target_object_sha if ref.object_type == "tag" else None,
                ref.target_object_sha, ref.peeled_commit_sha, tag_type, ref.tagger_time,
                int(is_release and ref.peeled_commit_sha is not None), reason, normalized, peel_status,
            ))
        connection.executemany("INSERT INTO git_ref VALUES (?, ?, ?, ?, ?, ?)", refs)
        connection.executemany("INSERT INTO git_tag VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", tags)
        return {"ref_count": len(refs), "raw_tag_count": len(tags), "release_tag_count": sum(row[7] for row in tags), "unresolved_tag_count": unresolved_count}

    def _semantic_hash(self, database: Path, snapshot: SnapshotFacts, counts: dict[str, int]) -> str:
        payload = {
            "repo_id": snapshot.repo_id,
            "snapshot_id": snapshot.snapshot_id,
            "object_format": snapshot.object_format,
            "shallow": snapshot.shallow,
            "refs_hash": snapshot.refs_hash,
            "tags_hash": snapshot.tags_hash,
            "counts": {key: counts[key] for key in sorted(counts)},
            "build_tool_version": BUILD_TOOL_VERSION,
        }
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode())
        connection = sqlite3.connect(database)
        try:
            for row in connection.execute("SELECT predecessor_tag, successor_tag FROM release_edge ORDER BY predecessor_tag, successor_tag"):
                digest.update("\0".join(row).encode())
        finally:
            connection.close()
        return digest.hexdigest()

    def _existing_result_if_unchanged(self, database: Path, output: Path, snapshot: SnapshotFacts) -> BuildResult | None:
        manifest_path = output / "manifest.json"
        if not manifest_path.exists():
            return None
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        if payload.get("snapshot_id") != snapshot.snapshot_id:
            return None
        payload["mode"] = "incremental_noop"
        return BuildResult(**{key: payload[key] for key in BuildResult.__dataclass_fields__})

    def _write_repo_artifacts(self, output: Path, result: BuildResult, snapshot: SnapshotFacts) -> None:
        manifest = asdict(result)
        manifest.update({
            "head_sha": snapshot.head_sha,
            "object_format": snapshot.object_format,
            "refs_hash": snapshot.refs_hash,
            "tags_hash": snapshot.tags_hash,
            "build_tool_version": BUILD_TOOL_VERSION,
            "release_policy_source": POLICY_SOURCE,
        })
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        connection = sqlite3.connect(result.index_path)
        connection.row_factory = sqlite3.Row
        try:
            raw_tags = [dict(row) for row in connection.execute("SELECT * FROM git_tag ORDER BY raw_tag_name")]
            releases = [row for row in raw_tags if row["is_release_tag"]]
            ancestry = [dict(row) for row in connection.execute("SELECT * FROM release_edge ORDER BY predecessor_tag, successor_tag")]
        finally:
            connection.close()
        artifacts = {
            "raw_tag_inventory.json": raw_tags,
            "release_tag_universe.json": releases,
            "release_ancestry.json": ancestry,
            "build_trace.json": {
                "git_commands": [
                    "git log --all --topo-order",
                    "git rev-list --all --parents --topo-order",
                    "git for-each-ref",
                ],
                "read_only": True,
            },
        }
        for name, payload in artifacts.items():
            (output / name).write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

