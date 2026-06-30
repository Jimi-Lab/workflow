from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from .schema import QueryResult, QueryStatus
from .sqlite_store import SQLiteGraphStore

_SHA = re.compile(r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")


class GitGraphQuery:
    def __init__(
        self,
        database: str | Path,
        repo_path: str | Path,
        *,
        expected_snapshot_id: str | None = None,
    ):
        self.database = Path(database)
        self.repo_path = Path(repo_path).resolve()
        self.store = SQLiteGraphStore(self.database)
        with self.store.connect() as connection:
            row = connection.execute("SELECT * FROM repository_snapshot").fetchone()
        if row is None:
            raise ValueError("repository snapshot is missing")
        self.repo_id = row["repo_id"]
        self.snapshot_id = row["snapshot_id"]
        self.object_format = row["object_format"]
        self.snapshot_matches = expected_snapshot_id in (None, self.snapshot_id)

    def _mismatch(self) -> QueryResult[Any] | None:
        if not self.snapshot_matches:
            return QueryResult(QueryStatus.REPOSITORY_SNAPSHOT_MISMATCH, reason="expected snapshot does not match index")
        return None

    def _valid_sha(self, sha: str) -> bool:
        return bool(_SHA.fullmatch(sha)) and len(sha) == (64 if self.object_format == "sha256" else 40)

    def get_commit(self, sha: str) -> QueryResult[dict[str, Any]]:
        if mismatch := self._mismatch():
            return mismatch
        if not self._valid_sha(sha):
            return QueryResult(QueryStatus.INVALID_INPUT, reason="invalid commit object id")
        with self.store.connect() as connection:
            row = connection.execute(
                "SELECT * FROM commit_node WHERE repo_id = ? AND commit_sha = ?",
                (self.repo_id, sha),
            ).fetchone()
        return QueryResult(QueryStatus.FOUND, dict(row)) if row else QueryResult(QueryStatus.NOT_FOUND)

    def get_parents(self, sha: str) -> QueryResult[list[str]]:
        return self._related_commits(sha, parents=True)

    def get_children(self, sha: str) -> QueryResult[list[str]]:
        return self._related_commits(sha, parents=False)

    def _related_commits(self, sha: str, *, parents: bool) -> QueryResult[list[str]]:
        commit = self.get_commit(sha)
        if commit.status is not QueryStatus.FOUND:
            return QueryResult(commit.status, reason=commit.reason)
        if parents:
            sql = "SELECT parent_sha AS sha FROM parent_edge WHERE repo_id = ? AND child_sha = ? ORDER BY parent_order"
        else:
            sql = "SELECT DISTINCT child_sha AS sha FROM parent_edge WHERE repo_id = ? AND parent_sha = ? ORDER BY child_sha"
        with self.store.connect() as connection:
            rows = connection.execute(sql, (self.repo_id, sha)).fetchall()
        return QueryResult(QueryStatus.FOUND, [row["sha"] for row in rows])

    def iter_commits(self) -> Iterator[dict[str, Any]]:
        with self.store.connect() as connection:
            cursor = connection.execute(
                "SELECT * FROM commit_node WHERE repo_id = ? ORDER BY topo_order",
                (self.repo_id,),
            )
            for row in cursor:
                yield dict(row)

    def evidence_cache_key(
        self,
        operation: str,
        arguments: dict[str, Any],
        *,
        revision: str | None = None,
        path: str | None = None,
    ) -> str:
        payload = {
            "repo_snapshot_id": self.snapshot_id,
            "operation": operation,
            "arguments": arguments,
            "revision": revision,
            "path": path,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def _cached_git(
        self,
        operation: str,
        arguments: dict[str, Any],
        command_args: list[str],
        *,
        revision: str | None = None,
        path: str | None = None,
        false_exit_codes: set[int] | None = None,
    ) -> QueryResult[str | bool]:
        if mismatch := self._mismatch():
            return mismatch
        key = self.evidence_cache_key(operation, arguments, revision=revision, path=path)
        with self.store.connect() as connection:
            row = connection.execute(
                "SELECT exit_code, output_text FROM evidence_cache WHERE repo_id = ? AND repo_snapshot_id = ? AND cache_key = ?",
                (self.repo_id, self.snapshot_id, key),
            ).fetchone()
        if row is not None:
            if false_exit_codes and row["exit_code"] in false_exit_codes:
                return QueryResult(QueryStatus.FOUND, False)
            if row["exit_code"] != 0:
                return QueryResult(QueryStatus.CENSORED, reason=row["output_text"])
            return QueryResult(QueryStatus.FOUND, row["output_text"])
        command = ["git", "-C", str(self.repo_path), *command_args]
        completed = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        output = completed.stdout if completed.returncode == 0 else completed.stderr
        with self.store.connect() as connection:
            connection.execute(
                "INSERT INTO evidence_cache VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    self.repo_id, self.snapshot_id, key, operation,
                    json.dumps(arguments, sort_keys=True, separators=(",", ":")),
                    revision, path, " ".join(command), completed.returncode,
                    hashlib.sha256(output.encode()).hexdigest(), output,
                    "wrapper_owned_native_git", datetime.now(UTC).isoformat(),
                ),
            )
        if false_exit_codes and completed.returncode in false_exit_codes:
            return QueryResult(QueryStatus.FOUND, False)
        if completed.returncode != 0:
            return QueryResult(QueryStatus.CENSORED, reason=output.strip())
        return QueryResult(QueryStatus.FOUND, output)

    def is_ancestor(self, ancestor: str, descendant: str) -> QueryResult[bool]:
        if not self._valid_sha(ancestor) or not self._valid_sha(descendant):
            return QueryResult(QueryStatus.INVALID_INPUT, reason="invalid commit object id")
        result = self._cached_git(
            "is_ancestor",
            {"ancestor": ancestor, "descendant": descendant},
            ["merge-base", "--is-ancestor", ancestor, descendant],
            false_exit_codes={1},
        )
        if result.status is not QueryStatus.FOUND:
            return QueryResult(result.status, reason=result.reason)
        return QueryResult(QueryStatus.FOUND, result.value is not False)

    def merge_base(self, left: str, right: str) -> QueryResult[str]:
        if not self._valid_sha(left) or not self._valid_sha(right):
            return QueryResult(QueryStatus.INVALID_INPUT, reason="invalid commit object id")
        result = self._cached_git(
            "merge_base", {"left": left, "right": right}, ["merge-base", left, right]
        )
        if result.status is not QueryStatus.FOUND:
            return QueryResult(result.status, reason=result.reason)
        return QueryResult(QueryStatus.FOUND, str(result.value).strip())

    def peel_tag(self, tag: str) -> QueryResult[dict[str, Any]]:
        if mismatch := self._mismatch():
            return mismatch
        with self.store.connect() as connection:
            row = connection.execute(
                "SELECT * FROM git_tag WHERE repo_id = ? AND raw_tag_name = ?",
                (self.repo_id, tag),
            ).fetchone()
        return QueryResult(QueryStatus.FOUND, dict(row)) if row else QueryResult(QueryStatus.NOT_FOUND)

    def tags_at_commit(self, sha: str) -> QueryResult[list[str]]:
        commit = self.get_commit(sha)
        if commit.status is not QueryStatus.FOUND:
            return QueryResult(commit.status, reason=commit.reason)
        with self.store.connect() as connection:
            rows = connection.execute(
                "SELECT raw_tag_name FROM git_tag WHERE repo_id = ? AND peeled_commit_sha = ? ORDER BY raw_tag_name",
                (self.repo_id, sha),
            ).fetchall()
        return QueryResult(QueryStatus.FOUND, [row[0] for row in rows])

    def list_tags(self, *, release_only: bool) -> list[dict[str, Any]]:
        clause = " AND is_release_tag = 1" if release_only else ""
        with self.store.connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM git_tag WHERE repo_id = ?{clause} ORDER BY raw_tag_name",
                (self.repo_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def refs_containing(self, sha: str) -> QueryResult[list[str]]:
        if not self._valid_sha(sha):
            return QueryResult(QueryStatus.INVALID_INPUT, reason="invalid commit object id")
        result = self._cached_git(
            "refs_containing", {"sha": sha}, ["for-each-ref", "--contains", sha, "--format=%(refname)"], revision=sha
        )
        if result.status is not QueryStatus.FOUND:
            return QueryResult(result.status, reason=result.reason)
        return QueryResult(QueryStatus.FOUND, sorted(filter(None, str(result.value).splitlines())))

    def tags_containing(self, sha: str, universe: str = "release_tag_universe") -> QueryResult[list[str]]:
        refs = self.refs_containing(sha)
        if refs.status is not QueryStatus.FOUND:
            return QueryResult(refs.status, reason=refs.reason)
        names = {ref.removeprefix("refs/tags/") for ref in refs.value or [] if ref.startswith("refs/tags/")}
        allowed = {row["raw_tag_name"] for row in self.list_tags(release_only=universe == "release_tag_universe")}
        return QueryResult(QueryStatus.FOUND, sorted(names & allowed))

    def get_changed_paths(self, sha: str) -> QueryResult[list[str]]:
        commit = self.get_commit(sha)
        if commit.status is not QueryStatus.FOUND:
            return QueryResult(commit.status, reason=commit.reason)
        result = self._cached_git(
            "changed_paths",
            {"sha": sha},
            ["diff-tree", "--no-commit-id", "--name-only", "-r", "--root", sha],
            revision=sha,
        )
        if result.status is not QueryStatus.FOUND:
            return QueryResult(result.status, reason=result.reason)
        return QueryResult(QueryStatus.FOUND, [line for line in str(result.value).splitlines() if line])

    def get_commit_diff(self, sha: str) -> QueryResult[str]:
        commit = self.get_commit(sha)
        if commit.status is not QueryStatus.FOUND:
            return QueryResult(commit.status, reason=commit.reason)
        result = self._cached_git(
            "commit_diff",
            {"sha": sha},
            ["show", "--no-ext-diff", "--format=", "--find-renames", "--find-copies", sha],
            revision=sha,
        )
        if result.status is not QueryStatus.FOUND:
            return QueryResult(result.status, reason=result.reason)
        return QueryResult(QueryStatus.FOUND, str(result.value))

    def read_file_at_revision(
        self,
        revision: str,
        path: str,
        *,
        max_bytes: int = 4 * 1024 * 1024,
    ) -> QueryResult[str]:
        commit = self.get_commit(revision)
        if commit.status is not QueryStatus.FOUND:
            return QueryResult(commit.status, reason=commit.reason)
        if not path or max_bytes < 1:
            return QueryResult(QueryStatus.INVALID_INPUT, reason="invalid revision path query")
        size = self._cached_git(
            "blob_size",
            {"revision": revision, "path": path},
            ["cat-file", "-s", f"{revision}:{path}"],
            revision=revision,
            path=path,
        )
        if size.status is not QueryStatus.FOUND:
            if size.status is QueryStatus.CENSORED:
                return QueryResult(QueryStatus.NOT_FOUND, reason=size.reason)
            return QueryResult(size.status, reason=size.reason)
        try:
            blob_size = int(str(size.value or "").strip())
        except ValueError:
            return QueryResult(QueryStatus.CENSORED, reason="invalid_blob_size")
        if blob_size > max_bytes:
            return QueryResult(
                QueryStatus.CENSORED,
                reason=f"blob_size_limit_exceeded:{blob_size}>{max_bytes}",
            )
        content = self._cached_git(
            "show_file",
            {"revision": revision, "path": path, "max_bytes": max_bytes},
            ["show", f"{revision}:{path}"],
            revision=revision,
            path=path,
        )
        if content.status is not QueryStatus.FOUND:
            return QueryResult(content.status, reason=content.reason)
        return QueryResult(QueryStatus.FOUND, str(content.value or ""))

    def diff_between_revisions(
        self,
        parent_sha: str,
        candidate_sha: str,
        *,
        paths: list[str] | tuple[str, ...] = (),
        unified: int = 12,
    ) -> QueryResult[str]:
        parent = self.get_commit(parent_sha)
        if parent.status is not QueryStatus.FOUND:
            return QueryResult(parent.status, reason=parent.reason)
        candidate = self.get_commit(candidate_sha)
        if candidate.status is not QueryStatus.FOUND:
            return QueryResult(candidate.status, reason=candidate.reason)
        normalized_paths = tuple(dict.fromkeys(path for path in paths if path))
        if unified < 0 or len(normalized_paths) > 32:
            return QueryResult(QueryStatus.INVALID_INPUT, reason="invalid revision diff query")
        command = [
            "diff",
            "--no-ext-diff",
            "--find-renames",
            "--find-copies",
            f"--unified={unified}",
            parent_sha,
            candidate_sha,
        ]
        if normalized_paths:
            command.extend(["--", *normalized_paths])
        result = self._cached_git(
            "revision_diff",
            {
                "parent_sha": parent_sha,
                "candidate_sha": candidate_sha,
                "paths": list(normalized_paths),
                "unified": unified,
            },
            command,
            revision=candidate_sha,
            path="\n".join(normalized_paths) if normalized_paths else None,
        )
        if result.status is not QueryStatus.FOUND:
            return QueryResult(result.status, reason=result.reason)
        return QueryResult(QueryStatus.FOUND, str(result.value or ""))

    def name_status_between_revisions(
        self,
        parent_sha: str,
        candidate_sha: str,
    ) -> QueryResult[str]:
        parent = self.get_commit(parent_sha)
        if parent.status is not QueryStatus.FOUND:
            return QueryResult(parent.status, reason=parent.reason)
        candidate = self.get_commit(candidate_sha)
        if candidate.status is not QueryStatus.FOUND:
            return QueryResult(candidate.status, reason=candidate.reason)
        result = self._cached_git(
            "revision_name_status",
            {"parent_sha": parent_sha, "candidate_sha": candidate_sha},
            [
                "diff",
                "--no-ext-diff",
                "--find-renames",
                "--find-copies",
                "--name-status",
                parent_sha,
                candidate_sha,
            ],
            revision=candidate_sha,
        )
        if result.status is not QueryStatus.FOUND:
            return QueryResult(result.status, reason=result.reason)
        return QueryResult(QueryStatus.FOUND, str(result.value or ""))

    def stable_patch_id(self, sha: str) -> QueryResult[str]:
        commit = self.get_commit(sha)
        if commit.status is not QueryStatus.FOUND:
            return QueryResult(commit.status, reason=commit.reason)
        diff_result = self._cached_git(
            "stable_patch_id_diff",
            {"sha": sha},
            ["show", "--no-ext-diff", "--format=", sha],
            revision=sha,
        )
        if diff_result.status is not QueryStatus.FOUND:
            return QueryResult(diff_result.status, reason=diff_result.reason)
        key = self.evidence_cache_key("stable_patch_id", {"sha": sha}, revision=sha)
        with self.store.connect() as connection:
            row = connection.execute(
                "SELECT exit_code, output_text FROM evidence_cache WHERE repo_id = ? AND repo_snapshot_id = ? AND cache_key = ?",
                (self.repo_id, self.snapshot_id, key),
            ).fetchone()
        if row is not None:
            if row["exit_code"] != 0:
                return QueryResult(QueryStatus.CENSORED, reason=row["output_text"])
            return QueryResult(QueryStatus.FOUND, str(row["output_text"]).split()[0])
        command = ["git", "-C", str(self.repo_path), "patch-id", "--stable"]
        completed = subprocess.run(
            command,
            input=str(diff_result.value),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        output = completed.stdout if completed.returncode == 0 else completed.stderr
        with self.store.connect() as connection:
            connection.execute(
                "INSERT INTO evidence_cache VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    self.repo_id, self.snapshot_id, key, "stable_patch_id",
                    json.dumps({"sha": sha}, sort_keys=True, separators=(",", ":")),
                    sha, None, " ".join(command), completed.returncode,
                    hashlib.sha256(output.encode()).hexdigest(), output,
                    "wrapper_owned_native_git", datetime.now(UTC).isoformat(),
                ),
            )
        if completed.returncode != 0:
            return QueryResult(QueryStatus.CENSORED, reason=output.strip())
        patch_id = output.split()[0] if output.split() else ""
        return QueryResult(QueryStatus.FOUND, patch_id)

    def blame(
        self,
        path: str,
        revision: str,
        start_line: int,
        end_line: int,
        *,
        options: list[str] | tuple[str, ...] | None = None,
    ) -> QueryResult[str]:
        if start_line < 1 or end_line < start_line:
            return QueryResult(QueryStatus.INVALID_INPUT, reason="invalid line range")
        normalized_options = tuple(options or ())
        if any(option not in {"-w", "-M", "-C"} for option in normalized_options):
            return QueryResult(QueryStatus.INVALID_INPUT, reason="unsupported blame option")
        operation = "blame" if not normalized_options else "blame_" + "_".join(option.lstrip("-") for option in normalized_options)
        result = self._cached_git(
            operation,
            {
                "path": path,
                "revision": revision,
                "start_line": start_line,
                "end_line": end_line,
                "options": list(normalized_options),
            },
            ["blame", *normalized_options, "--line-porcelain", f"-L{start_line},{end_line}", revision, "--", path],
            revision=revision,
            path=path,
        )
        if result.status is not QueryStatus.FOUND:
            return QueryResult(result.status, reason=result.reason)
        return QueryResult(QueryStatus.FOUND, str(result.value))

    def log_l(self, path: str, revision: str, start_line: int, end_line: int, *, max_count: int = 20) -> QueryResult[str]:
        if start_line < 1 or end_line < start_line or max_count < 1:
            return QueryResult(QueryStatus.INVALID_INPUT, reason="invalid log -L range")
        result = self._cached_git(
            "log_L",
            {
                "path": path,
                "revision": revision,
                "start_line": start_line,
                "end_line": end_line,
                "max_count": max_count,
            },
            ["log", f"--max-count={max_count}", "--format=%H %ct %s", f"-L{start_line},{end_line}:{path}", revision],
            revision=revision,
            path=path,
        )
        if result.status is not QueryStatus.FOUND:
            return QueryResult(result.status, reason=result.reason)
        return QueryResult(QueryStatus.FOUND, str(result.value))

    def log_pickaxe(
        self,
        needle: str,
        *,
        revision: str = "--all",
        mode: str = "S",
        path: str | None = None,
        max_count: int = 20,
    ) -> QueryResult[str]:
        if mode not in {"S", "G"} or not needle or max_count < 1:
            return QueryResult(QueryStatus.INVALID_INPUT, reason="invalid pickaxe query")
        command = ["log", f"--max-count={max_count}", "--format=%H %ct %s", f"-{mode}", needle, revision]
        if path:
            command.extend(["--", path])
        result = self._cached_git(
            f"log_{mode}",
            {"needle": needle, "revision": revision, "mode": mode, "path": path, "max_count": max_count},
            command,
            revision=revision,
            path=path,
        )
        if result.status is not QueryStatus.FOUND:
            return QueryResult(result.status, reason=result.reason)
        return QueryResult(QueryStatus.FOUND, str(result.value))

    def log_follow(self, path: str, *, revision: str = "--all", max_count: int = 20) -> QueryResult[str]:
        if not path or max_count < 1:
            return QueryResult(QueryStatus.INVALID_INPUT, reason="invalid path history query")
        result = self._cached_git(
            "log_follow",
            {"path": path, "revision": revision, "max_count": max_count},
            ["log", "--follow", f"--max-count={max_count}", "--format=%H %ct %s", revision, "--", path],
            revision=revision,
            path=path,
        )
        if result.status is not QueryStatus.FOUND:
            return QueryResult(result.status, reason=result.reason)
        return QueryResult(QueryStatus.FOUND, str(result.value))

    def per_parent_diff(self, commit_sha: str, parent_sha: str) -> QueryResult[str]:
        commit = self.get_commit(commit_sha)
        if commit.status is not QueryStatus.FOUND:
            return QueryResult(commit.status, reason=commit.reason)
        parent = self.get_commit(parent_sha)
        if parent.status is not QueryStatus.FOUND:
            return QueryResult(parent.status, reason=parent.reason)
        result = self._cached_git(
            "per_parent_diff",
            {"commit_sha": commit_sha, "parent_sha": parent_sha},
            ["diff", "--find-renames", "--find-copies", parent_sha, commit_sha],
            revision=commit_sha,
        )
        if result.status is not QueryStatus.FOUND:
            return QueryResult(result.status, reason=result.reason)
        return QueryResult(QueryStatus.FOUND, str(result.value))

    def _canonical_tag(self, connection: sqlite3.Connection, tag: str) -> str | None:
        row = connection.execute(
            "SELECT canonical_tag FROM tag_alias_group WHERE repo_id = ? AND raw_tag_name = ?",
            (self.repo_id, tag),
        ).fetchone()
        return row[0] if row else None

    def release_predecessors(self, tag: str) -> QueryResult[list[str]]:
        return self._release_neighbors(tag, predecessors=True)

    def release_successors(self, tag: str) -> QueryResult[list[str]]:
        return self._release_neighbors(tag, predecessors=False)

    def _release_neighbors(self, tag: str, *, predecessors: bool) -> QueryResult[list[str]]:
        with self.store.connect() as connection:
            canonical = self._canonical_tag(connection, tag)
            if canonical is None:
                return QueryResult(QueryStatus.NOT_FOUND)
            column, other = ("successor_tag", "predecessor_tag") if predecessors else ("predecessor_tag", "successor_tag")
            rows = connection.execute(
                f"SELECT {other} FROM release_edge WHERE repo_id = ? AND {column} = ? ORDER BY {other}",
                (self.repo_id, canonical),
            ).fetchall()
        return QueryResult(QueryStatus.FOUND, [row[0] for row in rows])

    def release_line_members(self, tag: str) -> QueryResult[list[str]]:
        with self.store.connect() as connection:
            canonical = self._canonical_tag(connection, tag)
            if canonical is None:
                return QueryResult(QueryStatus.NOT_FOUND)
            rows = connection.execute(
                """
                WITH RECURSIVE connected(tag) AS (
                    SELECT ?
                    UNION
                    SELECT predecessor_tag FROM release_edge JOIN connected ON successor_tag = connected.tag WHERE repo_id = ?
                    UNION
                    SELECT successor_tag FROM release_edge JOIN connected ON predecessor_tag = connected.tag WHERE repo_id = ?
                )
                SELECT tag FROM connected ORDER BY tag
                """,
                (canonical, self.repo_id, self.repo_id),
            ).fetchall()
        return QueryResult(QueryStatus.FOUND, [row[0] for row in rows])

    def get_snapshot_manifest(self, repo_id: str | None = None) -> QueryResult[dict[str, Any]]:
        if repo_id not in (None, self.repo_id):
            return QueryResult(QueryStatus.REPOSITORY_SNAPSHOT_MISMATCH, reason="repository id mismatch")
        with self.store.connect() as connection:
            row = connection.execute(
                "SELECT * FROM repository_snapshot WHERE repo_id = ?", (self.repo_id,)
            ).fetchone()
        return QueryResult(QueryStatus.FOUND, dict(row))
