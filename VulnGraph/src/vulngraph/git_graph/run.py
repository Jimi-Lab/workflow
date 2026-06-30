from __future__ import annotations

import csv
import hashlib
import json
import shutil
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .builder import GitGraphBuilder
from .query import GitGraphQuery
from .schema import SCHEMA_SQL
from .validation import audit_dataset_fix_coverage, validate_graph_index

TARGET_REPOSITORIES = ("FFmpeg", "ImageMagick", "curl", "httpd", "linux", "openjpeg", "openssl", "qemu", "wireshark")


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _query_parity_sample(database: Path, repo_path: Path) -> list[dict[str, Any]]:
    query = GitGraphQuery(database, repo_path)
    connection = sqlite3.connect(database)
    try:
        total = connection.execute("SELECT COUNT(*) FROM commit_node").fetchone()[0]
        offsets = sorted({0, max(0, total // 2), max(0, total - 1)})
        commits = [
            connection.execute("SELECT commit_sha FROM commit_node ORDER BY topo_order LIMIT 1 OFFSET ?", (offset,)).fetchone()[0]
            for offset in offsets if total
        ]
    finally:
        connection.close()
    rows: list[dict[str, Any]] = []
    for sha in commits:
        indexed = query.get_parents(sha)
        rows.append({"commit_sha": sha, "query_status": indexed.status.value, "parent_count": len(indexed.value or []), "native_parity": indexed.status.value == "found"})
    if len(commits) >= 2:
        ancestry = query.is_ancestor(commits[-1], commits[0])
        rows.append({"ancestor_sha": commits[-1], "descendant_sha": commits[0], "query_status": ancestry.status.value, "is_ancestor": ancestry.value, "native_parity": ancestry.status.value == "found"})
    return rows


def build_index_run(
    *,
    dataset_path: str | Path,
    repo_root: str | Path,
    out_dir: str | Path,
    repo_ids: list[str],
    reset: bool = False,
    reset_repo: bool = False,
    update: bool = False,
    batch_size: int = 5_000,
) -> dict[str, Any]:
    dataset = Path(dataset_path).resolve()
    repositories = Path(repo_root).resolve()
    output = Path(out_dir).resolve()
    unknown = sorted(set(repo_ids) - set(TARGET_REPOSITORIES))
    if unknown:
        raise ValueError(f"unsupported repositories: {unknown}")
    if reset and output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    builder = GitGraphBuilder(batch_size=batch_size)
    results = []
    validations: dict[str, Any] = {}
    snapshots: list[dict[str, Any]] = []
    for repo_id in repo_ids:
        repo_path = repositories / repo_id
        repo_output = output / repo_id
        if reset_repo and repo_output.exists():
            shutil.rmtree(repo_output)
        result = builder.build(
            repo_path, repo_output, repo_id=repo_id,
            reset=reset or reset_repo or not (repo_output / "graph.sqlite").exists(),
            update=update,
        )
        results.append(asdict(result))
        integrity = validate_graph_index(repo_output / "graph.sqlite", repo_path)
        validations[repo_id] = integrity
        _write_json(repo_output / "integrity_report.json", integrity)
        _write_json(repo_output / "query_parity_sample.json", _query_parity_sample(repo_output / "graph.sqlite", repo_path))
        manifest = json.loads((repo_output / "manifest.json").read_text(encoding="utf-8"))
        snapshots.append({"repo_id": repo_id, "snapshot_id": result.snapshot_id, "semantic_hash": result.semantic_hash, "head": manifest["head_sha"], "shallow": result.shallow})

    coverage = audit_dataset_fix_coverage(dataset, output, repositories)
    _write_csv(output / "dataset_fix_coverage.csv", coverage)
    resolved = sum(row["status"] == "resolved" for row in coverage)
    censored = len(coverage) - resolved
    selected_coverage = [row for row in coverage if row["repo_id"] in repo_ids]
    selected_resolved = sum(row["status"] == "resolved" for row in selected_coverage)
    fully_frozen = set(repo_ids) == set(TARGET_REPOSITORIES) and all(report["ok"] for report in validations.values()) and censored == 0
    summary = {
        "index_version": "v1",
        "repositories_requested": len(repo_ids),
        "repositories_built": len(results),
        "repository_ids": repo_ids,
        "all_repositories_shallow_false": all(not row["shallow"] for row in results),
        "commit_count": sum(row["commit_count"] for row in results),
        "parent_edge_count": sum(row["parent_edge_count"] for row in results),
        "raw_tag_count": sum(row["raw_tag_count"] for row in results),
        "release_tag_count": sum(row["release_tag_count"] for row in results),
        "fix_sha_total": len(coverage),
        "fix_sha_resolved": selected_resolved if len(repo_ids) < len(TARGET_REPOSITORIES) else resolved,
        "fix_sha_censored": len(selected_coverage) - selected_resolved if len(repo_ids) < len(TARGET_REPOSITORIES) else censored,
        "fully_frozen": fully_frozen,
        "git_is_fact_source": True,
        "sqlite_is_derived": True,
    }
    _write_json(output / "summary.json", summary)
    _write_json(output / "repository_snapshot_manifest.json", snapshots)
    _write_json(output / "validation_summary.json", {"repositories": validations, "all_valid": len(validations) == len(repo_ids) and all(value["ok"] for value in validations.values())})
    _write_csv(output / "build_performance.csv", [{"repo_id": row["repo_id"], "duration_seconds": row["duration_seconds"], "index_size_bytes": row["index_size_bytes"], "commit_count": row["commit_count"], "max_pending_batch": row["max_pending_batch"]} for row in results])
    _write_json(output / "provenance_manifest.json", {
        "dataset_path": str(dataset),
        "dataset_sha256": hashlib.sha256(dataset.read_bytes()).hexdigest(),
        "repo_root": str(repositories),
        "index_version": "v1",
        "read_only_git": True,
        "model_invocations": 0,
        "repositories": snapshots,
    })
    (output / "schema.sql").write_text(SCHEMA_SQL.strip() + "\n", encoding="utf-8")
    (output / "query_api_report.md").write_text(
        "# Query API\n\n"
        "get_commit, get_parents, get_children, is_ancestor, merge_base, peel_tag, "
        "tags_at_commit, refs_containing, tags_containing, release_predecessors, "
        "release_successors, release_line_members, and get_snapshot_manifest "
        "return explicit status-bearing results.\n\n"
        "On-demand evidence cache APIs are also exposed without full-repository "
        "precomputation: get_changed_paths, get_commit_diff, stable_patch_id, "
        "blame, blame with -w/-M/-C options, log_l, log_pickaxe (-S/-G), "
        "log_follow, and per_parent_diff. Cache entries include the repository "
        "snapshot id, operation, normalized arguments, revision/path, Git command, "
        "exit code, output hash, provenance, and generation time.\n",
        encoding="utf-8",
    )
    report_lines = [
        "# VulnGraph Git Graph Index v1", "",
        "Git object databases are the fact source; SQLite and JSON files are rebuildable indexes.", "",
        f"- Repositories built: {len(results)}",
        f"- Commits: {summary['commit_count']}",
        f"- Parent edges: {summary['parent_edge_count']}",
        f"- Raw tags: {summary['raw_tag_count']}",
        f"- Release tags: {summary['release_tag_count']}",
        f"- Selected fix SHAs resolved: {summary['fix_sha_resolved']}",
        f"- Selected fix SHAs censored: {summary['fix_sha_censored']}",
        f"- Fully frozen: {fully_frozen}", "",
        "This structural index does not infer vulnerability state or version predictions.",
    ]
    (output / "report.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    return summary


def validate_index_run(*, dataset_path: str | Path, repo_root: str | Path, index_root: str | Path) -> dict[str, Any]:
    root = Path(index_root)
    validations = {}
    for repo_id in TARGET_REPOSITORIES:
        database = root / repo_id / "graph.sqlite"
        repo = Path(repo_root) / repo_id
        if database.exists() and repo.exists():
            validations[repo_id] = validate_graph_index(database, repo)
    coverage = audit_dataset_fix_coverage(dataset_path, root, repo_root)
    _write_csv(root / "dataset_fix_coverage.csv", coverage)
    result = {
        "repositories_validated": len(validations),
        "all_valid": bool(validations) and all(value["ok"] for value in validations.values()),
        "fix_sha_total": len(coverage),
        "fix_sha_resolved": sum(row["status"] == "resolved" for row in coverage),
        "fix_sha_censored": sum(row["status"] != "resolved" for row in coverage),
        "repositories": validations,
    }
    _write_json(root / "validation_summary.json", result)
    return result

