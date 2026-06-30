# Git DAG Index v1 Implementation Plan

## Objective and boundary

Build a reusable structural Git index for FFmpeg, ImageMagick, curl, httpd,
linux, openjpeg, openssl, qemu, and wireshark. Git remains authoritative. The
implementation must not read benchmark affected-version labels or run any
Root Cause, SZZ, Judge, model, vulnerability-state, or Neo4j stage.

## Task 1: Contracts and synthetic fixtures

Files:

* `src/vulngraph/git_graph/schema.py`
* `src/vulngraph/git_graph/sqlite_store.py`
* `tests/test_git_graph_schema.py`
* `tests/fixtures/git_graph/`

Test first: snapshot determinism, foreign keys, ordered parents, roots, two-
parent and octopus merges, orphan roots, annotated/lightweight tags, aliases,
and invalid status handling. Create temporary Git repositories in tests rather
than committing generated object databases.

## Task 2: Snapshot and streaming builder

Files:

* `src/vulngraph/git_graph/snapshot.py`
* `src/vulngraph/git_graph/builder.py`
* `tests/test_git_graph_builder.py`

Test first: bounded line streaming, exact commit/edge counts, tag peeling,
deterministic rebuild, fast-forward update, ref deletion, and rewritten refs.
Use batched SQLite transactions. Never collect the full rev-list output.

## Task 3: Release projection

Files:

* `src/vulngraph/git_graph/release_view.py`
* `tests/test_git_graph_release_view.py`

Test first: repository filters, same-commit aliases, linear predecessors,
divergent/incomparable lines, orphan histories, cycle freedom, and proof that
version-name order does not create edges. Construct the partial order from the
stored parent DAG in one traversal and persist immediate edges only.

## Task 4: Query and evidence cache

Files:

* `src/vulngraph/git_graph/query.py`
* `tests/test_git_graph_query.py`

Test first: all public methods and all five statuses, snapshot mismatch,
ancestry/merge-base parity, containing refs/tags, release navigation, cache-key
normalization, and cache provenance. Native Git calls must be read-only.

## Task 5: Validation, preflight, and CLIs

Files:

* `src/vulngraph/git_graph/validation.py`
* `scripts/build_git_graph_index.py`
* `scripts/validate_git_graph_index.py`
* `tests/test_git_graph_validation.py`

Test first: fix-commit extraction without touching `affected_version`, explicit
censored reasons, count/parent/tag/release checks, deterministic semantic hash,
and leakage detection. CLIs call service functions and contain no graph logic.

## Gate A: synthetic verification

Run focused Git Graph tests, then full pytest and compileall. Stop if any DAG,
peeling, release, update, query, or leakage test fails.

## Gate B: openjpeg smoke

Build only `openjpeg` with `--reset`. Validate native/index counts, roots,
merges, parent edges, refs/tags, peel status, release DAG, deterministic rebuild,
incremental no-op/update parity, and fixed-seed query parity. Stop on any
failure; do not run Linux.

Artifacts are written below
`runs/batches/vulngraph-git-graph-index-v1/openjpeg/`.

## Gate C: Linux scalability

Build the complete Linux structural DAG and release view with streaming batches.
Record duration, SQLite size, batches, and peak working set when available. Do
not truncate history or precompute diffs/paths/patch IDs. Stop if native counts,
integrity, memory bounds, or semantic manifest checks fail.

## Gate D: nine repositories

After A/B/C pass, build/update all nine repositories, run dataset fix coverage,
validate every repository, and emit top-level manifests/reports. Drift from the
historical count baseline is recorded as a new snapshot, never hard-coded as a
test failure.

## Required artifacts

Top-level: `summary.json`, `report.md`,
`repository_snapshot_manifest.json`, `dataset_fix_coverage.csv`,
`build_performance.csv`, `validation_summary.json`,
`provenance_manifest.json`, `schema.sql`, and `query_api_report.md`.

Per repo: `graph.sqlite`, `manifest.json`, `integrity_report.json`,
`raw_tag_inventory.json`, `release_tag_universe.json`,
`release_ancestry.json`, `query_parity_sample.json`, and `build_trace.json`.

## Stop conditions

Stop at the current gate for corrupt/missing Git objects, native/index count
mismatch, unresolved parent edges, incorrect tag peeling, release cycles or
non-ancestral edges, non-deterministic semantic hashes, unbounded Linux memory,
repository modification, stale incremental rows, or any benchmark ground-truth
leakage. Report the exact failing repository, command, and artifact; do not
manufacture a 9/9 result.
