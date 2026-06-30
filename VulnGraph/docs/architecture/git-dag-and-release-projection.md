# Git DAG and Release Projection

## Scope

The Git Graph Index is a reusable, read-only fact layer for the nine benchmark
repositories. Git objects and refs are authoritative. SQLite, JSON manifests,
and future Neo4j projections are rebuildable derivatives. This component does
not infer root causes, vulnerability state, BICs, or affected versions.

## Layers

### Commit DAG fact layer

The fact layer stores repository snapshots, commits, ordered parent edges,
refs, and tags. Commits are streamed from `git rev-list --all --parents
--timestamp`; refs and peeled objects are read with `git for-each-ref`. Root,
merge, and octopus commits follow directly from parent cardinality. Disconnected
or orphan histories remain disconnected.

No transitive closure, changed-path inventory, diff inventory, patch IDs, or
rename history is materialized during the structural build.

### Release-tag ancestry view

Two universes are retained:

* `diagnostic_all_tags`: every raw tag with explicit peel status.
* `release_tag_universe`: tags accepted by the repository-specific filters in
  `VulnVersion/vulnversion/stage3_verify/version_registry.py`.

Version strings only classify and normalize tags. They never establish
ancestry. Release reachability is derived from the imported parent DAG.
Aliases are tags whose peeled commit is identical. Immediate predecessor and
successor edges form the transitive reduction of the release-only partial
order. Incomparable release lines and orphan histories are not connected.

The implementation computes release reachability in one DAG traversal using a
compact per-commit release frontier. It does not launch one Git process for
every tag pair. A native Git sample remains the validation oracle.

## Repository snapshot identity

`RepositorySnapshot` records canonical path, HEAD, object format, shallow
state, refs hash, tags hash, tool version, and creation time. `snapshot_id` is
the SHA-256 of repository identity plus Git-observable state. The semantic
manifest hash excludes timestamps and filesystem paths, so deterministic
rebuilds of the same object/ref state compare equal.

A snapshot is immutable. An update creates a new snapshot identity. Append-only
fast-forward changes may reuse unchanged commit rows. Ref deletion,
non-fast-forward movement, tag mutation, or object-format mismatch invalidates
and rebuilds affected derived release and cache rows. Stale edges are removed
transactionally.

## SQLite schema

Core tables are `repository_snapshot`, `commit_node`, `parent_edge`, `git_ref`,
`git_tag`, `tag_alias_group`, and `release_edge`. Foreign keys are enabled.
Indexes cover commit parents/children, peeled refs/tags, release edges, and
cache keys. Composite primary keys include `repo_id` to prevent cross-repo SHA
collisions.

Annotated tags store tag-object SHA, peeled commit, and tagger time.
Lightweight tags store their target SHA and peeled commit without inventing a
tag object. Unpeelable tags remain explicit with a reason.

## Branch and ref coverage

All refs returned by `git for-each-ref` are stored with ref type, direct target,
peeled commit, and symbolic target when present. Commit ingestion uses `--all`,
therefore every object reachable from indexed refs participates in the DAG.
Unreachable objects are intentionally outside this snapshot and dataset fix
coverage marks them as censored/unreachable.

## Incremental update

An update compares old and current snapshot manifests. If refs only advance,
new commits and edges are streamed with idempotent inserts, refs/tags are
replaced, and the release view is rebuilt. Deleted or rewritten refs also cause
the release view to be rebuilt and commits no longer reachable from any current
ref to be pruned. Full reset remains the reference operation. Semantic hashes
from update and reset builds must match.

## On-demand evidence cache

Expensive evidence is requested through a cache keyed by snapshot ID,
operation, canonical JSON arguments, revision, and path. Supported operation
families are changed paths, commit diff, stable patch ID, rename/move/copy
lineage, blame, `log -L/-S/-G`, refs/tags containing a commit, merge-base, and
ancestry. Values record the exact read-only Git command, exit code, output hash,
provenance, generation time, and optional bounded payload location.

The interface is implemented in v1; no all-commit precomputation is permitted.

## Dataset fix coverage preflight

The preflight parser reads only CVE ID, repository, and fixing commits from
`BaseDataOrder.json`. It never accesses `affected_version`. Each fix SHA is
classified as resolved commit, missing, invalid object, missing parent,
unreachable from indexed refs, or repository/snapshot mismatch. Missing data is
not fetched or guessed and prevents `fully_frozen=true` without blocking
independent repository indexing.

## Query boundary

The read-only API returns typed statuses: `found`, `not_found`, `censored`,
`invalid_input`, or `repository_snapshot_mismatch`. It covers commit lookup,
parents, children, native-Git ancestry with snapshot-keyed cache, merge-base,
tag peeling, tags at/containing commits, refs containing commits, release
predecessors/successors/line members, and snapshot manifests. Empty collections
are valid only with `found`; errors are not swallowed as empty results.

Future SZZ and Judge components may query this layer for wrapper-owned Git
facts. Backport, cherry-pick, equivalent-patch, and fix-series semantics remain
outside this index and must be supplied by separately audited evidence.

## Integrity checks

Validation compares indexed and native commit counts, verifies all parent
foreign keys, samples roots/merges, checks tag peeling and release commits,
checks fixed-seed ancestry against `git merge-base --is-ancestor`, proves
release-edge acyclicity and ancestry, compares deterministic semantic hashes,
audits every dataset fix SHA, and scans artifacts for ground-truth leakage.

## Technology boundaries

* Git: sole source of object, ref, tag, and ancestry truth.
* SQLite: local structural index and query/cache implementation.
* JSON/CSV: manifests, inventories, validation, and reproducibility reports.
* Neo4j: not used in v1; a later materialized query view may import stable IDs.

## Threats to validity

The index covers only objects reachable from current local refs. Missing remote
refs, pruned objects, replace/graft configuration, alternates, corrupt objects,
or later ref rewrites can change a snapshot. Repository-specific release
filters may omit legitimate releases or retain unusual non-release tags.
Ancestry establishes reachability, not semantic equivalence or vulnerability
state. Query parity sampling cannot prove every cached query result, so snapshot
identity and explicit censored statuses remain mandatory.
