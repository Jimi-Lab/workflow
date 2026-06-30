PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS repository_snapshot (
    repo_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL UNIQUE,
    canonical_repo_path TEXT NOT NULL,
    head_sha TEXT NOT NULL,
    object_format TEXT NOT NULL,
    shallow INTEGER NOT NULL CHECK (shallow IN (0, 1)),
    refs_hash TEXT NOT NULL,
    tags_hash TEXT NOT NULL,
    build_tool_version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    semantic_hash TEXT,
    fully_frozen INTEGER NOT NULL DEFAULT 0 CHECK (fully_frozen IN (0, 1))
);

CREATE TABLE IF NOT EXISTS commit_node (
    repo_id TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    author_time INTEGER NOT NULL,
    committer_time INTEGER NOT NULL,
    parent_count INTEGER NOT NULL,
    is_root INTEGER NOT NULL CHECK (is_root IN (0, 1)),
    is_merge INTEGER NOT NULL CHECK (is_merge IN (0, 1)),
    topo_order INTEGER NOT NULL,
    PRIMARY KEY (repo_id, commit_sha),
    UNIQUE (repo_id, topo_order),
    FOREIGN KEY (repo_id) REFERENCES repository_snapshot(repo_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS parent_edge (
    repo_id TEXT NOT NULL,
    child_sha TEXT NOT NULL,
    parent_sha TEXT NOT NULL,
    parent_order INTEGER NOT NULL,
    PRIMARY KEY (repo_id, child_sha, parent_order),
    FOREIGN KEY (repo_id, child_sha) REFERENCES commit_node(repo_id, commit_sha) ON DELETE CASCADE,
    FOREIGN KEY (repo_id, parent_sha) REFERENCES commit_node(repo_id, commit_sha) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS git_ref (
    repo_id TEXT NOT NULL,
    ref_name TEXT NOT NULL,
    ref_type TEXT NOT NULL,
    target_object_sha TEXT NOT NULL,
    peeled_commit_sha TEXT,
    symbolic_target TEXT,
    PRIMARY KEY (repo_id, ref_name),
    FOREIGN KEY (repo_id) REFERENCES repository_snapshot(repo_id) ON DELETE CASCADE,
    FOREIGN KEY (repo_id, peeled_commit_sha) REFERENCES commit_node(repo_id, commit_sha)
);

CREATE TABLE IF NOT EXISTS git_tag (
    repo_id TEXT NOT NULL,
    raw_tag_name TEXT NOT NULL,
    tag_object_sha TEXT,
    target_object_sha TEXT NOT NULL,
    peeled_commit_sha TEXT,
    tag_type TEXT NOT NULL CHECK (tag_type IN ('annotated', 'lightweight', 'unresolved')),
    tagger_time INTEGER,
    is_release_tag INTEGER NOT NULL CHECK (is_release_tag IN (0, 1)),
    filter_reason TEXT,
    normalized_release_name TEXT,
    peel_status TEXT NOT NULL,
    PRIMARY KEY (repo_id, raw_tag_name),
    FOREIGN KEY (repo_id) REFERENCES repository_snapshot(repo_id) ON DELETE CASCADE,
    FOREIGN KEY (repo_id, peeled_commit_sha) REFERENCES commit_node(repo_id, commit_sha)
);

CREATE TABLE IF NOT EXISTS tag_alias_group (
    repo_id TEXT NOT NULL,
    alias_group_id TEXT NOT NULL,
    canonical_tag TEXT NOT NULL,
    raw_tag_name TEXT NOT NULL,
    peeled_commit_sha TEXT NOT NULL,
    PRIMARY KEY (repo_id, raw_tag_name),
    FOREIGN KEY (repo_id, raw_tag_name) REFERENCES git_tag(repo_id, raw_tag_name) ON DELETE CASCADE,
    FOREIGN KEY (repo_id, peeled_commit_sha) REFERENCES commit_node(repo_id, commit_sha) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS release_edge (
    repo_id TEXT NOT NULL,
    predecessor_tag TEXT NOT NULL,
    successor_tag TEXT NOT NULL,
    derivation TEXT NOT NULL DEFAULT 'git_dag_frontier',
    PRIMARY KEY (repo_id, predecessor_tag, successor_tag),
    FOREIGN KEY (repo_id, predecessor_tag) REFERENCES git_tag(repo_id, raw_tag_name) ON DELETE CASCADE,
    FOREIGN KEY (repo_id, successor_tag) REFERENCES git_tag(repo_id, raw_tag_name) ON DELETE CASCADE,
    CHECK (predecessor_tag <> successor_tag)
);

CREATE TABLE IF NOT EXISTS evidence_cache (
    repo_id TEXT NOT NULL,
    repo_snapshot_id TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    operation TEXT NOT NULL,
    normalized_arguments TEXT NOT NULL,
    revision TEXT,
    path TEXT,
    git_command TEXT NOT NULL,
    exit_code INTEGER NOT NULL,
    output_hash TEXT NOT NULL,
    output_text TEXT,
    provenance TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    PRIMARY KEY (repo_id, repo_snapshot_id, cache_key),
    FOREIGN KEY (repo_id) REFERENCES repository_snapshot(repo_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_parent_parent ON parent_edge(repo_id, parent_sha);
CREATE INDEX IF NOT EXISTS idx_commit_topo ON commit_node(repo_id, topo_order);
CREATE INDEX IF NOT EXISTS idx_ref_peeled ON git_ref(repo_id, peeled_commit_sha);
CREATE INDEX IF NOT EXISTS idx_tag_peeled ON git_tag(repo_id, peeled_commit_sha);
CREATE INDEX IF NOT EXISTS idx_tag_release ON git_tag(repo_id, is_release_tag);
CREATE INDEX IF NOT EXISTS idx_release_successor ON release_edge(repo_id, successor_tag);
