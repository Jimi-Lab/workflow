# Query API

get_commit, get_parents, get_children, is_ancestor, merge_base, peel_tag, tags_at_commit, refs_containing, tags_containing, release_predecessors, release_successors, release_line_members, and get_snapshot_manifest return explicit status-bearing results.

On-demand evidence cache APIs are also exposed without full-repository precomputation: get_changed_paths, get_commit_diff, stable_patch_id, and blame. Cache entries include the repository snapshot id, operation, normalized arguments, Git command, exit code, output hash, provenance, and generation time.
