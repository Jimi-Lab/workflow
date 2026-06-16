"""git_reachability.py – batch tag-containment query via single DAG traversal.

Equivalent to running ``git tag --contains <commit>`` for each commit in a set,
but executes a single ``git rev-list --topo-order --parents <tag-tips>`` pass
and propagates reachability bits through the commit graph.  This avoids one
Git process per commit and is critical for multi-fix CVEs with many commits.

Algorithm (faithful copy of simulate_git_guided_scheduler._precompute_tags_containing_batch):
  1. Resolve each release tag to its tip commit sha; assign a unique bit index.
  2. Resolve each target commit sha (handle aliases / short shas).
  3. Run git rev-list --topo-order --parents over all tag tips.
  4. For each commit in the walk, inherit the OR of parent bits.
  5. A target commit C is "contained in tag T" iff bit(T) is set in bits[C].
"""
from __future__ import annotations

import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Sequence

from vulnversion.git_ops.repo import GitRepo


def _git_base_cmd(repo_path: Path) -> list[str]:
    repo_str = str(repo_path.resolve())
    return ["git", "-c", f"safe.directory={repo_str}", "-C", repo_str]


def _bits_to_tags(bits: int, release_tags: list[str]) -> list[str]:
    """Decode a bitmask back to the list of tag names."""
    out: list[str] = []
    value = bits
    while value:
        lsb = value & -value
        idx = lsb.bit_length() - 1
        if 0 <= idx < len(release_tags):
            out.append(release_tags[idx])
        value ^= lsb
    return out


def batch_tags_containing(
    *,
    repo: GitRepo,
    release_tags: list[str],
    target_commits: set[str] | Sequence[str],
) -> dict[str, dict]:
    """Return which release tags contain each target commit.

    Returns a dict keyed by the original (possibly unresolved) commit sha:
        {
          "ok": bool,
          "tags": list[str],   # release tags that contain this commit
          "error": str,        # non-empty if ok is False
        }

    Semantics: tag T "contains" commit C iff C is an ancestor of T's tip
    (i.e., ``git tag --contains C`` would include T).

    Args:
        repo: GitRepo instance with a valid repo_path.
        release_tags: Ordered list of release tags; order determines bit indices.
        target_commits: Set of commit shas (or aliases) to query.

    Complexity: O(|commit_graph| + |release_tags| + |target_commits|)
    vs. O(|target_commits| * |commit_graph|) for naive per-commit approach.
    """
    target_commits = list(target_commits)
    if not target_commits:
        return {}

    repo_path = Path(repo.repo_path)
    base = _git_base_cmd(repo_path)

    # Step 1: resolve each release tag → tip commit sha → bit index
    tag_tip_bits: dict[str, int] = {}
    valid_release_tags: list[str] = []
    for tag in release_tags:
        try:
            tip = repo.tag_commit(tag)
        except Exception:
            tip = None
        if not tip:
            try:
                tip = repo.rev_parse(tag)
            except Exception:
                tip = None
        if not tip:
            continue
        idx = len(valid_release_tags)
        valid_release_tags.append(tag)
        tag_tip_bits[tip] = tag_tip_bits.get(tip, 0) | (1 << idx)

    # Step 2: resolve target commits
    resolved_to_original: dict[str, list[str]] = defaultdict(list)
    out: dict[str, dict] = {}
    for commit in target_commits:
        try:
            resolved = repo.rev_parse(commit)
        except Exception as exc:
            out[commit] = {"ok": False, "tags": [], "error": str(exc)}
            continue
        resolved_to_original[resolved].append(commit)

    if not resolved_to_original and not out:
        return out

    # Step 3: single DAG walk with bitmap propagation
    bits_by_commit: dict[str, int] = dict(tag_tip_bits)
    tips = sorted(tag_tip_bits.keys())

    if tips:
        cmd = [*base, "rev-list", "--topo-order", "--parents", *tips]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            parts = raw_line.strip().split()
            if not parts:
                continue
            commit_sha = parts[0]
            bits = bits_by_commit.get(commit_sha, 0)
            if not bits:
                continue
            for parent in parts[1:]:
                bits_by_commit[parent] = bits_by_commit.get(parent, 0) | bits
        stderr_text = proc.stderr.read() if proc.stderr else ""
        code = proc.wait()
        if code != 0:
            error = stderr_text.strip() or f"git rev-list failed with exit code {code}"
            for originals in resolved_to_original.values():
                for original in originals:
                    out[original] = {"ok": False, "tags": [], "error": error}
            return out

    # Step 4: decode results
    for resolved, originals in resolved_to_original.items():
        tags = _bits_to_tags(bits_by_commit.get(resolved, 0), valid_release_tags)
        for original in originals:
            out[original] = {"ok": True, "tags": tags, "error": ""}

    return out


def tags_containing_set(
    *,
    repo: GitRepo,
    release_tags: list[str],
    target_commits: set[str] | Sequence[str],
) -> set[str]:
    """Convenience wrapper: return the union of all release tags that contain
    any of the given target commits.  Ignores commits that fail to resolve.
    """
    results = batch_tags_containing(
        repo=repo,
        release_tags=release_tags,
        target_commits=target_commits,
    )
    out: set[str] = set()
    for result in results.values():
        if result.get("ok"):
            out.update(result["tags"])
    return out
