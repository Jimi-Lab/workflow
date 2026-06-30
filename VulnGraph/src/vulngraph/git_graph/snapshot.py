from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RefRecord:
    ref_name: str
    target_object_sha: str
    object_type: str
    dereferenced_object_sha: str | None
    dereferenced_object_type: str | None
    symbolic_target: str | None
    tagger_time: int | None

    @property
    def peeled_commit_sha(self) -> str | None:
        if self.object_type == "commit":
            return self.target_object_sha
        if self.dereferenced_object_type == "commit":
            return self.dereferenced_object_sha
        return None


@dataclass(frozen=True)
class SnapshotFacts:
    repo_id: str
    canonical_repo_path: str
    head_sha: str
    object_format: str
    shallow: bool
    refs_hash: str
    tags_hash: str
    snapshot_id: str
    refs: tuple[RefRecord, ...]


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(repo), *args], check=check, capture_output=True, text=True, encoding="utf-8", errors="replace")


def collect_snapshot(repo: str | Path, repo_id: str) -> SnapshotFacts:
    repo_path = Path(repo).resolve()
    if _git(repo_path, "rev-parse", "--is-inside-work-tree", check=False).returncode != 0:
        raise ValueError(f"not a Git repository: {repo_path}")
    head_sha = _git(repo_path, "rev-parse", "HEAD").stdout.strip()
    object_result = _git(repo_path, "rev-parse", "--show-object-format", check=False)
    object_format = object_result.stdout.strip() if object_result.returncode == 0 else "sha1"
    shallow = _git(repo_path, "rev-parse", "--is-shallow-repository").stdout.strip().lower() == "true"
    format_spec = "%(refname)%00%(objectname)%00%(objecttype)%00%(*objectname)%00%(*objecttype)%00%(symref)%00%(taggerdate:unix)"
    output = _git(repo_path, "for-each-ref", f"--format={format_spec}").stdout
    refs: list[RefRecord] = []
    for raw_line in output.splitlines():
        parts = raw_line.split("\x00")
        if len(parts) != 7:
            raise ValueError(f"unexpected for-each-ref record with {len(parts)} fields")
        ref_name, target, object_type, deref, deref_type, symbolic, tagger = parts
        refs.append(RefRecord(ref_name, target, object_type, deref or None, deref_type or None, symbolic or None, int(tagger) if tagger.strip().isdigit() else None))
    refs.sort(key=lambda value: value.ref_name)
    refs_text = "\n".join("\0".join([ref.ref_name, ref.target_object_sha, ref.object_type, ref.dereferenced_object_sha or "", ref.dereferenced_object_type or "", ref.symbolic_target or "", str(ref.tagger_time or "")]) for ref in refs)
    tags_text = "\n".join(line for line in refs_text.splitlines() if line.startswith("refs/tags/"))
    refs_hash = hashlib.sha256(refs_text.encode()).hexdigest()
    tags_hash = hashlib.sha256(tags_text.encode()).hexdigest()
    identity = "\0".join([repo_id, head_sha, object_format, str(int(shallow)), refs_hash, tags_hash])
    return SnapshotFacts(repo_id, str(repo_path), head_sha, object_format, shallow, refs_hash, tags_hash, hashlib.sha256(identity.encode()).hexdigest(), tuple(refs))

