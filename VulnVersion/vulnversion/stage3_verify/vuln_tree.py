from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from typing import Any

from vulnversion.git_ops.repo import GitRepo
from vulnversion.stage3_verify.version_registry import (
  branch_model,
  filter_release_tags,
  infer_repo_name,
  line_key,
  line_family_key,
  line_partition_key,
  parse_version,
  sort_tags_for_line,
)


@dataclass
class TagRuntimeState:
  """Mutable Step3 state attached to one release-tag node."""

  plan_status: str = "unplanned"
  plan_roles: list[str] = field(default_factory=list)
  verdict: str | None = None
  verdict_source: str | None = None
  confidence: float | None = None
  contains_fix_clusters: list[str] = field(default_factory=list)
  contains_vic_clusters: list[str] = field(default_factory=list)
  probe_round: int | None = None
  inferred_from: list[str] = field(default_factory=list)
  certificate_id: str | None = None
  no_fic_reason: str | None = None
  search_mode: str | None = None
  boundary_status: str | None = None

  def to_dict(self) -> dict[str, Any]:
    return {
      "plan_status": self.plan_status,
      "plan_roles": self.plan_roles,
      "verdict": self.verdict,
      "verdict_source": self.verdict_source,
      "confidence": self.confidence,
      "contains_fix_clusters": self.contains_fix_clusters,
      "contains_vic_clusters": self.contains_vic_clusters,
      "probe_round": self.probe_round,
      "inferred_from": self.inferred_from,
      "certificate_id": self.certificate_id,
      "no_fic_reason": self.no_fic_reason,
      "search_mode": self.search_mode,
      "boundary_status": self.boundary_status,
    }


@dataclass
class LineRuntimeState:
  """Mutable Step3 state attached to one release line."""

  plan_status: str = "unplanned"
  plan_roles: list[str] = field(default_factory=list)
  verdict: str | None = None
  verdict_source: str | None = None
  confidence: float | None = None
  contains_fix_clusters: list[str] = field(default_factory=list)
  contains_vic_clusters: list[str] = field(default_factory=list)
  probe_round: int | None = None
  inferred_from: list[str] = field(default_factory=list)
  certificate_id: str | None = None
  no_fic_reason: str | None = None
  search_mode: str | None = None
  boundary_status: str | None = None

  def to_dict(self) -> dict[str, Any]:
    return {
      "plan_status": self.plan_status,
      "plan_roles": self.plan_roles,
      "verdict": self.verdict,
      "verdict_source": self.verdict_source,
      "confidence": self.confidence,
      "contains_fix_clusters": self.contains_fix_clusters,
      "contains_vic_clusters": self.contains_vic_clusters,
      "probe_round": self.probe_round,
      "inferred_from": self.inferred_from,
      "certificate_id": self.certificate_id,
      "no_fic_reason": self.no_fic_reason,
      "search_mode": self.search_mode,
      "boundary_status": self.boundary_status,
    }


@dataclass
class BoundaryRuntimeState:
  """Mutable Step3 state attached to one line boundary search."""

  plan_status: str = "unplanned"
  plan_roles: list[str] = field(default_factory=list)
  verdict: str | None = None
  verdict_source: str | None = None
  confidence: float | None = None
  contains_fix_clusters: list[str] = field(default_factory=list)
  contains_vic_clusters: list[str] = field(default_factory=list)
  probe_round: int | None = None
  inferred_from: list[str] = field(default_factory=list)
  certificate_id: str | None = None
  no_fic_reason: str | None = None
  search_mode: str | None = None
  boundary_status: str | None = None

  def to_dict(self) -> dict[str, Any]:
    return {
      "plan_status": self.plan_status,
      "plan_roles": self.plan_roles,
      "verdict": self.verdict,
      "verdict_source": self.verdict_source,
      "confidence": self.confidence,
      "contains_fix_clusters": self.contains_fix_clusters,
      "contains_vic_clusters": self.contains_vic_clusters,
      "probe_round": self.probe_round,
      "inferred_from": self.inferred_from,
      "certificate_id": self.certificate_id,
      "no_fic_reason": self.no_fic_reason,
      "search_mode": self.search_mode,
      "boundary_status": self.boundary_status,
    }


def _append_unique(values: list[str], value: str | None) -> None:
  if value and value not in values:
    values.append(value)


@dataclass
class TagNode:
  tag: str
  line: str
  family_key: str
  line_partition: str
  version_tuple: tuple[Any, ...]
  commit_sha: str
  index_in_line: int
  runtime: TagRuntimeState = field(default_factory=TagRuntimeState)

  def to_dict(self) -> dict[str, Any]:
    return {
      "tag": self.tag,
      "line": self.line,
      "family_key": self.family_key,
      "line_partition": self.line_partition,
      "version_tuple": list(self.version_tuple),
      "commit_sha": self.commit_sha,
      "index_in_line": self.index_in_line,
      "runtime": self.runtime.to_dict(),
    }


@dataclass
class LineNode:
  line_key: str
  family_key: str
  line_partition: str
  tags_asc: list[str]
  tags_desc: list[str]
  newer_line: str | None
  older_line: str | None
  tag_nodes: list[TagNode] = field(default_factory=list)
  runtime: LineRuntimeState = field(default_factory=LineRuntimeState)

  def to_dict(self) -> dict[str, Any]:
    return {
      "line_key": self.line_key,
      "family_key": self.family_key,
      "line_partition": self.line_partition,
      "tags_asc": self.tags_asc,
      "tags_desc": self.tags_desc,
      "newer_line": self.newer_line,
      "older_line": self.older_line,
      "tag_nodes": [n.to_dict() for n in self.tag_nodes],
      "runtime": self.runtime.to_dict(),
    }


@dataclass
class CommitCluster:
  cluster_id: str
  kind: str
  classification: str
  semantics: str
  commits: list[dict[str, Any]]
  components: list[list[str]]
  source: str
  evidence: list[dict[str, Any]] = field(default_factory=list)

  def to_dict(self) -> dict[str, Any]:
    return {
      "cluster_id": self.cluster_id,
      "kind": self.kind,
      "classification": self.classification,
      "semantics": self.semantics,
      "commits": self.commits,
      "components": self.components,
      "source": self.source,
      "evidence": self.evidence,
    }


@dataclass
class LineBoundary:
  line: str
  fic_tag: str | None = None
  fic_index: int | None = None
  vic_tag: str | None = None
  vic_index: int | None = None
  affected_interval: dict[str, Any] | None = None
  status: str = "unknown"
  evidence: list[dict[str, Any]] = field(default_factory=list)
  monotonicity_certificate: dict[str, Any] | None = None
  runtime: BoundaryRuntimeState = field(default_factory=BoundaryRuntimeState)

  def to_dict(self) -> dict[str, Any]:
    return {
      "line": self.line,
      "fic_tag": self.fic_tag,
      "fic_index": self.fic_index,
      "vic_tag": self.vic_tag,
      "vic_index": self.vic_index,
      "affected_interval": self.affected_interval,
      "status": self.status,
      "evidence": self.evidence,
      "monotonicity_certificate": self.monotonicity_certificate,
      "runtime": self.runtime.to_dict(),
    }


def normalize_commit_groups(fixing_commits: list[Any] | None) -> list[list[str]]:
  groups: list[list[str]] = []
  for item in fixing_commits or []:
    if isinstance(item, str):
      group = [item.strip()] if item.strip() else []
    else:
      group = [str(x).strip() for x in (item or []) if str(x).strip()]
    if group:
      groups.append(group)
  return groups


def _line_version(repo_name: str, line: str) -> tuple[Any, ...]:
  if repo_name == "FFmpeg":
    return parse_version(repo_name, f"n{line}")
  if repo_name == "qemu":
    return parse_version(repo_name, f"v{line}.0")
  if repo_name == "wireshark":
    return parse_version(repo_name, f"v{line}.0")
  if repo_name == "openssl":
    nums = [int(x) for x in re.findall(r"\d+", line)]
    if nums:
      while len(nums) < 4:
        nums.append(0)
      return tuple(nums)
    return (line,)
  if repo_name == "linux":
    return parse_version(repo_name, f"v{line}")
  if repo_name == "httpd":
    return parse_version(repo_name, f"{line}.0")
  if repo_name == "ImageMagick":
    return parse_version(repo_name, f"{line}.0-0")
  if repo_name == "openjpeg":
    return parse_version(repo_name, f"v{line}.0")
  if repo_name == "curl":
    return parse_version(repo_name, "curl-999_999_999")
  return tuple(int(x) for x in line.split(".") if x.isdigit()) or (line,)


def _line_family_rank(repo_name: str, family_key: str) -> tuple[Any, ...]:
  if repo_name == "openssl":
    order = {
      "openssl-mainline": 0,
      "openssl-fips": 1,
      "openssl-engine": 2,
    }
    return (order.get(family_key, 99), family_key)
  return (0, family_key)


def _group_release_tags(repo_name: str, tags: list[str]) -> dict[str, list[str]]:
  groups: dict[str, list[str]] = {}
  for tag in tags:
    groups.setdefault(line_key(repo_name, tag), []).append(tag)
  for line, vals in list(groups.items()):
    groups[line] = sort_tags_for_line(repo_name, vals, reverse=False)
  return groups


def _line_families_from_nodes(line_nodes: dict[str, "LineNode"]) -> dict[str, dict[str, Any]]:
  families: dict[str, dict[str, Any]] = {}
  for line, node in line_nodes.items():
    entry = families.setdefault(
      node.family_key,
      {
        "family_key": node.family_key,
        "line_partition": node.line_partition,
        "lines": [],
        "edges": {},
      },
    )
    entry["lines"].append(line)
    entry["edges"][line] = {
      "newer_line": node.newer_line,
      "older_line": node.older_line,
    }
  return families


def _safe_tag_commit(repo: GitRepo, tag: str) -> str:
  try:
    return repo.tag_commit(tag)
  except Exception:
    try:
      return repo.rev_parse(tag)
    except Exception:
      return ""


def build_base_vuln_tree(
  *,
  repo: GitRepo,
  repo_name: str,
  tags_glob: str | None = None,
) -> tuple[list[str], dict[str, LineNode], int, int]:
  """Build explicit release-line graph nodes from repository tags."""
  raw_tags = repo.list_tags(tags_glob=tags_glob, max_tags=None)
  release_tags = filter_release_tags(repo_name, raw_tags)
  release_lines = _group_release_tags(repo_name, release_tags)
  family_to_lines: dict[str, list[str]] = {}
  line_to_family: dict[str, str] = {}
  line_to_partition: dict[str, str] = {}
  for line in release_lines:
    family = line_family_key(repo_name, line)
    partition = line_partition_key(repo_name, line)
    line_to_family[line] = family
    line_to_partition[line] = partition
    family_to_lines.setdefault(family, []).append(line)
  for family, lines in list(family_to_lines.items()):
    family_to_lines[family] = sorted(
      lines,
      key=lambda line: _line_version(repo_name, line),
      reverse=True,
    )
  ordered_families = sorted(
    family_to_lines.keys(),
    key=lambda family: _line_family_rank(repo_name, family),
  )
  ordered_lines = [
    line
    for family in ordered_families
    for line in family_to_lines[family]
  ]
  family_neighbors: dict[str, dict[str, tuple[str | None, str | None]]] = {}
  for family, lines in family_to_lines.items():
    family_neighbors[family] = {}
    for idx, line in enumerate(lines):
      family_neighbors[family][line] = (
        lines[idx - 1] if idx > 0 else None,
        lines[idx + 1] if idx + 1 < len(lines) else None,
      )
  line_nodes: dict[str, LineNode] = {}
  for line in ordered_lines:
    tags_asc = release_lines[line]
    family = line_to_family[line]
    partition = line_to_partition[line]
    newer_line, older_line = family_neighbors[family][line]
    tag_nodes = [
      TagNode(
        tag=tag,
        line=line,
        family_key=family,
        line_partition=partition,
        version_tuple=parse_version(repo_name, tag),
        commit_sha=_safe_tag_commit(repo, tag),
        index_in_line=i,
      )
      for i, tag in enumerate(tags_asc)
    ]
    line_nodes[line] = LineNode(
      line_key=line,
      family_key=family,
      line_partition=partition,
      tags_asc=tags_asc,
      tags_desc=list(reversed(tags_asc)),
      newer_line=newer_line,
      older_line=older_line,
      tag_nodes=tag_nodes,
    )
  return ordered_lines, line_nodes, len(raw_tags), len(release_tags)


def _commit_record(repo: GitRepo, sha: str, *, source: str) -> dict[str, Any]:
  """Return lightweight evidence for a seed commit without equivalence search."""
  record: dict[str, Any] = {
    "sha": sha,
    "required": True,
    "source": source,
    "patch_id": None,
    "hunk_hash_count": 0,
    "changed_files": [],
    "profile_error": None,
  }
  try:
    record["resolved_sha"] = repo.rev_parse(sha)
  except Exception as e:
    record["resolved_sha"] = None
    record["profile_error"] = f"rev_parse_failed: {type(e).__name__}: {e}"
  try:
    record["changed_files"] = sorted(repo.changed_files(sha))
  except Exception as e:
    if record["profile_error"]:
      record["profile_error"] += f"; changed_files_failed: {type(e).__name__}: {e}"
    else:
      record["profile_error"] = f"changed_files_failed: {type(e).__name__}: {e}"
  return record


def build_fix_clusters(
  repo: GitRepo,
  fixing_commits: list[Any] | None,
  *,
  expand_equivalents: bool = True,
) -> list[CommitCluster]:
  """Build fix evidence clusters from dataset commits only.

  ``expand_equivalents`` is retained for API compatibility, but Step3 no
  longer performs BAPEE or line-local FIC recovery in the main path. Multi-fix
  CVEs are treated as an OR evidence bundle, matching the current Step3 design:
  any supplied fix commit can seed git reachability and scheduler priority, but
  agent/ASBS still decides affected tags.
  """
  del expand_equivalents
  clusters: list[CommitCluster] = []
  for idx, group in enumerate(normalize_commit_groups(fixing_commits)):
    commits = [_commit_record(repo, sha, source="dataset_fix_commit") for sha in group]
    clusters.append(CommitCluster(
      cluster_id=f"fix_cluster_{idx}",
      kind="fix",
      classification="dataset_or_evidence_bundle",
      semantics="any",
      commits=commits,
      components=[list(group)],
      source="dataset_fix_commits_no_equivalence",
      evidence=[{
        "source": "step3_design",
        "reason": "BAPEE/line-local FIC recovery is removed from the default path; supplied fixes are used as OR git evidence.",
      }],
    ))
  return clusters


def build_vic_clusters(
  repo: GitRepo,
  vuln_commit: str | None,
  *,
  expand_equivalents: bool = True,
) -> list[CommitCluster]:
  del expand_equivalents
  if not vuln_commit:
    return []
  return [CommitCluster(
    cluster_id="vic_cluster_0",
    kind="vic",
    classification="seed_vic_commit",
    semantics="any",
    commits=[_commit_record(repo, vuln_commit, source="provided_vuln_commit")],
    components=[[vuln_commit]],
    source="provided_vuln_commit_no_equivalence",
    evidence=[{
      "source": "optional_vuln_commit",
      "reason": "VIC seed is optional evidence only; default Step3 does not depend on SZZ or AgentSZZ.",
    }],
  )]


def _tags_containing_on_line(
  *,
  repo: GitRepo,
  repo_name: str,
  commit: str,
  line: str,
  line_tags: list[str],
  tags_glob: str | None,
  cache: dict[str, dict[str, list[str]]],
) -> list[str]:
  if commit not in cache:
    try:
      raw = repo.list_tags_containing(commit, tags_glob=tags_glob)
    except Exception:
      raw = []
    release = filter_release_tags(repo_name, raw)
    by_line: dict[str, list[str]] = {}
    for tag in release:
      by_line.setdefault(line_key(repo_name, tag), []).append(tag)
    for lk, tags in list(by_line.items()):
      by_line[lk] = sort_tags_for_line(repo_name, tags, reverse=False)
    cache[commit] = by_line
  allowed = set(line_tags)
  return [t for t in cache[commit].get(line, []) if t in allowed]


def _cluster_frontier_on_line(
  *,
  repo: GitRepo,
  repo_name: str,
  cluster: CommitCluster,
  line: str,
  line_tags: list[str],
  tags_glob: str | None,
  cache: dict[str, dict[str, list[str]]],
) -> dict[str, Any] | None:
  index = {tag: i for i, tag in enumerate(line_tags)}
  component_hits: list[dict[str, Any]] = []
  for component in cluster.components:
    best: dict[str, Any] | None = None
    for commit in component:
      tags = _tags_containing_on_line(
        repo=repo,
        repo_name=repo_name,
        commit=commit,
        line=line,
        line_tags=line_tags,
        tags_glob=tags_glob,
        cache=cache,
      )
      if not tags:
        continue
      first = min(tags, key=lambda tag: index[tag])
      hit = {"commit": commit, "tag": first, "index": index[first], "cluster_id": cluster.cluster_id}
      if best is None or hit["index"] < best["index"]:
        best = hit
    if best is None and cluster.semantics == "all":
      return None
    if best is not None:
      component_hits.append(best)

  if not component_hits:
    return None
  if cluster.semantics == "all":
    frontier = max(component_hits, key=lambda hit: hit["index"])
  else:
    frontier = min(component_hits, key=lambda hit: hit["index"])
  return {
    "tag": frontier["tag"],
    "index": frontier["index"],
    "commit": frontier["commit"],
    "cluster_id": cluster.cluster_id,
    "cluster_semantics": cluster.semantics,
    "component_hits": component_hits,
  }


def _best_frontier(
  *,
  repo: GitRepo,
  repo_name: str,
  clusters: list[CommitCluster],
  line: str,
  line_tags: list[str],
  tags_glob: str | None,
  cache: dict[str, dict[str, list[str]]],
  prefer: str,
) -> dict[str, Any] | None:
  hits = [
    h for cluster in clusters
    if (h := _cluster_frontier_on_line(
      repo=repo,
      repo_name=repo_name,
      cluster=cluster,
      line=line,
      line_tags=line_tags,
      tags_glob=tags_glob,
      cache=cache,
    )) is not None
  ]
  if not hits:
    return None
  if prefer == "earliest":
    return min(hits, key=lambda hit: hit["index"])
  return max(hits, key=lambda hit: hit["index"])


def _collect_cluster_hits_on_line(
  *,
  repo: GitRepo,
  repo_name: str,
  clusters: list[CommitCluster],
  line: str,
  line_tags: list[str],
  tags_glob: str | None,
  cache: dict[str, dict[str, list[str]]],
) -> list[dict[str, Any]]:
  """Return one hit dict per cluster that lands at least one tag on this line."""
  hits: list[dict[str, Any]] = []
  for cluster in clusters:
    h = _cluster_frontier_on_line(
      repo=repo,
      repo_name=repo_name,
      cluster=cluster,
      line=line,
      line_tags=line_tags,
      tags_glob=tags_glob,
      cache=cache,
    )
    if h is not None:
      hits.append(h)
  return hits


def _interval(line_tags: list[str], start: int, end: int) -> dict[str, Any] | None:
  if start < 0 or end < start or start >= len(line_tags):
    return None
  end = min(end, len(line_tags) - 1)
  return {
    "from_tag": line_tags[start],
    "to_tag": line_tags[end],
    "from_index": start,
    "to_index": end,
    "tags": line_tags[start:end + 1],
  }


def _load_vuln_commit_from_rci(rci_path: str | Path | None) -> str | None:
  if not rci_path:
    return None
  try:
    obj = json.loads(Path(rci_path).read_text(encoding="utf-8"))
    value = str(obj.get("vuln_commit") or "").strip()
    return value or None
  except Exception:
    return None


def build_vuln_tree_plan(
  *,
  repo_path: str,
  cve_id: str,
  fixing_commits: list[Any] | None,
  rci_path: str | Path | None = None,
  vuln_commit: str | None = None,
  tags_glob: str | None = None,
  mode: str = "eval",
) -> dict[str, Any]:
  """Build a deterministic VulnTree plan for Step3.
  """
  repo = GitRepo.open(repo_path)
  repo_name = infer_repo_name(repo_path)
  ordered_lines, line_nodes, raw_count, release_count = build_base_vuln_tree(
    repo=repo,
    repo_name=repo_name,
    tags_glob=tags_glob,
  )
  fix_clusters = build_fix_clusters(repo, fixing_commits, expand_equivalents=False)
  vic_seed = vuln_commit or _load_vuln_commit_from_rci(rci_path)
  vic_clusters = build_vic_clusters(repo, vic_seed, expand_equivalents=False)

  containing_cache: dict[str, dict[str, list[str]]] = {}
  line_boundaries: dict[str, dict[str, Any]] = {}
  line_plans: dict[str, dict[str, Any]] = {}
  verification_tasks: list[dict[str, Any]] = []
  affected_intervals: list[dict[str, Any]] = []
  probe_order: list[str] = []
  line_families = _line_families_from_nodes(line_nodes)

  # P0-C: precompute line-local frontier evidence before classification so
  # no-FIC subtype diagnosis can distinguish family-local ancestors from
  # cross-family fix hits that must be ignored.
  fic_by_line: dict[str, dict[str, Any] | None] = {}
  vic_by_line: dict[str, dict[str, Any] | None] = {}
  fix_hits_by_line: dict[str, list[dict[str, Any]]] = {}
  vic_hits_by_line: dict[str, list[dict[str, Any]]] = {}
  fix_cluster_ids_by_line: dict[str, list[str]] = {}
  vic_cluster_ids_by_line: dict[str, list[str]] = {}
  for line in ordered_lines:
    tags_asc = line_nodes[line].tags_asc
    fic_by_line[line] = _best_frontier(
      repo=repo,
      repo_name=repo_name,
      clusters=fix_clusters,
      line=line,
      line_tags=tags_asc,
      tags_glob=tags_glob,
      cache=containing_cache,
      prefer="earliest",
    )
    vic_by_line[line] = _best_frontier(
      repo=repo,
      repo_name=repo_name,
      clusters=vic_clusters,
      line=line,
      line_tags=tags_asc,
      tags_glob=tags_glob,
      cache=containing_cache,
      prefer="earliest",
    )
    fix_hits = _collect_cluster_hits_on_line(
      repo=repo,
      repo_name=repo_name,
      clusters=fix_clusters,
      line=line,
      line_tags=tags_asc,
      tags_glob=tags_glob,
      cache=containing_cache,
    )
    vic_hits = _collect_cluster_hits_on_line(
      repo=repo,
      repo_name=repo_name,
      clusters=vic_clusters,
      line=line,
      line_tags=tags_asc,
      tags_glob=tags_glob,
      cache=containing_cache,
    )
    fix_hits_by_line[line] = fix_hits
    vic_hits_by_line[line] = vic_hits
    fix_cluster_ids: list[str] = []
    for h in fix_hits:
      _append_unique(fix_cluster_ids, str(h.get("cluster_id") or ""))
    vic_cluster_ids: list[str] = []
    for h in vic_hits:
      _append_unique(vic_cluster_ids, str(h.get("cluster_id") or ""))
    fix_cluster_ids_by_line[line] = fix_cluster_ids
    vic_cluster_ids_by_line[line] = vic_cluster_ids

  for line in ordered_lines:
    node = line_nodes[line]
    tags_asc = node.tags_asc
    fic = fic_by_line[line]
    vic = vic_by_line[line]
    fix_hits_on_line = fix_hits_by_line[line]
    vic_hits_on_line = vic_hits_by_line[line]
    fix_cluster_ids_on_line = fix_cluster_ids_by_line[line]
    vic_cluster_ids_on_line = vic_cluster_ids_by_line[line]

    fic_index = int(fic["index"]) if fic else None
    vic_index = int(vic["index"]) if vic else None
    search_end = (fic_index - 1) if fic_index is not None else (len(tags_asc) - 1)
    candidate_tags = tags_asc[:search_end + 1] if search_end >= 0 else []

    boundary = LineBoundary(
      line=line,
      fic_tag=fic["tag"] if fic else None,
      fic_index=fic_index,
      vic_tag=vic["tag"] if vic else None,
      vic_index=vic_index,
      evidence=[],
    )
    if fic:
      boundary.evidence.append({"source": "fix_cluster_contains", **fic})
    else:
      boundary.evidence.append({"source": "fix_cluster_contains", "status": "no_line_local_fic"})
    if vic:
      boundary.evidence.append({"source": "vic_cluster_contains", **vic})
    else:
      boundary.evidence.append({"source": "vic_cluster_contains", "status": "no_line_local_vic"})

    task: dict[str, Any] | None = None
    if not candidate_tags:
      boundary.status = "born_fixed_or_empty_search_space" if fic_index == 0 else "empty_line"
    elif vic_index is not None and vic_index <= search_end:
      interval = _interval(tags_asc, vic_index, search_end)
      boundary.affected_interval = interval
      boundary.status = "bounded_by_vic_and_fic" if fic else "vic_known_no_line_local_fic"
      if interval:
        affected_intervals.append({"line": line, **interval, "source": boundary.status})
      probe_tags = []
      if vic_index > 0:
        probe_tags.append(tags_asc[vic_index - 1])
      probe_tags.append(tags_asc[vic_index])
      probe_tags.append(tags_asc[search_end])
      if fic:
        probe_tags.append(fic["tag"])
      probe_tags = list(dict.fromkeys(probe_tags))
      task = {
        "line": line,
        "mode": "confirm_interval",
        "candidate_tags": candidate_tags,
        "candidate_start_index": 0,
        "candidate_end_index": search_end,
        "fic_tag": fic["tag"] if fic else None,
        "fic_index": fic_index,
        "vic_tag": vic["tag"],
        "vic_index": vic_index,
        "probe_tags": probe_tags,
      }
    else:
      boundary.status = "needs_boundary_search" if fic else "no_line_local_fic_needs_boundary_search"
      probe_tags = []
      if candidate_tags:
        probe_tags.append(candidate_tags[0])
        probe_tags.append(candidate_tags[-1])
      if fic:
        probe_tags.append(fic["tag"])
      probe_tags = list(dict.fromkeys(probe_tags))
      task = {
        "line": line,
        "mode": "asbs_boundary_search",
        "candidate_tags": candidate_tags,
        "candidate_start_index": 0,
        "candidate_end_index": search_end,
        "fic_tag": fic["tag"] if fic else None,
        "fic_index": fic_index,
        "vic_tag": None,
        "vic_index": None,
        "probe_tags": probe_tags,
      }

    if task:
      verification_tasks.append(task)
      for tag in task["probe_tags"]:
        if tag not in probe_order:
          probe_order.append(tag)

    # ── P0-1: populate runtime state on LineNode / boundary / TagNodes ──
    has_task = task is not None
    search_mode = task["mode"] if has_task else "no_task"
    # ── P0-3/P0-C: deterministic no-FIC subtype classification ──
    # P0-C makes newer_line/older_line family-local. A line without FIC can
    # only inherit duplicate_expansion_missed from a comparable newer ancestor
    # in the same release family. Cross-family fix hits are recorded as ignored
    # evidence and must not drive the subtype.
    if fic:
      no_fic_reason: str | None = None
      no_fic_evidence: dict[str, Any] | None = None
    else:
      cur = line_nodes[line].newer_line
      same_family_newer_fix_lines: list[dict[str, Any]] = []
      while cur is not None:
        if fix_cluster_ids_by_line.get(cur):
          same_family_newer_fix_lines.append({
            "line": cur,
            "family_key": line_nodes[cur].family_key,
            "fix_clusters": list(fix_cluster_ids_by_line[cur]),
          })
        cur = line_nodes[cur].newer_line
      cross_family_fix_hits_ignored = [
        {
          "line": other_line,
          "family_key": line_nodes[other_line].family_key,
          "fix_clusters": list(fix_cluster_ids_by_line[other_line]),
        }
        for other_line in ordered_lines
        if line_nodes[other_line].family_key != node.family_key
        and fix_cluster_ids_by_line.get(other_line)
      ]
      no_fic_reason = (
        "duplicate_expansion_missed" if same_family_newer_fix_lines
        else "never_fixed_on_this_line"
      )
      no_fic_evidence = {
        "source": "family_local_no_fic_diagnosis",
        "line_family": node.family_key,
        "line_partition": node.line_partition,
        "same_family_newer_fix_lines": same_family_newer_fix_lines,
        "cross_family_fix_hits_ignored": cross_family_fix_hits_ignored,
        "subtype": no_fic_reason,
      }
      boundary.evidence.append(no_fic_evidence)
    line_plan_status = "planned" if has_task else boundary.status
    line_certificate = f"line:{line}:{boundary.status}:v1"
    boundary_certificate = f"boundary:{line}:{boundary.status}:v1"
    line_plan_roles: list[str] = []
    if fic:
      line_plan_roles.append("has_fic")
    if vic:
      line_plan_roles.append("has_vic")
    if has_task and task["mode"] == "asbs_boundary_search":
      line_plan_roles.append("needs_boundary_search")
    if has_task and task["mode"] == "confirm_interval":
      line_plan_roles.append("confirm_interval")
    if not candidate_tags:
      line_plan_roles.append("no_candidates")

    node.runtime.plan_status = line_plan_status
    node.runtime.plan_roles = list(line_plan_roles)
    node.runtime.search_mode = search_mode
    node.runtime.boundary_status = boundary.status
    node.runtime.contains_fix_clusters = list(fix_cluster_ids_on_line)
    node.runtime.contains_vic_clusters = list(vic_cluster_ids_on_line)
    node.runtime.no_fic_reason = no_fic_reason
    node.runtime.certificate_id = line_certificate

    boundary.runtime.plan_status = line_plan_status
    boundary.runtime.plan_roles = list(line_plan_roles)
    boundary.runtime.search_mode = search_mode
    boundary.runtime.boundary_status = boundary.status
    boundary.runtime.contains_fix_clusters = list(fix_cluster_ids_on_line)
    boundary.runtime.contains_vic_clusters = list(vic_cluster_ids_on_line)
    boundary.runtime.no_fic_reason = no_fic_reason
    boundary.runtime.certificate_id = boundary_certificate

    candidate_set = set(candidate_tags)
    probe_set = set(task["probe_tags"]) if has_task else set()
    fic_tag_value = boundary.fic_tag
    vic_tag_value = boundary.vic_tag
    fic_hit_tags = {str(h.get("tag") or "") for h in fix_hits_on_line}
    vic_hit_tags = {str(h.get("tag") or "") for h in vic_hits_on_line}

    for tn in node.tag_nodes:
      tag_roles: list[str] = []
      if tn.tag in candidate_set:
        tag_roles.append("candidate_tag")
        tn.runtime.plan_status = "in_candidate"
      else:
        tn.runtime.plan_status = "outside_candidate"
      if tn.tag in probe_set:
        tag_roles.append("probe_tag")
      if fic_tag_value and tn.tag == fic_tag_value:
        tag_roles.append("fic_tag")
      if vic_tag_value and tn.tag == vic_tag_value:
        tag_roles.append("vic_tag")
      tn.runtime.plan_roles = tag_roles

      tag_fix_clusters: list[str] = []
      if tn.tag in fic_hit_tags:
        for h in fix_hits_on_line:
          if h.get("tag") == tn.tag:
            _append_unique(tag_fix_clusters, str(h.get("cluster_id") or ""))
      tag_vic_clusters: list[str] = []
      if tn.tag in vic_hit_tags:
        for h in vic_hits_on_line:
          if h.get("tag") == tn.tag:
            _append_unique(tag_vic_clusters, str(h.get("cluster_id") or ""))
      tn.runtime.contains_fix_clusters = tag_fix_clusters
      tn.runtime.contains_vic_clusters = tag_vic_clusters

    line_boundaries[line] = boundary.to_dict()
    line_plans[line] = {
      "family_key": node.family_key,
      "line_partition": node.line_partition,
      "candidate_tags": candidate_tags,
      "verification_order": task["probe_tags"] if task else [],
      "frontier_status": boundary.status,
      "fic_tag": boundary.fic_tag,
      "fic_index": boundary.fic_index,
      "vic_tag": boundary.vic_tag,
      "vic_index": boundary.vic_index,
      "task_mode": task["mode"] if task else "none",
    }

  release_lines = {
    line: {
      "tags": line_nodes[line].tags_asc,
      "family_key": line_nodes[line].family_key,
      "line_partition": line_nodes[line].line_partition,
    }
    for line in ordered_lines
  }
  frontiers = {
    line: {
      "status": boundary["status"],
      "source": "vuln_tree",
      "family_key": line_nodes[line].family_key,
      "line_partition": line_nodes[line].line_partition,
      "first_fully_fixed_tag": boundary.get("fic_tag"),
      "first_fully_fixed_index": boundary.get("fic_index"),
      "line_local_vic_tag": boundary.get("vic_tag"),
      "line_local_vic_index": boundary.get("vic_index"),
      "family_frontiers": {},
    }
    for line, boundary in line_boundaries.items()
  }

  fix_family_records = [
    {
      "family_id": i,
      "commits": [{"sha": sha} for sha in group],
    }
    for i, group in enumerate(normalize_commit_groups(fixing_commits))
  ]

  return {
    "plan_kind": "vuln_tree",
    "repo": repo_name,
    "cve_id": cve_id,
    "mode": mode,
    "branch_model": branch_model(repo_name),
    "raw_tags_count": raw_count,
    "release_tags_count": release_count,
    "ordered_lines": ordered_lines,
    "line_families": line_families,
    "lines": {line: line_nodes[line].to_dict() for line in ordered_lines},
    "release_lines": release_lines,
    "fix_families": fix_family_records,
    "fix_clusters": [c.to_dict() for c in fix_clusters],
    "vic_clusters": [c.to_dict() for c in vic_clusters],
    "line_boundaries": line_boundaries,
    "frontiers": frontiers,
    "line_plans": line_plans,
    "verification_tasks": verification_tasks,
    "affected_intervals": affected_intervals,
    "verification_order": probe_order,
    "tags_glob": tags_glob,
  }


def write_vuln_tree_artifacts(out_dir: str | Path, plan: dict[str, Any]) -> None:
  out = Path(out_dir)
  out.mkdir(parents=True, exist_ok=True)
  (out / "vuln_tree.json").write_text(
    json.dumps({
      "repo": plan.get("repo"),
      "cve_id": plan.get("cve_id"),
      "ordered_lines": plan.get("ordered_lines"),
      "line_families": plan.get("line_families"),
      "lines": plan.get("lines"),
      "fix_clusters": plan.get("fix_clusters"),
      "vic_clusters": plan.get("vic_clusters"),
    }, ensure_ascii=False, indent=2),
    encoding="utf-8",
  )
  (out / "line_boundaries.json").write_text(
    json.dumps(plan.get("line_boundaries") or {}, ensure_ascii=False, indent=2),
    encoding="utf-8",
  )

  # ── P0-1: runtime state artifact ────────────────────────────────
  # Self-contained snapshot of every TagRuntimeState / LineRuntimeState /
  # BoundaryRuntimeState produced by build_vuln_tree_plan. Downstream
  # consumers (no-FIC subtype, ASBS verdict separation, ablation eval)
  # must read this file rather than guessing from line_plans / boundaries.
  lines_payload: dict[str, Any] = {}
  tag_payload: dict[str, dict[str, Any]] = {}
  for line, line_dict in (plan.get("lines") or {}).items():
    line_runtime = line_dict.get("runtime") or {}
    lines_payload[line] = line_runtime
    tag_payload[line] = {
      tn.get("tag"): tn.get("runtime") or {}
      for tn in (line_dict.get("tag_nodes") or [])
      if tn.get("tag")
    }
  boundary_payload: dict[str, Any] = {}
  for line, boundary_dict in (plan.get("line_boundaries") or {}).items():
    boundary_payload[line] = boundary_dict.get("runtime") or {}

  (out / "vuln_tree_runtime.json").write_text(
    json.dumps({
      "repo": plan.get("repo"),
      "cve_id": plan.get("cve_id"),
      "ordered_lines": plan.get("ordered_lines"),
      "line_families": plan.get("line_families"),
      "lines": lines_payload,
      "tags_by_line": tag_payload,
      "line_boundaries": boundary_payload,
    }, ensure_ascii=False, indent=2),
    encoding="utf-8",
  )
