from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
  sys.path.insert(0, str(ROOT))

from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.version_registry import filter_release_tags, line_key, sort_tags_for_line


DEFAULT_DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
DEFAULT_REPO_ROOT = ROOT / "repo"
DEFAULT_OUT_DIR = ROOT / "tests" / "fix_upper_bound_filter"


def _load_dataset(path: Path) -> dict[str, Any]:
  return json.loads(path.read_text(encoding="utf-8"))


def _flatten_fixing_commits(value: Any) -> list[str]:
  commits: list[str] = []
  if isinstance(value, list):
    for item in value:
      if isinstance(item, list):
        commits.extend(str(x) for x in item if x)
      elif item:
        commits.append(str(item))
  elif value:
    commits.append(str(value))
  seen: set[str] = set()
  out: list[str] = []
  for commit in commits:
    if commit in seen:
      continue
    seen.add(commit)
    out.append(commit)
  return out


def _release_context(repo_name: str, repo_path: Path) -> dict[str, Any]:
  repo = GitRepo.open(repo_path)
  release_tags = filter_release_tags(repo_name, repo.list_tags(max_tags=None))
  release_lines: dict[str, list[str]] = defaultdict(list)
  for tag in release_tags:
    release_lines[line_key(repo_name, tag)].append(tag)
  release_lines = {
    line: sort_tags_for_line(repo_name, tags)
    for line, tags in release_lines.items()
  }
  return {
    "repo": repo,
    "release_tags": release_tags,
    "release_tag_set": set(release_tags),
    "release_lines": release_lines,
    "tag_to_line": {
      tag: line
      for line, tags in release_lines.items()
      for tag in tags
    },
  }


def _safe_tags_containing(
  repo: GitRepo,
  commit: str,
  release_tag_set: set[str],
  cache: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
  key = (str(repo.repo_path), commit)
  if key in cache:
    return cache[key]
  try:
    tags = [tag for tag in repo.list_tags_containing(commit) if tag in release_tag_set]
    result = {"ok": True, "tags": tags, "error": ""}
  except Exception as exc:
    result = {"ok": False, "tags": [], "error": str(exc)}
  cache[key] = result
  return result


def _git_base_cmd(repo_path: Path) -> list[str]:
  repo_str = str(repo_path.resolve())
  return ["git", "-c", f"safe.directory={repo_str}", "-C", repo_str]


def _bits_to_tags(bits: int, release_tags: list[str]) -> list[str]:
  tags: list[str] = []
  value = bits
  while value:
    lsb = value & -value
    idx = lsb.bit_length() - 1
    if 0 <= idx < len(release_tags):
      tags.append(release_tags[idx])
    value ^= lsb
  return tags


def _precompute_tags_containing_batch(
  *,
  repo: GitRepo,
  release_tags: list[str],
  target_commits: set[str],
) -> dict[str, dict[str, Any]]:
  """Compute tag containment for many commits with one reverse graph pass.

  For each release tag tip we assign a bit.  `git rev-list --topo-order
  --parents <tag tips...>` yields descendants before parents, so tag reachability
  can be propagated from each commit to its parents.  The resulting bitset for a
  target commit is the exact set of release tags that contain that commit.
  """

  if not target_commits:
    return {}

  tag_tip_bits: dict[str, int] = {}
  valid_release_tags: list[str] = []
  for tag in release_tags:
    try:
      tip = repo.tag_commit(tag)
    except Exception:
      continue
    if not tip:
      continue
    idx = len(valid_release_tags)
    valid_release_tags.append(tag)
    tag_tip_bits[tip] = tag_tip_bits.get(tip, 0) | (1 << idx)

  resolved_to_original: dict[str, list[str]] = defaultdict(list)
  out: dict[str, dict[str, Any]] = {}
  for commit in sorted(target_commits):
    try:
      resolved = repo.rev_parse(commit)
    except Exception as exc:
      out[commit] = {"ok": False, "tags": [], "error": str(exc)}
      continue
    resolved_to_original[resolved].append(commit)

  bits_by_commit: dict[str, int] = dict(tag_tip_bits)
  tips = sorted(tag_tip_bits)
  if tips:
    cmd = [*_git_base_cmd(repo.repo_path), "rev-list", "--topo-order", "--parents", *tips]
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
      commit = parts[0]
      bits = bits_by_commit.get(commit, 0)
      if not bits:
        continue
      for parent in parts[1:]:
        bits_by_commit[parent] = bits_by_commit.get(parent, 0) | bits
    stderr = proc.stderr.read() if proc.stderr is not None else ""
    code = proc.wait()
    if code != 0:
      error = stderr.strip() or f"git rev-list failed with code {code}"
      for originals in resolved_to_original.values():
        for original in originals:
          out[original] = {"ok": False, "tags": [], "error": error}
      return out

  for resolved, originals in resolved_to_original.items():
    tags = _bits_to_tags(bits_by_commit.get(resolved, 0), valid_release_tags)
    for original in originals:
      out[original] = {"ok": True, "tags": tags, "error": ""}
  return out


def _analyze_cve(
  *,
  cve_id: str,
  repo_name: str,
  affected_versions: list[str],
  fixing_commits: list[str],
  context: dict[str, Any],
  contains_cache: dict[tuple[str, str], dict[str, Any]],
  precomputed_contains: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
  release_tags: list[str] = context["release_tags"]
  release_tag_set: set[str] = context["release_tag_set"]
  release_lines: dict[str, list[str]] = context["release_lines"]
  tag_to_line: dict[str, str] = context["tag_to_line"]
  repo: GitRepo = context["repo"]

  mapped_gt, unmapped_gt = map_gt_tags_to_repo_tags(affected_versions, release_tags, mode="loose")
  affected_set = set(mapped_gt)

  containing_union: set[str] = set()
  containing_by_commit: dict[str, Any] = {}
  commit_errors: dict[str, str] = {}
  for commit in fixing_commits:
    if precomputed_contains is not None:
      result = precomputed_contains.get(commit, {"ok": False, "tags": [], "error": "missing_precomputed_commit"})
    else:
      result = _safe_tags_containing(repo, commit, release_tag_set, contains_cache)
    containing_by_commit[commit] = {
      "ok": result["ok"],
      "tag_count": len(result["tags"]),
    }
    if not result["ok"]:
      commit_errors[commit] = result["error"]
    containing_union.update(result["tags"])

  candidate_tags = [tag for tag in release_tags if tag not in containing_union]
  candidate_set = set(candidate_tags)
  excluded_set = set(release_tags) - candidate_set

  gt_covered = affected_set & candidate_set
  gt_missed = affected_set - candidate_set

  candidate_lines = {tag_to_line[tag] for tag in candidate_tags if tag in tag_to_line}
  excluded_lines = {tag_to_line[tag] for tag in excluded_set if tag in tag_to_line}
  affected_lines = {tag_to_line[tag] for tag in affected_set if tag in tag_to_line}
  fully_excluded_lines = {
    line
    for line, tags in release_lines.items()
    if tags and all(tag in excluded_set for tag in tags)
  }

  line_candidate_counts: dict[str, dict[str, int]] = {}
  for line, tags in release_lines.items():
    line_candidate_counts[line] = {
      "line_tags": len(tags),
      "candidate_tags": sum(1 for tag in tags if tag in candidate_set),
      "excluded_tags": sum(1 for tag in tags if tag in excluded_set),
      "affected_tags": sum(1 for tag in tags if tag in affected_set),
    }

  return {
    "cve_id": cve_id,
    "repo": repo_name,
    "fixing_commit_count": len(fixing_commits),
    "fixing_commits": fixing_commits,
    "commit_errors": commit_errors,
    "release_tag_count": len(release_tags),
    "release_line_count": len(release_lines),
    "mapped_gt_count": len(mapped_gt),
    "unmapped_gt_count": len(unmapped_gt),
    "containing_fix_tag_count": len(containing_union),
    "candidate_tag_count": len(candidate_tags),
    "excluded_tag_count": len(excluded_set),
    "candidate_tag_rate": len(candidate_tags) / len(release_tags) if release_tags else 0.0,
    "tag_reduction_rate": len(excluded_set) / len(release_tags) if release_tags else 0.0,
    "candidate_line_count": len(candidate_lines),
    "excluded_line_count": len(excluded_lines),
    "fully_excluded_line_count": len(fully_excluded_lines),
    "affected_line_count": len(affected_lines),
    "gt_covered_count": len(gt_covered),
    "gt_missed_count": len(gt_missed),
    "gt_coverage_rate": len(gt_covered) / len(affected_set) if affected_set else 1.0,
    "full_gt_coverage": len(gt_missed) == 0 and not unmapped_gt,
    "missed_gt_tags": sorted(gt_missed),
    "unmapped_gt_tags": unmapped_gt,
    "candidate_lines": sorted(candidate_lines),
    "affected_lines": sorted(affected_lines),
    "fully_excluded_lines": sorted(fully_excluded_lines),
    "containing_by_commit": containing_by_commit,
    "line_candidate_counts": line_candidate_counts,
  }


def _avg(rows: list[dict[str, Any]], key: str) -> float:
  return round(sum(float(row[key]) for row in rows) / len(rows), 4) if rows else 0.0


def _summarize_group(rows: list[dict[str, Any]]) -> dict[str, Any]:
  if not rows:
    return {}
  mapped_total = sum(int(row["mapped_gt_count"]) for row in rows)
  covered_total = sum(int(row["gt_covered_count"]) for row in rows)
  return {
    "cves": len(rows),
    "full_gt_coverage_cves": sum(1 for row in rows if row["full_gt_coverage"]),
    "has_gt_miss_cves": sum(1 for row in rows if row["gt_missed_count"] > 0),
    "has_unmapped_cves": sum(1 for row in rows if row["unmapped_gt_count"] > 0),
    "commit_error_cves": sum(1 for row in rows if row["commit_errors"]),
    "micro_gt_coverage": round(covered_total / mapped_total, 6) if mapped_total else 1.0,
    "avg_gt_coverage": _avg(rows, "gt_coverage_rate"),
    "avg_release_tags": _avg(rows, "release_tag_count"),
    "avg_candidate_tags": _avg(rows, "candidate_tag_count"),
    "avg_excluded_tags": _avg(rows, "excluded_tag_count"),
    "avg_candidate_tag_rate": _avg(rows, "candidate_tag_rate"),
    "avg_tag_reduction_rate": _avg(rows, "tag_reduction_rate"),
    "avg_release_lines": _avg(rows, "release_line_count"),
    "avg_candidate_lines": _avg(rows, "candidate_line_count"),
    "avg_fully_excluded_lines": _avg(rows, "fully_excluded_line_count"),
    "avg_affected_lines": _avg(rows, "affected_line_count"),
  }


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
  by_repo_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
  for row in rows:
    by_repo_rows[row["repo"]].append(row)
  worst_misses = sorted(
    [
      {
        "repo": row["repo"],
        "cve_id": row["cve_id"],
        "gt_missed_count": row["gt_missed_count"],
        "mapped_gt_count": row["mapped_gt_count"],
        "gt_coverage_rate": round(float(row["gt_coverage_rate"]), 6),
        "candidate_tag_rate": round(float(row["candidate_tag_rate"]), 6),
        "tag_reduction_rate": round(float(row["tag_reduction_rate"]), 6),
        "missed_gt_tags": row["missed_gt_tags"][:20],
      }
      for row in rows
      if row["gt_missed_count"] > 0
    ],
    key=lambda item: (-item["gt_missed_count"], item["repo"], item["cve_id"]),
  )[:50]
  return {
    "overall": _summarize_group(rows),
    "by_repo": {
      repo: _summarize_group(group)
      for repo, group in sorted(by_repo_rows.items())
    },
    "worst_misses": worst_misses,
  }


def _write_json(path: Path, obj: Any) -> None:
  path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
  with path.open("w", encoding="utf-8") as fp:
    for row in rows:
      light = {key: value for key, value in row.items() if key != "line_candidate_counts"}
      fp.write(json.dumps(light, ensure_ascii=False) + "\n")


def _write_report(path: Path, summary: dict[str, Any]) -> None:
  overall = summary["overall"]
  lines = [
    "# Fix Upper-Bound Filter Analysis",
    "",
    "This report evaluates using seed fix commits as an upper-bound tag filter.",
    "Candidate tags are release tags that do not contain any seed fix commit.",
    "",
    "## Overall",
    "",
  ]
  for key, value in overall.items():
    lines.append(f"- {key}: `{value}`")
  lines.extend([
    "",
    "## By Repo",
    "",
    "| repo | cves | full GT coverage | micro coverage | avg candidate tag rate | avg tag reduction | avg lines | avg candidate lines | avg fully excluded lines |",
    "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
  ])
  for repo, row in summary["by_repo"].items():
    lines.append(
      f"| {repo} | {row['cves']} | {row['full_gt_coverage_cves']} | {row['micro_gt_coverage']} | "
      f"{row['avg_candidate_tag_rate']} | {row['avg_tag_reduction_rate']} | "
      f"{row['avg_release_lines']} | {row['avg_candidate_lines']} | {row['avg_fully_excluded_lines']} |"
    )
  lines.extend(["", "## Worst Misses", ""])
  for item in summary["worst_misses"][:20]:
    lines.append(
      f"- `{item['repo']}` `{item['cve_id']}`: missed `{item['gt_missed_count']}` / "
      f"`{item['mapped_gt_count']}`, coverage `{item['gt_coverage_rate']}`, "
      f"candidate rate `{item['candidate_tag_rate']}`"
    )
  path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
  parser = argparse.ArgumentParser(description="Analyze fix-commit no-contains filtering over all CVEs.")
  parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
  parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
  parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
  parser.add_argument(
    "--repo-filter",
    default="",
    help="Optional comma-separated repo names. Empty means all repos.",
  )
  parser.add_argument(
    "--backend",
    choices=["batch-reachability", "tag-contains"],
    default="batch-reachability",
    help="Containment backend. batch-reachability is faster for large repos.",
  )
  args = parser.parse_args(argv)

  dataset = _load_dataset(args.dataset)
  repo_filter = {item.strip() for item in args.repo_filter.split(",") if item.strip()}
  context_cache: dict[str, dict[str, Any]] = {}
  contains_cache: dict[tuple[str, str], dict[str, Any]] = {}
  repo_to_commits: dict[str, set[str]] = defaultdict(set)
  if args.backend == "batch-reachability":
    for rec in dataset.values():
      repo_name = str(rec.get("repo") or "").strip()
      if not repo_name:
        continue
      if repo_filter and repo_name not in repo_filter:
        continue
      repo_to_commits[repo_name].update(_flatten_fixing_commits(rec.get("fixing_commits")))

  batch_contains: dict[str, dict[str, dict[str, Any]]] = {}
  if args.backend == "batch-reachability":
    for repo_name, commits in sorted(repo_to_commits.items()):
      if repo_name not in context_cache:
        context_cache[repo_name] = _release_context(repo_name, args.repo_root / repo_name)
      batch_contains[repo_name] = _precompute_tags_containing_batch(
        repo=context_cache[repo_name]["repo"],
        release_tags=context_cache[repo_name]["release_tags"],
        target_commits=commits,
      )

  rows: list[dict[str, Any]] = []
  for cve_id, rec in sorted(dataset.items()):
    repo_name = str(rec.get("repo") or "").strip()
    if not repo_name:
      continue
    if repo_filter and repo_name not in repo_filter:
      continue
    if repo_name not in context_cache:
      context_cache[repo_name] = _release_context(repo_name, args.repo_root / repo_name)
    rows.append(_analyze_cve(
      cve_id=cve_id,
      repo_name=repo_name,
      affected_versions=list(rec.get("affected_version") or []),
      fixing_commits=_flatten_fixing_commits(rec.get("fixing_commits")),
      context=context_cache[repo_name],
      contains_cache=contains_cache,
      precomputed_contains=batch_contains.get(repo_name) if args.backend == "batch-reachability" else None,
    ))

  args.out_dir.mkdir(parents=True, exist_ok=True)
  summary = _summarize(rows)
  metadata = {
    "dataset": str(args.dataset),
    "repo_root": str(args.repo_root),
    "backend": args.backend,
    "contains_queries": len(contains_cache),
    "batch_repos": sorted(batch_contains),
    "batch_commits": sum(len(v) for v in batch_contains.values()),
    "candidate_definition": "release tags that do not contain any seed fix commit",
  }
  _write_json(args.out_dir / "summary.json", {"metadata": metadata, **summary})
  _write_jsonl(args.out_dir / "per_cve.jsonl", rows)
  _write_report(args.out_dir / "report.md", summary)
  print(json.dumps({"metadata": metadata, "overall": summary["overall"], "out_dir": str(args.out_dir)}, ensure_ascii=False, indent=2))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
