from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
  sys.path.insert(0, str(ROOT))

from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.version_registry import filter_release_tags, line_key, sort_tags_for_line


DEFAULT_DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
DEFAULT_REPO_ROOT = ROOT / "repo"
DEFAULT_OUT_DIR = ROOT / "tests" / "fix_containment_by_line"


def _flatten_fixing_commits(value: Any) -> list[str]:
  commits: list[str] = []
  if isinstance(value, list):
    for item in value:
      if isinstance(item, list):
        commits.extend(str(x) for x in item if x)
      elif item:
        commits.append(str(item))
  return commits


def _release_lines(repo_name: str, repo_path: Path) -> dict[str, list[str]]:
  repo = GitRepo.open(repo_path)
  tags = filter_release_tags(repo_name, repo.list_tags(max_tags=None))
  grouped: dict[str, list[str]] = defaultdict(list)
  for tag in tags:
    grouped[line_key(repo_name, tag)].append(tag)
  return {line: sort_tags_for_line(repo_name, vals) for line, vals in grouped.items()}


def _analyze_cve(
  *,
  cve_id: str,
  repo_name: str,
  repo_path: Path,
  affected_versions: list[str],
  fixing_commits: list[str],
  release_lines: dict[str, list[str]],
) -> dict[str, Any]:
  release_tags = [tag for tags in release_lines.values() for tag in tags]
  release_tag_set = set(release_tags)
  tag_to_line = {tag: line for line, tags in release_lines.items() for tag in tags}
  mapped_gt, unmapped_gt = map_gt_tags_to_repo_tags(affected_versions, release_tags, mode="loose")
  affected_lines = sorted({tag_to_line[tag] for tag in mapped_gt if tag in tag_to_line})

  repo = GitRepo.open(repo_path)
  fix_tags_by_commit: dict[str, list[str]] = {}
  fix_lines_by_commit: dict[str, list[str]] = {}
  fix_lines: set[str] = set()
  fix_errors: dict[str, str] = {}
  for commit in fixing_commits:
    try:
      containing = [tag for tag in repo.list_tags_containing(commit) if tag in release_tag_set]
    except Exception as exc:
      fix_errors[commit] = f"{type(exc).__name__}: {exc}"
      containing = []
    fix_tags_by_commit[commit] = sorted(containing)
    lines = sorted({tag_to_line[tag] for tag in containing if tag in tag_to_line})
    fix_lines_by_commit[commit] = lines
    fix_lines.update(lines)

  affected_line_set = set(affected_lines)
  affected_lines_with_fix = sorted(affected_line_set & fix_lines)
  affected_lines_without_fix = sorted(affected_line_set - fix_lines)
  fix_lines_without_affected_gt = sorted(fix_lines - affected_line_set)

  return {
    "cve_id": cve_id,
    "repo": repo_name,
    "affected_version_count": len(affected_versions),
    "mapped_gt_count": len(mapped_gt),
    "unmapped_gt_count": len(unmapped_gt),
    "fix_commit_count": len(fixing_commits),
    "affected_line_count": len(affected_lines),
    "fix_containing_line_count": len(fix_lines),
    "affected_lines_with_fix_count": len(affected_lines_with_fix),
    "affected_lines_without_fix_count": len(affected_lines_without_fix),
    "fix_lines_without_affected_gt_count": len(fix_lines_without_affected_gt),
    "affected_lines": affected_lines,
    "fix_containing_lines": sorted(fix_lines),
    "affected_lines_with_fix": affected_lines_with_fix,
    "affected_lines_without_fix": affected_lines_without_fix,
    "fix_lines_without_affected_gt": fix_lines_without_affected_gt,
    "unmapped_gt_tags": unmapped_gt,
    "fix_lines_by_commit": fix_lines_by_commit,
    "fix_tag_count_by_commit": {commit: len(tags) for commit, tags in fix_tags_by_commit.items()},
    "fix_errors": fix_errors,
  }


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
  total_affected_lines = sum(row["affected_line_count"] for row in rows)
  affected_lines_with_fix = sum(row["affected_lines_with_fix_count"] for row in rows)
  affected_lines_without_fix = sum(row["affected_lines_without_fix_count"] for row in rows)
  cves_with_any_affected_line_without_fix = sum(1 for row in rows if row["affected_lines_without_fix_count"] > 0)
  cves_all_affected_lines_have_fix = sum(
    1 for row in rows
    if row["affected_line_count"] > 0 and row["affected_lines_without_fix_count"] == 0
  )
  cves_with_no_fix_containing_line = sum(1 for row in rows if row["fix_containing_line_count"] == 0)

  by_repo_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
  for row in rows:
    by_repo_rows[row["repo"]].append(row)

  by_repo: dict[str, Any] = {}
  for repo, repo_rows in sorted(by_repo_rows.items()):
    repo_affected = sum(row["affected_line_count"] for row in repo_rows)
    repo_with_fix = sum(row["affected_lines_with_fix_count"] for row in repo_rows)
    repo_without_fix = sum(row["affected_lines_without_fix_count"] for row in repo_rows)
    by_repo[repo] = {
      "cves": len(repo_rows),
      "affected_lines": repo_affected,
      "affected_lines_with_fix": repo_with_fix,
      "affected_lines_without_fix": repo_without_fix,
      "affected_lines_without_fix_rate": (repo_without_fix / repo_affected) if repo_affected else 0.0,
      "cves_with_any_affected_line_without_fix": sum(1 for row in repo_rows if row["affected_lines_without_fix_count"] > 0),
      "cves_all_affected_lines_have_fix": sum(
        1 for row in repo_rows
        if row["affected_line_count"] > 0 and row["affected_lines_without_fix_count"] == 0
      ),
      "cves_with_no_fix_containing_line": sum(1 for row in repo_rows if row["fix_containing_line_count"] == 0),
    }

  return {
    "overall": {
      "total_cves": len(rows),
      "total_affected_lines": total_affected_lines,
      "affected_lines_with_fix": affected_lines_with_fix,
      "affected_lines_without_fix": affected_lines_without_fix,
      "affected_lines_without_fix_rate": (affected_lines_without_fix / total_affected_lines) if total_affected_lines else 0.0,
      "cves_with_any_affected_line_without_fix": cves_with_any_affected_line_without_fix,
      "cves_all_affected_lines_have_fix": cves_all_affected_lines_have_fix,
      "cves_with_no_fix_containing_line": cves_with_no_fix_containing_line,
    },
    "by_repo": by_repo,
  }


def _write_report(path: Path, summary: dict[str, Any], rows: list[dict[str, Any]]) -> None:
  overall = summary["overall"]
  by_repo = summary["by_repo"]
  lines = [
    "# Fix Containment by Affected Line",
    "",
    "This report checks whether dataset fix commits are contained by release tags on each affected release line.",
    "",
    "It does not run BAPEE or patch-equivalence expansion.",
    "",
    "## Overall",
    "",
    f"- total_cves: `{overall['total_cves']}`",
    f"- total_affected_lines: `{overall['total_affected_lines']}`",
    f"- affected_lines_with_fix: `{overall['affected_lines_with_fix']}`",
    f"- affected_lines_without_fix: `{overall['affected_lines_without_fix']}`",
    f"- affected_lines_without_fix_rate: `{overall['affected_lines_without_fix_rate']:.4f}`",
    f"- cves_with_any_affected_line_without_fix: `{overall['cves_with_any_affected_line_without_fix']}`",
    f"- cves_all_affected_lines_have_fix: `{overall['cves_all_affected_lines_have_fix']}`",
    f"- cves_with_no_fix_containing_line: `{overall['cves_with_no_fix_containing_line']}`",
    "",
    "## By Repo",
    "",
    "| repo | cves | affected lines | with fix | without fix | without-fix rate | CVEs any no-fix line | CVEs all lines have fix |",
    "|---|---:|---:|---:|---:|---:|---:|---:|",
  ]
  for repo, row in by_repo.items():
    lines.append(
      f"| {repo} | {row['cves']} | {row['affected_lines']} | {row['affected_lines_with_fix']} | "
      f"{row['affected_lines_without_fix']} | {row['affected_lines_without_fix_rate']:.4f} | "
      f"{row['cves_with_any_affected_line_without_fix']} | {row['cves_all_affected_lines_have_fix']} |"
    )
  lines.extend([
    "",
    "## Worst CVEs by Affected Lines Without Fix",
    "",
  ])
  for row in sorted(rows, key=lambda r: (-r["affected_lines_without_fix_count"], r["repo"], r["cve_id"]))[:40]:
    if row["affected_lines_without_fix_count"] <= 0:
      continue
    lines.append(
      f"- `{row['repo']}` `{row['cve_id']}`: affected lines `{row['affected_line_count']}`, "
      f"without fix `{row['affected_lines_without_fix_count']}`"
    )
  path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
  parser = argparse.ArgumentParser(description="Analyze original fix-commit containment on affected release lines.")
  parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
  parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
  parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
  parser.add_argument("--repo", default=None, help="Optional repo filter.")
  parser.add_argument("--sample-size", type=int, default=None, help="Optional sample size after repo filtering.")
  parser.add_argument("--seed", type=int, default=42)
  args = parser.parse_args(argv)

  data = json.loads(args.dataset.read_text(encoding="utf-8"))
  if args.repo:
    data = {cve: rec for cve, rec in data.items() if str(rec.get("repo") or "") == args.repo}
  if args.sample_size is not None and args.sample_size > 0 and len(data) > args.sample_size:
    rng = random.Random(args.seed)
    sampled_keys = sorted(rng.sample(sorted(data), args.sample_size))
    data = {key: data[key] for key in sampled_keys}

  orig_list_tags = GitRepo.list_tags
  orig_list_tags_containing = GitRepo.list_tags_containing

  @lru_cache(maxsize=None)
  def _cached_list_tags(repo_path: str, tags_glob: str | None, max_tags: int | None):
    repo = GitRepo.open(repo_path)
    return tuple(orig_list_tags(repo, tags_glob=tags_glob, max_tags=max_tags))

  @lru_cache(maxsize=None)
  def _cached_list_tags_containing(repo_path: str, commit: str):
    repo = GitRepo.open(repo_path)
    return tuple(orig_list_tags_containing(repo, commit))

  def _list_tags(self, tags_glob=None, max_tags=None):
    return list(_cached_list_tags(str(self.repo_path), tags_glob, max_tags))

  def _list_tags_containing(self, commit, *, tags_glob=None):
    return list(_cached_list_tags_containing(str(self.repo_path), commit))

  GitRepo.list_tags = _list_tags  # type: ignore[method-assign]
  GitRepo.list_tags_containing = _list_tags_containing  # type: ignore[method-assign]

  rows: list[dict[str, Any]] = []
  release_cache: dict[str, dict[str, list[str]]] = {}
  try:
    for cve_id, rec in sorted(data.items()):
      repo_name = str(rec.get("repo") or "").strip()
      if not repo_name:
        continue
      repo_path = args.repo_root / repo_name
      if repo_name not in release_cache:
        release_cache[repo_name] = _release_lines(repo_name, repo_path)
      rows.append(_analyze_cve(
        cve_id=cve_id,
        repo_name=repo_name,
        repo_path=repo_path,
        affected_versions=list(rec.get("affected_version") or []),
        fixing_commits=_flatten_fixing_commits(rec.get("fixing_commits")),
        release_lines=release_cache[repo_name],
      ))
  finally:
    GitRepo.list_tags = orig_list_tags  # type: ignore[method-assign]
    GitRepo.list_tags_containing = orig_list_tags_containing  # type: ignore[method-assign]

  summary = _summarize(rows)
  args.out_dir.mkdir(parents=True, exist_ok=True)
  (args.out_dir / "per_cve.jsonl").write_text(
    "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
    encoding="utf-8",
  )
  (args.out_dir / "summary.json").write_text(
    json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
  )
  _write_report(args.out_dir / "report.md", summary, rows)
  print(json.dumps({"overall": summary["overall"], "out_dir": str(args.out_dir)}, ensure_ascii=False, indent=2))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
