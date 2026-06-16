from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
  sys.path.insert(0, str(ROOT))

from vulnversion.git_ops.repo import GitRepo
from vulnversion.stage3_verify.version_registry import (
  filter_release_tags,
  line_family_key,
  line_key,
  parse_version,
)


def _line_sort_key(repo: str, line: str) -> tuple[Any, ...]:
  if repo == "curl":
    return (0, 0, 0, 0)
  if repo == "openssl":
    nums = tuple(int(x) for x in re.findall(r"\d+", line))
    if line.startswith("fips-"):
      return (1, *nums)
    if line.startswith("engine-"):
      return (2, *nums)
    return (0, *nums)
  nums = tuple(int(x) for x in re.findall(r"\d+", line))
  return (0, *nums) if nums else (99, line)


def global_release_sort_key(repo: str, tag: str) -> tuple[Any, ...]:
  line = line_key(repo, tag)
  return (line_family_key(repo, line), _line_sort_key(repo, line), parse_version(repo, tag), tag)


def build_global_fic_tag_plan(
  *,
  repo_path: str | Path,
  repo_name: str,
  cve_id: str,
  fixing_commits: list[str],
  tags_glob: str | None = None,
) -> dict[str, Any]:
  """Build a no-line global-FIC baseline plan for comparison experiments.

  This intentionally ignores release-line boundaries.  It sorts all release
  tags in one global sequence, finds the first tag containing any fix commit,
  and marks every earlier release tag as candidate-to-verify.
  """

  repo = GitRepo.open(repo_path)
  raw_tags = repo.list_tags(tags_glob=tags_glob, max_tags=None)
  release_tags = filter_release_tags(repo_name, raw_tags)
  tag_plan = sorted(release_tags, key=lambda tag: global_release_sort_key(repo_name, tag))
  tag_index = {tag: idx for idx, tag in enumerate(tag_plan)}

  containing_by_commit: dict[str, list[str]] = {}
  global_fic_candidates: list[dict[str, Any]] = []
  release_tag_set = set(tag_plan)
  for commit in fixing_commits:
    containing = [
      tag for tag in repo.list_tags_containing(commit, tags_glob=tags_glob)
      if tag in release_tag_set
    ]
    containing = sorted(containing, key=lambda tag: tag_index[tag])
    containing_by_commit[commit] = containing
    if containing:
      first = containing[0]
      global_fic_candidates.append({
        "commit": commit,
        "fic_tag": first,
        "fic_index": tag_index[first],
      })

  if global_fic_candidates:
    best = min(global_fic_candidates, key=lambda item: int(item["fic_index"]))
    fic_tag = str(best["fic_tag"])
    fic_index = int(best["fic_index"])
    candidate_tags = tag_plan[:fic_index]
    status = "global_fic_found"
  else:
    fic_tag = None
    fic_index = None
    candidate_tags = list(tag_plan)
    status = "no_global_fic"

  return {
    "plan_kind": "global_fic_baseline",
    "repo": repo_name,
    "repo_path": str(repo_path),
    "cve_id": cve_id,
    "fixing_commits": fixing_commits,
    "status": status,
    "global_tag_plan": tag_plan,
    "global_tag_count": len(tag_plan),
    "global_fic_tag": fic_tag,
    "global_fic_index": fic_index,
    "candidate_tags_before_fic": candidate_tags,
    "candidate_count": len(candidate_tags),
    "containing_by_commit": containing_by_commit,
    "global_fic_candidates": global_fic_candidates,
    "semantics": "any_fix_commit_global_first_tag",
  }


def _load_dataset_record(dataset_path: Path, cve_id: str) -> dict[str, Any]:
  data = json.loads(dataset_path.read_text(encoding="utf-8"))
  if cve_id not in data:
    raise KeyError(f"cve_not_found: {cve_id}")
  return data[cve_id]


def _flatten_fixing_commits(value: Any) -> list[str]:
  commits: list[str] = []
  if isinstance(value, list):
    for item in value:
      if isinstance(item, list):
        commits.extend(str(x) for x in item if x)
      elif item:
        commits.append(str(item))
  return commits


def main(argv: list[str] | None = None) -> int:
  parser = argparse.ArgumentParser(description="Build no-line global-FIC tag plan for one CVE.")
  parser.add_argument("--repo-root", type=Path, default=ROOT / "repo")
  parser.add_argument("--repo", default=None)
  parser.add_argument("--repo-path", type=Path, default=None)
  parser.add_argument("--cve-id", required=True)
  parser.add_argument("--fix-commit", action="append", default=[])
  parser.add_argument("--dataset", type=Path, default=None)
  parser.add_argument("--tags-glob", default=None)
  parser.add_argument("--out", type=Path, default=ROOT / "tests" / "global_fic_tag_plan")
  args = parser.parse_args(argv)

  repo_name = args.repo
  fixing_commits = list(args.fix_commit)
  if args.dataset:
    rec = _load_dataset_record(args.dataset, args.cve_id)
    repo_name = repo_name or str(rec.get("repo") or "")
    if not fixing_commits:
      fixing_commits = _flatten_fixing_commits(rec.get("fixing_commits"))

  if not repo_name:
    raise ValueError("repo is required when dataset is not provided")
  if not fixing_commits:
    raise ValueError("at least one fix commit is required")

  repo_path = args.repo_path or (args.repo_root / repo_name)
  plan = build_global_fic_tag_plan(
    repo_path=repo_path,
    repo_name=repo_name,
    cve_id=args.cve_id,
    fixing_commits=fixing_commits,
    tags_glob=args.tags_glob,
  )

  args.out.mkdir(parents=True, exist_ok=True)
  out_path = args.out / f"{args.cve_id}.global_fic_tag_plan.json"
  out_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
  print(json.dumps({
    "out": str(out_path),
    "repo": repo_name,
    "cve_id": args.cve_id,
    "status": plan["status"],
    "global_tag_count": plan["global_tag_count"],
    "global_fic_tag": plan["global_fic_tag"],
    "global_fic_index": plan["global_fic_index"],
    "candidate_count": plan["candidate_count"],
  }, ensure_ascii=False, indent=2))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
