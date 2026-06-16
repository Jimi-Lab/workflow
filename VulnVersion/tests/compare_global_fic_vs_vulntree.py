from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
  sys.path.insert(0, str(ROOT))

from tests.global_fic_tag_plan_experiment import build_global_fic_tag_plan
from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.plan_tags import build_tag_plan
from vulnversion.stage3_verify.version_registry import filter_release_tags, line_key, sort_tags_for_line


def _flatten_fixing_commits(value: Any) -> list[str]:
  commits: list[str] = []
  if isinstance(value, list):
    for item in value:
      if isinstance(item, list):
        commits.extend(str(x) for x in item if x)
      elif item:
        commits.append(str(item))
  return commits


def _sample_by_repo(data: dict[str, Any], *, per_repo: int, seed: int) -> list[tuple[str, dict[str, Any]]]:
  grouped: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
  for cve_id, rec in data.items():
    repo = str(rec.get("repo") or "")
    if repo:
      grouped[repo].append((cve_id, rec))

  rng = random.Random(seed)
  sampled: list[tuple[str, dict[str, Any]]] = []
  for repo in sorted(grouped):
    rows = sorted(grouped[repo], key=lambda item: item[0])
    if len(rows) > per_repo:
      rows = rng.sample(rows, per_repo)
      rows = sorted(rows, key=lambda item: item[0])
    sampled.extend(rows)
  return sampled


def _unique(values: list[str]) -> list[str]:
  seen: set[str] = set()
  out: list[str] = []
  for value in values:
    if value in seen:
      continue
    seen.add(value)
    out.append(value)
  return out


def _vulntree_candidate_tags(plan: dict[str, Any]) -> list[str]:
  tags: list[str] = []
  for line_plan in (plan.get("line_plans") or {}).values():
    tags.extend(line_plan.get("candidate_tags") or [])
  return _unique(tags)


def _line_status_counts(plan: dict[str, Any]) -> dict[str, int]:
  counter: Counter[str] = Counter()
  for boundary in (plan.get("line_boundaries") or {}).values():
    counter[str(boundary.get("status") or "unknown")] += 1
  return dict(counter)


def build_fast_line_local_plan(
  *,
  repo_path: str | Path,
  repo_name: str,
  cve_id: str,
  fixing_commits: list[str],
) -> dict[str, Any]:
  """Build a lightweight line-local FIC plan for this comparison.

  It uses the same release-tag universe as Step3 but only models the core
  question under test: per-line FIC vs one global FIC.  It intentionally avoids
  patch-equivalence expansion and verifier scheduling side effects.
  """

  repo = GitRepo.open(repo_path)
  raw_tags = repo.list_tags(max_tags=None)
  release_tags = filter_release_tags(repo_name, raw_tags)
  release_lines: dict[str, list[str]] = defaultdict(list)
  for tag in release_tags:
    release_lines[line_key(repo_name, tag)].append(tag)
  release_lines = {
    line: sort_tags_for_line(repo_name, tags)
    for line, tags in release_lines.items()
  }

  release_tag_set = set(release_tags)
  containing_by_commit = {
    commit: {tag for tag in repo.list_tags_containing(commit) if tag in release_tag_set}
    for commit in fixing_commits
  }

  line_plans: dict[str, Any] = {}
  verification_order: list[str] = []
  for line, tags in sorted(release_lines.items()):
    tag_index = {tag: idx for idx, tag in enumerate(tags)}
    containing = [
      tag for tag in tags
      if any(tag in hits for hits in containing_by_commit.values())
    ]
    if containing:
      fic_tag = min(containing, key=lambda tag: tag_index[tag])
      fic_index = tag_index[fic_tag]
      candidate_tags = tags[:fic_index]
      status = "bounded_by_line_local_fic"
    else:
      fic_tag = None
      fic_index = None
      candidate_tags = list(tags)
      status = "no_line_local_fic"

    probes: list[str] = []
    if candidate_tags:
      probes.append(candidate_tags[0])
      probes.append(candidate_tags[-1])
    if fic_tag:
      probes.append(fic_tag)
    probes = _unique(probes)
    verification_order.extend(probes)
    line_plans[line] = {
      "line": line,
      "tags": tags,
      "fic_tag": fic_tag,
      "fic_index": fic_index,
      "status": status,
      "candidate_tags": candidate_tags,
      "probe_tags": probes,
    }

  return {
    "plan_kind": "fast_line_local_fic_baseline",
    "repo": repo_name,
    "repo_path": str(repo_path),
    "cve_id": cve_id,
    "line_plans": line_plans,
    "line_boundaries": line_plans,
    "verification_order": _unique(verification_order),
    "release_lines": release_lines,
    "containing_by_commit": {
      commit: sorted(tags)
      for commit, tags in containing_by_commit.items()
    },
  }


def _coverage(gt_tags: list[str], release_tags: list[str], candidate_tags: list[str]) -> dict[str, Any]:
  mapped_gt, unmapped_gt = map_gt_tags_to_repo_tags(gt_tags, release_tags, mode="loose")
  candidate_set = set(candidate_tags)
  covered = [tag for tag in mapped_gt if tag in candidate_set]
  missed = [tag for tag in mapped_gt if tag not in candidate_set]
  return {
    "mapped_gt_count": len(mapped_gt),
    "unmapped_gt_count": len(unmapped_gt),
    "covered_gt_count": len(covered),
    "missed_gt_count": len(missed),
    "coverage_rate": (len(covered) / len(mapped_gt)) if mapped_gt else 1.0,
    "missed_gt_tags": missed,
    "unmapped_gt_tags": unmapped_gt,
  }


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
  if not rows:
    return {}

  def avg(key: str) -> float:
    return round(statistics.mean(float(row[key]) for row in rows), 2)

  def med(key: str) -> float:
    return float(statistics.median(float(row[key]) for row in rows))

  return {
    "cves": len(rows),
    "global_candidate_avg": avg("global_candidate_count"),
    "global_candidate_median": med("global_candidate_count"),
    "global_candidate_max": max(row["global_candidate_count"] for row in rows),
    "vulntree_candidate_avg": avg("vulntree_candidate_count"),
    "vulntree_candidate_median": med("vulntree_candidate_count"),
    "vulntree_candidate_max": max(row["vulntree_candidate_count"] for row in rows),
    "vulntree_probe_avg": avg("vulntree_probe_count"),
    "vulntree_probe_median": med("vulntree_probe_count"),
    "vulntree_probe_max": max(row["vulntree_probe_count"] for row in rows),
    "global_full_gt_coverage_cves": sum(1 for row in rows if row["global_gt_coverage_rate"] >= 1.0),
    "vulntree_full_gt_candidate_coverage_cves": sum(1 for row in rows if row["vulntree_gt_candidate_coverage_rate"] >= 1.0),
    "global_avg_gt_coverage": round(statistics.mean(float(row["global_gt_coverage_rate"]) for row in rows), 4),
    "vulntree_avg_gt_candidate_coverage": round(statistics.mean(float(row["vulntree_gt_candidate_coverage_rate"]) for row in rows), 4),
    "avg_global_minus_vulntree_candidate": round(
      statistics.mean(float(row["global_candidate_count"] - row["vulntree_candidate_count"]) for row in rows),
      2,
    ),
    "avg_global_minus_vulntree_probe": round(
      statistics.mean(float(row["global_candidate_count"] - row["vulntree_probe_count"]) for row in rows),
      2,
    ),
  }


def _write_report(path: Path, *, summary: dict[str, Any], by_repo: dict[str, Any], rows: list[dict[str, Any]]) -> None:
  lines = [
    "# Global FIC Baseline vs VulnTree Line-Local Planning",
    "",
    "This experiment samples CVEs per repo and compares two planning strategies:",
    "",
    "- `global_fic_baseline`: one global release-tag sequence, first global FIC, all earlier tags as candidates.",
    "- `vuln_tree_line_local`: current Step3 planner with line-local FIC and ASBS probe scheduling.",
    "",
    "## Overall",
    "",
  ]
  for key, value in summary.items():
    lines.append(f"- {key}: `{value}`")
  lines.extend([
    "",
    "## By Repo",
    "",
    "| repo | cves | global avg cand | vt avg cand | vt avg probes | global full GT | vt full GT candidate |",
    "|---|---:|---:|---:|---:|---:|---:|",
  ])
  for repo, row in by_repo.items():
    lines.append(
      f"| {repo} | {row['cves']} | {row['global_candidate_avg']} | "
      f"{row['vulntree_candidate_avg']} | {row['vulntree_probe_avg']} | "
      f"{row['global_full_gt_coverage_cves']} | {row['vulntree_full_gt_candidate_coverage_cves']} |"
    )
  lines.extend([
    "",
    "## Most Expensive Global FIC Cases",
    "",
  ])
  for row in sorted(rows, key=lambda r: (-r["global_candidate_count"], r["repo"], r["cve_id"]))[:20]:
    lines.append(
      f"- `{row['repo']}` `{row['cve_id']}`: global `{row['global_candidate_count']}`, "
      f"vulntree candidates `{row['vulntree_candidate_count']}`, probes `{row['vulntree_probe_count']}`"
    )
  path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
  parser = argparse.ArgumentParser(description="Compare global FIC baseline with VulnTree line-local planning.")
  parser.add_argument("--dataset", type=Path, default=ROOT / "DataSet" / "BaseDataOrder.json")
  parser.add_argument("--repo-root", type=Path, default=ROOT / "repo")
  parser.add_argument("--out-dir", type=Path, default=ROOT / "tests" / "global_fic_vs_vulntree")
  parser.add_argument("--per-repo", type=int, default=10)
  parser.add_argument("--seed", type=int, default=42)
  parser.add_argument(
    "--enable-expensive-equivalence",
    action="store_true",
    help="Run current planner with patch-id/message/file equivalence enabled. This is much slower.",
  )
  parser.add_argument(
    "--use-current-vulntree",
    action="store_true",
    help="Use build_tag_plan() instead of the lightweight line-local FIC baseline.",
  )
  args = parser.parse_args(argv)

  data = json.loads(args.dataset.read_text(encoding="utf-8"))
  sampled = _sample_by_repo(data, per_repo=args.per_repo, seed=args.seed)

  orig_list_tags = GitRepo.list_tags
  orig_list_tags_containing = GitRepo.list_tags_containing
  orig_patch_id = GitRepo.patch_id
  orig_show_patch = GitRepo.show_patch
  orig_changed_files = GitRepo.changed_files
  orig_commit_parents = GitRepo.commit_parents
  orig_commit_message = GitRepo.commit_message
  orig_list_remote_branches_containing = GitRepo.list_remote_branches_containing

  @lru_cache(maxsize=None)
  def _cached_list_tags(repo_path: str, tags_glob: str | None, max_tags: int | None):
    repo = GitRepo.open(repo_path)
    return tuple(orig_list_tags(repo, tags_glob=tags_glob, max_tags=max_tags))

  @lru_cache(maxsize=None)
  def _cached_list_tags_containing(repo_path: str, commit: str, tags_glob: str | None):
    repo = GitRepo.open(repo_path)
    return tuple(orig_list_tags_containing(repo, commit, tags_glob=tags_glob))

  def _list_tags(self, tags_glob=None, max_tags=None):
    return list(_cached_list_tags(str(self.repo_path), tags_glob, max_tags))

  def _list_tags_containing(self, commit, *, tags_glob=None):
    return list(_cached_list_tags_containing(str(self.repo_path), commit, tags_glob))

  GitRepo.list_tags = _list_tags  # type: ignore[method-assign]
  GitRepo.list_tags_containing = _list_tags_containing  # type: ignore[method-assign]
  if not args.enable_expensive_equivalence:
    GitRepo.patch_id = lambda self, commit: ""  # type: ignore[method-assign]
    GitRepo.show_patch = lambda self, commit: ""  # type: ignore[method-assign]
    GitRepo.changed_files = lambda self, commit: []  # type: ignore[method-assign]
    GitRepo.commit_parents = lambda self, commit: []  # type: ignore[method-assign]
    GitRepo.commit_message = lambda self, commit: ""  # type: ignore[method-assign]
    GitRepo.list_remote_branches_containing = lambda self, commit: []  # type: ignore[method-assign]

  rows: list[dict[str, Any]] = []
  failures: list[dict[str, Any]] = []
  try:
    for cve_id, rec in sampled:
      repo = str(rec.get("repo") or "")
      repo_path = args.repo_root / repo
      fixing_commits = _flatten_fixing_commits(rec.get("fixing_commits"))
      gt_tags = list(rec.get("affected_version") or [])
      try:
        global_plan = build_global_fic_tag_plan(
          repo_path=repo_path,
          repo_name=repo,
          cve_id=cve_id,
          fixing_commits=fixing_commits,
        )
        if args.use_current_vulntree:
          vt_plan = build_tag_plan(
            repo_path=str(repo_path),
            cve_id=cve_id,
            fixing_commits=rec.get("fixing_commits"),
            mode="eval",
          )
        else:
          vt_plan = build_fast_line_local_plan(
            repo_path=repo_path,
            repo_name=repo,
            cve_id=cve_id,
            fixing_commits=fixing_commits,
          )
        global_candidates = list(global_plan.get("candidate_tags_before_fic") or [])
        global_release_tags = list(global_plan.get("global_tag_plan") or [])
        vt_candidates = _vulntree_candidate_tags(vt_plan)
        vt_probes = list(vt_plan.get("verification_order") or [])

        global_cov = _coverage(gt_tags, global_release_tags, global_candidates)
        vt_candidate_cov = _coverage(gt_tags, global_release_tags, vt_candidates)
        vt_probe_cov = _coverage(gt_tags, global_release_tags, vt_probes)

        rows.append({
          "repo": repo,
          "cve_id": cve_id,
          "fix_commit_count": len(fixing_commits),
          "affected_version_count": len(gt_tags),
          "global_status": global_plan.get("status"),
          "global_tag_count": global_plan.get("global_tag_count"),
          "global_fic_tag": global_plan.get("global_fic_tag"),
          "global_fic_index": global_plan.get("global_fic_index"),
          "global_candidate_count": len(global_candidates),
          "global_gt_coverage_rate": global_cov["coverage_rate"],
          "global_gt_missed_count": global_cov["missed_gt_count"],
          "global_unmapped_gt_count": global_cov["unmapped_gt_count"],
          "vulntree_line_count": len(vt_plan.get("line_boundaries") or {}),
          "vulntree_status_counts": _line_status_counts(vt_plan),
          "vulntree_candidate_count": len(vt_candidates),
          "vulntree_probe_count": len(vt_probes),
          "vulntree_gt_candidate_coverage_rate": vt_candidate_cov["coverage_rate"],
          "vulntree_gt_candidate_missed_count": vt_candidate_cov["missed_gt_count"],
          "vulntree_gt_probe_coverage_rate": vt_probe_cov["coverage_rate"],
          "vulntree_gt_probe_missed_count": vt_probe_cov["missed_gt_count"],
          "global_missed_gt_tags": global_cov["missed_gt_tags"][:100],
          "vulntree_candidate_missed_gt_tags": vt_candidate_cov["missed_gt_tags"][:100],
        })
      except Exception as exc:
        failures.append({
          "repo": repo,
          "cve_id": cve_id,
          "error": f"{type(exc).__name__}: {exc}",
        })
  finally:
    GitRepo.list_tags = orig_list_tags  # type: ignore[method-assign]
    GitRepo.list_tags_containing = orig_list_tags_containing  # type: ignore[method-assign]
    GitRepo.patch_id = orig_patch_id  # type: ignore[method-assign]
    GitRepo.show_patch = orig_show_patch  # type: ignore[method-assign]
    GitRepo.changed_files = orig_changed_files  # type: ignore[method-assign]
    GitRepo.commit_parents = orig_commit_parents  # type: ignore[method-assign]
    GitRepo.commit_message = orig_commit_message  # type: ignore[method-assign]
    GitRepo.list_remote_branches_containing = orig_list_remote_branches_containing  # type: ignore[method-assign]

  by_repo_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
  for row in rows:
    by_repo_rows[row["repo"]].append(row)
  by_repo = {repo: _summarize(repo_rows) for repo, repo_rows in sorted(by_repo_rows.items())}
  summary = _summarize(rows)
  summary["sampled_cves"] = len(sampled)
  summary["successful_cves"] = len(rows)
  summary["failed_cves"] = len(failures)
  summary["per_repo"] = args.per_repo
  summary["seed"] = args.seed
  summary["expensive_equivalence_enabled"] = bool(args.enable_expensive_equivalence)
  summary["line_local_planner"] = "current_vulntree" if args.use_current_vulntree else "fast_line_local_fic_baseline"

  args.out_dir.mkdir(parents=True, exist_ok=True)
  (args.out_dir / "rows.jsonl").write_text(
    "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
    encoding="utf-8",
  )
  (args.out_dir / "failures.jsonl").write_text(
    "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in failures),
    encoding="utf-8",
  )
  (args.out_dir / "summary.json").write_text(
    json.dumps({"overall": summary, "by_repo": by_repo, "failures": failures}, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
  )
  _write_report(args.out_dir / "report.md", summary=summary, by_repo=by_repo, rows=rows)

  print(json.dumps({"overall": summary, "out_dir": str(args.out_dir)}, ensure_ascii=False, indent=2))
  return 0 if not failures else 1


if __name__ == "__main__":
  raise SystemExit(main())
