from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
  sys.path.insert(0, str(ROOT))

from tests.global_fic_tag_plan_experiment import global_release_sort_key
from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.version_registry import filter_release_tags


DEFAULT_DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
DEFAULT_REPO_ROOT = ROOT / "repo"
DEFAULT_OUT_DIR = ROOT / "tests" / "global_affected_runs"


def _load_dataset(path: Path) -> dict[str, Any]:
  return json.loads(path.read_text(encoding="utf-8"))


def _release_tags_by_order(repo_name: str, repo_path: Path) -> dict[str, list[str]]:
  repo = GitRepo.open(repo_path)
  newest_first = filter_release_tags(repo_name, repo.list_tags(max_tags=None))
  semantic = sorted(newest_first, key=lambda tag: global_release_sort_key(repo_name, tag))
  creatordate_oldest = list(reversed(newest_first))
  return {
    "semantic_global": semantic,
    "creatordate_oldest": creatordate_oldest,
    "creatordate_newest": newest_first,
  }


def _runs(indices: list[int]) -> list[dict[str, int]]:
  if not indices:
    return []
  sorted_indices = sorted(indices)
  runs: list[dict[str, int]] = []
  start = prev = sorted_indices[0]
  for idx in sorted_indices[1:]:
    if idx == prev + 1:
      prev = idx
      continue
    runs.append({"start": start, "end": prev, "length": prev - start + 1})
    start = prev = idx
  runs.append({"start": start, "end": prev, "length": prev - start + 1})
  return runs


def _analyze_order(order_name: str, tags: list[str], affected_tags: set[str]) -> dict[str, Any]:
  affected_indices = [idx for idx, tag in enumerate(tags) if tag in affected_tags]
  runs = _runs(affected_indices)
  transitions = 0
  last = None
  for tag in tags:
    cur = tag in affected_tags
    if last is not None and cur != last:
      transitions += 1
    last = cur
  has_ana = len(runs) > 1
  run_details = [
    {
      **run,
      "start_tag": tags[run["start"]],
      "end_tag": tags[run["end"]],
    }
    for run in runs
  ]
  return {
    "order": order_name,
    "tag_count": len(tags),
    "affected_count": len(affected_indices),
    "run_count": len(runs),
    "is_global_contiguous": len(runs) <= 1,
    "has_a_n_a_pattern": has_ana,
    "state_transition_count": transitions,
    "runs": run_details,
  }


def _analyze_cve(
  *,
  cve_id: str,
  repo_name: str,
  affected_versions: list[str],
  orders: dict[str, list[str]],
) -> dict[str, Any]:
  release_tags = orders["semantic_global"]
  mapped_tags, unmapped_tags = map_gt_tags_to_repo_tags(affected_versions, release_tags, mode="loose")
  affected_set = set(mapped_tags)
  order_results = {
    name: _analyze_order(name, tags, affected_set)
    for name, tags in orders.items()
  }
  return {
    "cve_id": cve_id,
    "repo": repo_name,
    "affected_version_count": len(affected_versions),
    "mapped_count": len(mapped_tags),
    "unmapped_count": len(unmapped_tags),
    "unmapped_tags": unmapped_tags,
    "orders": order_results,
  }


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
  orders = ["semantic_global", "creatordate_oldest", "creatordate_newest"]
  overall: dict[str, Any] = {
    "total_cves": len(rows),
    "fully_mapped_cves": sum(1 for row in rows if row["unmapped_count"] == 0),
    "partially_or_unmapped_cves": sum(1 for row in rows if row["unmapped_count"] > 0),
  }
  by_repo: dict[str, Any] = {}
  grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
  for row in rows:
    grouped[row["repo"]].append(row)

  for order in orders:
    noncontig = [row for row in rows if not row["orders"][order]["is_global_contiguous"]]
    overall[f"{order}_global_contiguous_cves"] = len(rows) - len(noncontig)
    overall[f"{order}_has_a_n_a_cves"] = len(noncontig)
    overall[f"{order}_max_run_count"] = max((row["orders"][order]["run_count"] for row in rows), default=0)
    repo_counter = Counter(row["repo"] for row in noncontig)
    overall[f"{order}_top_repos_with_a_n_a"] = repo_counter.most_common()

  for repo, repo_rows in sorted(grouped.items()):
    repo_summary: dict[str, Any] = {
      "cves": len(repo_rows),
      "fully_mapped_cves": sum(1 for row in repo_rows if row["unmapped_count"] == 0),
    }
    for order in orders:
      noncontig = [row for row in repo_rows if not row["orders"][order]["is_global_contiguous"]]
      repo_summary[f"{order}_global_contiguous_cves"] = len(repo_rows) - len(noncontig)
      repo_summary[f"{order}_has_a_n_a_cves"] = len(noncontig)
      repo_summary[f"{order}_max_run_count"] = max((row["orders"][order]["run_count"] for row in repo_rows), default=0)
    by_repo[repo] = repo_summary
  return {"overall": overall, "by_repo": by_repo}


def _write_report(path: Path, summary: dict[str, Any], rows: list[dict[str, Any]]) -> None:
  overall = summary["overall"]
  by_repo = summary["by_repo"]
  lines = [
    "# Global Affected-Run Analysis",
    "",
    "This report checks whether affected versions form one contiguous run when all release tags are flattened into one repo-level sequence.",
    "",
    "If a CVE has more than one affected run (`A ... N ... A`), global ASBS over that sequence is not monotonic.",
    "",
    "## Overall",
    "",
    f"- total_cves: `{overall['total_cves']}`",
    f"- fully_mapped_cves: `{overall['fully_mapped_cves']}`",
    f"- partially_or_unmapped_cves: `{overall['partially_or_unmapped_cves']}`",
    "",
    "| order | global_contiguous_cves | has_A_N_A_cves | max_run_count |",
    "|---|---:|---:|---:|",
  ]
  for order in ["semantic_global", "creatordate_oldest", "creatordate_newest"]:
    lines.append(
      f"| {order} | {overall[f'{order}_global_contiguous_cves']} | "
      f"{overall[f'{order}_has_a_n_a_cves']} | {overall[f'{order}_max_run_count']} |"
    )

  lines.extend([
    "",
    "## By Repo",
    "",
    "| repo | cves | semantic A-N-A | time-oldest A-N-A | time-newest A-N-A |",
    "|---|---:|---:|---:|---:|",
  ])
  for repo, row in by_repo.items():
    lines.append(
      f"| {repo} | {row['cves']} | {row['semantic_global_has_a_n_a_cves']} | "
      f"{row['creatordate_oldest_has_a_n_a_cves']} | {row['creatordate_newest_has_a_n_a_cves']} |"
    )

  lines.extend([
    "",
    "## Worst Semantic-Order Cases",
    "",
  ])
  worst = sorted(
    rows,
    key=lambda row: (-row["orders"]["semantic_global"]["run_count"], row["repo"], row["cve_id"]),
  )[:30]
  for row in worst:
    order = row["orders"]["semantic_global"]
    if order["run_count"] <= 1:
      continue
    lines.append(
      f"- `{row['repo']}` `{row['cve_id']}`: runs `{order['run_count']}`, "
      f"affected `{order['affected_count']}` / tags `{order['tag_count']}`"
    )
  path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
  parser = argparse.ArgumentParser(description="Analyze A-N-A patterns in flattened global release-tag sequences.")
  parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
  parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
  parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
  args = parser.parse_args(argv)

  dataset = _load_dataset(args.dataset)
  order_cache: dict[str, dict[str, list[str]]] = {}
  rows: list[dict[str, Any]] = []
  for cve_id, rec in sorted(dataset.items()):
    repo_name = str(rec.get("repo") or "").strip()
    if not repo_name:
      continue
    if repo_name not in order_cache:
      order_cache[repo_name] = _release_tags_by_order(repo_name, args.repo_root / repo_name)
    rows.append(_analyze_cve(
      cve_id=cve_id,
      repo_name=repo_name,
      affected_versions=list(rec.get("affected_version") or []),
      orders=order_cache[repo_name],
    ))

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
