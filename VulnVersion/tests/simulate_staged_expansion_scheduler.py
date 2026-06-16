from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
  sys.path.insert(0, str(ROOT))
if str(ROOT / "tests") not in sys.path:
  sys.path.insert(0, str(ROOT / "tests"))

from simulate_active_line_scheduler import (  # noqa: E402
  _batch_path_exists,
  _changed_files_for_commits,
  _flatten_fixing_commits,
  _neighbors,
  _precompute_tags_containing_batch,
  _release_context,
  _simulate_cve,
  _simulate_git_guided_line,
)
from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags  # noqa: E402


DEFAULT_DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
DEFAULT_REPO_ROOT = ROOT / "repo"
DEFAULT_OUT_DIR = ROOT / "tests" / "staged_expansion_scheduler_simulator"


def _load_dataset(path: Path) -> dict[str, Any]:
  return json.loads(path.read_text(encoding="utf-8"))


def _percentile(values: list[float], pct: float) -> float:
  if not values:
    return 0.0
  sorted_values = sorted(values)
  idx = round((len(sorted_values) - 1) * pct)
  return float(sorted_values[idx])


def _line_groups(ordered_by_family: dict[str, list[str]]) -> dict[str, str]:
  return {
    line: family
    for family, lines in ordered_by_family.items()
    for line in lines
  }


def _stride_lines(ordered_by_family: dict[str, list[str]], stride: int, *, lines_subset: set[str] | None = None) -> set[str]:
  if stride <= 0:
    return set()
  out: set[str] = set()
  subset = lines_subset
  for _, lines in ordered_by_family.items():
    scoped = [line for line in lines if subset is None or line in subset]
    for idx, line in enumerate(scoped):
      if idx % stride == 0:
        out.add(line)
    if scoped:
      out.add(scoped[-1])
  return out


def _file_neighbor_lines(
  ordered_by_family: dict[str, list[str]],
  file_endpoint_lines: set[str],
  radius: int,
) -> set[str]:
  out: set[str] = set()
  for _, lines in ordered_by_family.items():
    out.update(_neighbors(lines, set(file_endpoint_lines) & set(lines), radius))
  return out


def _no_fix_lines(release_lines: dict[str, list[str]], fix_containing_tags: set[str]) -> set[str]:
  return {
    line
    for line, tags in release_lines.items()
    if any(tag not in fix_containing_tags for tag in tags)
  }


def _initial_lines_for_policy(
  *,
  policy: str,
  release_lines: dict[str, list[str]],
  ordered_by_family: dict[str, list[str]],
  fix_containing_tags: set[str],
  file_endpoint_lines: set[str],
) -> tuple[set[str], str]:
  all_lines = set(release_lines)
  no_fix = _no_fix_lines(release_lines, fix_containing_tags)
  file_neighbor1 = _file_neighbor_lines(ordered_by_family, file_endpoint_lines, 1)

  if policy == "staged_file_neighbor1":
    return file_neighbor1, "none"
  if policy == "staged_file_neighbor1_nohit_nofix":
    return file_neighbor1, "nohit_nofix"
  if policy == "staged_file_neighbor1_nohit_all":
    return file_neighbor1, "nohit_all"
  if policy == "staged_file_or_stride4":
    return file_neighbor1 | _stride_lines(ordered_by_family, 4), "none"
  if policy == "staged_file_or_stride3":
    return file_neighbor1 | _stride_lines(ordered_by_family, 3), "none"
  if policy == "staged_file_or_stride2":
    return file_neighbor1 | _stride_lines(ordered_by_family, 2), "none"
  if policy == "staged_nofix_stride4_file":
    return file_neighbor1 | _stride_lines(ordered_by_family, 4, lines_subset=no_fix), "none"
  if policy == "staged_nofix_stride3_file":
    return file_neighbor1 | _stride_lines(ordered_by_family, 3, lines_subset=no_fix), "none"
  if policy == "staged_nofix_stride2_file":
    return file_neighbor1 | _stride_lines(ordered_by_family, 2, lines_subset=no_fix), "none"
  if policy == "oracle_affected_lines":
    return all_lines, "oracle"
  raise ValueError(f"unknown staged policy: {policy}")


def _family_neighbors(
  ordered_by_family: dict[str, list[str]],
  line_to_family: dict[str, str],
  line: str,
  radius: int,
) -> set[str]:
  family = line_to_family.get(line)
  if family is None:
    return set()
  lines = ordered_by_family.get(family, [])
  idx_by_line = {value: idx for idx, value in enumerate(lines)}
  idx = idx_by_line.get(line)
  if idx is None:
    return set()
  out: set[str] = set()
  for delta in range(1, radius + 1):
    if idx - delta >= 0:
      out.add(lines[idx - delta])
    if idx + delta < len(lines):
      out.add(lines[idx + delta])
  return out


def _simulate_staged_cve(
  *,
  cve_id: str,
  repo_name: str,
  affected_versions: list[str],
  release_lines: dict[str, list[str]],
  ordered_by_family: dict[str, list[str]],
  release_tags: list[str],
  fix_containing_tags: set[str],
  file_endpoint_lines: set[str],
  policy: str,
  sentinel_count: int,
  fixed_segment_sentinels: int,
  expansion_radius: int,
  fallback_scan_conflicts: bool,
) -> dict[str, Any]:
  mapped_gt, unmapped_gt = map_gt_tags_to_repo_tags(sorted(str(t) for t in affected_versions), release_tags, mode="loose")
  affected_set = set(mapped_gt)
  release_set = set(release_tags)
  affected_lines = {
    line for line, tags in release_lines.items()
    if any(tag in affected_set for tag in tags)
  }

  if policy == "all_lines_soft":
    return _simulate_cve(
      cve_id=cve_id,
      repo_name=repo_name,
      affected_versions=affected_versions,
      release_lines=release_lines,
      ordered_by_family=ordered_by_family,
      release_tags=release_tags,
      fix_containing_tags=fix_containing_tags,
      file_endpoint_lines=file_endpoint_lines,
      policy="all_lines_soft",
      sentinel_count=sentinel_count,
      fixed_segment_sentinels=fixed_segment_sentinels,
      fallback_scan_conflicts=fallback_scan_conflicts,
    )

  if policy == "oracle_affected_lines":
    initial_lines = set(affected_lines)
    fallback_mode = "oracle"
  else:
    initial_lines, fallback_mode = _initial_lines_for_policy(
      policy=policy,
      release_lines=release_lines,
      ordered_by_family=ordered_by_family,
      fix_containing_tags=fix_containing_tags,
      file_endpoint_lines=file_endpoint_lines,
    )

  line_to_family = _line_groups(ordered_by_family)
  queue = deque(sorted(initial_lines))
  visited: set[str] = set()
  predicted_set: set[str] = set()
  probe_tags: set[str] = set()
  positive_lines: set[str] = set()
  status_counter: Counter[str] = Counter()
  fallback_used = False

  def run_line(line: str) -> None:
    if line in visited:
      return
    tags = release_lines.get(line, [])
    visited.add(line)
    sim = _simulate_git_guided_line(
      tags,
      affected_set,
      fix_containing_tags,
      sentinel_count=sentinel_count,
      fixed_segment_sentinels=fixed_segment_sentinels,
      fallback_scan_conflicts=fallback_scan_conflicts,
    )
    predicted = set(sim["predicted_affected"])
    probes = set(sim["probe_tags"])
    predicted_set.update(predicted)
    probe_tags.update(probes)
    status_counter.update(sim["statuses"])
    if predicted or (probes & affected_set):
      positive_lines.add(line)
      for neighbor in _family_neighbors(ordered_by_family, line_to_family, line, expansion_radius):
        if neighbor not in visited:
          queue.append(neighbor)

  while queue:
    run_line(queue.popleft())

  if not positive_lines and fallback_mode in {"nohit_nofix", "nohit_all"}:
    fallback_used = True
    if fallback_mode == "nohit_nofix":
      fallback_lines = _no_fix_lines(release_lines, fix_containing_tags)
    else:
      fallback_lines = set(release_lines)
    for line in sorted(fallback_lines - visited):
      queue.append(line)
    while queue:
      run_line(queue.popleft())

  skipped_affected_lines = len(affected_lines - visited)
  for _ in range(len(release_lines) - len(visited)):
    status_counter["skipped_line"] += 1

  tp = len(predicted_set & affected_set)
  fp = len(predicted_set - affected_set)
  fn = len(affected_set - predicted_set)
  tn = len(release_set - predicted_set - affected_set)
  precision = tp / (tp + fp) if (tp + fp) else (1.0 if not affected_set else 0.0)
  recall = tp / (tp + fn) if (tp + fn) else 1.0
  f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

  return {
    "cve_id": cve_id,
    "repo": repo_name,
    "policy": policy,
    "release_tag_count": len(release_tags),
    "line_count": len(release_lines),
    "seed_line_count": len(initial_lines),
    "active_line_count": len(visited),
    "positive_line_count": len(positive_lines),
    "affected_line_count": len(affected_lines),
    "skipped_affected_lines": skipped_affected_lines,
    "file_endpoint_line_count": len(file_endpoint_lines),
    "fix_containing_tag_count": len(fix_containing_tags),
    "mapped_gt_count": len(mapped_gt),
    "unmapped_gt_count": len(unmapped_gt),
    "probe_count": len(probe_tags),
    "predicted_count": len(predicted_set),
    "fallback_used": fallback_used,
    "tp": tp,
    "fp": fp,
    "fn": fn,
    "tn": tn,
    "precision": precision,
    "recall": recall,
    "f1": f1,
    "exact_match": fp == 0 and fn == 0 and len(unmapped_gt) == 0,
    "full_mapped_recall": fn == 0,
    "has_fp": fp > 0,
    "has_fn": fn > 0,
    "status_counts": dict(status_counter),
  }


def _summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
  if not rows:
    return {}
  probe_values = [float(row["probe_count"]) for row in rows]
  active_line_values = [float(row["active_line_count"]) for row in rows]
  seed_line_values = [float(row.get("seed_line_count", row["active_line_count"])) for row in rows]
  skipped_affected_values = [float(row["skipped_affected_lines"]) for row in rows]
  tp = sum(int(row["tp"]) for row in rows)
  fp = sum(int(row["fp"]) for row in rows)
  fn = sum(int(row["fn"]) for row in rows)
  tn = sum(int(row["tn"]) for row in rows)
  precision = tp / (tp + fp) if (tp + fp) else 1.0
  recall = tp / (tp + fn) if (tp + fn) else 1.0
  f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
  return {
    "cves": len(rows),
    "probe_avg": round(statistics.mean(probe_values), 2),
    "probe_median": round(statistics.median(probe_values), 2),
    "probe_p90": round(_percentile(probe_values, 0.90), 2),
    "probe_p95": round(_percentile(probe_values, 0.95), 2),
    "probe_max": int(max(probe_values)),
    "seed_line_avg": round(statistics.mean(seed_line_values), 2),
    "active_line_avg": round(statistics.mean(active_line_values), 2),
    "skipped_affected_line_avg": round(statistics.mean(skipped_affected_values), 2),
    "exact_match_cves": sum(1 for row in rows if row["exact_match"]),
    "full_mapped_recall_cves": sum(1 for row in rows if row["full_mapped_recall"]),
    "has_fp_cves": sum(1 for row in rows if row["has_fp"]),
    "has_fn_cves": sum(1 for row in rows if row["has_fn"]),
    "unmapped_cves": sum(1 for row in rows if row["unmapped_gt_count"] > 0),
    "skipped_affected_line_cves": sum(1 for row in rows if row["skipped_affected_lines"] > 0),
    "fallback_used_cves": sum(1 for row in rows if row.get("fallback_used")),
    "micro_tp": tp,
    "micro_fp": fp,
    "micro_fn": fn,
    "micro_tn": tn,
    "micro_precision": round(precision, 6),
    "micro_recall": round(recall, 6),
    "micro_f1": round(f1, 6),
    "macro_precision": round(statistics.mean(float(row["precision"]) for row in rows), 6),
    "macro_recall": round(statistics.mean(float(row["recall"]) for row in rows), 6),
    "macro_f1": round(statistics.mean(float(row["f1"]) for row in rows), 6),
  }


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
  grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
  for row in rows:
    grouped[row["policy"]].append(row)
  overall = {key: _summarize_rows(vals) for key, vals in sorted(grouped.items())}
  by_repo: dict[str, dict[str, Any]] = {}
  for key, vals in sorted(grouped.items()):
    repo_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in vals:
      repo_groups[row["repo"]].append(row)
    by_repo[key] = {repo: _summarize_rows(repo_rows) for repo, repo_rows in sorted(repo_groups.items())}
  worst: dict[str, list[dict[str, Any]]] = {}
  for key, vals in sorted(grouped.items()):
    worst[key] = [
      {
        "repo": row["repo"],
        "cve_id": row["cve_id"],
        "probe_count": row["probe_count"],
        "seed_line_count": row.get("seed_line_count", row["active_line_count"]),
        "active_line_count": row["active_line_count"],
        "affected_line_count": row["affected_line_count"],
        "skipped_affected_lines": row["skipped_affected_lines"],
        "fp": row["fp"],
        "fn": row["fn"],
        "precision": round(float(row["precision"]), 6),
        "recall": round(float(row["recall"]), 6),
      }
      for row in sorted(vals, key=lambda item: (-int(item["fn"]), -int(item["skipped_affected_lines"]), -int(item["probe_count"])))[:30]
    ]
  return {"overall": overall, "by_repo": by_repo, "worst_cases": worst}


def _write_json(path: Path, obj: Any) -> None:
  path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
  with path.open("w", encoding="utf-8") as fp:
    for row in rows:
      fp.write(json.dumps(row, ensure_ascii=False) + "\n")


def _write_report(path: Path, summary: dict[str, Any]) -> None:
  lines = [
    "# Staged Expansion Scheduler GT Simulator",
    "",
    "This is a GT-oracle simulation. It uses affected_version as an ideal tag verdict oracle and measures scheduling behavior, not real agent accuracy.",
    "",
    "| policy | cves | avg probes | p95 | avg seed lines | avg active lines | exact CVEs | FN CVEs | skipped-affected-line CVEs | micro P | micro R | micro F1 |",
    "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
  ]
  for key, row in summary["overall"].items():
    lines.append(
      f"| {key} | {row['cves']} | {row['probe_avg']} | {row['probe_p95']} | "
      f"{row['seed_line_avg']} | {row['active_line_avg']} | "
      f"{row['exact_match_cves']} | {row['has_fn_cves']} | {row['skipped_affected_line_cves']} | "
      f"{row['micro_precision']} | {row['micro_recall']} | {row['micro_f1']} |"
    )
  lines.extend(["", "## By Repo", ""])
  for key, repos in summary["by_repo"].items():
    lines.extend([
      f"### {key}",
      "",
      "| repo | cves | avg probes | p95 | avg seed lines | avg active lines | exact CVEs | FN CVEs | micro R | micro F1 |",
      "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for repo, row in repos.items():
      lines.append(
        f"| {repo} | {row['cves']} | {row['probe_avg']} | {row['probe_p95']} | "
        f"{row['seed_line_avg']} | {row['active_line_avg']} | "
        f"{row['exact_match_cves']} | {row['has_fn_cves']} | "
        f"{row['micro_recall']} | {row['micro_f1']} |"
      )
    lines.append("")
  path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
  parser = argparse.ArgumentParser(description="Simulate evidence-driven staged line expansion with GT affected versions.")
  parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
  parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
  parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
  parser.add_argument("--sentinel-count", type=int, default=3)
  parser.add_argument("--fixed-segment-sentinels", type=int, default=1)
  parser.add_argument("--expansion-radius", type=int, default=1)
  parser.add_argument(
    "--policies",
    default=(
      "all_lines_soft,"
      "staged_file_neighbor1,"
      "staged_file_neighbor1_nohit_nofix,"
      "staged_file_neighbor1_nohit_all,"
      "staged_file_or_stride4,"
      "staged_file_or_stride3,"
      "staged_file_or_stride2,"
      "staged_nofix_stride4_file,"
      "staged_nofix_stride3_file,"
      "staged_nofix_stride2_file,"
      "oracle_affected_lines"
    ),
  )
  parser.add_argument("--no-fallback-scan-conflicts", action="store_true")
  args = parser.parse_args(argv)

  dataset = _load_dataset(args.dataset)
  policies = [part.strip() for part in args.policies.split(",") if part.strip()]
  fallback_scan_conflicts = not args.no_fallback_scan_conflicts

  by_repo_records: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
  for cve_id, rec in sorted(dataset.items()):
    repo_name = str(rec.get("repo") or "").strip()
    if repo_name:
      by_repo_records[repo_name].append((cve_id, rec))

  contexts: dict[str, dict[str, Any]] = {}
  commit_contains_by_repo: dict[str, dict[str, dict[str, Any]]] = {}
  changed_files_by_cve: dict[str, list[str]] = {}
  endpoint_queries_by_repo: dict[str, set[tuple[str, str]]] = defaultdict(set)

  for repo_name, records in sorted(by_repo_records.items()):
    context = _release_context(repo_name, args.repo_root / repo_name)
    contexts[repo_name] = context
    repo: GitRepo = context["repo"]
    target_commits: set[str] = set()
    changed_cache: dict[str, list[str]] = {}
    endpoint_tags = {
      tag
      for tags in context["release_lines"].values()
      for tag in ([tags[0], tags[-1]] if tags else [])
    }
    for cve_id, rec in records:
      commits = _flatten_fixing_commits(rec.get("fixing_commits") or rec.get("fixing_commit"))
      target_commits.update(commits)
      files = _changed_files_for_commits(repo, commits, changed_cache)
      changed_files_by_cve[cve_id] = files
      for tag in endpoint_tags:
        for path in files:
          endpoint_queries_by_repo[repo_name].add((tag, path))
    commit_contains_by_repo[repo_name] = _precompute_tags_containing_batch(
      repo=repo,
      release_tags=context["release_tags"],
      target_commits=target_commits,
    )

  path_exists_by_repo: dict[str, dict[tuple[str, str], bool]] = {}
  for repo_name, queries in sorted(endpoint_queries_by_repo.items()):
    path_exists_by_repo[repo_name] = _batch_path_exists(contexts[repo_name]["repo"], queries)

  rows: list[dict[str, Any]] = []
  for repo_name, records in sorted(by_repo_records.items()):
    context = contexts[repo_name]
    release_lines: dict[str, list[str]] = context["release_lines"]
    for cve_id, rec in records:
      commits = _flatten_fixing_commits(rec.get("fixing_commits") or rec.get("fixing_commit"))
      fix_containing_tags: set[str] = set()
      for commit in commits:
        result = commit_contains_by_repo[repo_name].get(commit, {"ok": False, "tags": []})
        if result.get("ok"):
          fix_containing_tags.update(result.get("tags", []))
      files = changed_files_by_cve.get(cve_id, [])
      file_endpoint_lines: set[str] = set()
      path_exists = path_exists_by_repo.get(repo_name, {})
      for line, tags in release_lines.items():
        if not tags:
          continue
        endpoints = {tags[0], tags[-1]}
        if any(path_exists.get((tag, path), False) for tag in endpoints for path in files):
          file_endpoint_lines.add(line)

      for policy in policies:
        rows.append(_simulate_staged_cve(
          cve_id=cve_id,
          repo_name=repo_name,
          affected_versions=list(rec.get("affected_version") or []),
          release_lines=release_lines,
          ordered_by_family=context["ordered_by_family"],
          release_tags=context["release_tags"],
          fix_containing_tags=fix_containing_tags,
          file_endpoint_lines=file_endpoint_lines,
          policy=policy,
          sentinel_count=args.sentinel_count,
          fixed_segment_sentinels=args.fixed_segment_sentinels,
          expansion_radius=args.expansion_radius,
          fallback_scan_conflicts=fallback_scan_conflicts,
        ))

  args.out_dir.mkdir(parents=True, exist_ok=True)
  summary = _summarize(rows)
  metadata = {
    "dataset": str(args.dataset),
    "repo_root": str(args.repo_root),
    "policies": policies,
    "sentinel_count": args.sentinel_count,
    "fixed_segment_sentinels": args.fixed_segment_sentinels,
    "expansion_radius": args.expansion_radius,
    "fallback_scan_conflicts": fallback_scan_conflicts,
    "total_simulation_rows": len(rows),
    "oracle_note": "GT-oracle simulator: affected_version supplies ideal probe verdicts; this measures scheduling, not real agent accuracy.",
  }
  _write_json(args.out_dir / "summary.json", {"metadata": metadata, **summary})
  _write_jsonl(args.out_dir / "per_cve.jsonl", rows)
  _write_report(args.out_dir / "report.md", summary)
  print(json.dumps({"metadata": metadata, "overall": summary["overall"], "out_dir": str(args.out_dir)}, ensure_ascii=False, indent=2))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
