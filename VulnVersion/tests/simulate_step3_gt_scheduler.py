from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
  sys.path.insert(0, str(ROOT))

from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.version_registry import (
  filter_release_tags,
  line_family_key,
  line_key,
  sort_tags_for_line,
)


DEFAULT_DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
DEFAULT_REPO_ROOT = ROOT / "repo"
DEFAULT_OUT_DIR = ROOT / "tests" / "step3_gt_scheduler_simulator"


def _load_dataset(path: Path) -> dict[str, Any]:
  return json.loads(path.read_text(encoding="utf-8"))


def _release_lines(repo_name: str, repo_path: Path) -> dict[str, list[str]]:
  repo = GitRepo.open(repo_path)
  tags = repo.list_tags(max_tags=None)
  release_tags = filter_release_tags(repo_name, tags)
  grouped: dict[str, list[str]] = defaultdict(list)
  for tag in release_tags:
    grouped[line_key(repo_name, tag)].append(tag)
  return {
    line: sort_tags_for_line(repo_name, vals, reverse=False)
    for line, vals in sorted(grouped.items())
  }


def _flatten_lines(lines: dict[str, list[str]]) -> list[str]:
  tags: list[str] = []
  for line_tags in lines.values():
    tags.extend(line_tags)
  return tags


def _even_sentinels(n: int, count: int, *, exclude: set[int] | None = None) -> list[int]:
  if n <= 2 or count <= 0:
    return []
  excluded = exclude or set()
  out: list[int] = []
  for k in range(1, count + 1):
    idx = round(k * (n - 1) / (count + 1))
    idx = max(1, min(n - 2, idx))
    if idx not in excluded and idx not in out:
      out.append(idx)
  return out


def _binary_first_true(lo_false: int, hi_true: int, probe) -> int:
  lo = lo_false
  hi = hi_true
  while hi - lo > 1:
    mid = (lo + hi) // 2
    if probe(mid):
      hi = mid
    else:
      lo = mid
  return hi


def _binary_first_false(lo_true: int, hi_false: int, probe) -> int:
  lo = lo_true
  hi = hi_false
  while hi - lo > 1:
    mid = (lo + hi) // 2
    if probe(mid):
      lo = mid
    else:
      hi = mid
  return hi


def _line_runs(states: list[bool]) -> list[tuple[int, int]]:
  runs: list[tuple[int, int]] = []
  start: int | None = None
  for idx, value in enumerate(states):
    if value and start is None:
      start = idx
    elif not value and start is not None:
      runs.append((start, idx - 1))
      start = None
  if start is not None:
    runs.append((start, len(states) - 1))
  return runs


def _simulate_active_line(
  tags: list[str],
  affected_set: set[str],
  *,
  sentinel_count: int,
  fallback_scan_conflicts: bool,
) -> dict[str, Any]:
  n = len(tags)
  if n == 0:
    return {
      "predicted_affected": set(),
      "probe_indices": set(),
      "status": "empty_line",
      "actual_runs": [],
    }

  actual = [tag in affected_set for tag in tags]
  known: dict[int, bool] = {}

  def probe(idx: int) -> bool:
    known[idx] = actual[idx]
    return actual[idx]

  left = probe(0)
  right = probe(n - 1)
  predicted = [False] * n
  status = "unknown"
  conflict = False

  if n == 1:
    predicted[0] = left
    status = "singleton"

  elif left and right:
    for idx in _even_sentinels(n, sentinel_count, exclude={0, n - 1}):
      probe(idx)
    if all(known[idx] for idx in known):
      predicted = [True] * n
      status = "aa_full_line_inferred"
    else:
      conflict = True
      status = "aa_conflict"

  elif not left and right:
    first = _binary_first_true(0, n - 1, probe)
    for idx in range(first, n):
      predicted[idx] = True
    status = "na_suffix_boundary"

  elif left and not right:
    first_false = _binary_first_false(0, n - 1, probe)
    for idx in range(0, first_false):
      predicted[idx] = True
    status = "an_prefix_boundary"

  else:
    sentinels = _even_sentinels(n, sentinel_count, exclude={0, n - 1})
    affected_sentinels = [idx for idx in sentinels if probe(idx)]
    if not affected_sentinels:
      predicted = [False] * n
      status = "nn_no_affected_inferred"
    else:
      left_a = min(affected_sentinels)
      right_a = max(affected_sentinels)
      left_false_candidates = [idx for idx, value in known.items() if idx < left_a and not value]
      right_false_candidates = [idx for idx, value in known.items() if idx > right_a and not value]
      left_false = max(left_false_candidates) if left_false_candidates else 0
      right_false = min(right_false_candidates) if right_false_candidates else n - 1
      first = _binary_first_true(left_false, left_a, probe)
      first_false = _binary_first_false(right_a, right_false, probe)
      for idx in range(first, first_false):
        predicted[idx] = True
      status = "nn_middle_interval_inferred"

  if conflict and fallback_scan_conflicts:
    for idx in range(n):
      probe(idx)
    predicted = list(actual)
    status = f"{status}_fallback_scan"

  predicted_affected = {tag for tag, value in zip(tags, predicted) if value}
  return {
    "predicted_affected": predicted_affected,
    "probe_indices": set(known),
    "status": status,
    "actual_runs": _line_runs(actual),
    "actual_affected_count": sum(1 for value in actual if value),
    "line_tag_count": n,
  }


def _simulate_cve(
  *,
  cve_id: str,
  repo_name: str,
  affected_versions: list[str],
  release_lines: dict[str, list[str]],
  sentinel_count: int,
  active_policy: str,
  fallback_scan_conflicts: bool,
) -> dict[str, Any]:
  release_tags = _flatten_lines(release_lines)
  mapped_gt, unmapped_gt = map_gt_tags_to_repo_tags(sorted(str(t) for t in affected_versions), release_tags, mode="loose")
  affected_set = set(mapped_gt)
  predicted_set: set[str] = set()
  probe_tags: set[str] = set()
  line_records: dict[str, Any] = {}
  status_counter: Counter[str] = Counter()
  line_count = len(release_lines)
  active_line_count = 0
  affected_line_count = 0
  skipped_affected_lines = 0

  for line, tags in release_lines.items():
    line_affected = any(tag in affected_set for tag in tags)
    if line_affected:
      affected_line_count += 1
    if active_policy == "all_lines":
      active = True
    elif active_policy == "oracle_affected_lines":
      active = line_affected
    else:
      raise ValueError(f"unknown active_policy: {active_policy}")

    if not active:
      if line_affected:
        skipped_affected_lines += 1
      status_counter["skipped_line"] += 1
      line_records[line] = {
        "active": False,
        "line_family": line_family_key(repo_name, line),
        "line_tag_count": len(tags),
        "actual_affected_count": sum(1 for tag in tags if tag in affected_set),
        "probe_count": 0,
        "status": "skipped_line",
      }
      continue

    active_line_count += 1
    sim = _simulate_active_line(
      tags,
      affected_set,
      sentinel_count=sentinel_count,
      fallback_scan_conflicts=fallback_scan_conflicts,
    )
    predicted_set.update(sim["predicted_affected"])
    for idx in sim["probe_indices"]:
      probe_tags.add(tags[idx])
    status_counter[str(sim["status"])] += 1
    line_records[line] = {
      "active": True,
      "line_family": line_family_key(repo_name, line),
      "line_tag_count": len(tags),
      "actual_affected_count": sim["actual_affected_count"],
      "actual_runs": sim["actual_runs"],
      "probe_count": len(sim["probe_indices"]),
      "probe_tags": [tags[idx] for idx in sorted(sim["probe_indices"])],
      "predicted_affected_count": len(sim["predicted_affected"]),
      "status": sim["status"],
    }

  release_set = set(release_tags)
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
    "sentinel_count": sentinel_count,
    "active_policy": active_policy,
    "fallback_scan_conflicts": fallback_scan_conflicts,
    "release_tag_count": len(release_tags),
    "line_count": line_count,
    "active_line_count": active_line_count,
    "affected_line_count": affected_line_count,
    "skipped_affected_lines": skipped_affected_lines,
    "mapped_gt_count": len(mapped_gt),
    "unmapped_gt_count": len(unmapped_gt),
    "probe_count": len(probe_tags),
    "predicted_count": len(predicted_set),
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
    "unmapped_gt_tags": unmapped_gt,
    "status_counts": dict(status_counter),
    "line_records": line_records,
  }


def _percentile(values: list[float], pct: float) -> float:
  if not values:
    return 0.0
  sorted_values = sorted(values)
  idx = round((len(sorted_values) - 1) * pct)
  return float(sorted_values[idx])


def _summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
  if not rows:
    return {}
  probe_values = [float(row["probe_count"]) for row in rows]
  active_line_values = [float(row["active_line_count"]) for row in rows]
  line_values = [float(row["line_count"]) for row in rows]
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
    "line_avg": round(statistics.mean(line_values), 2),
    "active_line_avg": round(statistics.mean(active_line_values), 2),
    "mapped_gt_avg": round(statistics.mean(float(row["mapped_gt_count"]) for row in rows), 2),
    "predicted_avg": round(statistics.mean(float(row["predicted_count"]) for row in rows), 2),
    "exact_match_cves": sum(1 for row in rows if row["exact_match"]),
    "full_mapped_recall_cves": sum(1 for row in rows if row["full_mapped_recall"]),
    "has_fp_cves": sum(1 for row in rows if row["has_fp"]),
    "has_fn_cves": sum(1 for row in rows if row["has_fn"]),
    "unmapped_cves": sum(1 for row in rows if row["unmapped_gt_count"] > 0),
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
    key = f"{row['active_policy']}|sentinel={row['sentinel_count']}"
    grouped[key].append(row)

  overall = {
    key: _summarize_rows(vals)
    for key, vals in sorted(grouped.items())
  }

  by_repo: dict[str, dict[str, Any]] = {}
  for key, vals in sorted(grouped.items()):
    repo_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in vals:
      repo_groups[row["repo"]].append(row)
    by_repo[key] = {
      repo: _summarize_rows(repo_rows)
      for repo, repo_rows in sorted(repo_groups.items())
    }

  worst: dict[str, list[dict[str, Any]]] = {}
  for key, vals in sorted(grouped.items()):
    worst[key] = [
      {
        "repo": row["repo"],
        "cve_id": row["cve_id"],
        "probe_count": row["probe_count"],
        "line_count": row["line_count"],
        "active_line_count": row["active_line_count"],
        "mapped_gt_count": row["mapped_gt_count"],
        "fp": row["fp"],
        "fn": row["fn"],
        "precision": round(float(row["precision"]), 6),
        "recall": round(float(row["recall"]), 6),
        "status_counts": row["status_counts"],
      }
      for row in sorted(vals, key=lambda item: (-int(item["probe_count"]), -int(item["fn"]), -int(item["fp"])))[:20]
    ]

  return {
    "overall": overall,
    "by_repo": by_repo,
    "worst_cases": worst,
  }


def _write_json(path: Path, obj: Any) -> None:
  path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
  with path.open("w", encoding="utf-8") as fp:
    for row in rows:
      light = {key: value for key, value in row.items() if key != "line_records"}
      fp.write(json.dumps(light, ensure_ascii=False) + "\n")


def _write_report(path: Path, summary: dict[str, Any]) -> None:
  lines = [
    "# Step3 GT Scheduler Simulator",
    "",
    "This report simulates line-aware ASBS-first scheduling with ground-truth affected versions.",
    "It does not call the agent and does not inspect fix commits.",
    "",
    "Policies:",
    "- `all_lines`: every release line is active. This is runnable but may over-estimate cost.",
    "- `oracle_affected_lines`: only GT-affected lines are active. This is an unrealizable lower-bound for a future line scheduler.",
    "",
    "## Overall",
    "",
    "| policy | cves | probe avg | probe median | p90 | p95 | max | exact CVEs | recall CVEs | FP CVEs | FN CVEs | micro P | micro R | micro F1 |",
    "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
  ]
  for key, row in summary["overall"].items():
    lines.append(
      f"| {key} | {row['cves']} | {row['probe_avg']} | {row['probe_median']} | "
      f"{row['probe_p90']} | {row['probe_p95']} | {row['probe_max']} | "
      f"{row['exact_match_cves']} | {row['full_mapped_recall_cves']} | "
      f"{row['has_fp_cves']} | {row['has_fn_cves']} | "
      f"{row['micro_precision']} | {row['micro_recall']} | {row['micro_f1']} |"
    )

  lines.extend(["", "## By Repo: all_lines, highest sentinel count", ""])
  all_line_keys = [key for key in summary["overall"] if key.startswith("all_lines|")]
  if all_line_keys:
    highest = sorted(all_line_keys, key=lambda key: int(key.split("sentinel=")[1]))[-1]
    lines.extend([
      f"Policy: `{highest}`",
      "",
      "| repo | cves | probe avg | p95 | max | exact CVEs | micro P | micro R | micro F1 |",
      "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for repo, row in summary["by_repo"][highest].items():
      lines.append(
        f"| {repo} | {row['cves']} | {row['probe_avg']} | {row['probe_p95']} | "
        f"{row['probe_max']} | {row['exact_match_cves']} | {row['micro_precision']} | "
        f"{row['micro_recall']} | {row['micro_f1']} |"
      )

  lines.extend(["", "## Worst Probe Cases", ""])
  first_key = sorted(summary["worst_cases"])[0] if summary["worst_cases"] else ""
  for key in sorted(summary["worst_cases"]):
    if key != first_key and not key.startswith("all_lines|"):
      continue
    lines.append(f"### {key}")
    for row in summary["worst_cases"][key][:10]:
      lines.append(
        f"- `{row['repo']}` `{row['cve_id']}`: probes `{row['probe_count']}`, "
        f"active lines `{row['active_line_count']}/{row['line_count']}`, "
        f"FP `{row['fp']}`, FN `{row['fn']}`, R `{row['recall']}`"
      )
    lines.append("")

  path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _parse_sentinel_counts(value: str) -> list[int]:
  counts: list[int] = []
  for part in value.split(","):
    part = part.strip()
    if not part:
      continue
    counts.append(max(0, int(part)))
  return sorted(set(counts))


def main(argv: list[str] | None = None) -> int:
  parser = argparse.ArgumentParser(description="Simulate Step3 ASBS-first line scheduler using GT affected versions.")
  parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
  parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
  parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
  parser.add_argument("--sentinel-counts", default="0,1,2,3")
  parser.add_argument(
    "--active-policies",
    default="all_lines,oracle_affected_lines",
    help="Comma-separated policies: all_lines, oracle_affected_lines",
  )
  parser.add_argument(
    "--no-fallback-scan-conflicts",
    action="store_true",
    help="Do not scan conflicted A...A lines. Useful for measuring strict low-cost behavior.",
  )
  args = parser.parse_args(argv)

  dataset = _load_dataset(args.dataset)
  sentinel_counts = _parse_sentinel_counts(args.sentinel_counts)
  active_policies = [part.strip() for part in args.active_policies.split(",") if part.strip()]
  fallback_scan_conflicts = not args.no_fallback_scan_conflicts

  release_cache: dict[str, dict[str, list[str]]] = {}
  rows: list[dict[str, Any]] = []
  for cve_id, rec in sorted(dataset.items()):
    repo_name = str(rec.get("repo") or "").strip()
    if not repo_name:
      continue
    if repo_name not in release_cache:
      release_cache[repo_name] = _release_lines(repo_name, args.repo_root / repo_name)
    for sentinel_count in sentinel_counts:
      for active_policy in active_policies:
        rows.append(_simulate_cve(
          cve_id=cve_id,
          repo_name=repo_name,
          affected_versions=list(rec.get("affected_version") or []),
          release_lines=release_cache[repo_name],
          sentinel_count=sentinel_count,
          active_policy=active_policy,
          fallback_scan_conflicts=fallback_scan_conflicts,
        ))

  args.out_dir.mkdir(parents=True, exist_ok=True)
  summary = _summarize(rows)
  metadata = {
    "dataset": str(args.dataset),
    "repo_root": str(args.repo_root),
    "sentinel_counts": sentinel_counts,
    "active_policies": active_policies,
    "fallback_scan_conflicts": fallback_scan_conflicts,
    "total_simulation_rows": len(rows),
  }
  _write_json(args.out_dir / "summary.json", {"metadata": metadata, **summary})
  _write_jsonl(args.out_dir / "per_cve.jsonl", rows)
  _write_report(args.out_dir / "report.md", summary)
  print(json.dumps({"metadata": metadata, "overall": summary["overall"], "out_dir": str(args.out_dir)}, ensure_ascii=False, indent=2))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
