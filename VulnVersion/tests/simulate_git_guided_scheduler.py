from __future__ import annotations

import argparse
import json
import statistics
import subprocess
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
DEFAULT_OUT_DIR = ROOT / "tests" / "git_guided_scheduler_simulator"


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
    line: sort_tags_for_line(repo_name, tags, reverse=False)
    for line, tags in release_lines.items()
  }
  release_tags_ordered = [tag for tags in release_lines.values() for tag in tags]
  return {
    "repo": repo,
    "release_tags": release_tags_ordered,
    "release_tag_set": set(release_tags_ordered),
    "release_lines": release_lines,
    "tag_to_line": {
      tag: line
      for line, tags in release_lines.items()
      for tag in tags
    },
  }


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
  """Compute exact tag containment for many commits with one graph pass.

  This is equivalent to `git tag --contains <commit>` restricted to release
  tags, but avoids thousands of per-CVE Git invocations.
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


def _simulate_asbs_segment(
  tags: list[str],
  affected_set: set[str],
  *,
  sentinel_count: int,
  fallback_scan_conflicts: bool,
) -> dict[str, Any]:
  n = len(tags)
  if n == 0:
    return {"predicted_affected": set(), "probe_tags": set(), "status": "empty_segment"}

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
      status = "aa_full_segment_inferred"
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

  return {
    "predicted_affected": {tag for tag, value in zip(tags, predicted) if value},
    "probe_tags": {tags[idx] for idx in known},
    "status": status,
    "actual_runs": _line_runs(actual),
    "actual_affected_count": sum(1 for value in actual if value),
  }


def _runs_by_value(tags: list[str], fixed_tags: set[str]) -> list[dict[str, Any]]:
  if not tags:
    return []
  runs: list[dict[str, Any]] = []
  start = 0
  current = tags[0] in fixed_tags
  for idx, tag in enumerate(tags[1:], start=1):
    value = tag in fixed_tags
    if value == current:
      continue
    runs.append({"is_fix_containing": current, "tags": tags[start:idx]})
    start = idx
    current = value
  runs.append({"is_fix_containing": current, "tags": tags[start:]})
  return runs


def _simulate_fixed_segment_sentinel(
  tags: list[str],
  affected_set: set[str],
  *,
  sentinel_count: int,
) -> dict[str, Any]:
  if not tags:
    return {"predicted_affected": set(), "probe_tags": set(), "status": "empty_fixed_segment"}
  n = len(tags)
  probe_indices = {0, n - 1}
  probe_indices.update(_even_sentinels(n, sentinel_count, exclude={0, n - 1}))
  probe_tags = {tags[idx] for idx in sorted(probe_indices)}
  hit = any(tag in affected_set for tag in probe_tags)
  return {
    "predicted_affected": set(),
    "probe_tags": probe_tags,
    "status": "fixed_segment_probe_hit" if hit else "fixed_segment_probe_clear",
    "probe_hit": hit,
    "actual_affected_count": sum(1 for tag in tags if tag in affected_set),
  }


def _simulate_cve(
  *,
  cve_id: str,
  repo_name: str,
  affected_versions: list[str],
  fixing_commits: list[str],
  release_lines: dict[str, list[str]],
  release_tags: list[str],
  fix_containing_tags: set[str],
  sentinel_count: int,
  fixed_segment_sentinels: int,
  policy: str,
  fallback_scan_conflicts: bool,
) -> dict[str, Any]:
  mapped_gt, unmapped_gt = map_gt_tags_to_repo_tags(sorted(str(t) for t in affected_versions), release_tags, mode="loose")
  affected_set = set(mapped_gt)
  release_set = set(release_tags)
  predicted_set: set[str] = set()
  probe_tags: set[str] = set()
  status_counter: Counter[str] = Counter()
  line_records: dict[str, Any] = {}
  active_line_count = 0
  affected_line_count = 0
  fixed_segment_missed_affected_tags: set[str] = set()
  hard_filter_missed_gt: set[str] = set()

  for line, tags in release_lines.items():
    line_affected = any(tag in affected_set for tag in tags)
    if line_affected:
      affected_line_count += 1
    segments = _runs_by_value(tags, fix_containing_tags)
    line_probe_tags: set[str] = set()
    line_predicted: set[str] = set()
    line_statuses: Counter[str] = Counter()

    if policy == "all_lines_asbs":
      active_line_count += 1
      sim = _simulate_asbs_segment(
        tags,
        affected_set,
        sentinel_count=sentinel_count,
        fallback_scan_conflicts=fallback_scan_conflicts,
      )
      line_predicted.update(sim["predicted_affected"])
      line_probe_tags.update(sim["probe_tags"])
      line_statuses[str(sim["status"])] += 1

    elif policy == "hard_no_fix_filter":
      candidate_tags = [tag for tag in tags if tag not in fix_containing_tags]
      missed = {tag for tag in tags if tag in fix_containing_tags and tag in affected_set}
      hard_filter_missed_gt.update(missed)
      if candidate_tags:
        active_line_count += 1
        sim = _simulate_asbs_segment(
          candidate_tags,
          affected_set,
          sentinel_count=sentinel_count,
          fallback_scan_conflicts=fallback_scan_conflicts,
        )
        line_predicted.update(sim["predicted_affected"])
        line_probe_tags.update(sim["probe_tags"])
        line_statuses[str(sim["status"])] += 1
      else:
        line_statuses["hard_filter_skipped_line"] += 1

    elif policy == "git_guided_soft":
      any_active = False
      for segment in segments:
        seg_tags = segment["tags"]
        if not segment["is_fix_containing"]:
          any_active = True
          sim = _simulate_asbs_segment(
            seg_tags,
            affected_set,
            sentinel_count=sentinel_count,
            fallback_scan_conflicts=fallback_scan_conflicts,
          )
          line_predicted.update(sim["predicted_affected"])
          line_probe_tags.update(sim["probe_tags"])
          line_statuses[str(sim["status"])] += 1
          continue

        sentinel = _simulate_fixed_segment_sentinel(
          seg_tags,
          affected_set,
          sentinel_count=fixed_segment_sentinels,
        )
        line_probe_tags.update(sentinel["probe_tags"])
        line_statuses[str(sentinel["status"])] += 1
        if sentinel["probe_hit"]:
          any_active = True
          sim = _simulate_asbs_segment(
            seg_tags,
            affected_set,
            sentinel_count=sentinel_count,
            fallback_scan_conflicts=fallback_scan_conflicts,
          )
          line_predicted.update(sim["predicted_affected"])
          line_probe_tags.update(sim["probe_tags"])
          line_statuses[f"fallback_{sim['status']}"] += 1
        else:
          missed = {tag for tag in seg_tags if tag in affected_set}
          fixed_segment_missed_affected_tags.update(missed)

      if any_active or line_probe_tags:
        active_line_count += 1
    else:
      raise ValueError(f"unknown policy: {policy}")

    predicted_set.update(line_predicted)
    probe_tags.update(line_probe_tags)
    status_counter.update(line_statuses)
    line_records[line] = {
      "line_family": line_family_key(repo_name, line),
      "line_tag_count": len(tags),
      "actual_affected_count": sum(1 for tag in tags if tag in affected_set),
      "fix_containing_count": sum(1 for tag in tags if tag in fix_containing_tags),
      "probe_count": len(line_probe_tags),
      "predicted_affected_count": len(line_predicted),
      "statuses": dict(line_statuses),
    }

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
    "sentinel_count": sentinel_count,
    "fixed_segment_sentinels": fixed_segment_sentinels,
    "fixing_commit_count": len(fixing_commits),
    "release_tag_count": len(release_tags),
    "line_count": len(release_lines),
    "active_line_count": active_line_count,
    "affected_line_count": affected_line_count,
    "mapped_gt_count": len(mapped_gt),
    "unmapped_gt_count": len(unmapped_gt),
    "fix_containing_tag_count": len(fix_containing_tags),
    "probe_count": len(probe_tags),
    "predicted_count": len(predicted_set),
    "fixed_segment_missed_gt_count": len(fixed_segment_missed_affected_tags),
    "hard_filter_missed_gt_count": len(hard_filter_missed_gt),
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
    "active_line_avg": round(statistics.mean(active_line_values), 2),
    "exact_match_cves": sum(1 for row in rows if row["exact_match"]),
    "full_mapped_recall_cves": sum(1 for row in rows if row["full_mapped_recall"]),
    "has_fp_cves": sum(1 for row in rows if row["has_fp"]),
    "has_fn_cves": sum(1 for row in rows if row["has_fn"]),
    "unmapped_cves": sum(1 for row in rows if row["unmapped_gt_count"] > 0),
    "fixed_segment_missed_gt_cves": sum(1 for row in rows if row["fixed_segment_missed_gt_count"] > 0),
    "hard_filter_missed_gt_cves": sum(1 for row in rows if row["hard_filter_missed_gt_count"] > 0),
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
    key = f"{row['policy']}|s={row['sentinel_count']}|fs={row['fixed_segment_sentinels']}"
    grouped[key].append(row)

  overall = {key: _summarize_rows(vals) for key, vals in sorted(grouped.items())}

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
        "active_line_count": row["active_line_count"],
        "mapped_gt_count": row["mapped_gt_count"],
        "fixed_segment_missed_gt_count": row["fixed_segment_missed_gt_count"],
        "hard_filter_missed_gt_count": row["hard_filter_missed_gt_count"],
        "fp": row["fp"],
        "fn": row["fn"],
        "precision": round(float(row["precision"]), 6),
        "recall": round(float(row["recall"]), 6),
        "status_counts": row["status_counts"],
      }
      for row in sorted(vals, key=lambda item: (-int(item["fn"]), -int(item["probe_count"]), -int(item["fp"])))[:30]
    ]

  return {"overall": overall, "by_repo": by_repo, "worst_cases": worst}


def _write_json(path: Path, obj: Any) -> None:
  path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
  with path.open("w", encoding="utf-8") as fp:
    for row in rows:
      light = {key: value for key, value in row.items() if key != "line_records"}
      fp.write(json.dumps(light, ensure_ascii=False) + "\n")


def _write_report(path: Path, summary: dict[str, Any]) -> None:
  lines = [
    "# Git-Guided Step3 Scheduler Simulator",
    "",
    "This GT simulator compares hard fix-containment pruning with a safer paper-guided soft strategy.",
    "",
    "Policies:",
    "- `all_lines_asbs`: current ASBS-first cost/accuracy reference.",
    "- `hard_no_fix_filter`: only keep tags that do not contain any seed fix commit. This is unsafe and is included as a negative control.",
    "- `git_guided_soft`: split each line into fix-containing and no-fix segments. No-fix segments run ASBS. Fix-containing segments are not deleted; they receive sentinel probes and fall back to ASBS if a sentinel is affected.",
    "",
    "## Overall",
    "",
    "| policy | cves | probe avg | p95 | max | exact CVEs | recall CVEs | FN CVEs | hard-filter-miss CVEs | fixed-segment-miss CVEs | micro P | micro R | micro F1 |",
    "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
  ]
  for key, row in summary["overall"].items():
    lines.append(
      f"| {key} | {row['cves']} | {row['probe_avg']} | {row['probe_p95']} | {row['probe_max']} | "
      f"{row['exact_match_cves']} | {row['full_mapped_recall_cves']} | {row['has_fn_cves']} | "
      f"{row['hard_filter_missed_gt_cves']} | {row['fixed_segment_missed_gt_cves']} | "
      f"{row['micro_precision']} | {row['micro_recall']} | {row['micro_f1']} |"
    )

  lines.extend(["", "## By Repo", ""])
  for key in sorted(summary["by_repo"]):
    lines.extend([
      f"### {key}",
      "",
      "| repo | cves | probe avg | p95 | max | exact CVEs | FN CVEs | micro P | micro R | micro F1 |",
      "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for repo, row in summary["by_repo"][key].items():
      lines.append(
        f"| {repo} | {row['cves']} | {row['probe_avg']} | {row['probe_p95']} | {row['probe_max']} | "
        f"{row['exact_match_cves']} | {row['has_fn_cves']} | {row['micro_precision']} | "
        f"{row['micro_recall']} | {row['micro_f1']} |"
      )
    lines.append("")

  lines.extend(["", "## Worst FN Cases", ""])
  for key, vals in summary["worst_cases"].items():
    lines.append(f"### {key}")
    for row in vals[:10]:
      lines.append(
        f"- `{row['repo']}` `{row['cve_id']}`: probes `{row['probe_count']}`, "
        f"FN `{row['fn']}`, FP `{row['fp']}`, fixed-segment missed GT `{row['fixed_segment_missed_gt_count']}`, "
        f"hard-filter missed GT `{row['hard_filter_missed_gt_count']}`, R `{row['recall']}`"
      )
    lines.append("")

  path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _parse_int_list(value: str) -> list[int]:
  nums: list[int] = []
  for part in value.split(","):
    part = part.strip()
    if part:
      nums.append(max(0, int(part)))
  return sorted(set(nums))


def main(argv: list[str] | None = None) -> int:
  parser = argparse.ArgumentParser(description="Simulate Git-guided Step3 tag scheduling using GT affected versions.")
  parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
  parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
  parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
  parser.add_argument("--sentinel-counts", default="3")
  parser.add_argument("--fixed-segment-sentinels", default="0,1,2,3")
  parser.add_argument(
    "--policies",
    default="all_lines_asbs,hard_no_fix_filter,git_guided_soft",
    help="Comma-separated policies.",
  )
  parser.add_argument("--no-fallback-scan-conflicts", action="store_true")
  args = parser.parse_args(argv)

  dataset = _load_dataset(args.dataset)
  sentinel_counts = _parse_int_list(args.sentinel_counts)
  fixed_segment_sentinels = _parse_int_list(args.fixed_segment_sentinels)
  policies = [part.strip() for part in args.policies.split(",") if part.strip()]
  fallback_scan_conflicts = not args.no_fallback_scan_conflicts

  by_repo_records: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
  for cve_id, rec in sorted(dataset.items()):
    repo_name = str(rec.get("repo") or "").strip()
    if repo_name:
      by_repo_records[repo_name].append((cve_id, rec))

  contexts: dict[str, dict[str, Any]] = {}
  contains_by_repo: dict[str, dict[str, dict[str, Any]]] = {}
  for repo_name, records in sorted(by_repo_records.items()):
    context = _release_context(repo_name, args.repo_root / repo_name)
    contexts[repo_name] = context
    target_commits: set[str] = set()
    for _, rec in records:
      target_commits.update(_flatten_fixing_commits(rec.get("fixing_commits") or rec.get("fixing_commit")))
    contains_by_repo[repo_name] = _precompute_tags_containing_batch(
      repo=context["repo"],
      release_tags=context["release_tags"],
      target_commits=target_commits,
    )

  rows: list[dict[str, Any]] = []
  commit_errors: dict[str, dict[str, str]] = defaultdict(dict)
  for repo_name, records in sorted(by_repo_records.items()):
    context = contexts[repo_name]
    for cve_id, rec in records:
      fixing_commits = _flatten_fixing_commits(rec.get("fixing_commits") or rec.get("fixing_commit"))
      fix_containing_tags: set[str] = set()
      for commit in fixing_commits:
        result = contains_by_repo[repo_name].get(commit, {"ok": False, "tags": [], "error": "missing_precomputed_commit"})
        if not result["ok"]:
          commit_errors[repo_name][commit] = result["error"]
          continue
        fix_containing_tags.update(result["tags"])
      for sentinel_count in sentinel_counts:
        for fixed_sentinels in fixed_segment_sentinels:
          for policy in policies:
            if policy != "git_guided_soft" and fixed_sentinels != fixed_segment_sentinels[0]:
              continue
            rows.append(_simulate_cve(
              cve_id=cve_id,
              repo_name=repo_name,
              affected_versions=list(rec.get("affected_version") or []),
              fixing_commits=fixing_commits,
              release_lines=context["release_lines"],
              release_tags=context["release_tags"],
              fix_containing_tags=fix_containing_tags,
              sentinel_count=sentinel_count,
              fixed_segment_sentinels=fixed_sentinels,
              policy=policy,
              fallback_scan_conflicts=fallback_scan_conflicts,
            ))

  args.out_dir.mkdir(parents=True, exist_ok=True)
  summary = _summarize(rows)
  metadata = {
    "dataset": str(args.dataset),
    "repo_root": str(args.repo_root),
    "sentinel_counts": sentinel_counts,
    "fixed_segment_sentinels": fixed_segment_sentinels,
    "policies": policies,
    "fallback_scan_conflicts": fallback_scan_conflicts,
    "total_simulation_rows": len(rows),
    "commit_error_count": sum(len(v) for v in commit_errors.values()),
  }
  _write_json(args.out_dir / "summary.json", {"metadata": metadata, **summary})
  _write_json(args.out_dir / "commit_errors.json", commit_errors)
  _write_jsonl(args.out_dir / "per_cve.jsonl", rows)
  _write_report(args.out_dir / "report.md", summary)
  print(json.dumps({"metadata": metadata, "overall": summary["overall"], "out_dir": str(args.out_dir)}, ensure_ascii=False, indent=2))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
