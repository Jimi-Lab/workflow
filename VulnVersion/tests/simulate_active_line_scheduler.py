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
  parse_version,
  sort_tags_for_line,
)


DEFAULT_DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
DEFAULT_REPO_ROOT = ROOT / "repo"
DEFAULT_OUT_DIR = ROOT / "tests" / "active_line_scheduler_simulator"


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


def _git_base_cmd(repo_path: Path) -> list[str]:
  repo_str = str(repo_path.resolve())
  return ["git", "-c", f"safe.directory={repo_str}", "-C", repo_str]


def _line_version(repo_name: str, line: str) -> tuple[Any, ...]:
  if repo_name == "FFmpeg":
    return parse_version(repo_name, f"n{line}")
  if repo_name == "qemu":
    return parse_version(repo_name, f"v{line}.0")
  if repo_name == "wireshark":
    return parse_version(repo_name, f"v{line}.0")
  if repo_name == "openssl":
    import re

    nums = [int(x) for x in re.findall(r"\d+", line)]
    if nums:
      while len(nums) < 4:
        nums.append(0)
      prefix = 2 if line.startswith("fips-") else 1 if line.startswith("engine-") else 0
      return (prefix, *nums)
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
  family_to_lines: dict[str, list[str]] = defaultdict(list)
  for line in release_lines:
    family_to_lines[line_family_key(repo_name, line)].append(line)
  ordered_by_family = {
    family: sorted(lines, key=lambda item: _line_version(repo_name, item), reverse=True)
    for family, lines in family_to_lines.items()
  }
  release_tags_ordered = [tag for tags in release_lines.values() for tag in tags]
  return {
    "repo": repo,
    "release_tags": release_tags_ordered,
    "release_lines": release_lines,
    "ordered_by_family": ordered_by_family,
  }


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
    proc = subprocess.Popen(
      [*_git_base_cmd(repo.repo_path), "rev-list", "--topo-order", "--parents", *tips],
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


def _batch_path_exists(repo: GitRepo, queries: set[tuple[str, str]]) -> dict[tuple[str, str], bool]:
  if not queries:
    return {}
  ordered = sorted(queries)
  payload = "".join(f"{tag}:{path}\n" for tag, path in ordered)
  proc = subprocess.Popen(
    [*_git_base_cmd(repo.repo_path), "cat-file", "--batch-check"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    encoding="utf-8",
    errors="replace",
  )
  stdout, _ = proc.communicate(payload)
  out: dict[tuple[str, str], bool] = {}
  for query, raw_line in zip(ordered, stdout.splitlines()):
    line = raw_line.strip()
    out[query] = not line.endswith(" missing")
  for query in ordered[len(out):]:
    out[query] = False
  return out


def _changed_files_for_commits(repo: GitRepo, commits: list[str], cache: dict[str, list[str]]) -> list[str]:
  files: list[str] = []
  seen: set[str] = set()
  for commit in commits:
    if commit not in cache:
      try:
        cache[commit] = repo.changed_files(commit)
      except Exception:
        cache[commit] = []
    for path in cache[commit]:
      if path and path not in seen:
        seen.add(path)
        files.append(path)
  return files


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
    return {"predicted_affected": set(), "probe_tags": set(), "status": "empty_fixed_segment", "probe_hit": False}
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
  }


def _simulate_git_guided_line(
  tags: list[str],
  affected_set: set[str],
  fix_containing_tags: set[str],
  *,
  sentinel_count: int,
  fixed_segment_sentinels: int,
  fallback_scan_conflicts: bool,
) -> dict[str, Any]:
  predicted: set[str] = set()
  probes: set[str] = set()
  statuses: Counter[str] = Counter()
  for segment in _runs_by_value(tags, fix_containing_tags):
    seg_tags = segment["tags"]
    if not segment["is_fix_containing"]:
      sim = _simulate_asbs_segment(
        seg_tags,
        affected_set,
        sentinel_count=sentinel_count,
        fallback_scan_conflicts=fallback_scan_conflicts,
      )
      predicted.update(sim["predicted_affected"])
      probes.update(sim["probe_tags"])
      statuses[str(sim["status"])] += 1
      continue
    sentinel = _simulate_fixed_segment_sentinel(
      seg_tags,
      affected_set,
      sentinel_count=fixed_segment_sentinels,
    )
    probes.update(sentinel["probe_tags"])
    statuses[str(sentinel["status"])] += 1
    if sentinel["probe_hit"]:
      sim = _simulate_asbs_segment(
        seg_tags,
        affected_set,
        sentinel_count=sentinel_count,
        fallback_scan_conflicts=fallback_scan_conflicts,
      )
      predicted.update(sim["predicted_affected"])
      probes.update(sim["probe_tags"])
      statuses[f"fallback_{sim['status']}"] += 1
  return {"predicted_affected": predicted, "probe_tags": probes, "statuses": statuses}


def _neighbors(lines: list[str], seeds: set[str], radius: int) -> set[str]:
  if radius <= 0 or not seeds:
    return set(seeds)
  out = set(seeds)
  idx_by_line = {line: idx for idx, line in enumerate(lines)}
  for line in seeds:
    idx = idx_by_line.get(line)
    if idx is None:
      continue
    for delta in range(1, radius + 1):
      if idx - delta >= 0:
        out.add(lines[idx - delta])
      if idx + delta < len(lines):
        out.add(lines[idx + delta])
  return out


def _span(lines: list[str], seeds: set[str]) -> set[str]:
  idxs = [idx for idx, line in enumerate(lines) if line in seeds]
  if not idxs:
    return set()
  return set(lines[min(idxs): max(idxs) + 1])


def _active_lines_for_policy(
  *,
  policy: str,
  release_lines: dict[str, list[str]],
  ordered_by_family: dict[str, list[str]],
  fix_containing_tags: set[str],
  file_endpoint_lines: set[str],
) -> set[str]:
  all_lines = set(release_lines)
  no_fix_lines = {
    line for line, tags in release_lines.items()
    if any(tag not in fix_containing_tags for tag in tags)
  }

  if policy == "all_lines_soft":
    return all_lines
  if policy == "no_fix_lines_only":
    return no_fix_lines
  if policy == "file_exists_endpoints":
    return set(file_endpoint_lines)
  if policy == "file_exists_neighbor1":
    out: set[str] = set()
    for _, lines in ordered_by_family.items():
      out.update(_neighbors(lines, set(file_endpoint_lines) & set(lines), 1))
    return out
  if policy == "file_exists_span":
    out = set()
    for _, lines in ordered_by_family.items():
      out.update(_span(lines, set(file_endpoint_lines) & set(lines)))
    return out
  if policy == "hybrid_fix_file_neighbor":
    out: set[str] = set()
    for _, lines in ordered_by_family.items():
      seeds = (set(file_endpoint_lines) & set(lines) & no_fix_lines)
      expanded = _neighbors(lines, seeds, 1)
      out.update(expanded & no_fix_lines)
    return out
  raise ValueError(f"unknown policy: {policy}")


def _simulate_cve(
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
  fallback_scan_conflicts: bool,
) -> dict[str, Any]:
  mapped_gt, unmapped_gt = map_gt_tags_to_repo_tags(sorted(str(t) for t in affected_versions), release_tags, mode="loose")
  affected_set = set(mapped_gt)
  release_set = set(release_tags)
  active_lines = _active_lines_for_policy(
    policy=policy,
    release_lines=release_lines,
    ordered_by_family=ordered_by_family,
    fix_containing_tags=fix_containing_tags,
    file_endpoint_lines=file_endpoint_lines,
  )
  predicted_set: set[str] = set()
  probe_tags: set[str] = set()
  status_counter: Counter[str] = Counter()
  affected_lines = {
    line for line, tags in release_lines.items()
    if any(tag in affected_set for tag in tags)
  }

  for line, tags in release_lines.items():
    if line not in active_lines:
      status_counter["skipped_line"] += 1
      continue
    sim = _simulate_git_guided_line(
      tags,
      affected_set,
      fix_containing_tags,
      sentinel_count=sentinel_count,
      fixed_segment_sentinels=fixed_segment_sentinels,
      fallback_scan_conflicts=fallback_scan_conflicts,
    )
    predicted_set.update(sim["predicted_affected"])
    probe_tags.update(sim["probe_tags"])
    status_counter.update(sim["statuses"])

  tp = len(predicted_set & affected_set)
  fp = len(predicted_set - affected_set)
  fn = len(affected_set - predicted_set)
  tn = len(release_set - predicted_set - affected_set)
  precision = tp / (tp + fp) if (tp + fp) else (1.0 if not affected_set else 0.0)
  recall = tp / (tp + fn) if (tp + fn) else 1.0
  f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
  skipped_affected_lines = len(affected_lines - active_lines)

  return {
    "cve_id": cve_id,
    "repo": repo_name,
    "policy": policy,
    "release_tag_count": len(release_tags),
    "line_count": len(release_lines),
    "active_line_count": len(active_lines),
    "affected_line_count": len(affected_lines),
    "skipped_affected_lines": skipped_affected_lines,
    "file_endpoint_line_count": len(file_endpoint_lines),
    "fix_containing_tag_count": len(fix_containing_tags),
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
    "status_counts": dict(status_counter),
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
    "active_line_avg": round(statistics.mean(active_line_values), 2),
    "skipped_affected_line_avg": round(statistics.mean(skipped_affected_values), 2),
    "exact_match_cves": sum(1 for row in rows if row["exact_match"]),
    "full_mapped_recall_cves": sum(1 for row in rows if row["full_mapped_recall"]),
    "has_fp_cves": sum(1 for row in rows if row["has_fp"]),
    "has_fn_cves": sum(1 for row in rows if row["has_fn"]),
    "unmapped_cves": sum(1 for row in rows if row["unmapped_gt_count"] > 0),
    "skipped_affected_line_cves": sum(1 for row in rows if row["skipped_affected_lines"] > 0),
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
        "line_count": row["line_count"],
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
    "# Active-Line Scheduler GT Simulator",
    "",
    "All policies use git-guided soft ASBS inside active lines. The only difference is active-line selection.",
    "",
    "| policy | cves | avg probes | p95 | avg active lines | avg skipped affected lines | exact CVEs | FN CVEs | skipped-affected-line CVEs | micro P | micro R | micro F1 |",
    "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
  ]
  for key, row in summary["overall"].items():
    lines.append(
      f"| {key} | {row['cves']} | {row['probe_avg']} | {row['probe_p95']} | "
      f"{row['active_line_avg']} | {row['skipped_affected_line_avg']} | "
      f"{row['exact_match_cves']} | {row['has_fn_cves']} | {row['skipped_affected_line_cves']} | "
      f"{row['micro_precision']} | {row['micro_recall']} | {row['micro_f1']} |"
    )
  lines.extend(["", "## By Repo", ""])
  for key, repos in summary["by_repo"].items():
    lines.extend([
      f"### {key}",
      "",
      "| repo | cves | avg probes | p95 | avg active lines | exact CVEs | FN CVEs | micro R | micro F1 |",
      "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for repo, row in repos.items():
      lines.append(
        f"| {repo} | {row['cves']} | {row['probe_avg']} | {row['probe_p95']} | "
        f"{row['active_line_avg']} | {row['exact_match_cves']} | {row['has_fn_cves']} | "
        f"{row['micro_recall']} | {row['micro_f1']} |"
      )
    lines.append("")
  path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
  parser = argparse.ArgumentParser(description="Simulate deterministic active-line schedulers using GT affected versions.")
  parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
  parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
  parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
  parser.add_argument("--sentinel-count", type=int, default=3)
  parser.add_argument("--fixed-segment-sentinels", type=int, default=1)
  parser.add_argument(
    "--policies",
    default="all_lines_soft,no_fix_lines_only,file_exists_endpoints,file_exists_neighbor1,file_exists_span,hybrid_fix_file_neighbor",
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
        rows.append(_simulate_cve(
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
