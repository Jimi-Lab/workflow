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
  _precompute_tags_containing_batch,
  _release_context,
  _runs_by_value,
  _simulate_asbs_segment,
  _simulate_git_guided_line,
)
from simulate_staged_expansion_scheduler import (  # noqa: E402
  _family_neighbors,
  _initial_lines_for_policy,
  _line_groups,
)
from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags  # noqa: E402


DEFAULT_DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
DEFAULT_REPO_ROOT = ROOT / "repo"
DEFAULT_OUT_DIR = ROOT / "tests" / "fix_contains_pruning_eval"


def _load_dataset(path: Path) -> dict[str, Any]:
  return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, obj: Any) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  with path.open("w", encoding="utf-8") as f:
    for row in rows:
      f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _percentile(values: list[float], pct: float) -> float:
  if not values:
    return 0.0
  ordered = sorted(values)
  idx = round((len(ordered) - 1) * pct)
  return float(ordered[idx])


def _group_dataset_by_repo(dataset: dict[str, Any]) -> dict[str, list[tuple[str, dict[str, Any]]]]:
  out: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
  for cve_id, rec in dataset.items():
    repo = str((rec or {}).get("repo") or "").strip()
    if not repo:
      continue
    out[repo].append((str(cve_id), rec or {}))
  return {repo: sorted(rows) for repo, rows in sorted(out.items())}


def _fix_tags_for_commits(
  *,
  commits: list[str],
  commit_contains: dict[str, dict[str, Any]],
  mode: str,
) -> tuple[set[str], dict[str, Any]]:
  """Resolve release tags containing fix commits.

  mode="any" matches the current Step3 convention and the single-fix case:
  a tag is fixed if it contains at least one listed fix commit.

  mode="all" is a conservative multi-commit reference:
  a tag is fixed only if it contains every resolvable fix commit.
  """

  ok_sets: list[set[str]] = []
  errors: dict[str, str] = {}
  for commit in commits:
    result = commit_contains.get(commit, {"ok": False, "tags": [], "error": "missing_contains_result"})
    if result.get("ok"):
      ok_sets.append(set(str(t) for t in result.get("tags", [])))
    else:
      errors[commit] = str(result.get("error") or "unknown_error")

  if not ok_sets:
    return set(), {"mode": mode, "ok_commit_count": 0, "error_count": len(errors), "errors": errors}
  if mode == "any":
    tags = set().union(*ok_sets)
  elif mode == "all":
    tags = set(ok_sets[0])
    for s in ok_sets[1:]:
      tags &= s
  else:
    raise ValueError(f"unknown contains mode: {mode}")
  return tags, {
    "mode": mode,
    "ok_commit_count": len(ok_sets),
    "error_count": len(errors),
    "errors": errors,
  }


def _simulate_git_guided_line_hard_prune(
  tags: list[str],
  affected_set: set[str],
  fix_containing_tags: set[str],
  *,
  sentinel_count: int,
  fallback_scan_conflicts: bool,
) -> dict[str, Any]:
  """Simulate the proposed hard-prune idea for one release line.

  Fix-containing segments are treated as definitely NOT_AFFECTED and produce
  zero agent probes. Non-fix segments still use the existing ASBS simulator.
  """

  predicted: set[str] = set()
  probes: set[str] = set()
  hard_pruned_tags: set[str] = set()
  statuses: Counter[str] = Counter()

  for segment in _runs_by_value(tags, fix_containing_tags):
    seg_tags = list(segment["tags"])
    if segment["is_fix_containing"]:
      hard_pruned_tags.update(seg_tags)
      statuses["fixed_segment_hard_pruned"] += 1
      continue
    sim = _simulate_asbs_segment(
      seg_tags,
      affected_set,
      sentinel_count=sentinel_count,
      fallback_scan_conflicts=fallback_scan_conflicts,
    )
    predicted.update(sim["predicted_affected"])
    probes.update(sim["probe_tags"])
    statuses[str(sim["status"])] += 1

  return {
    "predicted_affected": predicted,
    "probe_tags": probes,
    "hard_pruned_tags": hard_pruned_tags,
    "statuses": statuses,
  }


def _simulate_staged_hard_prune_cve(
  *,
  cve_id: str,
  repo_name: str,
  affected_versions: list[str],
  release_lines: dict[str, list[str]],
  ordered_by_family: dict[str, list[str]],
  release_tags: list[str],
  fix_containing_tags: set[str],
  scheduler_fix_containing_tags: set[str] | None = None,
  file_endpoint_lines: set[str],
  policy: str,
  sentinel_count: int,
  expansion_radius: int,
  fallback_scan_conflicts: bool,
  commit_count: int,
  contains_mode: str,
  contains_meta: dict[str, Any],
) -> dict[str, Any]:
  mapped_gt, unmapped_gt = map_gt_tags_to_repo_tags(
    sorted(str(t) for t in affected_versions),
    release_tags,
    mode="loose",
  )
  affected_set = set(mapped_gt)
  release_set = set(release_tags)
  affected_lines = {
    line for line, tags in release_lines.items()
    if any(tag in affected_set for tag in tags)
  }

  scheduler_fix_tags = scheduler_fix_containing_tags if scheduler_fix_containing_tags is not None else fix_containing_tags
  initial_lines, fallback_mode = _initial_lines_for_policy(
    policy=policy,
    release_lines=release_lines,
    ordered_by_family=ordered_by_family,
    fix_containing_tags=scheduler_fix_tags,
    file_endpoint_lines=file_endpoint_lines,
  )

  line_to_family = _line_groups(ordered_by_family)
  queue: deque[str] = deque(sorted(initial_lines))
  visited: set[str] = set()
  predicted_set: set[str] = set()
  probe_tags: set[str] = set()
  positive_lines: set[str] = set()
  hard_pruned_tags: set[str] = set()
  status_counter: Counter[str] = Counter()
  fallback_used = False

  def run_line(line: str) -> None:
    if line in visited:
      return
    tags = release_lines.get(line, [])
    visited.add(line)
    sim = _simulate_git_guided_line_hard_prune(
      tags,
      affected_set,
      fix_containing_tags,
      sentinel_count=sentinel_count,
      fallback_scan_conflicts=fallback_scan_conflicts,
    )
    predicted = set(sim["predicted_affected"])
    probes = set(sim["probe_tags"])
    pruned = set(sim["hard_pruned_tags"])
    predicted_set.update(predicted)
    probe_tags.update(probes)
    hard_pruned_tags.update(pruned)
    status_counter.update(sim["statuses"])
    if predicted or (probes & affected_set):
      positive_lines.add(line)
      for neighbor in _family_neighbors(ordered_by_family, line_to_family, line, expansion_radius):
        if neighbor not in visited:
          queue.append(neighbor)

  while queue:
    run_line(queue.popleft())

  # Keep fallback behavior identical to the staged scheduler.
  if not positive_lines and fallback_mode in {"nohit_nofix", "nohit_all"}:
    fallback_used = True
    if fallback_mode == "nohit_nofix":
      fallback_lines = {
        line for line, tags in release_lines.items()
        if any(tag not in scheduler_fix_tags for tag in tags)
      }
    else:
      fallback_lines = set(release_lines)
    for line in sorted(fallback_lines):
      queue.append(line)
    while queue:
      run_line(queue.popleft())

  tp_tags = sorted(predicted_set & affected_set)
  fp_tags = sorted(predicted_set - affected_set)
  fn_tags = sorted(affected_set - predicted_set)
  tn = len(release_set - predicted_set - affected_set)
  tp = len(tp_tags)
  fp = len(fp_tags)
  fn = len(fn_tags)
  precision = tp / (tp + fp) if (tp + fp) else (1.0 if not affected_set else 0.0)
  recall = tp / (tp + fn) if (tp + fn) else 1.0
  f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
  hard_pruned_gt_tags = sorted(hard_pruned_tags & affected_set)
  total_fix_gt_tags = sorted(set(fix_containing_tags) & affected_set)

  return {
    "cve_id": cve_id,
    "repo": repo_name,
    "strategy": f"hard_prune_{contains_mode}",
    "policy": policy,
    "contains_mode": contains_mode,
    "commit_count": commit_count,
    "contains_ok_commit_count": int(contains_meta.get("ok_commit_count") or 0),
    "contains_error_count": int(contains_meta.get("error_count") or 0),
    "release_tag_count": len(release_tags),
    "line_count": len(release_lines),
    "seed_line_count": len(initial_lines),
    "active_line_count": len(visited),
    "positive_line_count": len(positive_lines),
    "affected_line_count": len(affected_lines),
    "skipped_affected_lines": len(affected_lines - visited),
    "file_endpoint_line_count": len(file_endpoint_lines),
    "fix_containing_tag_count": len(fix_containing_tags),
    "scheduler_fix_containing_tag_count": len(scheduler_fix_tags),
    "mapped_gt_count": len(mapped_gt),
    "unmapped_gt_count": len(unmapped_gt),
    "probe_count": len(probe_tags),
    "predicted_count": len(predicted_set),
    "hard_pruned_active_tag_count": len(hard_pruned_tags),
    "hard_pruned_gt_count": len(hard_pruned_gt_tags),
    "total_fix_containing_gt_count": len(total_fix_gt_tags),
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
    "tp_tags": tp_tags,
    "fp_tags": fp_tags,
    "fn_tags": fn_tags,
    "hard_pruned_gt_tags": hard_pruned_gt_tags,
    "total_fix_containing_gt_tags": total_fix_gt_tags,
    "unmapped_gt_tags": list(unmapped_gt),
    "status_counts": dict(status_counter),
  }


def _simulate_staged_soft_cve_with_tags(
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
  commit_count: int,
  contains_mode: str,
  contains_meta: dict[str, Any],
) -> dict[str, Any]:
  """Reproduce the current staged git-guided baseline while retaining tag sets.

  tests/simulate_staged_expansion_scheduler.py reports aggregate counts only.
  This local copy keeps the predicted/probe/FN/FP tag lists so case_diffs.json
  can report true deltas against the current strategy.
  """

  mapped_gt, unmapped_gt = map_gt_tags_to_repo_tags(
    sorted(str(t) for t in affected_versions),
    release_tags,
    mode="loose",
  )
  affected_set = set(mapped_gt)
  release_set = set(release_tags)
  affected_lines = {
    line for line, tags in release_lines.items()
    if any(tag in affected_set for tag in tags)
  }

  initial_lines, fallback_mode = _initial_lines_for_policy(
    policy=policy,
    release_lines=release_lines,
    ordered_by_family=ordered_by_family,
    fix_containing_tags=fix_containing_tags,
    file_endpoint_lines=file_endpoint_lines,
  )

  line_to_family = _line_groups(ordered_by_family)
  queue: deque[str] = deque(sorted(initial_lines))
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
      fallback_lines = {
        line for line, tags in release_lines.items()
        if any(tag not in fix_containing_tags for tag in tags)
      }
    else:
      fallback_lines = set(release_lines)
    for line in sorted(fallback_lines - visited):
      queue.append(line)
    while queue:
      run_line(queue.popleft())

  tp_tags = sorted(predicted_set & affected_set)
  fp_tags = sorted(predicted_set - affected_set)
  fn_tags = sorted(affected_set - predicted_set)
  tn = len(release_set - predicted_set - affected_set)
  tp = len(tp_tags)
  fp = len(fp_tags)
  fn = len(fn_tags)
  precision = tp / (tp + fp) if (tp + fp) else (1.0 if not affected_set else 0.0)
  recall = tp / (tp + fn) if (tp + fn) else 1.0
  f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

  return {
    "cve_id": cve_id,
    "repo": repo_name,
    "strategy": "baseline_current_any_fs1",
    "policy": policy,
    "sentinel_count": sentinel_count,
    "fixed_segment_sentinels": fixed_segment_sentinels,
    "expansion_radius": expansion_radius,
    "commit_count": commit_count,
    "contains_mode": contains_mode,
    "contains_ok_commit_count": int(contains_meta.get("ok_commit_count") or 0),
    "contains_error_count": int(contains_meta.get("error_count") or 0),
    "release_tag_count": len(release_tags),
    "line_count": len(release_lines),
    "active_line_count": len(visited),
    "affected_line_count": len(affected_lines),
    "skipped_affected_line_count": len(affected_lines - visited),
    "mapped_gt_count": len(mapped_gt),
    "unmapped_gt_count": len(unmapped_gt),
    "unmapped_gt_tags": sorted(unmapped_gt),
    "probe_count": len(probe_tags),
    "predicted_count": len(predicted_set),
    "fallback_used": fallback_used,
    "tp": tp,
    "fp": fp,
    "fn": fn,
    "tn": tn,
    "tp_tags": tp_tags,
    "fp_tags": fp_tags,
    "fn_tags": fn_tags,
    "precision": precision,
    "recall": recall,
    "f1": f1,
    "exact_match": fp == 0 and fn == 0 and len(unmapped_gt) == 0,
    "full_mapped_recall": fn == 0,
    "has_fp": fp > 0,
    "has_fn": fn > 0,
    "status_counts": dict(sorted(status_counter.items())),
    "fix_containing_tag_count": len(fix_containing_tags),
    "hard_pruned_active_tag_count": 0,
    "hard_pruned_gt_count": 0,
    "hard_pruned_gt_tags": [],
    "total_fix_containing_gt_count": len(sorted(affected_set & fix_containing_tags)),
    "total_fix_containing_gt_tags": sorted(affected_set & fix_containing_tags),
  }


def _strictly_after_first_fix_tags(
  release_lines: dict[str, list[str]],
  fix_containing_tags: set[str],
) -> tuple[set[str], set[str]]:
  """Return (first_containing_tags, later_containing_tags) per release line."""

  first_tags: set[str] = set()
  later_tags: set[str] = set()
  for tags in release_lines.values():
    indices = [idx for idx, tag in enumerate(tags) if tag in fix_containing_tags]
    if not indices:
      continue
    first_idx = min(indices)
    first_tags.add(tags[first_idx])
    for idx in indices:
      if idx > first_idx:
        later_tags.add(tags[idx])
  return first_tags, later_tags


def _metric_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
  if not rows:
    return {}
  probes = [float(r["probe_count"]) for r in rows]
  active_lines = [float(r.get("active_line_count", 0)) for r in rows]
  tp = sum(int(r["tp"]) for r in rows)
  fp = sum(int(r["fp"]) for r in rows)
  fn = sum(int(r["fn"]) for r in rows)
  tn = sum(int(r["tn"]) for r in rows)
  precision = tp / (tp + fp) if (tp + fp) else 1.0
  recall = tp / (tp + fn) if (tp + fn) else 1.0
  f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
  return {
    "cves": len(rows),
    "probe_total": int(sum(probes)),
    "probe_avg": round(sum(probes) / len(probes), 2),
    "probe_median": round(statistics.median(probes), 2),
    "probe_p90": round(_percentile(probes, 0.90), 2),
    "probe_p95": round(_percentile(probes, 0.95), 2),
    "probe_max": int(max(probes)),
    "active_line_avg": round(sum(active_lines) / len(active_lines), 2),
    "exact_match_cves": sum(1 for r in rows if r["exact_match"]),
    "full_mapped_recall_cves": sum(1 for r in rows if r["full_mapped_recall"]),
    "has_fp_cves": sum(1 for r in rows if r["has_fp"]),
    "has_fn_cves": sum(1 for r in rows if r["has_fn"]),
    "unmapped_cves": sum(1 for r in rows if int(r.get("unmapped_gt_count", 0)) > 0),
    "hard_pruned_gt_cves": sum(1 for r in rows if int(r.get("hard_pruned_gt_count", 0)) > 0),
    "hard_pruned_tag_total": sum(int(r.get("hard_pruned_active_tag_count", 0)) for r in rows),
    "hard_pruned_gt_tag_total": sum(int(r.get("hard_pruned_gt_count", 0)) for r in rows),
    "total_fix_containing_gt_cves": sum(1 for r in rows if int(r.get("total_fix_containing_gt_count", 0)) > 0),
    "total_fix_containing_gt_tag_total": sum(int(r.get("total_fix_containing_gt_count", 0)) for r in rows),
    "micro_tp": tp,
    "micro_fp": fp,
    "micro_fn": fn,
    "micro_tn": tn,
    "micro_precision": round(precision, 6),
    "micro_recall": round(recall, 6),
    "micro_f1": round(f1, 6),
  }


def _summarize(rows_by_strategy: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
  overall = {name: _metric_summary(rows) for name, rows in rows_by_strategy.items()}
  by_repo: dict[str, dict[str, Any]] = {}
  by_commit_count: dict[str, dict[str, Any]] = {}
  for name, rows in rows_by_strategy.items():
    repo_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    commit_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
      repo_groups[str(row["repo"])].append(row)
      commit_groups["single_commit" if int(row.get("commit_count", 0)) <= 1 else "multi_commit"].append(row)
    by_repo[name] = {repo: _metric_summary(group) for repo, group in sorted(repo_groups.items())}
    by_commit_count[name] = {group: _metric_summary(group_rows) for group, group_rows in sorted(commit_groups.items())}
  return {"overall": overall, "by_repo": by_repo, "by_commit_count": by_commit_count}


def _diff_rows(
  baseline_rows: list[dict[str, Any]],
  candidate_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
  base = {(r["repo"], r["cve_id"]): r for r in baseline_rows}
  out: list[dict[str, Any]] = []
  for cand in candidate_rows:
    key = (cand["repo"], cand["cve_id"])
    b = base.get(key)
    if not b:
      continue
    base_fn = set(b.get("fn_tags") or [])
    cand_fn = set(cand.get("fn_tags") or [])
    base_fp = set(b.get("fp_tags") or [])
    cand_fp = set(cand.get("fp_tags") or [])
    out.append({
      "repo": cand["repo"],
      "cve_id": cand["cve_id"],
      "strategy": cand["strategy"],
      "commit_count": cand.get("commit_count"),
      "baseline_probe_count": b["probe_count"],
      "candidate_probe_count": cand["probe_count"],
      "probe_saved": int(b["probe_count"]) - int(cand["probe_count"]),
      "baseline_fn": b["fn"],
      "candidate_fn": cand["fn"],
      "additional_fn_count": len(cand_fn - base_fn),
      "additional_fn_tags": sorted(cand_fn - base_fn),
      "baseline_fp": b["fp"],
      "candidate_fp": cand["fp"],
      "additional_fp_count": len(cand_fp - base_fp),
      "additional_fp_tags": sorted(cand_fp - base_fp),
      "hard_pruned_gt_count": cand.get("hard_pruned_gt_count", 0),
      "hard_pruned_gt_tags": cand.get("hard_pruned_gt_tags", []),
      "total_fix_containing_gt_count": cand.get("total_fix_containing_gt_count", 0),
      "total_fix_containing_gt_tags": cand.get("total_fix_containing_gt_tags", []),
      "fix_containing_tag_count": cand.get("fix_containing_tag_count", 0),
      "active_line_count": cand.get("active_line_count", 0),
    })
  return sorted(out, key=lambda r: (-int(r["additional_fn_count"]), -int(r["probe_saved"]), r["repo"], r["cve_id"]))


def _strip_tag_lists(row: dict[str, Any]) -> dict[str, Any]:
  out = dict(row)
  for key in ("tp_tags", "fp_tags", "fn_tags", "hard_pruned_gt_tags", "total_fix_containing_gt_tags", "unmapped_gt_tags"):
    out.pop(key, None)
  return out


def _write_report(path: Path, summary: dict[str, Any], diffs: dict[str, list[dict[str, Any]]]) -> None:
  lines = [
    "# Fix-Contains Hard-Pruning Evaluation",
    "",
    "This evaluates the idea: after Step3 creates its release-tag plan, tags matched by",
    "`git tag --contains <fix_commit>` are treated as definitely fixed and are removed",
    "from agent probing.",
    "",
    "The simulator uses GT labels only as an oracle for evaluation; GT is not part of",
    "the production Step3 algorithm.",
    "",
    "## Overall",
    "",
    "| strategy | total probes | avg probes | p95 | exact CVEs | FN CVEs | FP CVEs | micro P | micro R | micro F1 | hard-pruned GT tags/CVEs |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
  ]
  for name, row in summary["overall"].items():
    lines.append(
      f"| `{name}` | {row['probe_total']} | {row['probe_avg']} | {row['probe_p95']} | "
      f"{row['exact_match_cves']}/{row['cves']} | {row['has_fn_cves']} | {row['has_fp_cves']} | "
      f"{row['micro_precision']} | {row['micro_recall']} | {row['micro_f1']} | "
      f"{row.get('hard_pruned_gt_tag_total', 0)}/{row.get('hard_pruned_gt_cves', 0)} |"
    )
  lines.extend(["", "## Highest-Risk Cases", ""])
  for strategy, rows in diffs.items():
    lines.append(f"### {strategy}")
    lines.append("")
    lines.append("| repo | CVE | probes saved | additional FN tags | hard-pruned GT tags |")
    lines.append("| --- | --- | ---: | ---: | ---: |")
    for row in rows[:20]:
      lines.append(
        f"| {row['repo']} | {row['cve_id']} | {row['probe_saved']} | "
        f"{row['additional_fn_count']} | {row['hard_pruned_gt_count']} |"
      )
    lines.append("")
  path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
  ap = argparse.ArgumentParser()
  ap.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
  ap.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
  ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
  ap.add_argument("--policy", default="staged_nofix_stride3_file")
  ap.add_argument("--sentinel-count", type=int, default=3)
  ap.add_argument("--fixed-segment-sentinels", type=int, default=1)
  ap.add_argument("--expansion-radius", type=int, default=1)
  ap.add_argument("--no-fallback-scan-conflicts", action="store_true")
  args = ap.parse_args(argv)

  dataset = _load_dataset(args.dataset)
  by_repo = _group_dataset_by_repo(dataset)
  fallback_scan_conflicts = not args.no_fallback_scan_conflicts

  contexts: dict[str, dict[str, Any]] = {}
  changed_files_by_cve: dict[str, list[str]] = {}
  changed_files_cache_by_repo: dict[str, dict[str, list[str]]] = defaultdict(dict)
  target_commits_by_repo: dict[str, set[str]] = defaultdict(set)
  endpoint_queries_by_repo: dict[str, set[tuple[str, str]]] = defaultdict(set)

  for repo_name, records in sorted(by_repo.items()):
    repo_path = args.repo_root / repo_name
    context = _release_context(repo_name, repo_path)
    contexts[repo_name] = context
    repo: GitRepo = context["repo"]
    endpoint_tags = {
      tag
      for tags in context["release_lines"].values()
      if tags
      for tag in (tags[0], tags[-1])
    }
    for cve_id, rec in records:
      commits = _flatten_fixing_commits(rec.get("fixing_commits") or rec.get("fixing_commit"))
      target_commits_by_repo[repo_name].update(commits)
      files = _changed_files_for_commits(repo, commits, changed_files_cache_by_repo[repo_name])
      changed_files_by_cve[cve_id] = files
      for tag in endpoint_tags:
        for path in files:
          endpoint_queries_by_repo[repo_name].add((tag, path))

  commit_contains_by_repo: dict[str, dict[str, dict[str, Any]]] = {}
  for repo_name, commits in sorted(target_commits_by_repo.items()):
    commit_contains_by_repo[repo_name] = _precompute_tags_containing_batch(
      repo=contexts[repo_name]["repo"],
      release_tags=contexts[repo_name]["release_tags"],
      target_commits=commits,
    )

  path_exists_by_repo: dict[str, dict[tuple[str, str], bool]] = {}
  for repo_name, queries in sorted(endpoint_queries_by_repo.items()):
    path_exists_by_repo[repo_name] = _batch_path_exists(contexts[repo_name]["repo"], queries)

  rows_by_strategy: dict[str, list[dict[str, Any]]] = {
    "baseline_current_any_fs1": [],
    "hard_prune_any": [],
    "hard_prune_all": [],
    "hard_prune_any_after_first": [],
    "hard_prune_all_after_first": [],
  }
  per_cve_rows: list[dict[str, Any]] = []

  for repo_name, records in sorted(by_repo.items()):
    context = contexts[repo_name]
    release_lines: dict[str, list[str]] = context["release_lines"]
    for cve_id, rec in records:
      commits = _flatten_fixing_commits(rec.get("fixing_commits") or rec.get("fixing_commit"))
      files = changed_files_by_cve.get(cve_id, [])
      path_exists = path_exists_by_repo.get(repo_name, {})
      file_endpoint_lines: set[str] = set()
      for line, tags in release_lines.items():
        if not tags:
          continue
        endpoints = {tags[0], tags[-1]}
        if any(path_exists.get((tag, path), False) for tag in endpoints for path in files):
          file_endpoint_lines.add(line)

      fix_tags_any, meta_any = _fix_tags_for_commits(
        commits=commits,
        commit_contains=commit_contains_by_repo.get(repo_name, {}),
        mode="any",
      )
      fix_tags_all, meta_all = _fix_tags_for_commits(
        commits=commits,
        commit_contains=commit_contains_by_repo.get(repo_name, {}),
        mode="all",
      )
      _, fix_tags_any_after_first = _strictly_after_first_fix_tags(release_lines, fix_tags_any)
      _, fix_tags_all_after_first = _strictly_after_first_fix_tags(release_lines, fix_tags_all)

      baseline = _simulate_staged_soft_cve_with_tags(
        cve_id=cve_id,
        repo_name=repo_name,
        affected_versions=list(rec.get("affected_version") or []),
        release_lines=release_lines,
        ordered_by_family=context["ordered_by_family"],
        release_tags=context["release_tags"],
        fix_containing_tags=fix_tags_any,
        file_endpoint_lines=file_endpoint_lines,
        policy=args.policy,
        sentinel_count=args.sentinel_count,
        fixed_segment_sentinels=args.fixed_segment_sentinels,
        expansion_radius=args.expansion_radius,
        fallback_scan_conflicts=fallback_scan_conflicts,
        commit_count=len(commits),
        contains_mode="any",
        contains_meta=meta_any,
      )

      hard_any = _simulate_staged_hard_prune_cve(
        cve_id=cve_id,
        repo_name=repo_name,
        affected_versions=list(rec.get("affected_version") or []),
        release_lines=release_lines,
        ordered_by_family=context["ordered_by_family"],
        release_tags=context["release_tags"],
        fix_containing_tags=fix_tags_any,
        file_endpoint_lines=file_endpoint_lines,
        policy=args.policy,
        sentinel_count=args.sentinel_count,
        expansion_radius=args.expansion_radius,
        fallback_scan_conflicts=fallback_scan_conflicts,
        commit_count=len(commits),
        contains_mode="any",
        contains_meta=meta_any,
      )
      hard_all = _simulate_staged_hard_prune_cve(
        cve_id=cve_id,
        repo_name=repo_name,
        affected_versions=list(rec.get("affected_version") or []),
        release_lines=release_lines,
        ordered_by_family=context["ordered_by_family"],
        release_tags=context["release_tags"],
        fix_containing_tags=fix_tags_all,
        file_endpoint_lines=file_endpoint_lines,
        policy=args.policy,
        sentinel_count=args.sentinel_count,
        expansion_radius=args.expansion_radius,
        fallback_scan_conflicts=fallback_scan_conflicts,
        commit_count=len(commits),
        contains_mode="all",
        contains_meta=meta_all,
      )
      hard_any_after_first = _simulate_staged_hard_prune_cve(
        cve_id=cve_id,
        repo_name=repo_name,
        affected_versions=list(rec.get("affected_version") or []),
        release_lines=release_lines,
        ordered_by_family=context["ordered_by_family"],
        release_tags=context["release_tags"],
        fix_containing_tags=fix_tags_any_after_first,
        scheduler_fix_containing_tags=fix_tags_any,
        file_endpoint_lines=file_endpoint_lines,
        policy=args.policy,
        sentinel_count=args.sentinel_count,
        expansion_radius=args.expansion_radius,
        fallback_scan_conflicts=fallback_scan_conflicts,
        commit_count=len(commits),
        contains_mode="any_after_first",
        contains_meta=meta_any,
      )
      hard_all_after_first = _simulate_staged_hard_prune_cve(
        cve_id=cve_id,
        repo_name=repo_name,
        affected_versions=list(rec.get("affected_version") or []),
        release_lines=release_lines,
        ordered_by_family=context["ordered_by_family"],
        release_tags=context["release_tags"],
        fix_containing_tags=fix_tags_all_after_first,
        scheduler_fix_containing_tags=fix_tags_all,
        file_endpoint_lines=file_endpoint_lines,
        policy=args.policy,
        sentinel_count=args.sentinel_count,
        expansion_radius=args.expansion_radius,
        fallback_scan_conflicts=fallback_scan_conflicts,
        commit_count=len(commits),
        contains_mode="all_after_first",
        contains_meta=meta_all,
      )

      rows_by_strategy["baseline_current_any_fs1"].append(baseline)
      rows_by_strategy["hard_prune_any"].append(hard_any)
      rows_by_strategy["hard_prune_all"].append(hard_all)
      rows_by_strategy["hard_prune_any_after_first"].append(hard_any_after_first)
      rows_by_strategy["hard_prune_all_after_first"].append(hard_all_after_first)
      per_cve_rows.extend([
        _strip_tag_lists(baseline),
        _strip_tag_lists(hard_any),
        _strip_tag_lists(hard_all),
        _strip_tag_lists(hard_any_after_first),
        _strip_tag_lists(hard_all_after_first),
      ])

  diffs = {
    "hard_prune_any": _diff_rows(rows_by_strategy["baseline_current_any_fs1"], rows_by_strategy["hard_prune_any"]),
    "hard_prune_all": _diff_rows(rows_by_strategy["baseline_current_any_fs1"], rows_by_strategy["hard_prune_all"]),
    "hard_prune_any_after_first": _diff_rows(rows_by_strategy["baseline_current_any_fs1"], rows_by_strategy["hard_prune_any_after_first"]),
    "hard_prune_all_after_first": _diff_rows(rows_by_strategy["baseline_current_any_fs1"], rows_by_strategy["hard_prune_all_after_first"]),
  }
  summary = _summarize(rows_by_strategy)
  metadata = {
    "dataset": str(args.dataset),
    "repo_root": str(args.repo_root),
    "policy": args.policy,
    "sentinel_count": args.sentinel_count,
    "fixed_segment_sentinels_baseline": args.fixed_segment_sentinels,
    "expansion_radius": args.expansion_radius,
    "fallback_scan_conflicts": fallback_scan_conflicts,
    "total_cves": sum(len(v) for v in by_repo.values()),
    "note": "GT-oracle evaluation of hard-pruning tags containing fix commits. It measures scheduling/probe impact, not real agent accuracy.",
  }

  args.out_dir.mkdir(parents=True, exist_ok=True)
  _write_json(args.out_dir / "summary.json", {"metadata": metadata, **summary})
  _write_jsonl(args.out_dir / "per_cve.jsonl", per_cve_rows)
  _write_json(args.out_dir / "case_diffs.json", diffs)
  _write_report(args.out_dir / "report.md", summary, diffs)
  print(json.dumps({"metadata": metadata, "overall": summary["overall"], "out_dir": str(args.out_dir)}, ensure_ascii=False, indent=2))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
