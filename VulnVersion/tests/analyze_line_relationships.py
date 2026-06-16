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
DEFAULT_OUT_DIR = ROOT / "tests" / "line_relationships"


def _load_dataset(path: Path) -> dict[str, Any]:
  return json.loads(path.read_text(encoding="utf-8"))


def _line_version(repo_name: str, line: str) -> tuple[Any, ...]:
  if repo_name == "FFmpeg":
    return parse_version(repo_name, f"n{line}")
  if repo_name == "qemu":
    return parse_version(repo_name, f"v{line}.0")
  if repo_name == "wireshark":
    return parse_version(repo_name, f"v{line}.0")
  if repo_name == "openssl":
    nums = [int(x) for x in __import__("re").findall(r"\d+", line)]
    if nums:
      while len(nums) < 4:
        nums.append(0)
      return tuple(nums)
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


def _release_lines(repo_name: str, repo_path: Path) -> dict[str, list[str]]:
  repo = GitRepo.open(repo_path)
  release_tags = filter_release_tags(repo_name, repo.list_tags(max_tags=None))
  grouped: dict[str, list[str]] = defaultdict(list)
  for tag in release_tags:
    grouped[line_key(repo_name, tag)].append(tag)
  return {
    line: sort_tags_for_line(repo_name, tags)
    for line, tags in grouped.items()
  }


def _ordered_lines_by_family(repo_name: str, release_lines: dict[str, list[str]]) -> dict[str, list[str]]:
  family_to_lines: dict[str, list[str]] = defaultdict(list)
  for line in release_lines:
    family_to_lines[line_family_key(repo_name, line)].append(line)
  return {
    family: sorted(lines, key=lambda line: _line_version(repo_name, line), reverse=True)
    for family, lines in sorted(family_to_lines.items())
  }


def _runs(indices: list[int]) -> list[tuple[int, int]]:
  if not indices:
    return []
  sorted_indices = sorted(indices)
  runs: list[tuple[int, int]] = []
  start = prev = sorted_indices[0]
  for idx in sorted_indices[1:]:
    if idx == prev + 1:
      prev = idx
      continue
    runs.append((start, prev))
    start = prev = idx
  runs.append((start, prev))
  return runs


def _line_runs(states: list[bool]) -> list[tuple[int, int]]:
  return _runs([idx for idx, value in enumerate(states) if value])


def _line_shape(states: list[bool]) -> str:
  if not states:
    return "empty_line"
  runs = _line_runs(states)
  if not runs:
    return "none"
  if len(runs) > 1:
    return "multi_interval"
  start, end = runs[0]
  if start == 0 and end == len(states) - 1:
    return "full"
  if start == 0:
    return "prefix"
  if end == len(states) - 1:
    return "suffix"
  return "middle"


def _endpoint_shape(states: list[bool]) -> str:
  if not states:
    return "empty_line"
  left = states[0]
  right = states[-1]
  if left and right:
    return "aa_full" if all(states) else "aa_gap"
  if left and not right:
    return "an_prefix_like"
  if not left and right:
    return "na_suffix_like"
  return "nn_empty" if not any(states) else "nn_middle"


def _analyze_cve(
  *,
  cve_id: str,
  repo_name: str,
  affected_versions: list[str],
  release_lines: dict[str, list[str]],
  ordered_by_family: dict[str, list[str]],
) -> dict[str, Any]:
  release_tags = [tag for tags in release_lines.values() for tag in tags]
  mapped_gt, unmapped_gt = map_gt_tags_to_repo_tags(affected_versions, release_tags, mode="loose")
  affected_set = set(mapped_gt)

  line_records: dict[str, Any] = {}
  line_shape_counter: Counter[str] = Counter()
  endpoint_counter: Counter[str] = Counter()
  affected_lines: set[str] = set()
  for line, tags in release_lines.items():
    states = [tag in affected_set for tag in tags]
    shape = _line_shape(states)
    endpoint = _endpoint_shape(states)
    line_shape_counter[shape] += 1
    endpoint_counter[endpoint] += 1
    if any(states):
      affected_lines.add(line)
    line_records[line] = {
      "line": line,
      "family": line_family_key(repo_name, line),
      "tag_count": len(tags),
      "affected_count": sum(1 for value in states if value),
      "shape": shape,
      "endpoint_shape": endpoint,
      "runs": _line_runs(states),
      "oldest_affected": states[0] if states else False,
      "newest_affected": states[-1] if states else False,
    }

  family_records: dict[str, Any] = {}
  line_run_counts: list[int] = []
  line_gap_counts: list[int] = []
  for family, ordered_lines in ordered_by_family.items():
    affected_indices = [idx for idx, line in enumerate(ordered_lines) if line in affected_lines]
    runs = _runs(affected_indices)
    gaps = 0
    if len(runs) > 1:
      for left, right in zip(runs, runs[1:]):
        gaps += right[0] - left[1] - 1
    line_run_counts.append(len(runs))
    line_gap_counts.append(gaps)
    family_records[family] = {
      "ordered_lines_newest_to_oldest": ordered_lines,
      "affected_line_indices": affected_indices,
      "affected_lines": [ordered_lines[idx] for idx in affected_indices],
      "run_count": len(runs),
      "runs": [
        {
          "start_index": start,
          "end_index": end,
          "start_line": ordered_lines[start],
          "end_line": ordered_lines[end],
          "length": end - start + 1,
        }
        for start, end in runs
      ],
      "gap_count": gaps,
    }

  return {
    "cve_id": cve_id,
    "repo": repo_name,
    "mapped_gt_count": len(mapped_gt),
    "unmapped_gt_count": len(unmapped_gt),
    "line_count": len(release_lines),
    "affected_line_count": len(affected_lines),
    "family_count": len(ordered_by_family),
    "line_shape_counts": dict(line_shape_counter),
    "endpoint_shape_counts": dict(endpoint_counter),
    "family_records": family_records,
    "line_records": line_records,
    "line_level_contiguous_in_all_families": all(count <= 1 for count in line_run_counts),
    "max_line_run_count": max(line_run_counts, default=0),
    "total_line_gap_count": sum(line_gap_counts),
  }


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
  overall_shapes: Counter[str] = Counter()
  overall_endpoints: Counter[str] = Counter()
  repo_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
  for row in rows:
    overall_shapes.update(row["line_shape_counts"])
    overall_endpoints.update(row["endpoint_shape_counts"])
    repo_rows[row["repo"]].append(row)

  def summarize_group(group: list[dict[str, Any]]) -> dict[str, Any]:
    shapes: Counter[str] = Counter()
    endpoints: Counter[str] = Counter()
    for row in group:
      shapes.update(row["line_shape_counts"])
      endpoints.update(row["endpoint_shape_counts"])
    return {
      "cves": len(group),
      "line_avg": round(sum(row["line_count"] for row in group) / len(group), 2) if group else 0,
      "affected_line_avg": round(sum(row["affected_line_count"] for row in group) / len(group), 2) if group else 0,
      "line_level_contiguous_cves": sum(1 for row in group if row["line_level_contiguous_in_all_families"]),
      "line_level_multirun_cves": sum(1 for row in group if not row["line_level_contiguous_in_all_families"]),
      "max_line_run_count": max((row["max_line_run_count"] for row in group), default=0),
      "total_line_gap_count": sum(row["total_line_gap_count"] for row in group),
      "line_shape_counts": dict(shapes),
      "endpoint_shape_counts": dict(endpoints),
    }

  by_repo = {
    repo: summarize_group(group)
    for repo, group in sorted(repo_rows.items())
  }
  worst_multirun = sorted(
    [
      {
        "repo": row["repo"],
        "cve_id": row["cve_id"],
        "affected_line_count": row["affected_line_count"],
        "max_line_run_count": row["max_line_run_count"],
        "total_line_gap_count": row["total_line_gap_count"],
        "family_records": {
          family: {
            "affected_lines": rec["affected_lines"],
            "run_count": rec["run_count"],
            "gap_count": rec["gap_count"],
          }
          for family, rec in row["family_records"].items()
          if rec["run_count"] > 1
        },
      }
      for row in rows
      if not row["line_level_contiguous_in_all_families"]
    ],
    key=lambda item: (-item["max_line_run_count"], -item["total_line_gap_count"], item["repo"], item["cve_id"]),
  )[:50]

  return {
    "overall": {
      "total_cves": len(rows),
      "fully_mapped_cves": sum(1 for row in rows if row["unmapped_gt_count"] == 0),
      "partially_or_unmapped_cves": sum(1 for row in rows if row["unmapped_gt_count"] > 0),
      "line_avg": round(sum(row["line_count"] for row in rows) / len(rows), 2) if rows else 0,
      "affected_line_avg": round(sum(row["affected_line_count"] for row in rows) / len(rows), 2) if rows else 0,
      "line_level_contiguous_cves": sum(1 for row in rows if row["line_level_contiguous_in_all_families"]),
      "line_level_multirun_cves": sum(1 for row in rows if not row["line_level_contiguous_in_all_families"]),
      "max_line_run_count": max((row["max_line_run_count"] for row in rows), default=0),
      "total_line_gap_count": sum(row["total_line_gap_count"] for row in rows),
      "line_shape_counts": dict(overall_shapes),
      "endpoint_shape_counts": dict(overall_endpoints),
    },
    "by_repo": by_repo,
    "worst_multirun_cves": worst_multirun,
  }


def _write_json(path: Path, obj: Any) -> None:
  path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
  with path.open("w", encoding="utf-8") as fp:
    for row in rows:
      light = {key: value for key, value in row.items() if key != "line_records"}
      fp.write(json.dumps(light, ensure_ascii=False) + "\n")


def _write_report(path: Path, summary: dict[str, Any]) -> None:
  overall = summary["overall"]
  lines = [
    "# Step3 Line Relationship Analysis",
    "",
    "This report analyzes affected-version patterns over release lines and line-family order.",
    "",
    "## Overall",
    "",
    f"- total_cves: `{overall['total_cves']}`",
    f"- line_level_contiguous_cves: `{overall['line_level_contiguous_cves']}`",
    f"- line_level_multirun_cves: `{overall['line_level_multirun_cves']}`",
    f"- line_avg: `{overall['line_avg']}`",
    f"- affected_line_avg: `{overall['affected_line_avg']}`",
    f"- max_line_run_count: `{overall['max_line_run_count']}`",
    f"- total_line_gap_count: `{overall['total_line_gap_count']}`",
    "",
    "## Endpoint Shapes",
    "",
  ]
  for key, value in sorted(overall["endpoint_shape_counts"].items()):
    lines.append(f"- `{key}`: `{value}`")
  lines.extend([
    "",
    "## Line Shapes",
    "",
  ])
  for key, value in sorted(overall["line_shape_counts"].items()):
    lines.append(f"- `{key}`: `{value}`")
  lines.extend([
    "",
    "## By Repo",
    "",
    "| repo | cves | lines avg | affected lines avg | line contiguous CVEs | multirun CVEs | max runs | endpoint nn_middle | endpoint aa_gap |",
    "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
  ])
  for repo, row in summary["by_repo"].items():
    endpoints = row["endpoint_shape_counts"]
    lines.append(
      f"| {repo} | {row['cves']} | {row['line_avg']} | {row['affected_line_avg']} | "
      f"{row['line_level_contiguous_cves']} | {row['line_level_multirun_cves']} | "
      f"{row['max_line_run_count']} | {endpoints.get('nn_middle', 0)} | {endpoints.get('aa_gap', 0)} |"
    )
  lines.extend(["", "## Worst Multi-Run CVEs", ""])
  for item in summary["worst_multirun_cves"][:20]:
    lines.append(
      f"- `{item['repo']}` `{item['cve_id']}`: affected lines `{item['affected_line_count']}`, "
      f"max runs `{item['max_line_run_count']}`, gaps `{item['total_line_gap_count']}`"
    )
  path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
  parser = argparse.ArgumentParser(description="Analyze Step3 release-line relationships using GT affected versions.")
  parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
  parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
  parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
  args = parser.parse_args(argv)

  dataset = _load_dataset(args.dataset)
  release_cache: dict[str, dict[str, list[str]]] = {}
  ordered_cache: dict[str, dict[str, list[str]]] = {}
  rows: list[dict[str, Any]] = []
  for cve_id, rec in sorted(dataset.items()):
    repo_name = str(rec.get("repo") or "").strip()
    if not repo_name:
      continue
    if repo_name not in release_cache:
      release_cache[repo_name] = _release_lines(repo_name, args.repo_root / repo_name)
      ordered_cache[repo_name] = _ordered_lines_by_family(repo_name, release_cache[repo_name])
    rows.append(_analyze_cve(
      cve_id=cve_id,
      repo_name=repo_name,
      affected_versions=list(rec.get("affected_version") or []),
      release_lines=release_cache[repo_name],
      ordered_by_family=ordered_cache[repo_name],
    ))

  args.out_dir.mkdir(parents=True, exist_ok=True)
  summary = _summarize(rows)
  _write_json(args.out_dir / "summary.json", summary)
  _write_jsonl(args.out_dir / "per_cve.jsonl", rows)
  _write_report(args.out_dir / "report.md", summary)
  print(json.dumps({"overall": summary["overall"], "out_dir": str(args.out_dir)}, ensure_ascii=False, indent=2))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
