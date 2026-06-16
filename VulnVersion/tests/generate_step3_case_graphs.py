from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT.parent
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
)
from simulate_staged_expansion_scheduler import (  # noqa: E402
  _family_neighbors,
  _initial_lines_for_policy,
  _line_groups,
  _simulate_git_guided_line,
)
from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags  # noqa: E402


DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
REPO_ROOT = ROOT / "repo"
PER_CVE = ROOT / "tests" / "staged_expansion_scheduler_simulator" / "per_cve.jsonl"
TAXONOMY = ROOT / "tests" / "multi_commit_taxonomy_analysis" / "summary.json"
OUT = WORKFLOW / "SystemDesign" / "Architecture" / "Develop" / "step3_case_graphs.md"


SELECTED = [
  ("CVE-2020-13904", "FFmpeg", "15 commits; branch_backport_bundle_or; high-probe full-line case"),
  ("CVE-2021-38114", "FFmpeg", "fixed-segment probe hit then fallback ASBS"),
  ("CVE-2021-3409", "qemu", "same_component_patchset; many qemu lines"),
  ("CVE-2021-3416", "qemu", "10 commits; component-level patchset"),
  ("CVE-2021-22235", "wireshark", "current FN case; sparse affected tags"),
  ("CVE-2020-26421", "wireshark", "large affected set with one residual FN"),
  ("CVE-2022-2274", "openssl", "OpenSSL line-family complexity; residual FN"),
  ("CVE-2021-41773", "httpd", "single affected release missed by endpoint/sentinel"),
  ("CVE-2021-40438", "httpd", "multi_component_or_composite taxonomy"),
  ("CVE-2020-27844", "openjpeg", "wrapper/merge commit evidence case"),
]


def _load_json(path: Path) -> Any:
  return json.loads(path.read_text(encoding="utf-8"))


def _load_per_cve() -> dict[tuple[str, str], dict[str, Any]]:
  rows: dict[tuple[str, str], dict[str, Any]] = {}
  for line in PER_CVE.read_text(encoding="utf-8").splitlines():
    if not line.strip():
      continue
    row = json.loads(line)
    rows[(row["policy"], row["cve_id"])] = row
  return rows


def _load_taxonomy() -> dict[str, dict[str, Any]]:
  if not TAXONOMY.exists():
    return {}
  data = _load_json(TAXONOMY)
  return {row["cve"]: row for row in data.get("rows", [])}


def _line_runs(tags: list[str], affected: set[str]) -> list[tuple[int, int]]:
  runs: list[tuple[int, int]] = []
  start: int | None = None
  for idx, tag in enumerate(tags):
    if tag in affected and start is None:
      start = idx
    elif tag not in affected and start is not None:
      runs.append((start, idx - 1))
      start = None
  if start is not None:
    runs.append((start, len(tags) - 1))
  return runs


def _line_shape(tags: list[str], affected: set[str]) -> tuple[str, str, int]:
  runs = _line_runs(tags, affected)
  if not runs:
    return "no_affected", "", 0
  if len(runs) > 1:
    label = "; ".join(f"{tags[a]}..{tags[b]}" if a != b else tags[a] for a, b in runs[:3])
    more = "" if len(runs) <= 3 else f"; +{len(runs) - 3} runs"
    return "multi_interval", label + more, sum(b - a + 1 for a, b in runs)
  a, b = runs[0]
  count = b - a + 1
  if a == 0 and b == len(tags) - 1:
    shape = "full"
  elif a == 0:
    shape = "prefix"
  elif b == len(tags) - 1:
    shape = "suffix"
  else:
    shape = "middle"
  label = f"{tags[a]}..{tags[b]}" if a != b else tags[a]
  return shape, label, count


def _compute_case_runtime(
  *,
  cve_id: str,
  repo_name: str,
  rec: dict[str, Any],
  context: dict[str, Any],
  contains_by_commit: dict[str, dict[str, Any]],
  changed_files: list[str],
  path_exists: dict[tuple[str, str], bool],
) -> dict[str, Any]:
  release_lines: dict[str, list[str]] = context["release_lines"]
  release_tags: list[str] = context["release_tags"]
  mapped_gt, unmapped_gt = map_gt_tags_to_repo_tags(list(rec.get("affected_version") or []), release_tags, mode="loose")
  affected_set = set(mapped_gt)

  commits = _flatten_fixing_commits(rec.get("fixing_commits") or rec.get("fixing_commit"))
  fix_containing_tags: set[str] = set()
  for commit in commits:
    result = contains_by_commit.get(commit, {"ok": False, "tags": []})
    if result.get("ok"):
      fix_containing_tags.update(result.get("tags", []))

  file_endpoint_lines: set[str] = set()
  for line, tags in release_lines.items():
    if not tags:
      continue
    endpoints = {tags[0], tags[-1]}
    if any(path_exists.get((tag, path), False) for tag in endpoints for path in changed_files):
      file_endpoint_lines.add(line)

  initial_lines, _ = _initial_lines_for_policy(
    policy="staged_nofix_stride3_file",
    release_lines=release_lines,
    ordered_by_family=context["ordered_by_family"],
    fix_containing_tags=fix_containing_tags,
    file_endpoint_lines=file_endpoint_lines,
  )
  line_to_family = _line_groups(context["ordered_by_family"])
  queue = deque(sorted(initial_lines))
  visited: set[str] = set()
  positive_lines: set[str] = set()
  status_counter: Counter[str] = Counter()
  while queue:
    line = queue.popleft()
    if line in visited:
      continue
    visited.add(line)
    sim = _simulate_git_guided_line(
      release_lines[line],
      affected_set,
      fix_containing_tags,
      sentinel_count=3,
      fixed_segment_sentinels=1,
      fallback_scan_conflicts=True,
    )
    status_counter.update(sim["statuses"])
    predicted = set(sim["predicted_affected"])
    probes = set(sim["probe_tags"])
    if predicted or (probes & affected_set):
      positive_lines.add(line)
      for neighbor in _family_neighbors(context["ordered_by_family"], line_to_family, line, 1):
        if neighbor not in visited:
          queue.append(neighbor)

  affected_lines = {
    line for line, tags in release_lines.items()
    if any(tag in affected_set for tag in tags)
  }
  line_summaries = []
  for line, tags in sorted(release_lines.items()):
    shape, interval, count = _line_shape(tags, affected_set)
    if line in affected_lines or line in positive_lines or line in initial_lines:
      line_summaries.append({
        "line": line,
        "tags": len(tags),
        "gt_shape": shape,
        "gt_interval": interval,
        "gt_count": count,
        "seed": line in initial_lines,
        "active": line in visited,
        "positive": line in positive_lines,
        "fix_tags": sum(1 for tag in tags if tag in fix_containing_tags),
      })

  return {
    "mapped_gt": mapped_gt,
    "unmapped_gt": unmapped_gt,
    "affected_lines": affected_lines,
    "initial_lines": initial_lines,
    "active_lines": visited,
    "positive_lines": positive_lines,
    "file_endpoint_lines": file_endpoint_lines,
    "fix_containing_tags": fix_containing_tags,
    "line_summaries": line_summaries,
    "status_counts": dict(status_counter),
  }


def _mermaid(case: dict[str, Any]) -> str:
  row = case["row"]
  tax = case["taxonomy"]
  runtime = case["runtime"]
  taxonomy_label = tax.get("class", "single_fix")
  commit_count = case["commit_count"]
  repo = case["repo"]
  cve = case["cve"]
  return f"""```mermaid
flowchart LR
  I["{cve}<br/>{repo}<br/>fix commits: {commit_count}<br/>taxonomy: {taxonomy_label}"]
  V["VulnTree<br/>release tags: {row['release_tag_count']}<br/>lines: {row['line_count']}<br/>affected lines: {row['affected_line_count']}"]
  E["Fix evidence<br/>fix-containing tags: {row['fix_containing_tag_count']}<br/>file-endpoint lines: {row['file_endpoint_line_count']}<br/>multi-fix: OR evidence bundle"]
  S["Staged scheduler<br/>seed lines: {row.get('seed_line_count', row['active_line_count'])}<br/>active lines: {row['active_line_count']}<br/>skipped affected lines: {row['skipped_affected_lines']}"]
  A["Line ASBS<br/>probes: {row['probe_count']}<br/>positive lines: {len(runtime['positive_lines'])}<br/>status classes: {len(row['status_counts'])}"]
  O["Output<br/>TP/FP/FN: {row['tp']}/{row['fp']}/{row['fn']}<br/>exact: {row['exact_match']}<br/>F1: {row['f1']:.6f}"]
  I --> V --> E --> S --> A --> O
```"""


def _line_table(lines: list[dict[str, Any]], limit: int = 18) -> str:
  if not lines:
    return "No affected/seed/active lines to display.\n"
  out = [
    "| line | tags | GT shape | GT interval | GT tags | seed | active | positive | fix-tags |",
    "| --- | ---: | --- | --- | ---: | --- | --- | --- | ---: |",
  ]
  for item in lines[:limit]:
    out.append(
      f"| `{item['line']}` | {item['tags']} | `{item['gt_shape']}` | "
      f"{item['gt_interval'] or '-'} | {item['gt_count']} | "
      f"{'Y' if item['seed'] else 'N'} | {'Y' if item['active'] else 'N'} | "
      f"{'Y' if item['positive'] else 'N'} | {item['fix_tags']} |"
    )
  if len(lines) > limit:
    out.append(f"| ... | ... | ... | showing {limit}/{len(lines)} lines | ... | ... | ... | ... | ... |")
  return "\n".join(out) + "\n"


def _status_table(status: dict[str, int]) -> str:
  if not status:
    return ""
  out = ["| ASBS/scheduler status | count |", "| --- | ---: |"]
  for key, value in sorted(status.items(), key=lambda kv: (-kv[1], kv[0])):
    out.append(f"| `{key}` | {value} |")
  return "\n".join(out) + "\n"


def main() -> int:
  dataset = _load_json(DATASET)
  per_cve = _load_per_cve()
  taxonomy = _load_taxonomy()

  contexts: dict[str, dict[str, Any]] = {}
  by_repo_selected: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
  for cve, repo, _ in SELECTED:
    by_repo_selected[repo].append((cve, dataset[cve]))

  contains_by_repo: dict[str, dict[str, dict[str, Any]]] = {}
  changed_files_by_cve: dict[str, list[str]] = {}
  endpoint_queries_by_repo: dict[str, set[tuple[str, str]]] = defaultdict(set)
  for repo_name, records in by_repo_selected.items():
    context = _release_context(repo_name, REPO_ROOT / repo_name)
    contexts[repo_name] = context
    repo: GitRepo = context["repo"]
    target_commits: set[str] = set()
    changed_cache: dict[str, list[str]] = {}
    endpoint_tags = {
      tag for tags in context["release_lines"].values()
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
    contains_by_repo[repo_name] = _precompute_tags_containing_batch(
      repo=repo,
      release_tags=context["release_tags"],
      target_commits=target_commits,
    )

  path_exists_by_repo: dict[str, dict[tuple[str, str], bool]] = {}
  for repo_name, queries in endpoint_queries_by_repo.items():
    path_exists_by_repo[repo_name] = _batch_path_exists(contexts[repo_name]["repo"], queries)

  cases: list[dict[str, Any]] = []
  for cve, repo, reason in SELECTED:
    rec = dataset[cve]
    row = per_cve[("staged_nofix_stride3_file", cve)]
    runtime = _compute_case_runtime(
      cve_id=cve,
      repo_name=repo,
      rec=rec,
      context=contexts[repo],
      contains_by_commit=contains_by_repo[repo],
      changed_files=changed_files_by_cve[cve],
      path_exists=path_exists_by_repo[repo],
    )
    commits = _flatten_fixing_commits(rec.get("fixing_commits") or rec.get("fixing_commit"))
    cases.append({
      "cve": cve,
      "repo": repo,
      "reason": reason,
      "commit_count": len(commits),
      "affected_version_count": len(rec.get("affected_version") or []),
      "row": row,
      "taxonomy": taxonomy.get(cve, {"class": "single_fix"}),
      "runtime": runtime,
      "changed_files": changed_files_by_cve[cve],
    })

  lines: list[str] = [
    "# Step3 Case Graphs: 10 Complex CVEs",
    "",
    "This report visualizes the current Step3 design in `step3.md` on 10 complex CVEs.",
    "",
    "Policy shown: `staged_nofix_stride3_file` with `sentinel_count=3`, `fixed_segment_sentinels=1`, and same-family expansion radius 1.",
    "",
    "Important: these are GT-oracle simulations. `affected_version` is used as the ideal tag verdict oracle to explain planning logic. This is not a real-agent run.",
    "",
    "Legend:",
    "",
    "- `seed`: line selected before dynamic expansion.",
    "- `active`: line actually evaluated after staged expansion.",
    "- `positive`: line where ASBS predicted affected tags or probed an affected tag.",
    "- `fix-tags`: release tags on that line that contain at least one strong fix evidence commit.",
    "",
    "## Overview",
    "",
    "| CVE | repo | why selected | commits | taxonomy | lines | active | affected lines | probes | TP/FP/FN | exact |",
    "| --- | --- | --- | ---: | --- | ---: | ---: | ---: | ---: | --- | --- |",
  ]
  for case in cases:
    row = case["row"]
    tax = case["taxonomy"].get("class", "single_fix")
    lines.append(
      f"| `{case['cve']}` | {case['repo']} | {case['reason']} | {case['commit_count']} | "
      f"`{tax}` | {row['line_count']} | {row['active_line_count']} | {row['affected_line_count']} | "
      f"{row['probe_count']} | {row['tp']}/{row['fp']}/{row['fn']} | {row['exact_match']} |"
    )
  lines.append("")

  for idx, case in enumerate(cases, start=1):
    row = case["row"]
    tax = case["taxonomy"]
    runtime = case["runtime"]
    changed_top = Counter(path.split("/")[0] for path in case["changed_files"]).most_common(6)
    lines.extend([
      f"## {idx}. {case['cve']} ({case['repo']})",
      "",
      f"Reason selected: {case['reason']}.",
      "",
      _mermaid(case),
      "",
      "### Key Facts",
      "",
      f"- Dataset affected_version count: `{case['affected_version_count']}`.",
      f"- Mapped GT tags: `{len(runtime['mapped_gt'])}`; unmapped GT tags: `{len(runtime['unmapped_gt'])}`.",
      f"- Fix commits: `{case['commit_count']}`; taxonomy: `{tax.get('class', 'single_fix')}`.",
      f"- Fix evidence tags: `{len(runtime['fix_containing_tags'])}`; touched-file endpoint lines: `{len(runtime['file_endpoint_lines'])}`.",
      f"- Changed-file top dirs: `{dict(changed_top)}`.",
      f"- Scheduler: seed lines `{row.get('seed_line_count', row['active_line_count'])}`, active lines `{row['active_line_count']}`, affected lines `{row['affected_line_count']}`, skipped affected lines `{row['skipped_affected_lines']}`.",
      f"- Output: TP `{row['tp']}`, FP `{row['fp']}`, FN `{row['fn']}`, exact `{row['exact_match']}`, F1 `{row['f1']:.6f}`.",
      "",
      "### Line Graph Summary",
      "",
      _line_table(runtime["line_summaries"]),
      "",
      "### ASBS / Scheduler Status",
      "",
      _status_table(row["status_counts"]),
      "",
    ])

  OUT.parent.mkdir(parents=True, exist_ok=True)
  OUT.write_text("\n".join(lines), encoding="utf-8")
  print(str(OUT))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
