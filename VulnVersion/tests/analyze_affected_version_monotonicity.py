from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.version_registry import (
    filter_release_tags,
    line_key,
    sort_tags_for_line,
)
DEFAULT_DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
DEFAULT_REPO_ROOT = ROOT / "repo"
DEFAULT_OUT_DIR = ROOT / "tests" / "affected_version_monotonicity"


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
        for line, vals in grouped.items()
    }


def _is_contiguous(indices: list[int]) -> bool:
    if not indices:
        return True
    return indices == list(range(indices[0], indices[-1] + 1))


def _is_monotonic_non_decreasing(values: list[int]) -> bool:
    if not values:
        return True
    return all(left <= right for left, right in zip(values, values[1:]))


def _analyze_cve(
    *,
    cve_id: str,
    repo_name: str,
    affected_versions: list[str],
    release_lines: dict[str, list[str]],
) -> dict[str, Any]:
    all_repo_tags = [tag for tags in release_lines.values() for tag in tags]
    mapped_tags, unmapped_tags = map_gt_tags_to_repo_tags(affected_versions, all_repo_tags, mode="loose")

    tag_to_line = {tag: line for line, tags in release_lines.items() for tag in tags}
    tag_to_index = {
        tag: idx
        for line, tags in release_lines.items()
        for idx, tag in enumerate(tags)
    }

    per_line_original_indices: dict[str, list[int]] = defaultdict(list)
    mapped_by_line: dict[str, list[str]] = defaultdict(list)
    for tag in mapped_tags:
        line = tag_to_line.get(tag)
        if line is None:
            continue
        mapped_by_line[line].append(tag)
        per_line_original_indices[line].append(tag_to_index[tag])

    line_details: dict[str, Any] = {}
    noncontiguous_lines: list[str] = []
    nonmonotonic_input_lines: list[str] = []
    total_line_intervals = 0
    suffix_lines = 0
    prefix_lines = 0
    singleton_lines = 0
    full_line_lines = 0

    for line, raw_tags in sorted(mapped_by_line.items()):
        unique_tags = sorted(set(raw_tags), key=lambda tag: tag_to_index[tag])
        indices = [tag_to_index[tag] for tag in unique_tags]
        contiguous = _is_contiguous(indices)
        input_monotonic = _is_monotonic_non_decreasing(per_line_original_indices[line])
        interval = None
        if indices:
            interval = {
                "from_tag": unique_tags[0],
                "to_tag": unique_tags[-1],
                "from_index": indices[0],
                "to_index": indices[-1],
            }
            total_line_intervals += 1
            if len(indices) == 1:
                singleton_lines += 1
            line_size = len(release_lines[line])
            if contiguous and indices[0] == 0:
                prefix_lines += 1
            if contiguous and indices[-1] == line_size - 1:
                suffix_lines += 1
            if contiguous and indices[0] == 0 and indices[-1] == line_size - 1:
                full_line_lines += 1
        if not contiguous:
            noncontiguous_lines.append(line)
        if not input_monotonic:
            nonmonotonic_input_lines.append(line)
        line_details[line] = {
            "mapped_count": len(unique_tags),
            "mapped_tags_sorted": unique_tags,
            "indices_sorted": indices,
            "input_indices_in_dataset_order": per_line_original_indices[line],
            "is_contiguous_subset": contiguous,
            "is_input_order_monotonic": input_monotonic,
            "interval": interval,
            "line_tag_count": len(release_lines[line]),
        }

    return {
        "cve_id": cve_id,
        "repo": repo_name,
        "affected_version_count": len(affected_versions),
        "mapped_count": len(mapped_tags),
        "unmapped_count": len(unmapped_tags),
        "mapped_tags": mapped_tags,
        "unmapped_tags": unmapped_tags,
        "line_count_with_affected_tags": len(line_details),
        "all_lines_contiguous": not noncontiguous_lines,
        "all_lines_input_monotonic": not nonmonotonic_input_lines,
        "noncontiguous_lines": noncontiguous_lines,
        "nonmonotonic_input_lines": nonmonotonic_input_lines,
        "line_interval_count": total_line_intervals,
        "suffix_line_count": suffix_lines,
        "prefix_line_count": prefix_lines,
        "singleton_line_count": singleton_lines,
        "full_line_count": full_line_lines,
        "line_details": line_details,
    }


def _repo_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_repo: dict[str, dict[str, Any]] = {}
    for row in rows:
        repo = row["repo"]
        acc = by_repo.setdefault(
            repo,
            {
                "cves": 0,
                "all_lines_contiguous_cves": 0,
                "has_noncontiguous_line_cves": 0,
                "all_lines_input_monotonic_cves": 0,
                "fully_mapped_cves": 0,
                "partially_mapped_cves": 0,
                "total_lines_with_affected_tags": 0,
                "total_noncontiguous_lines": 0,
                "noncontiguous_line_counter": Counter(),
            },
        )
        acc["cves"] += 1
        if row["all_lines_contiguous"]:
            acc["all_lines_contiguous_cves"] += 1
        else:
            acc["has_noncontiguous_line_cves"] += 1
        if row["all_lines_input_monotonic"]:
            acc["all_lines_input_monotonic_cves"] += 1
        if row["unmapped_count"] == 0:
            acc["fully_mapped_cves"] += 1
        else:
            acc["partially_mapped_cves"] += 1
        acc["total_lines_with_affected_tags"] += row["line_count_with_affected_tags"]
        acc["total_noncontiguous_lines"] += len(row["noncontiguous_lines"])
        for line in row["noncontiguous_lines"]:
            acc["noncontiguous_line_counter"][line] += 1

    out: dict[str, Any] = {}
    for repo, acc in sorted(by_repo.items()):
        out[repo] = {
            "cves": acc["cves"],
            "all_lines_contiguous_cves": acc["all_lines_contiguous_cves"],
            "has_noncontiguous_line_cves": acc["has_noncontiguous_line_cves"],
            "all_lines_input_monotonic_cves": acc["all_lines_input_monotonic_cves"],
            "fully_mapped_cves": acc["fully_mapped_cves"],
            "partially_mapped_cves": acc["partially_mapped_cves"],
            "total_lines_with_affected_tags": acc["total_lines_with_affected_tags"],
            "total_noncontiguous_lines": acc["total_noncontiguous_lines"],
            "top_noncontiguous_lines": acc["noncontiguous_line_counter"].most_common(10),
        }
    return out


def _overall_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    noncontiguous_cves = [row for row in rows if not row["all_lines_contiguous"]]
    nonmonotonic_input_cves = [row for row in rows if not row["all_lines_input_monotonic"]]
    fully_mapped = [row for row in rows if row["unmapped_count"] == 0]
    line_counter = Counter()
    repo_counter = Counter()
    for row in noncontiguous_cves:
        repo_counter[row["repo"]] += 1
        for line in row["noncontiguous_lines"]:
            line_counter[(row["repo"], line)] += 1
    return {
        "total_cves": len(rows),
        "all_lines_contiguous_cves": len(rows) - len(noncontiguous_cves),
        "has_noncontiguous_line_cves": len(noncontiguous_cves),
        "all_lines_input_monotonic_cves": len(rows) - len(nonmonotonic_input_cves),
        "has_nonmonotonic_input_line_cves": len(nonmonotonic_input_cves),
        "fully_mapped_cves": len(fully_mapped),
        "partially_or_unmapped_cves": len(rows) - len(fully_mapped),
        "top_repos_with_noncontiguous_cases": repo_counter.most_common(),
        "top_noncontiguous_repo_lines": [
            {"repo": repo, "line": line, "count": count}
            for (repo, line), count in line_counter.most_common(20)
        ],
    }


def _write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as fp:
        for row in rows:
            fp.write(json.dumps(row, ensure_ascii=False) + "\n")


def _write_report(path: Path, *, overall: dict[str, Any], by_repo: dict[str, Any]) -> None:
    lines = [
        "# Affected Version Monotonicity / Contiguity Report",
        "",
        "This report checks whether each CVE's `affected_version` forms a contiguous subset on each repo release line.",
        "",
        "Definitions:",
        "- `contiguous subset`: after mapping affected tags onto one line and sorting by version, their indices form one continuous interval.",
        "- `input monotonic`: the original dataset order, restricted to one line, is non-decreasing by version index.",
        "",
        "## Overall",
        "",
        f"- total_cves: `{overall['total_cves']}`",
        f"- all_lines_contiguous_cves: `{overall['all_lines_contiguous_cves']}`",
        f"- has_noncontiguous_line_cves: `{overall['has_noncontiguous_line_cves']}`",
        f"- all_lines_input_monotonic_cves: `{overall['all_lines_input_monotonic_cves']}`",
        f"- has_nonmonotonic_input_line_cves: `{overall['has_nonmonotonic_input_line_cves']}`",
        f"- fully_mapped_cves: `{overall['fully_mapped_cves']}`",
        f"- partially_or_unmapped_cves: `{overall['partially_or_unmapped_cves']}`",
        "",
        "## By Repo",
        "",
        "| repo | cves | contiguous_cves | noncontiguous_cves | input_monotonic_cves | fully_mapped | noncontiguous_lines |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for repo, row in by_repo.items():
        lines.append(
            f"| {repo} | {row['cves']} | {row['all_lines_contiguous_cves']} | "
            f"{row['has_noncontiguous_line_cves']} | {row['all_lines_input_monotonic_cves']} | "
            f"{row['fully_mapped_cves']} | {row['total_noncontiguous_lines']} |"
        )
    lines.extend([
        "",
        "## Top Noncontiguous Repo Lines",
        "",
    ])
    for item in overall["top_noncontiguous_repo_lines"]:
        lines.append(f"- `{item['repo']}` / line `{item['line']}`: `{item['count']}` CVEs")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze whether each CVE affected_version is contiguous on repo release lines.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    args = parser.parse_args(argv)

    dataset = _load_dataset(args.dataset)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    release_cache: dict[str, dict[str, list[str]]] = {}
    rows: list[dict[str, Any]] = []
    for cve_id, rec in sorted(dataset.items()):
        repo_name = str(rec.get("repo") or "").strip()
        if not repo_name:
            continue
        if repo_name not in release_cache:
            release_cache[repo_name] = _release_lines(repo_name, args.repo_root / repo_name)
        rows.append(_analyze_cve(
            cve_id=cve_id,
            repo_name=repo_name,
            affected_versions=list(rec.get("affected_version") or []),
            release_lines=release_cache[repo_name],
        ))

    overall = _overall_summary(rows)
    by_repo = _repo_summary(rows)
    _write_json(args.out_dir / "summary.json", {"overall": overall, "by_repo": by_repo})
    _write_jsonl(args.out_dir / "per_cve.jsonl", rows)
    _write_report(args.out_dir / "report.md", overall=overall, by_repo=by_repo)
    print(json.dumps({"overall": overall, "out_dir": str(args.out_dir)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
