"""Case-level review for OpenSSL Step3 release-line merge candidates.

This script is intentionally simulator-only. GT is used only to evaluate
whether a candidate OpenSSL line merge touches affected tags in the dataset.

It complements ``simulate_openssl_version_tree_variants.py`` by explaining
*why* a variant is safe or risky:

- cross-origin merge: mainline/fips/engine are mixed in one line.
- cross-family merge: current line families are merged.
- patch-series merge: multiple current mainline maintenance lines are merged.

The output is meant to support Step3 design decisions before any source-code
line builder changes are made.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = ROOT / "tests"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

import simulate_openssl_version_tree_variants as openssl_variants

from vulnversion.git_ops.repo import GitRepo, map_gt_tags_to_repo_tags
from vulnversion.stage3_verify.version_registry import filter_release_tags, line_key


DEFAULT_DATASET = ROOT / "DataSet" / "BaseDataOrder.json"
DEFAULT_REPO_ROOT = ROOT / "repo"
DEFAULT_VARIANT_DIR = ROOT / "tests" / "openssl_version_tree_variant_simulator"
DEFAULT_OUT_DIR = ROOT / "tests" / "openssl_version_tree_case_review"
REPO = "openssl"


def _current_family(line: str) -> str:
    if line.startswith("fips-"):
        return "openssl-fips"
    if line.startswith("engine-"):
        return "openssl-engine"
    return "openssl-mainline"


def _load_per_cve(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _merge_kind(current_lines: set[str], origins: set[str], families: set[str]) -> str:
    if len(origins) > 1:
        return "unsafe_cross_origin"
    if len(families) > 1:
        return "unsafe_cross_family"
    if len(current_lines) <= 1:
        return "no_merge"
    if origins == {"mainline"} and all(line.startswith("0.9.") for line in current_lines):
        return "candidate_legacy_mainline_09_merge"
    if origins == {"mainline"}:
        return "review_patch_series_merge"
    return "review_same_origin_non_mainline_merge"


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_report(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# OpenSSL VersionTree Case Review",
        "",
        f"Dataset: `{summary['metadata']['dataset']}`",
        "",
        "GT is used only for affected-line impact review and final simulator metrics.",
        "",
        "## Variant Decision Table",
        "",
        "| variant | avg probes | exact CVEs | version FN | unsafe affected CVEs | review affected CVEs | decision |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for name, row in summary["variant_decisions"].items():
        metrics = row["metrics"]
        lines.append(
            "| {name} | {avg:.2f} | {exact}/{total} | {vfn} | {unsafe} | {review} | {decision} |".format(
                name=name,
                avg=float(metrics["avg_probes"]),
                exact=int(metrics["exact_cves"]),
                total=int(metrics["cves"]),
                vfn=int(metrics["version_fn"]),
                unsafe=int(row["unsafe_affected_cves"]),
                review=int(row["review_affected_cves"]),
                decision=row["decision"],
            )
        )
    lines.extend([
        "",
        "## Interpretation",
        "",
        "- `unsafe_cross_origin` means mainline/fips/engine are merged. This must not enter the main path even if GT-oracle metrics do not drop.",
        "- `candidate_legacy_mainline_09_merge` only merges OpenSSL mainline `0.9.x` current lines. This is the safest current cost-saving candidate.",
        "- `review_patch_series_merge` merges current patch-series lines such as `1.0.0/1.0.1/1.0.2` or `1.1.0/1.1.1`. It needs manual case review before adoption.",
        "",
        "## Recommendation",
        "",
        summary["recommendation"],
        "",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Review OpenSSL VersionTree line-merge candidates.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
    parser.add_argument("--variant-dir", type=Path, default=DEFAULT_VARIANT_DIR)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    args = parser.parse_args(argv)

    dataset = json.loads(args.dataset.read_text(encoding="utf-8"))
    records = {
        cve_id: rec
        for cve_id, rec in sorted(dataset.items())
        if str(rec.get("repo") or "") == REPO
    }
    repo = GitRepo.open(args.repo_root / REPO)
    repo_tags = filter_release_tags(REPO, repo.list_tags(max_tags=None))
    repo_tags_set = set(repo_tags)

    variants = {variant.name: variant for variant in openssl_variants._variant_defs()}
    contexts = {
        name: openssl_variants._build_variant_context(repo, variant)
        for name, variant in variants.items()
    }
    current_context = contexts["current"]

    tag_current_line = {
        tag: line_key(REPO, tag)
        for tag in repo_tags
    }
    tag_origin = {
        tag: openssl_variants._origin(tag)
        for tag in repo_tags
    }
    tag_to_variant_line: dict[str, dict[str, str]] = {}
    for name, variant in variants.items():
        tag_to_variant_line[name] = {
            tag: variant.line_fn(tag)
            for tag in repo_tags
        }

    merge_review: dict[str, dict[str, Any]] = {}
    for name in variants:
        by_line: dict[str, set[str]] = defaultdict(set)
        origins_by_line: dict[str, set[str]] = defaultdict(set)
        families_by_line: dict[str, set[str]] = defaultdict(set)
        for tag in repo_tags:
            vline = tag_to_variant_line[name][tag]
            cline = tag_current_line[tag]
            by_line[vline].add(cline)
            origins_by_line[vline].add(tag_origin[tag])
            families_by_line[vline].add(_current_family(cline))
        lines: dict[str, Any] = {}
        for vline, current_lines in sorted(by_line.items()):
            origins = origins_by_line[vline]
            families = families_by_line[vline]
            kind = _merge_kind(current_lines, origins, families)
            if kind != "no_merge":
                lines[vline] = {
                    "kind": kind,
                    "origins": sorted(origins),
                    "families": sorted(families),
                    "current_lines": sorted(current_lines),
                    "tag_count": len(contexts[name]["release_lines"].get(vline, [])),
                    "sample_tags": contexts[name]["release_lines"].get(vline, [])[:8],
                }
        merge_review[name] = {
            "line_count": len(contexts[name]["release_lines"]),
            "merge_line_count": len(lines),
            "lines": lines,
        }

    affected_impact: dict[str, dict[str, Any]] = {
        name: {
            "unsafe_affected_cves": [],
            "review_affected_cves": [],
            "candidate_09_affected_cves": [],
            "per_cve": [],
        }
        for name in variants
    }
    for cve_id, rec in records.items():
        mapped_list, _unmapped = map_gt_tags_to_repo_tags(
            list(rec.get("affected_version") or []),
            repo_tags,
            mode="loose",
        )
        mapped = set(mapped_list)
        for name in variants:
            affected_lines = {tag_to_variant_line[name][tag] for tag in mapped if tag in tag_to_variant_line[name]}
            touched_merge_kinds: dict[str, list[str]] = defaultdict(list)
            for line in sorted(affected_lines):
                detail = merge_review[name]["lines"].get(line)
                if detail:
                    touched_merge_kinds[detail["kind"]].append(line)
            row = {
                "cve_id": cve_id,
                "affected_tag_count": len(mapped),
                "affected_lines": sorted(affected_lines),
                "touched_merge_kinds": {k: sorted(v) for k, v in touched_merge_kinds.items()},
            }
            affected_impact[name]["per_cve"].append(row)
            if any(k.startswith("unsafe_") for k in touched_merge_kinds):
                affected_impact[name]["unsafe_affected_cves"].append(row)
            if "review_patch_series_merge" in touched_merge_kinds:
                affected_impact[name]["review_affected_cves"].append(row)
            if "candidate_legacy_mainline_09_merge" in touched_merge_kinds:
                affected_impact[name]["candidate_09_affected_cves"].append(row)

    variant_summary = json.loads((args.variant_dir / "summary.json").read_text(encoding="utf-8"))
    metrics_by_variant = variant_summary["overall"]
    current_avg = float(metrics_by_variant["current"]["avg_probes"])
    variant_decisions: dict[str, Any] = {}
    for name, metrics in metrics_by_variant.items():
        unsafe_count = len(affected_impact[name]["unsafe_affected_cves"])
        review_count = len(affected_impact[name]["review_affected_cves"])
        candidate_09_count = len(affected_impact[name]["candidate_09_affected_cves"])
        avg = float(metrics["avg_probes"])
        probe_reduction = round((current_avg - avg) / current_avg, 4) if current_avg else 0.0
        if name == "generic_major_minor_single_family":
            decision = "reject: unsafe cross-origin affected cases"
        elif name == "current_plus_merge_mainline_09":
            decision = "candidate: safe-first guarded OpenSSL strategy"
        elif name == "major_minor_family_partition":
            decision = "candidate-after-review: lower cost but patch-series merges need review"
        elif name == "hybrid_patch_series_family_partition":
            decision = "candidate: equivalent to current_plus_merge_mainline_09 in this run"
        else:
            decision = "baseline"
        variant_decisions[name] = {
            "metrics": metrics,
            "probe_reduction_vs_current": probe_reduction,
            "unsafe_affected_cves": unsafe_count,
            "review_affected_cves": review_count,
            "candidate_09_affected_cves": candidate_09_count,
            "decision": decision,
        }

    summary = {
        "metadata": {
            "dataset": str(args.dataset),
            "repo_root": str(args.repo_root),
            "repo": REPO,
            "cves": len(records),
            "release_tags": len(repo_tags),
            "variant_summary_source": str(args.variant_dir / "summary.json"),
            "gt_note": "GT is used only for affected-line impact review and final metrics.",
        },
        "variant_decisions": variant_decisions,
        "merge_review": merge_review,
    }
    recommendation = (
        "Do not use generic_major_minor_single_family for OpenSSL. "
        "If source code is changed, first implement a guarded OpenSSL option equivalent to "
        "`current_plus_merge_mainline_09`: merge only mainline 0.9.x current lines, keep "
        "fips/engine families separate, and keep 1.x patch-series lines unchanged. "
        "`major_minor_family_partition` has better probe reduction but should wait for manual "
        "review of patch-series affected cases."
    )
    summary["recommendation"] = recommendation

    args.out_dir.mkdir(parents=True, exist_ok=True)
    _write_json(args.out_dir / "summary.json", summary)
    _write_json(args.out_dir / "merge_review.json", merge_review)
    _write_json(args.out_dir / "affected_impact.json", affected_impact)
    _write_report(args.out_dir / "report.md", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
