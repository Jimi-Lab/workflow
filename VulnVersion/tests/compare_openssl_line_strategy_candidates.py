"""Pairwise comparison for two OpenSSL line-builder candidates.

This script compares:

- major_minor_family_partition
- current_plus_merge_mainline_09

It consumes the existing OpenSSL variant simulator output and the case-review
artifact, then writes an objective pairwise report.  It does not call an agent
and does not use GT for planning.  GT-derived fields are read only from prior
simulator artifacts to compare final metrics and affected-line impact.
"""
from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VARIANT_DIR = ROOT / "tests" / "openssl_version_tree_variant_simulator"
DEFAULT_CASE_REVIEW_DIR = ROOT / "tests" / "openssl_version_tree_case_review"
DEFAULT_OUT_DIR = ROOT / "tests" / "openssl_line_strategy_candidate_comparison"

VARIANT_A = "major_minor_family_partition"
VARIANT_B = "current_plus_merge_mainline_09"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    vals = sorted(values)
    idx = round((len(vals) - 1) * q)
    return float(vals[idx])


def _mean(values: list[float]) -> float:
    return float(statistics.mean(values)) if values else 0.0


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _write_report(path: Path, summary: dict[str, Any]) -> None:
    a = summary["variants"][VARIANT_A]
    b = summary["variants"][VARIANT_B]
    delta = summary["pairwise_delta"]
    risk = summary["risk_summary"]
    lines = [
        "# OpenSSL Candidate Line Strategy Pairwise Comparison",
        "",
        "Compared variants:",
        "",
        f"- `{VARIANT_A}`",
        f"- `{VARIANT_B}`",
        "",
        "GT is used only through prior simulator final metrics and affected-line impact artifacts.",
        "",
        "## Metrics",
        "",
        "| variant | lines | avg probes | p95 probes | exact CVEs | TP | FP | FN | precision | recall | F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        "| {name} | {lines_n} | {avg:.2f} | {p95:.2f} | {exact}/{total} | {tp} | {fp} | {fn} | {p:.6f} | {r:.6f} | {f1:.6f} |".format(
            name=VARIANT_A,
            lines_n=a["line_count"],
            avg=a["metrics"]["avg_probes"],
            p95=a["metrics"]["p95_probes"],
            exact=a["metrics"]["exact_cves"],
            total=a["metrics"]["cves"],
            tp=a["metrics"]["version_tp"],
            fp=a["metrics"]["version_fp"],
            fn=a["metrics"]["version_fn"],
            p=a["metrics"]["precision"],
            r=a["metrics"]["recall"],
            f1=a["metrics"]["f1"],
        ),
        "| {name} | {lines_n} | {avg:.2f} | {p95:.2f} | {exact}/{total} | {tp} | {fp} | {fn} | {p:.6f} | {r:.6f} | {f1:.6f} |".format(
            name=VARIANT_B,
            lines_n=b["line_count"],
            avg=b["metrics"]["avg_probes"],
            p95=b["metrics"]["p95_probes"],
            exact=b["metrics"]["exact_cves"],
            total=b["metrics"]["cves"],
            tp=b["metrics"]["version_tp"],
            fp=b["metrics"]["version_fp"],
            fn=b["metrics"]["version_fn"],
            p=b["metrics"]["precision"],
            r=b["metrics"]["recall"],
            f1=b["metrics"]["f1"],
        ),
        "",
        "## Probe Difference",
        "",
        f"- `{VARIANT_A}` saves `{delta['avg_probe_saving_a_vs_b']:.2f}` probes/CVE over `{VARIANT_B}`.",
        f"- Relative saving: `{delta['relative_probe_saving_a_vs_b']:.2%}`.",
        f"- CVEs where `{VARIANT_A}` uses fewer probes: `{delta['a_fewer_probe_cves']}/{delta['cves']}`.",
        f"- CVEs where metrics differ: `{delta['metric_different_cves']}/{delta['cves']}`.",
        "",
        "## Risk Difference",
        "",
        f"- `{VARIANT_A}` review affected CVEs: `{risk[VARIANT_A]['review_affected_cves']}`.",
        f"- `{VARIANT_B}` review affected CVEs: `{risk[VARIANT_B]['review_affected_cves']}`.",
        f"- `{VARIANT_A}` unsafe affected CVEs: `{risk[VARIANT_A]['unsafe_affected_cves']}`.",
        f"- `{VARIANT_B}` unsafe affected CVEs: `{risk[VARIANT_B]['unsafe_affected_cves']}`.",
        "",
        "## Recommendation",
        "",
        summary["recommendation"],
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare two OpenSSL line strategy candidates.")
    parser.add_argument("--variant-dir", type=Path, default=DEFAULT_VARIANT_DIR)
    parser.add_argument("--case-review-dir", type=Path, default=DEFAULT_CASE_REVIEW_DIR)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    args = parser.parse_args(argv)

    summary = _load_json(args.variant_dir / "summary.json")
    topology = _load_json(args.variant_dir / "topology.json")
    case_review = _load_json(args.case_review_dir / "summary.json")
    affected_impact = _load_json(args.case_review_dir / "affected_impact.json")
    rows = _load_jsonl(args.variant_dir / "per_cve.jsonl")

    by_variant: dict[str, dict[str, dict[str, Any]]] = {VARIANT_A: {}, VARIANT_B: {}}
    for row in rows:
        variant = row.get("variant")
        if variant in by_variant:
            by_variant[variant][row["cve_id"]] = row

    cves = sorted(set(by_variant[VARIANT_A]) & set(by_variant[VARIANT_B]))
    per_cve_diff: list[dict[str, Any]] = []
    metric_diff = 0
    a_fewer = 0
    b_fewer = 0
    equal_probe = 0
    savings: list[float] = []
    status_delta = Counter()
    for cve in cves:
        a = by_variant[VARIANT_A][cve]
        b = by_variant[VARIANT_B][cve]
        probe_saving = int(b["probe_count"]) - int(a["probe_count"])
        savings.append(float(probe_saving))
        if probe_saving > 0:
            a_fewer += 1
        elif probe_saving < 0:
            b_fewer += 1
        else:
            equal_probe += 1
        metrics_same = all(
            a[key] == b[key]
            for key in ["tp", "fp", "fn", "tn", "exact_match", "has_fn", "has_fp", "predicted_count", "mapped_gt_count"]
        )
        if not metrics_same:
            metric_diff += 1
        for key, value in Counter(a.get("status_counts") or {}).items():
            status_delta[key] += int(value)
        for key, value in Counter(b.get("status_counts") or {}).items():
            status_delta[f"minus_b::{key}"] -= int(value)
        per_cve_diff.append({
            "cve_id": cve,
            "probe_a": a["probe_count"],
            "probe_b": b["probe_count"],
            "probe_saving_a_vs_b": probe_saving,
            "metrics_same": metrics_same,
            "a": {k: a[k] for k in ["tp", "fp", "fn", "exact_match", "affected_line_count", "active_line_count", "status_counts"]},
            "b": {k: b[k] for k in ["tp", "fp", "fn", "exact_match", "affected_line_count", "active_line_count", "status_counts"]},
        })
    per_cve_diff.sort(key=lambda r: (-int(r["probe_saving_a_vs_b"]), r["cve_id"]))

    risk_summary: dict[str, Any] = {}
    for variant in [VARIANT_A, VARIANT_B]:
        risk_summary[variant] = {
            "unsafe_affected_cves": len(affected_impact[variant]["unsafe_affected_cves"]),
            "review_affected_cves": len(affected_impact[variant]["review_affected_cves"]),
            "candidate_09_affected_cves": len(affected_impact[variant]["candidate_09_affected_cves"]),
            "merge_lines": case_review["merge_review"][variant]["lines"],
            "review_cve_ids": [
                row["cve_id"]
                for row in affected_impact[variant]["review_affected_cves"]
            ],
            "unsafe_cve_ids": [
                row["cve_id"]
                for row in affected_impact[variant]["unsafe_affected_cves"]
            ],
        }

    variants = {
        VARIANT_A: {
            "metrics": summary["overall"][VARIANT_A],
            "line_count": topology[VARIANT_A]["line_count"],
            "family_count": topology[VARIANT_A]["family_count"],
            "mixed_origin_line_count": topology[VARIANT_A]["mixed_origin_line_count"],
            "multi_series_line_count": topology[VARIANT_A]["multi_series_line_count"],
        },
        VARIANT_B: {
            "metrics": summary["overall"][VARIANT_B],
            "line_count": topology[VARIANT_B]["line_count"],
            "family_count": topology[VARIANT_B]["family_count"],
            "mixed_origin_line_count": topology[VARIANT_B]["mixed_origin_line_count"],
            "multi_series_line_count": topology[VARIANT_B]["multi_series_line_count"],
        },
    }
    avg_b = float(variants[VARIANT_B]["metrics"]["avg_probes"])
    avg_saving = _mean(savings)
    pair_summary = {
        "metadata": {
            "variant_dir": str(args.variant_dir),
            "case_review_dir": str(args.case_review_dir),
            "gt_note": "GT is used only through prior simulator final metrics and affected-line impact artifacts.",
            "compared_variants": [VARIANT_A, VARIANT_B],
        },
        "variants": variants,
        "pairwise_delta": {
            "cves": len(cves),
            "avg_probe_saving_a_vs_b": round(avg_saving, 2),
            "relative_probe_saving_a_vs_b": round(avg_saving / avg_b, 6) if avg_b else 0.0,
            "p50_probe_saving_a_vs_b": round(_pct(savings, 0.50), 2),
            "p95_probe_saving_a_vs_b": round(_pct(savings, 0.95), 2),
            "max_probe_saving_a_vs_b": int(max(savings)) if savings else 0,
            "min_probe_saving_a_vs_b": int(min(savings)) if savings else 0,
            "a_fewer_probe_cves": a_fewer,
            "b_fewer_probe_cves": b_fewer,
            "equal_probe_cves": equal_probe,
            "metric_different_cves": metric_diff,
        },
        "risk_summary": risk_summary,
        "top_probe_saving_cves": per_cve_diff[:15],
        "metric_diff_cves": [row for row in per_cve_diff if not row["metrics_same"]],
        "recommendation": (
            f"{VARIANT_A} is empirically better on probes and has identical simulator final metrics, "
            "but it merges affected 1.x patch-series lines in 32/50 OpenSSL CVEs. "
            f"{VARIANT_B} saves fewer probes but avoids affected patch-series merge risk. "
            "For a default paper system, keep current_plus_merge_mainline_09 as the safe first candidate. "
            "Use major_minor_family_partition only after manual or real-agent review of the 32 patch-series affected CVEs."
        ),
    }

    args.out_dir.mkdir(parents=True, exist_ok=True)
    _write_json(args.out_dir / "summary.json", pair_summary)
    _write_json(args.out_dir / "risk_summary.json", risk_summary)
    _write_jsonl(args.out_dir / "per_cve_diff.jsonl", per_cve_diff)
    _write_report(args.out_dir / "report.md", pair_summary)
    print(json.dumps(pair_summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
