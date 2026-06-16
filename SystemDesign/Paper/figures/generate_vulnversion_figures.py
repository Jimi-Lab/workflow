from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


FIG_DIR = Path(__file__).resolve().parent
WORKFLOW_ROOT = FIG_DIR.parents[2]
RESULT_ROOT = WORKFLOW_ROOT / "VulnVersion" / "Result"


PAPER_TABLE3_BASELINES: list[dict[str, Any]] = [
    {"type": "Tracing-based", "tool": "VCCFinder", "vuln_tp": 506, "accuracy_pct": 44.9, "no_miss": 776, "nmr_pct": 68.8, "version_fp": 12020, "version_fn": 13879, "version_tp": 45308, "precision_pct": 79.0, "recall_pct": 76.6, "f1_pct": 77.8, "dataset_note": "paper_1128_cves"},
    {"type": "Tracing-based", "tool": "V-SZZ", "vuln_tp": 468, "accuracy_pct": 41.5, "no_miss": 768, "nmr_pct": 68.1, "version_fp": 16086, "version_fn": 12215, "version_tp": 46972, "precision_pct": 74.5, "recall_pct": 79.4, "f1_pct": 76.8, "dataset_note": "paper_1128_cves"},
    {"type": "Tracing-based", "tool": "Lifetime", "vuln_tp": 505, "accuracy_pct": 44.8, "no_miss": 773, "nmr_pct": 68.5, "version_fp": 11974, "version_fn": 13922, "version_tp": 45265, "precision_pct": 79.1, "recall_pct": 76.5, "f1_pct": 77.8, "dataset_note": "paper_1128_cves"},
    {"type": "Tracing-based", "tool": "SEM-SZZ", "vuln_tp": 463, "accuracy_pct": 41.0, "no_miss": 621, "nmr_pct": 55.1, "version_fp": 6257, "version_fn": 21375, "version_tp": 37812, "precision_pct": 85.8, "recall_pct": 63.9, "f1_pct": 73.2, "dataset_note": "paper_1128_cves"},
    {"type": "Tracing-based", "tool": "TC-SZZ", "vuln_tp": 195, "accuracy_pct": 17.3, "no_miss": 518, "nmr_pct": 45.9, "version_fp": 24356, "version_fn": 23719, "version_tp": 35468, "precision_pct": 59.3, "recall_pct": 59.9, "f1_pct": 59.6, "dataset_note": "paper_1128_cves"},
    {"type": "Tracing-based", "tool": "LLM4SZZ", "vuln_tp": 459, "accuracy_pct": 40.7, "no_miss": 664, "nmr_pct": 58.9, "version_fp": 9491, "version_fn": 20281, "version_tp": 38906, "precision_pct": 80.4, "recall_pct": 65.7, "f1_pct": 72.3, "dataset_note": "paper_1128_cves"},
    {"type": "Matching-based", "tool": "ReDeBug", "vuln_tp": 417, "accuracy_pct": 37.0, "no_miss": 536, "nmr_pct": 47.5, "version_fp": 3989, "version_fn": 23289, "version_tp": 35898, "precision_pct": 90.0, "recall_pct": 60.7, "f1_pct": 72.5, "dataset_note": "paper_1128_cves"},
    {"type": "Matching-based", "tool": "VUDDY", "vuln_tp": 243, "accuracy_pct": 21.5, "no_miss": 296, "nmr_pct": 26.2, "version_fp": 1227, "version_fn": 39426, "version_tp": 19761, "precision_pct": 94.2, "recall_pct": 33.4, "f1_pct": 49.3, "dataset_note": "paper_1128_cves"},
    {"type": "Matching-based", "tool": "MOVERY", "vuln_tp": 374, "accuracy_pct": 33.2, "no_miss": 622, "nmr_pct": 55.1, "version_fp": 11604, "version_fn": 18642, "version_tp": 40545, "precision_pct": 77.7, "recall_pct": 68.5, "f1_pct": 72.8, "dataset_note": "paper_1128_cves"},
    {"type": "Matching-based", "tool": "V1SCAN", "vuln_tp": 326, "accuracy_pct": 28.9, "no_miss": 424, "nmr_pct": 37.6, "version_fp": 2692, "version_fn": 26719, "version_tp": 32468, "precision_pct": 92.3, "recall_pct": 54.9, "f1_pct": 68.8, "dataset_note": "paper_1128_cves"},
    {"type": "Matching-based", "tool": "FIRE", "vuln_tp": 406, "accuracy_pct": 36.0, "no_miss": 517, "nmr_pct": 45.8, "version_fp": 4316, "version_fn": 23236, "version_tp": 35951, "precision_pct": 89.3, "recall_pct": 60.7, "f1_pct": 72.3, "dataset_note": "paper_1128_cves"},
    {"type": "Matching-based", "tool": "VULTURE", "vuln_tp": 44, "accuracy_pct": 3.9, "no_miss": 622, "nmr_pct": 55.1, "version_fp": 54889, "version_fn": 28063, "version_tp": 31124, "precision_pct": 36.2, "recall_pct": 52.6, "f1_pct": 42.9, "dataset_note": "paper_1128_cves"},
]


VALID_SEMANTIC_STATUS = {"OK", "PREFILTER", "BISECT_INFER"}


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, "") for k in fieldnames})


def pct(x: float) -> float:
    return round(x * 100.0, 1)


def safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def load_pred_affected(verdict_path: Path) -> tuple[set[str], dict[str, int], dict[str, int]]:
    pred: set[str] = set()
    status_counts: dict[str, int] = {}
    verdict_counts: dict[str, int] = {}
    if not verdict_path.exists():
        return pred, status_counts, verdict_counts
    for line in verdict_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue
        tag = str(row.get("tag") or "")
        status = str(row.get("run_status") or "PARSE_ERROR")
        verdict = str(row.get("verdict") or "UNKNOWN")
        status_counts[status] = status_counts.get(status, 0) + 1
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        if tag and status in VALID_SEMANTIC_STATUS and verdict == "AFFECTED":
            pred.add(tag)
    return pred, status_counts, verdict_counts


def load_resource_metrics(case_dir: Path) -> dict[str, Any]:
    """Summarize exported OpenCode messages.

    Current main.py exports the shared/root session messages only. Stage 3 uses
    per-tag sessions and those sessions are not fully exported in the current
    result layout, so these values are lower bounds for total LLM usage.
    """
    path = case_dir / "opencode_messages.json"
    out = {
        "exported_messages": 0,
        "assistant_turns_exported": 0,
        "input_tokens_exported": 0,
        "output_tokens_exported": 0,
        "cache_read_tokens_exported": 0,
        "cache_write_tokens_exported": 0,
        "total_tokens_exported": 0,
        "cost_usd_exported": 0.0,
    }
    if not path.exists():
        return out
    try:
        messages = read_json(path)
    except Exception:
        return out
    if not isinstance(messages, list):
        return out
    out["exported_messages"] = len(messages)
    for msg in messages:
        info = msg.get("info") if isinstance(msg, dict) else {}
        if not isinstance(info, dict):
            continue
        if info.get("role") == "assistant":
            out["assistant_turns_exported"] += 1
        tokens = info.get("tokens") or {}
        if isinstance(tokens, dict):
            out["input_tokens_exported"] += int(tokens.get("input") or 0)
            out["output_tokens_exported"] += int(tokens.get("output") or 0)
            out["total_tokens_exported"] += int(tokens.get("total") or 0)
            cache = tokens.get("cache") or {}
            if isinstance(cache, dict):
                out["cache_read_tokens_exported"] += int(cache.get("read") or 0)
                out["cache_write_tokens_exported"] += int(cache.get("write") or 0)
        out["cost_usd_exported"] += float(info.get("cost") or 0.0)
    out["cost_usd_exported"] = round(out["cost_usd_exported"], 8)
    return out


def collect_case_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case_dir in sorted([p for p in RESULT_ROOT.glob("*/*") if p.is_dir()]):
        repo = case_dir.parent.name
        cve = case_dir.name
        eval_path = case_dir / "eval.json"
        verdict_path = case_dir / "per_tag_verdict.jsonl"
        dataset_path = case_dir / "dataset_record.json"
        run_error_path = case_dir / "run_error.json"

        pred, status_counts, verdict_counts = load_pred_affected(verdict_path)
        partial_pred_count = len(pred)
        gt_raw: set[str] = set()
        gt_mapped: set[str] = set()
        gt_unmapped: set[str] = set()
        scanned: set[str] = set()
        status = "ok"
        error_type = ""

        if eval_path.exists():
            e = read_json(eval_path)
            gt_raw = set(map(str, e.get("gt_affected_tags") or []))
            gt_mapped = set(map(str, e.get("mapped_gt_tags") or []))
            gt_unmapped = set(map(str, e.get("unmapped_gt_tags") or []))
            scanned = set(map(str, e.get("scanned_tags") or []))
            if not status_counts:
                status_counts = dict(e.get("run_status_counts") or {})
        else:
            status = "failed"
            # Paper-comparable scoring should not credit an incomplete run as
            # a successful tool output. Keep partial verdict counts only for
            # diagnostics, but score failed CVEs as empty predictions.
            pred = set()
            if dataset_path.exists():
                d = read_json(dataset_path)
                gt_raw = set(map(str, d.get("affected_version") or []))
                gt_mapped = set(gt_raw)
            if run_error_path.exists():
                err = read_json(run_error_path)
                error_type = str(err.get("type") or err.get("error_type") or "")

        tp = len(gt_mapped & pred)
        fp = len(pred - gt_mapped)
        fn = len(gt_mapped - pred) + len(gt_unmapped)
        precision = safe_div(tp, tp + fp)
        recall = safe_div(tp, tp + fn)
        f1 = safe_div(2 * precision * recall, precision + recall)
        exact_match = bool(pred == gt_mapped and not gt_unmapped and status == "ok")
        no_miss = bool(gt_mapped <= pred and not gt_unmapped and status == "ok")
        resource = load_resource_metrics(case_dir)

        row: dict[str, Any] = {
            "repo": repo,
            "cve": cve,
            "status": status,
            "error_type": error_type,
            "gt_raw_count": len(gt_raw),
            "gt_mapped_count": len(gt_mapped),
            "gt_unmapped_count": len(gt_unmapped),
            "pred_affected_count": len(pred),
            "partial_pred_affected_count": partial_pred_count,
            "scanned_count": len(scanned),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "exact_match": int(exact_match),
            "no_miss": int(no_miss),
            "run_status_counts_json": json.dumps(status_counts, ensure_ascii=False, sort_keys=True),
            "verdict_counts_json": json.dumps(verdict_counts, ensure_ascii=False, sort_keys=True),
        }
        row.update(resource)
        rows.append(row)
    return rows


def aggregate_rows(rows: list[dict[str, Any]], *, label: str, group_key: str | None = None) -> list[dict[str, Any]] | dict[str, Any]:
    def agg(sub: list[dict[str, Any]], name: str) -> dict[str, Any]:
        n = len(sub)
        tp = sum(int(r["tp"]) for r in sub)
        fp = sum(int(r["fp"]) for r in sub)
        fn = sum(int(r["fn"]) for r in sub)
        precision = safe_div(tp, tp + fp)
        recall = safe_div(tp, tp + fn)
        f1 = safe_div(2 * precision * recall, precision + recall)
        exact = sum(int(r["exact_match"]) for r in sub)
        nm = sum(int(r["no_miss"]) for r in sub)
        failed = sum(1 for r in sub if r["status"] != "ok")
        return {
            "group": name,
            "cases": n,
            "completed_cases": n - failed,
            "failed_cases": failed,
            "exact_match_count": exact,
            "accuracy": safe_div(exact, n),
            "no_miss_count": nm,
            "nmr": safe_div(nm, n),
            "version_tp": tp,
            "version_fp": fp,
            "version_fn": fn,
            "version_precision": precision,
            "version_recall": recall,
            "version_f1": f1,
            "exported_total_tokens": sum(int(r["total_tokens_exported"]) for r in sub),
            "exported_cost_usd": round(sum(float(r["cost_usd_exported"]) for r in sub), 8),
        }

    if group_key is None:
        return agg(rows, label)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row[group_key]), []).append(row)
    return [agg(sub, key) for key, sub in sorted(grouped.items())]


def table3_vulnversion_row(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "Agent-based",
        "tool": "VulnVersion-current32",
        "vuln_tp": int(summary["exact_match_count"]),
        "accuracy_pct": pct(float(summary["accuracy"])),
        "no_miss": int(summary["no_miss_count"]),
        "nmr_pct": pct(float(summary["nmr"])),
        "version_fp": int(summary["version_fp"]),
        "version_fn": int(summary["version_fn"]),
        "version_tp": int(summary["version_tp"]),
        "precision_pct": pct(float(summary["version_precision"])),
        "recall_pct": pct(float(summary["version_recall"])),
        "f1_pct": pct(float(summary["version_f1"])),
        "dataset_note": f"current_{int(summary['cases'])}_case_subset; not paper full 1128 CVEs",
    }


def write_markdown_table(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = ["type", "tool", "vuln_tp", "accuracy_pct", "no_miss", "nmr_pct", "version_fp", "version_fn", "version_tp", "precision_pct", "recall_pct", "f1_pct", "dataset_note"]
    header = "| " + " | ".join(fields) + " |"
    sep = "| " + " | ".join(["---"] * len(fields)) + " |"
    lines = [header, sep]
    for r in rows:
        lines.append("| " + " | ".join(str(r.get(f, "")) for f in fields) + " |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def make_figures(table_rows: list[dict[str, Any]], repo_rows: list[dict[str, Any]], case_rows: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    try:
        import matplotlib.pyplot as plt
    except Exception as exc:
        (FIG_DIR / "figure_generation_skipped.txt").write_text(f"matplotlib unavailable: {type(exc).__name__}: {exc}\n", encoding="utf-8")
        return

    # Table III plus VulnVersion row as a PNG.
    table_fields = ["type", "tool", "accuracy_pct", "nmr_pct", "precision_pct", "recall_pct", "f1_pct", "dataset_note"]
    cell_text = [[str(r.get(f, "")) for f in table_fields] for r in table_rows]
    fig, ax = plt.subplots(figsize=(18, 8))
    ax.axis("off")
    tbl = ax.table(cellText=cell_text, colLabels=table_fields, loc="center", cellLoc="center")
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(8)
    tbl.scale(1, 1.3)
    ax.set_title("Paper Table III Baselines + VulnVersion Current 32-case Subset", fontsize=14, pad=12)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "table3_with_vulnversion_current32.png", dpi=220)
    plt.close(fig)

    # Baseline F1 comparison.
    sorted_rows = sorted(table_rows, key=lambda r: float(r["f1_pct"]), reverse=True)
    labels = [r["tool"] for r in sorted_rows]
    vals = [float(r["f1_pct"]) for r in sorted_rows]
    colors = ["#c0392b" if "VulnVersion" in x else "#4c78a8" for x in labels]
    fig, ax = plt.subplots(figsize=(13, 5))
    ax.bar(labels, vals, color=colors)
    ax.set_ylabel("Version-level F1 (%)")
    ax.set_title("Version-level F1: Paper Table III Baselines vs VulnVersion Current Subset")
    ax.tick_params(axis="x", rotation=55)
    ax.set_ylim(0, max(vals) * 1.18)
    for i, v in enumerate(vals):
        ax.text(i, v + 1, f"{v:.1f}", ha="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "table3_f1_bar_with_vulnversion.png", dpi=220)
    plt.close(fig)

    # VulnVersion repo-level F1.
    repo_sorted = sorted(repo_rows, key=lambda r: str(r["group"]))
    fig, ax = plt.subplots(figsize=(11, 5))
    labels = [r["group"] for r in repo_sorted]
    vals = [pct(float(r["version_f1"])) for r in repo_sorted]
    ax.bar(labels, vals, color="#59a14f")
    ax.set_ylabel("Version-level micro F1 within repo (%)")
    ax.set_title("VulnVersion Current Results by Repo")
    ax.tick_params(axis="x", rotation=45)
    for i, v in enumerate(vals):
        ax.text(i, v + 1, f"{v:.1f}", ha="center", fontsize=8)
    ax.set_ylim(0, max(vals + [1]) * 1.2)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "vulnversion_repo_f1_bar.png", dpi=220)
    plt.close(fig)

    # Case-level F1 distribution.
    fig, ax = plt.subplots(figsize=(14, 6))
    case_sorted = sorted(case_rows, key=lambda r: (r["repo"], r["cve"]))
    labels = [f"{r['repo']}/{r['cve'].replace('CVE-', '')}" for r in case_sorted]
    vals = [pct(float(r["f1"])) for r in case_sorted]
    colors = ["#bab0ac" if r["status"] != "ok" else "#f28e2b" for r in case_sorted]
    ax.bar(range(len(labels)), vals, color=colors)
    ax.set_ylabel("Per-CVE version-level F1 (%)")
    ax.set_title("VulnVersion Current 32-case Per-CVE F1")
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=75, ha="right", fontsize=7)
    ax.set_ylim(0, 105)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "vulnversion_case_f1_bar.png", dpi=220)
    plt.close(fig)

    # Failure and exact/no-miss summary.
    fig, ax = plt.subplots(figsize=(7, 4))
    names = ["Exact Match", "No Miss", "Failed Case"]
    vals = [int(summary["exact_match_count"]), int(summary["no_miss_count"]), int(summary["failed_cases"])]
    ax.bar(names, vals, color=["#4e79a7", "#76b7b2", "#e15759"])
    ax.set_title("VulnVersion CVE-level Counts on Current 32 Cases")
    ax.set_ylabel("CVE count")
    for i, v in enumerate(vals):
        ax.text(i, v + 0.3, str(v), ha="center")
    fig.tight_layout()
    fig.savefig(FIG_DIR / "vulnversion_cve_level_counts.png", dpi=220)
    plt.close(fig)


def main() -> None:
    case_rows = collect_case_rows()
    summary = aggregate_rows(case_rows, label="VulnVersion-current32")
    assert isinstance(summary, dict)
    repo_rows = aggregate_rows(case_rows, label="repo", group_key="repo")
    assert isinstance(repo_rows, list)

    table3_rows = PAPER_TABLE3_BASELINES + [table3_vulnversion_row(summary)]
    table_fields = ["type", "tool", "vuln_tp", "accuracy_pct", "no_miss", "nmr_pct", "version_fp", "version_fn", "version_tp", "precision_pct", "recall_pct", "f1_pct", "dataset_note"]
    case_fields = [
        "repo", "cve", "status", "error_type", "gt_raw_count", "gt_mapped_count", "gt_unmapped_count",
        "pred_affected_count", "partial_pred_affected_count", "scanned_count", "tp", "fp", "fn", "precision", "recall", "f1",
        "exact_match", "no_miss", "run_status_counts_json", "verdict_counts_json",
        "exported_messages", "assistant_turns_exported", "input_tokens_exported", "output_tokens_exported",
        "cache_read_tokens_exported", "cache_write_tokens_exported", "total_tokens_exported", "cost_usd_exported",
    ]
    summary_fields = ["group", "cases", "completed_cases", "failed_cases", "exact_match_count", "accuracy", "no_miss_count", "nmr", "version_tp", "version_fp", "version_fn", "version_precision", "version_recall", "version_f1", "exported_total_tokens", "exported_cost_usd"]

    write_csv(FIG_DIR / "paper_table3_baselines.csv", PAPER_TABLE3_BASELINES, table_fields)
    write_csv(FIG_DIR / "table3_with_vulnversion_current32.csv", table3_rows, table_fields)
    write_markdown_table(FIG_DIR / "table3_with_vulnversion_current32.md", table3_rows)
    write_csv(FIG_DIR / "vulnversion_current_case_metrics.csv", case_rows, case_fields)
    write_csv(FIG_DIR / "vulnversion_repo_summary.csv", repo_rows, summary_fields)
    write_csv(FIG_DIR / "vulnversion_current_summary.csv", [summary], summary_fields)

    report = {
        "source_result_root": str(RESULT_ROOT),
        "paper_table": "Table III from Vulnerability-affected versions identification: How far are we?",
        "baseline_dataset_note": "Paper baseline values are from the 1128-CVE dataset reported in Table III.",
        "vulnversion_dataset_note": "VulnVersion row is computed only from current local Result directory (32 CVE case directories), including failed cases as empty predictions.",
        "resource_note": "Token/cost fields are lower bounds from exported opencode_messages.json; current result layout does not export every per-tag stage3 session.",
        "summary": summary,
        "failure_cases": [
            {"repo": r["repo"], "cve": r["cve"], "error_type": r["error_type"], "fn": r["fn"]}
            for r in case_rows if r["status"] != "ok"
        ],
    }
    (FIG_DIR / "vulnversion_current_summary.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (FIG_DIR / "vulnversion_vs_table3_notes.txt").write_text(
        "\n".join([
            "Generated comparison artifacts for VulnVersion current local results.",
            "Important: the VulnVersion row is NOT a full-paper-dataset result.",
            "Paper Table III baselines use 1128 CVEs; VulnVersion-current32 uses the 32 CVE result directories currently present under VulnVersion/Result.",
            "Failed VulnVersion cases are included as empty predictions to avoid inflating effectiveness.",
            "Use table3_with_vulnversion_current32.csv/png for visual comparison, and vulnversion_current_case_metrics.csv for audit.",
        ]) + "\n",
        encoding="utf-8",
    )
    make_figures(table3_rows, repo_rows, case_rows, summary)


if __name__ == "__main__":
    main()
