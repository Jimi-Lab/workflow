#!/usr/bin/env python3
"""Summarize CitationAnalysis reference-corpus readiness."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


DEFAULT_REFERENCE_ROOT = Path(r"E:\AI\Agent\workflow\Paper\reference")


def is_paper_dir(path: Path) -> bool:
    return path.is_dir() and re.match(r"^p\d+_", path.name) is not None


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def files_have_marker(files: list[Path], markers: list[str]) -> bool:
    text = "\n".join(read_text(path).lower()[:3000] for path in files if path.suffix.lower() in {".txt", ".md", ".csv", ".json"})
    return any(marker.lower() in text for marker in markers)


def infer_pdf_text(raw_dir: Path) -> str:
    full_text = raw_dir / "full_text.txt"
    page_dir = raw_dir / "page_text"
    page_count = len(list(page_dir.glob("*.txt"))) if page_dir.exists() else 0
    if full_text.exists() and page_count > 0:
        return f"complete ({page_count} pages)"
    if full_text.exists() or page_count > 0:
        return "partial"
    return "missing"


def infer_layout(raw_dir: Path) -> str:
    layout_dir = raw_dir / "layout_blocks"
    if layout_dir.exists() and any(layout_dir.glob("*.json")):
        return "partial"
    profile = read_text(raw_dir / "extraction_profile.txt").lower()
    if "layout block layer:" in profile:
        for line in profile.splitlines():
            if line.lower().startswith("layout block layer:"):
                return line.split(":", 1)[1].strip() or "unknown"
    return "missing"


def infer_table(raw_dir: Path) -> str:
    table_dir = raw_dir / "tables"
    if not table_dir.exists():
        return "missing"
    files = [p for p in table_dir.iterdir() if p.is_file()]
    if not files:
        return "missing"
    if files_have_marker(files, ["needs table repair", "caption-neighbor", "\"repair_needed\": true", "\"cells\": []"]):
        return "raw/caption"
    if any(p.suffix.lower() == ".csv" for p in files) or any(p.name.endswith("_cells.json") for p in files):
        return "structured"
    if any(p.suffix.lower() in {".md", ".txt"} for p in files):
        return "raw/caption"
    return "partial"


def infer_figure(raw_dir: Path) -> str:
    figure_dir = raw_dir / "figures"
    if not figure_dir.exists():
        return "missing"
    files = [p for p in figure_dir.iterdir() if p.is_file()]
    if not files:
        return "missing"
    image_exts = {".png", ".jpg", ".jpeg", ".webp", ".tif", ".tiff"}
    has_image = any(p.suffix.lower() in image_exts for p in files)
    has_caption = any("caption" in p.name.lower() for p in files)
    has_repair_marker = files_have_marker(files, ["needs figure extraction", "page crop", "page-crop", "not precise figure crop", "not verified"])
    if has_image and has_caption:
        return "page-crop+caption" if has_repair_marker else "image+caption"
    if has_image:
        return "image-only"
    if has_caption:
        return "caption-only"
    return "partial"


def infer_artifact_static(raw_dir: Path) -> str:
    inventory = raw_dir / "source_static_inventory.txt"
    if inventory.exists():
        return "yes"
    manifest = read_text(raw_dir / "00_source_manifest.txt").lower()
    source_markers = ["source code path:", "source code path or url:", "artifact/data path or url:"]
    has_nonempty_source = False
    for line in manifest.splitlines():
        lowered = line.lower()
        if any(lowered.startswith(marker) for marker in source_markers):
            value = line.split(":", 1)[1].strip() if ":" in line else ""
            if value and value.lower() not in {"none", "n/a", "na", "not available", "unknown"}:
                has_nonempty_source = True
    if has_nonempty_source:
        return "missing inventory"
    return "not applicable/unknown"


def infer_writing_readiness(paper_dir: Path, raw_dir: Path, analysis_dir: Path) -> str:
    if not analysis_dir.exists():
        return "low"
    audit = read_text(analysis_dir / "13_completeness_audit.txt").lower()
    if "usefulness grade:" in audit:
        for line in audit.splitlines():
            if line.lower().startswith("usefulness grade:"):
                return line.split(":", 1)[1].strip() or "partial"
    required_analysis = [analysis_dir / f"{i:02d}_{name}.txt" for i, name in [
        (0, "meta"),
        (1, "abstract"),
        (2, "introduction"),
        (3, "background_motivation"),
        (4, "problem_definition"),
        (5, "method"),
        (6, "experiments"),
        (7, "evaluation"),
        (8, "limitations_ethics"),
        (9, "figures_tables"),
        (10, "writing_patterns"),
        (11, "relevance_to_our_paper"),
        (12, "artifact_consistency"),
    ]]
    has_all_analysis = all(p.exists() for p in required_analysis)
    has_agent = (raw_dir / "agent_index.json").exists() and (raw_dir / "extraction_profile.txt").exists()
    if has_all_analysis and has_agent:
        return "medium"
    if has_all_analysis:
        return "partial"
    return "low"


def collect_missing(raw_dir: Path, analysis_dir: Path) -> str:
    gaps: list[str] = []
    checks = [
        (raw_dir / "agent_index.json", "NEEDS_AGENT_INDEX"),
        (raw_dir / "extraction_profile.txt", "NEEDS_EXTRACTION_PROFILE"),
        (analysis_dir / "13_completeness_audit.txt", "NEEDS_COMPLETENESS_AUDIT"),
    ]
    for path, label in checks:
        if not path.exists():
            gaps.append(label)

    audit = read_text(analysis_dir / "13_completeness_audit.txt")
    for label in sorted(set(re.findall(r"\[(NEEDS [^\]]+|EXECUTION NOT REQUESTED)\]", audit))):
        normalized = label.replace(" ", "_")
        if normalized not in gaps:
            gaps.append(normalized)

    agent_index = raw_dir / "agent_index.json"
    if agent_index.exists():
        try:
            data = json.loads(agent_index.read_text(encoding="utf-8"))
            known_gaps = data.get("known_gaps", [])
            if isinstance(known_gaps, list):
                for item in known_gaps:
                    for label in re.findall(r"\[(NEEDS [^\]]+|EXECUTION NOT REQUESTED)\]", str(item)):
                        normalized = label.replace(" ", "_")
                        if normalized not in gaps:
                            gaps.append(normalized)
        except Exception as exc:  # noqa: BLE001 - surface corrupt index as a corpus gap
            label = f"INVALID_AGENT_INDEX:{exc}"
            if label not in gaps:
                gaps.append(label)

    if not gaps:
        return "none recorded"
    return "; ".join(gaps)


def build_rows(reference_root: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for paper_dir in sorted([p for p in reference_root.iterdir() if is_paper_dir(p)], key=lambda p: p.name):
        raw_dir = paper_dir / "raw_extraction"
        analysis_dir = paper_dir / "analysis"
        rows.append({
            "paper_id": paper_dir.name,
            "pdf_text": infer_pdf_text(raw_dir),
            "layout": infer_layout(raw_dir),
            "table": infer_table(raw_dir),
            "figure": infer_figure(raw_dir),
            "artifact_static": infer_artifact_static(raw_dir),
            "writing_readiness": infer_writing_readiness(paper_dir, raw_dir, analysis_dir),
            "missing_evidence": collect_missing(raw_dir, analysis_dir),
        })
    return rows


def render_markdown(rows: list[dict[str, str]]) -> str:
    headers = [
        "paper_id",
        "pdf_text",
        "layout",
        "table",
        "figure",
        "artifact_static",
        "writing_readiness",
        "missing_evidence",
    ]
    lines = ["# CitationAnalysis Corpus Status", ""]
    if not rows:
        lines.append("No paper directories found.")
        return "\n".join(lines)
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for row in rows:
        values = [row[h].replace("|", "\\|") for h in headers]
        lines.append("| " + " | ".join(values) + " |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize CitationAnalysis corpus readiness.")
    parser.add_argument("--reference-root", type=Path, default=DEFAULT_REFERENCE_ROOT)
    parser.add_argument("--out", type=Path, default=None, help="Markdown output path. Defaults to <reference-root>/00_corpus_status.md.")
    parser.add_argument("--no-write", action="store_true", help="Print only; do not write a file.")
    args = parser.parse_args()

    if not args.reference_root.exists():
        print(f"Reference root does not exist: {args.reference_root}", file=sys.stderr)
        return 1

    rows = build_rows(args.reference_root)
    markdown = render_markdown(rows)
    print(markdown)

    if not args.no_write:
        out = args.out or (args.reference_root / "00_corpus_status.md")
        out.write_text(markdown, encoding="utf-8")
        print(f"Wrote: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
