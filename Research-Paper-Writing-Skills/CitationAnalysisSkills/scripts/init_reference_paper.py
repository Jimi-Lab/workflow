#!/usr/bin/env python3
"""Initialize a standard CitationAnalysis reference-paper directory."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path


DEFAULT_REFERENCE_ROOT = Path(r"E:\AI\Agent\workflow\Paper\reference")


ANALYSIS_FILES = [
    "00_meta.txt",
    "01_abstract.txt",
    "02_introduction.txt",
    "03_background_motivation.txt",
    "04_problem_definition.txt",
    "05_method.txt",
    "06_experiments.txt",
    "07_evaluation.txt",
    "08_limitations_ethics.txt",
    "09_figures_tables.txt",
    "10_writing_patterns.txt",
    "11_relevance_to_our_paper.txt",
    "12_artifact_consistency.txt",
    "13_completeness_audit.txt",
]


RAW_SUBDIRS = [
    "page_text",
    "layout_blocks",
    "section_text",
    "tables",
    "figures",
    "formulas",
    "algorithms",
    "prompts",
]


def slugify(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    return value.strip("_") or "untitled"


def next_paper_id(reference_root: Path, title: str, year: str | None) -> str:
    max_id = 0
    if reference_root.exists():
        for path in reference_root.iterdir():
            match = re.match(r"^p(\d+)_", path.name)
            if match:
                max_id = max(max_id, int(match.group(1)))
    suffix = slugify(title)
    if year:
        suffix = f"{suffix}_{year}"
    return f"p{max_id + 1:02d}_{suffix}"


def write_if_missing(path: Path, content: str, force: bool = False) -> bool:
    if path.exists() and not force:
        return False
    path.write_text(content, encoding="utf-8")
    return True


def source_manifest(args: argparse.Namespace, paper_id: str) -> str:
    return "\n".join([
        f"Paper ID: {paper_id}",
        f"Original PDF Path: {args.pdf_path or ''}",
        "Original Text Path: ",
        f"Source Code Path or URL: {args.source_path or ''}",
        f"Artifact/Data Path or URL: {args.artifact_path or ''}",
        f"Extraction Date: {date.today().isoformat()}",
        "Extraction Tools: ",
        f"Artifact Type: {args.artifact_type}",
        "Notes: initialized by init_reference_paper.py",
        "",
    ])


def extraction_log() -> str:
    return "\n".join([
        "Status: initialized",
        "Tools Used: ",
        "Successful Outputs: ",
        "Failed Outputs: ",
        "Pages With Empty Text: ",
        "OCR Needed: unknown",
        "Tables Extracted: not attempted",
        "Figures/Captions Extracted: not attempted",
        "References Extracted: not attempted",
        "Known Losses: raw extraction not performed yet",
        "Next Repair Step: run raw extraction and build_agent_index.py",
        "",
    ])


def extraction_profile() -> str:
    return "\n".join([
        "Primary Consumer: agent",
        "PDF Text Layer: missing",
        "Layout Block Layer: missing/not attempted",
        "Table Layer: missing",
        "Figure Layer: missing",
        "Formula Layer: not detected/not attempted",
        "Algorithm Layer: not detected/not attempted",
        "Prompt Layer: not detected/not attempted",
        "Known Ordering Losses: raw extraction not performed yet",
        "Known Layout Losses: raw extraction not performed yet",
        "Agent Retrieval Usability: low",
        "Citation Readiness: low",
        "Next Repair Step: run raw extraction and build_agent_index.py",
        "",
    ])


def agent_index(paper_id: str, title: str) -> str:
    data = {
        "paper_id": paper_id,
        "title": title,
        "source_manifest": "00_source_manifest.txt",
        "extraction_profile": "extraction_profile.txt",
        "generated_by": "init_reference_paper.py",
        "evidence_units": [],
        "known_gaps": [
            "[NEEDS EVIDENCE] raw extraction not performed yet",
            "[NEEDS TABLE REPAIR] tables not extracted yet",
            "[NEEDS FIGURE EXTRACTION] figures not extracted yet",
            "[NEEDS LAYOUT BLOCK EXTRACTION] layout blocks not extracted yet",
            "[NEEDS CITATION VERIFICATION] references not verified yet",
        ],
    }
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def metadata(args: argparse.Namespace, paper_id: str) -> str:
    data = {
        "paper_id": paper_id,
        "title": args.title or "",
        "authors": [],
        "venue": "",
        "year": args.year or "",
        "doi": "",
        "arxiv": "",
        "pdf_path": args.pdf_path or "",
        "artifact_type": args.artifact_type,
        "page_count": None,
        "citation_status": "unverified",
    }
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def analysis_template(filename: str, paper_id: str) -> str:
    return "\n".join([
        f"Paper ID: {paper_id}",
        f"Analysis File: {filename}",
        "Status: initialized",
        "",
        "[NEEDS EVIDENCE]",
        "",
    ])


def init_reference(args: argparse.Namespace) -> tuple[Path, int]:
    reference_root = args.reference_root
    paper_id = args.paper_id or next_paper_id(reference_root, args.title or "untitled", args.year)
    paper_dir = reference_root / paper_id
    raw_dir = paper_dir / "raw_extraction"
    analysis_dir = paper_dir / "analysis"

    created = 0
    for directory in [paper_dir, raw_dir, analysis_dir]:
        directory.mkdir(parents=True, exist_ok=True)
    for subdir in RAW_SUBDIRS:
        (raw_dir / subdir).mkdir(parents=True, exist_ok=True)

    templates = {
        raw_dir / "00_source_manifest.txt": source_manifest(args, paper_id),
        raw_dir / "metadata.json": metadata(args, paper_id),
        raw_dir / "extraction_log.txt": extraction_log(),
        raw_dir / "extraction_profile.txt": extraction_profile(),
        raw_dir / "agent_index.json": agent_index(paper_id, args.title or ""),
        raw_dir / "sections.txt": "Status: initialized\n[NEEDS SECTION SPLIT]\n",
        raw_dir / "references.txt": "Status: initialized\n[NEEDS CITATION VERIFICATION]\n",
        raw_dir / "appendix.txt": "Status: initialized\n",
    }
    for path, content in templates.items():
        created += 1 if write_if_missing(path, content, args.force) else 0

    for filename in ANALYSIS_FILES:
        path = analysis_dir / filename
        created += 1 if write_if_missing(path, analysis_template(filename, paper_id), args.force) else 0

    return paper_dir, created


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize a CitationAnalysis reference-paper directory.")
    parser.add_argument("--reference-root", type=Path, default=DEFAULT_REFERENCE_ROOT)
    parser.add_argument("--paper-id", default=None, help="Stable ID like p05_short_title_2026. If omitted, the next pNN ID is generated.")
    parser.add_argument("--title", default="", help="Paper title used when generating a paper ID and metadata.")
    parser.add_argument("--year", default="", help="Publication year.")
    parser.add_argument("--pdf-path", default="", help="Original PDF path.")
    parser.add_argument("--source-path", default="", help="Source code path or URL.")
    parser.add_argument("--artifact-path", default="", help="Artifact/data path or URL.")
    parser.add_argument("--artifact-type", default="Type U", choices=["Type A", "Type B", "Type C", "Type D", "Type U"])
    parser.add_argument("--force", action="store_true", help="Overwrite existing template files.")
    args = parser.parse_args()

    if not args.reference_root.exists():
        args.reference_root.mkdir(parents=True, exist_ok=True)

    paper_dir, created = init_reference(args)
    print(f"Initialized: {paper_dir}")
    print(f"Files created or overwritten: {created}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
