#!/usr/bin/env python3
"""Phase-2 evidence enhancement for CitationAnalysis PDF-only papers.

This script performs static PDF enhancement only:
- layout block extraction with PyMuPDF
- table detection via PyMuPDF Page.find_tables()
- page-crop evidence for table and figure caption pages
- URL/DOI/arXiv/GitHub extraction from text and annotations
- section retrieval map and phase-2 gap/readiness notes

It does not run paper code, install dependencies, or reproduce experiments.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from datetime import date
from pathlib import Path
from typing import Any

import fitz


WEB_METADATA: dict[str, dict[str, str]] = {
    "p14_accurate_identification_of_the_vulnerability_introducing_commit_based_on_differential_anal": {
        "venue_year": "NDSS Symposium 2026 [NEEDS CITATION VERIFICATION]",
        "source_url": "https://www.ndss-symposium.org/ndss-paper/auto-draft-548/",
        "notes": "NDSS page found for the title; exact DOI/BibTeX still needs verification.",
    },
    "p16_agentszz_teaching_the_llm_agent_to_play_detective_with_bug_inducing_commits": {
        "venue_year": "arXiv:2604.02665, 2026 [NEEDS CITATION VERIFICATION]",
        "source_url": "https://arxiv.org/abs/2604.02665",
        "notes": "arXiv page found for the title; artifact/source URL still needs confirmation from PDF or author page.",
    },
    "p19_beyond_blame_rethinking_szz_with_knowledge_graph_search": {
        "venue_year": "arXiv:2603.29378, 2026 [NEEDS CITATION VERIFICATION]",
        "source_url": "https://arxiv.org/abs/2603.29378",
        "notes": "arXiv page found for the title; artifact/source URL still needs confirmation from PDF or author page.",
    },
    "p20_cavulner_automated_context_aware_identification_of_vulnerable_versions": {
        "venue_year": "[NEEDS CITATION VERIFICATION]",
        "source_url": "",
        "notes": "PDF first page lists anonymous author(s); no verified external metadata source was recorded in this phase.",
    },
    "p25_how_and_why_agents_can_identify_bug_introducing_commits": {
        "venue_year": "arXiv:2603.29378, 2026 [NEEDS CITATION VERIFICATION]",
        "source_url": "https://arxiv.org/abs/2603.29378",
        "notes": "arXiv page found for the title; overlaps with the Beyond Blame title family and needs citation disambiguation.",
    },
    "p32_tdsc_automatically_identifying_cve_affected_versions_with_patches_and_developer_logs": {
        "venue_year": "IEEE Transactions on Dependable and Secure Computing 21(2), 2024 [NEEDS CITATION VERIFICATION]",
        "source_url": "https://www.cse.psu.edu/~gxt29/papers/TDSC2023-DY-final.pdf",
        "notes": "Public author-hosted PDF found; DOI/BibTeX still needs verification.",
    },
    "p33_vercation_precise_vulnerable_open_source_software_version_identification_based_on_static_a": {
        "venue_year": "2024 [NEEDS CITATION VERIFICATION]",
        "source_url": "https://www.smingk.com/publications/vercation.pdf",
        "notes": "Public PDF found; venue/DOI/BibTeX still needs verification.",
    },
}


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8", newline="\n")


def clean(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def rel(path: Path, paper_dir: Path) -> str:
    try:
        return path.relative_to(paper_dir).as_posix()
    except ValueError:
        return path.as_posix()


def load_metadata(raw_dir: Path) -> dict[str, Any]:
    path = raw_dir / "metadata.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_metadata(raw_dir: Path, metadata: dict[str, Any]) -> None:
    write(raw_dir / "metadata.json", json.dumps(metadata, ensure_ascii=False, indent=2))


def render_page_crop(doc: fitz.Document, page_index: int, out_path: Path, clip: fitz.Rect | None = None) -> None:
    page = doc[page_index]
    matrix = fitz.Matrix(1.8, 1.8)
    pix = page.get_pixmap(matrix=matrix, clip=clip, alpha=False)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pix.save(str(out_path))


def extract_layout_blocks(doc: fitz.Document, raw_dir: Path) -> int:
    count = 0
    for page_number, page in enumerate(doc, 1):
        blocks: list[dict[str, Any]] = []
        for block_index, block in enumerate(page.get_text("dict").get("blocks", []), 1):
            text_parts: list[str] = []
            for line in block.get("lines", []):
                for span in line.get("spans", []):
                    text_parts.append(span.get("text", ""))
            text = clean(" ".join(text_parts))
            if not text:
                continue
            blocks.append({
                "page": page_number,
                "block_id": f"page_{page_number:03d}:block_{block_index:03d}",
                "block_type": "text" if block.get("type") == 0 else str(block.get("type")),
                "text": text,
                "bbox": list(block.get("bbox", [])),
                "reading_order": len(blocks) + 1,
                "column_guess": None,
                "confidence": "medium",
            })
        write(raw_dir / "layout_blocks" / f"page_{page_number:03d}_blocks.json", json.dumps(blocks, ensure_ascii=False, indent=2))
        count += len(blocks)
    return count


def table_to_markdown(rows: list[list[str]]) -> str:
    if not rows:
        return ""
    width = max(len(row) for row in rows)
    norm = [[clean(cell) for cell in row] + [""] * (width - len(row)) for row in rows]
    header = norm[0]
    lines = ["| " + " | ".join(cell.replace("|", "/") for cell in header) + " |"]
    lines.append("| " + " | ".join(["---"] * width) + " |")
    for row in norm[1:]:
        lines.append("| " + " | ".join(cell.replace("|", "/") for cell in row) + " |")
    return "\n".join(lines)


def normalize_table_rows(rows: list[list[Any]]) -> list[list[str]]:
    return [[clean("" if cell is None else str(cell)) for cell in row] for row in rows]


def enhance_tables(doc: fitz.Document, paper_dir: Path, raw_dir: Path) -> list[dict[str, Any]]:
    table_dir = raw_dir / "tables"
    units: list[dict[str, Any]] = []
    index_lines: list[str] = []
    table_id = 1
    for page_index, page in enumerate(doc):
        try:
            found = page.find_tables()
            tables = list(found.tables)
        except Exception:
            tables = []
        for table in tables:
            rows = normalize_table_rows(table.extract())
            prefix = f"table_{table_id:03d}"
            bbox = list(table.bbox)
            csv_path = table_dir / f"{prefix}.csv"
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            with csv_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerows(rows)
            write(table_dir / f"{prefix}.md", table_to_markdown(rows) or "[NEEDS TABLE REPAIR] empty table extraction")
            write(table_dir / f"{prefix}_cells.json", json.dumps({
                "table_id": prefix,
                "page": page_index + 1,
                "bbox": bbox,
                "cells": rows,
                "repair_needed": False if rows and any(any(clean(cell) for cell in row) for row in rows) else True,
                "notes": "PyMuPDF table extraction; verify numeric values against page crop before citation use.",
            }, ensure_ascii=False, indent=2))
            context = page.get_text("text")
            write(table_dir / f"{prefix}_context.txt", f"Page: {page_index + 1}\nBBox: {bbox}\nContext:\n{context[:5000]}\n\nCitation Readiness: medium; verify against page crop.")
            crop_path = table_dir / f"{prefix}_page_crop.png"
            render_page_crop(doc, page_index, crop_path, fitz.Rect(table.bbox) + (-20, -20, 20, 20))
            index_lines.append(f"{prefix}: page {page_index + 1}, rows={len(rows)}, cols={max((len(row) for row in rows), default=0)}, crop={crop_path.name}")
            units.append({
                "id": f"{paper_dir.name}:table:{prefix}:phase2",
                "type": "table",
                "page": page_index + 1,
                "section": None,
                "topic": "phase2 table extraction",
                "text_anchor": clean(" | ".join(rows[0]))[:220] if rows else "",
                "bbox": bbox,
                "files": [rel(csv_path, paper_dir), rel(table_dir / f"{prefix}.md", paper_dir), rel(table_dir / f"{prefix}_cells.json", paper_dir), rel(crop_path, paper_dir)],
                "confidence": "medium" if rows else "partial",
                "repair_needed": False if rows else True,
                "usable_for": ["evaluation", "experiments", "numeric_followup"],
                "do_not_use_for": ["final numeric claim without page-crop verification"],
                "notes": "Phase-2 PyMuPDF table extraction. Treat as closer to citation-ready than caption-only, but still verify critical numbers.",
            })
            table_id += 1
    if index_lines:
        write(table_dir / "table_index_phase2.txt", "\n".join(index_lines))
    else:
        write(table_dir / "table_index_phase2.txt", "No tables detected by PyMuPDF Page.find_tables(). [NEEDS TABLE REPAIR]")
    return units


def caption_candidates(page_text: str, kind: str) -> list[str]:
    pattern = re.compile(rf"(?im)^\s*({kind}\s+\d+[^\n]{{0,600}})")
    return [clean(match.group(1)) for match in pattern.finditer(page_text)]


def enhance_figures(doc: fitz.Document, paper_dir: Path, raw_dir: Path) -> list[dict[str, Any]]:
    figure_dir = raw_dir / "figures"
    units: list[dict[str, Any]] = []
    index_lines: list[str] = []
    figure_id = 1
    seen: set[tuple[int, str]] = set()
    for page_index, page in enumerate(doc):
        text = page.get_text("text")
        for caption in caption_candidates(text, "Figure"):
            key = (page_index + 1, caption)
            if key in seen:
                continue
            seen.add(key)
            prefix = f"figure_{figure_id:03d}"
            caption_path = figure_dir / f"{prefix}_caption.txt"
            context_path = figure_dir / f"{prefix}_context.txt"
            crop_path = figure_dir / f"{prefix}_page_crop.png"
            write(caption_path, caption)
            write(context_path, f"Page: {page_index + 1}\nCaption: {caption}\n\nPage text context:\n{text[:5000]}\n\nFigure Readiness: page-crop+caption; exact subfigure crop still [NEEDS FIGURE EXTRACTION] if visual details are cited.")
            render_page_crop(doc, page_index, crop_path)
            write(figure_dir / f"{prefix}_agent_summary.txt", "Phase-2 page crop plus caption. Use for layout/argument inspection; verify exact visual details manually before citing.")
            index_lines.append(f"{prefix}: page {page_index + 1}, crop={crop_path.name}, caption={caption}")
            units.append({
                "id": f"{paper_dir.name}:figure:{prefix}:phase2",
                "type": "figure",
                "page": page_index + 1,
                "section": None,
                "topic": "phase2 figure page crop",
                "text_anchor": caption[:220],
                "bbox": None,
                "files": [rel(caption_path, paper_dir), rel(context_path, paper_dir), rel(crop_path, paper_dir)],
                "confidence": "medium",
                "repair_needed": False,
                "usable_for": ["method", "evaluation", "figure_followup"],
                "do_not_use_for": ["pixel-level visual claim without manual inspection"],
                "notes": "Phase-2 page crop and caption extraction.",
            })
            figure_id += 1
    if index_lines:
        write(figure_dir / "figure_index_phase2.txt", "\n".join(index_lines))
    else:
        write(figure_dir / "figure_index_phase2.txt", "No figure captions detected in phase-2 scan. [NEEDS FIGURE EXTRACTION]")
    return units


def extract_links(doc: fitz.Document, full_text: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    url_pattern = re.compile(r"https?://[^\s)\]}>,;\"']+|www\.[^\s)\]}>,;\"']+", re.I)
    for match in url_pattern.finditer(full_text):
        url = match.group(0).rstrip(".")
        if url not in seen:
            seen.add(url)
            entries.append({"kind": "text_url", "url": url, "page": None, "context": clean(full_text[max(0, match.start()-140):match.end()+140])})
    doi_pattern = re.compile(r"\b10\.\d{4,9}/[-._;()/:A-Z0-9]+\b", re.I)
    for match in doi_pattern.finditer(full_text):
        doi = match.group(0).rstrip(".")
        url = f"https://doi.org/{doi}"
        if url not in seen:
            seen.add(url)
            entries.append({"kind": "doi", "url": url, "page": None, "context": clean(full_text[max(0, match.start()-140):match.end()+140])})
    arxiv_pattern = re.compile(r"\barXiv[:\s]+(\d{4}\.\d{4,5})\b", re.I)
    for match in arxiv_pattern.finditer(full_text):
        url = f"https://arxiv.org/abs/{match.group(1)}"
        if url not in seen:
            seen.add(url)
            entries.append({"kind": "arxiv", "url": url, "page": None, "context": clean(full_text[max(0, match.start()-140):match.end()+140])})
    for page_index, page in enumerate(doc):
        for link in page.get_links():
            uri = link.get("uri")
            if uri and uri not in seen:
                seen.add(uri)
                entries.append({"kind": "pdf_annotation", "url": uri, "page": page_index + 1, "context": ""})
    return entries


def write_link_inventory(paper_dir: Path, raw_dir: Path, links: list[dict[str, Any]], metadata_note: dict[str, str]) -> list[dict[str, Any]]:
    github_links = [item for item in links if "github.com" in item.get("url", "").lower()]
    data = {
        "generated_at": date.today().isoformat(),
        "links": links,
        "github_or_artifact_candidates": github_links,
        "external_metadata_note": metadata_note,
        "artifact_status": "candidate links only; no repository was cloned or executed",
    }
    write(raw_dir / "artifact_link_inventory.json", json.dumps(data, ensure_ascii=False, indent=2))
    lines = ["Artifact / Link Inventory", "", f"External Metadata Source: {metadata_note.get('source_url', '') or '[NEEDS CITATION VERIFICATION]'}", f"Metadata Note: {metadata_note.get('notes', '')}", ""]
    if not links:
        lines.append("[NEEDS ARTIFACT] No URLs/DOIs/arXiv identifiers were extracted from the PDF text or annotations.")
    for item in links:
        lines.append(f"- {item.get('kind')}: {item.get('url')} page={item.get('page')} context={item.get('context', '')[:260]}")
    write(raw_dir / "artifact_link_inventory.txt", "\n".join(lines))
    return github_links


def update_agent_index(raw_dir: Path, paper_dir: Path, extra_units: list[dict[str, Any]], gaps_to_remove: list[str]) -> int:
    path = raw_dir / "agent_index.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    units = data.setdefault("evidence_units", [])
    seen_ids = {unit.get("id") for unit in units if isinstance(unit, dict)}
    for unit in extra_units:
        if unit["id"] not in seen_ids:
            units.append(unit)
            seen_ids.add(unit["id"])
    gaps = [str(item) for item in data.get("known_gaps", [])]
    filtered = []
    for gap in gaps:
        if any(marker in gap for marker in gaps_to_remove):
            continue
        filtered.append(gap)
    data["known_gaps"] = filtered
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return len(units)


def write_retrieval_map(analysis_dir: Path, paper_id: str) -> None:
    write(analysis_dir / "14_section_retrieval_map.txt", f"""Paper ID: {paper_id}

For Introduction:
- Read analysis/02_introduction.txt
- Read raw_extraction/section_text/*introduction*.txt
- Useful claims: problem framing and motivation only.
- Must not claim: exact numeric results without table/page-crop verification.

For Background / Motivation:
- Read analysis/03_background_motivation.txt
- Read raw_extraction/artifact_link_inventory.txt
- Useful claims: terminology and relation to affected versions / SZZ / commit or version validation.
- Must not claim: artifact availability unless a concrete URL or local source path is verified.

For Method:
- Read analysis/05_method.txt
- Read raw_extraction/layout_blocks/page_*_blocks.json
- Read raw_extraction/figures/figure_index_phase2.txt when present.
- Useful claims: pipeline shape and method components.
- Must not claim: runtime implementation behavior. [EXECUTION NOT REQUESTED]

For Experiments / Evaluation:
- Read analysis/06_experiments.txt and analysis/07_evaluation.txt
- Read raw_extraction/tables/table_index_phase2.txt and table page crops.
- Useful claims: RQ/evaluation structure and candidate metrics.
- Must not claim: final exact metrics until table values are manually checked against page crops.

For Limitations:
- Read analysis/08_limitations_ethics.txt
- Read analysis/13_completeness_audit.txt
- Useful claims: paper-stated limitations plus corpus extraction limitations.

For Related Work:
- Read analysis/11_relevance_to_our_paper.txt
- Read raw_extraction/references.txt
- Useful claims: positioning and comparison axes.
- Must not claim: verified bibliography metadata until citation verification is complete.
""")


def write_phase2_notes(
    analysis_dir: Path,
    paper_id: str,
    layout_blocks: int,
    table_units: int,
    figure_units: int,
    links: list[dict[str, Any]],
    github_links: list[dict[str, Any]],
    evidence_units: int,
    metadata_note: dict[str, str],
) -> None:
    table_status = "improved: PyMuPDF table candidates + page crops" if table_units else "still weak: no PyMuPDF tables detected [NEEDS TABLE REPAIR]"
    figure_status = "improved: page-crop+caption" if figure_units else "still weak: no figure caption/page crop detected [NEEDS FIGURE EXTRACTION]"
    artifact_status = "candidate GitHub/artifact URLs found; static URL inventory only" if github_links else "[NEEDS ARTIFACT] no GitHub/artifact URL confirmed"
    write(analysis_dir / "15_phase2_enhanced_findings.txt", f"""Paper ID: {paper_id}
Phase-2 Date: {date.today().isoformat()}

Enhancement Summary:
- Layout blocks extracted: {layout_blocks}
- Table evidence units added: {table_units}
- Figure/page-crop evidence units added: {figure_units}
- URL/DOI/arXiv/link entries found: {len(links)}
- GitHub/artifact candidate links found: {len(github_links)}
- Agent index evidence units after phase-2: {evidence_units}

Citation Metadata:
- External source: {metadata_note.get('source_url', '') or '[NEEDS CITATION VERIFICATION]'}
- Venue/year note: {metadata_note.get('venue_year', '[NEEDS CITATION VERIFICATION]')}
- Status: [NEEDS CITATION VERIFICATION] unless DOI/BibTeX is verified manually.

Table/Figure/Layout Readiness:
- Table readiness: {table_status}
- Figure readiness: {figure_status}
- Layout readiness: improved to partial because per-page text blocks with bboxes are available.

Artifact / Source Readiness:
- {artifact_status}
- No code was run, no dependency installed, no repository cloned, and no experiment reproduced. [EXECUTION NOT REQUESTED]

Writing Readiness After Phase-2:
- Related-work and motivation use: high
- Method framing use: medium-high when figure/page-crop evidence exists, otherwise medium
- Evaluation use: medium only when PyMuPDF table candidates exist; otherwise weak
- Exact numeric claims: blocked until manual table/page-crop verification
- Artifact/reproducibility claims: blocked until source/artifact is locally provided or explicitly fetched for static inspection

Remaining Gaps:
- [NEEDS TABLE REPAIR] for final numeric citation claims
- [NEEDS FIGURE EXTRACTION] for exact subfigure crops or visual-detail claims
- [NEEDS CITATION VERIFICATION] for DOI/BibTeX/venue
- [NEEDS ARTIFACT] for source, README, scripts, configs, datasets, result artifacts
- [EXECUTION NOT REQUESTED]
""")


def update_profile(raw_dir: Path, table_units: int, figure_units: int, layout_blocks: int, evidence_units: int) -> None:
    profile = read_text(raw_dir / "extraction_profile.txt")
    table_layer = "cells+csv/needs verification" if table_units else "missing"
    figure_layer = "page-crop+caption" if figure_units else "missing"
    layout_layer = "partial" if layout_blocks else "missing/not attempted"
    write(raw_dir / "extraction_profile.txt", profile.rstrip() + f"""

Phase-2 Enhancement:
Layout Block Layer: {layout_layer}
Table Layer: {table_layer}
Figure Layer: {figure_layer}
Agent Retrieval Usability: medium-high
Citation Readiness: medium for structural claims; low for exact numeric claims until manual verification
Agent Index Evidence Units After Phase-2: {evidence_units}
""")


def update_audit(analysis_dir: Path, layout_blocks: int, table_units: int, figure_units: int, links: int, evidence_units: int) -> None:
    audit = read_text(analysis_dir / "13_completeness_audit.txt")
    write(analysis_dir / "13_completeness_audit.txt", audit.rstrip() + f"""

Phase-2 Enhancement Audit:
- Layout blocks extracted: partial, {layout_blocks} text blocks with bboxes
- Table extraction: {'cells+csv/page-crop candidates, manual verification still needed' if table_units else 'missing/failed by PyMuPDF [NEEDS TABLE REPAIR]'}
- Figure extraction: {'page-crop+caption candidates' if figure_units else 'missing/failed by caption scan [NEEDS FIGURE EXTRACTION]'}
- URL/DOI/arXiv/link inventory: {links} entries
- Agent index evidence units after phase-2: {evidence_units}
- Runtime behavior: [EXECUTION NOT REQUESTED]
- Artifact/source status: [NEEDS ARTIFACT] unless artifact_link_inventory lists a verified candidate and the user requests static fetch/inspection
""")


def enhance_paper(paper_dir: Path) -> dict[str, Any]:
    raw_dir = paper_dir / "raw_extraction"
    analysis_dir = paper_dir / "analysis"
    metadata = load_metadata(raw_dir)
    pdf_path = Path(metadata.get("pdf_path", ""))
    if not pdf_path.exists():
        raise FileNotFoundError(f"PDF not found for {paper_dir.name}: {pdf_path}")
    metadata_note = WEB_METADATA.get(paper_dir.name, {"venue_year": "[NEEDS CITATION VERIFICATION]", "source_url": "", "notes": ""})
    if metadata_note.get("venue_year"):
        metadata["venue_year_phase2"] = metadata_note["venue_year"]
    if metadata_note.get("source_url"):
        metadata.setdefault("citation_verification_sources", [])
        if metadata_note["source_url"] not in metadata["citation_verification_sources"]:
            metadata["citation_verification_sources"].append(metadata_note["source_url"])
    metadata["citation_status"] = "partial_external_source_found_needs_verification"
    save_metadata(raw_dir, metadata)

    doc = fitz.open(str(pdf_path))
    try:
        layout_blocks = extract_layout_blocks(doc, raw_dir)
        table_units = enhance_tables(doc, paper_dir, raw_dir)
        figure_units = enhance_figures(doc, paper_dir, raw_dir)
        full_text = read_text(raw_dir / "full_text.txt")
        links = extract_links(doc, full_text)
        github_links = write_link_inventory(paper_dir, raw_dir, links, metadata_note)

        link_units: list[dict[str, Any]] = []
        if links:
            link_units.append({
                "id": f"{paper_dir.name}:artifact:artifact_link_inventory:phase2",
                "type": "artifact",
                "page": None,
                "section": "artifact_link_inventory",
                "topic": "URLs DOI arXiv GitHub candidates",
                "text_anchor": clean(" ".join(item.get("url", "") for item in links[:5]))[:220],
                "bbox": None,
                "files": ["raw_extraction/artifact_link_inventory.json", "raw_extraction/artifact_link_inventory.txt"],
                "confidence": "medium",
                "repair_needed": not bool(github_links),
                "usable_for": ["citation_verification", "artifact_followup", "related_work"],
                "do_not_use_for": ["local artifact behavior", "reproduced result"],
                "notes": "Static link inventory only. No URL was fetched by this script.",
            })
        citation_unit = {
            "id": f"{paper_dir.name}:reference:citation_metadata_phase2",
            "type": "reference",
            "page": None,
            "section": "citation_metadata",
            "topic": "phase2 citation metadata verification",
            "text_anchor": clean(f"{metadata_note.get('venue_year', '')} {metadata_note.get('source_url', '')}")[:220],
            "bbox": None,
            "files": ["raw_extraction/citation_metadata_verified.txt", "raw_extraction/metadata.json"],
            "confidence": "partial" if metadata_note.get("source_url") else "low",
            "repair_needed": True,
            "usable_for": ["citation_verification", "bibliography"],
            "do_not_use_for": ["final BibTeX without manual verification"],
            "notes": metadata_note.get("notes", ""),
        }
        write(raw_dir / "citation_metadata_verified.txt", f"""Paper ID: {paper_dir.name}
Phase-2 Citation Check Date: {date.today().isoformat()}
Candidate Venue / Year: {metadata_note.get('venue_year', '[NEEDS CITATION VERIFICATION]')}
External Source URL: {metadata_note.get('source_url', '') or '[NEEDS CITATION VERIFICATION]'}
Status: [NEEDS CITATION VERIFICATION]
Notes: {metadata_note.get('notes', '')}
""")

        evidence_units = update_agent_index(
            raw_dir,
            paper_dir,
            table_units + figure_units + link_units + [citation_unit],
            ["no layout blocks extracted"],
        )
        write_retrieval_map(analysis_dir, paper_dir.name)
        write_phase2_notes(analysis_dir, paper_dir.name, layout_blocks, len(table_units), len(figure_units), links, github_links, evidence_units, metadata_note)
        update_profile(raw_dir, len(table_units), len(figure_units), layout_blocks, evidence_units)
        update_audit(analysis_dir, layout_blocks, len(table_units), len(figure_units), len(links), evidence_units)

        return {
            "paper_id": paper_dir.name,
            "layout_blocks": layout_blocks,
            "table_units_added": len(table_units),
            "figure_units_added": len(figure_units),
            "links": len(links),
            "github_links": len(github_links),
            "evidence_units": evidence_units,
            "metadata_source": metadata_note.get("source_url", ""),
        }
    finally:
        doc.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase-2 enhance selected CitationAnalysis paper directories.")
    parser.add_argument("--reference-root", type=Path, required=True)
    parser.add_argument("--paper-ids", required=True, help="Comma-separated paper IDs")
    args = parser.parse_args()

    results = []
    for paper_id in [item.strip() for item in args.paper_ids.split(",") if item.strip()]:
        results.append(enhance_paper(args.reference_root / paper_id))
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
