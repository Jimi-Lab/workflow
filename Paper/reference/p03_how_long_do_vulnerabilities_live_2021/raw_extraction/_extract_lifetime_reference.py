from __future__ import annotations

import ast
import csv
import json
import os
import re
from datetime import datetime
from pathlib import Path

from pypdf import PdfReader


PAPER_ID = "p03_how_long_do_vulnerabilities_live_2021"
TITLE = "How Long Do Vulnerabilities Live in the Code? A Large-Scale Empirical Measurement Study on FOSS Vulnerability Lifetimes"
YEAR = "2021"
ROOT = Path(r"E:\AI\Agent\workflow\Paper\reference") / PAPER_ID
RAW = ROOT / "raw_extraction"
ANALYSIS = ROOT / "analysis"
INPUT_ROOT = Path(r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)\Direct_Comparison_Papers(Baseline_Paper+Code)\Lifetime")
SOURCE = INPUT_ROOT / "Lifetime"


def long_path(path: Path) -> str:
    text = str(path)
    if os.name == "nt" and not text.startswith("\\\\?\\"):
        return "\\\\?\\" + text
    return text


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def read(path: Path, limit: int | None = None) -> str:
    data = Path(long_path(path)).read_text(encoding="utf-8", errors="replace")
    return data if limit is None else data[:limit]


def stable_id(text: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "_", text.strip().lower()).strip("_")
    return text[:60] or "unit"


def find_pdf() -> Path:
    pdfs = list(INPUT_ROOT.glob("*.pdf"))
    if len(pdfs) != 1:
        raise RuntimeError(f"expected one PDF, found {len(pdfs)}")
    return pdfs[0]


def extract_pdf(pdf: Path) -> dict:
    reader = PdfReader(long_path(pdf))
    page_text_dir = RAW / "page_text"
    page_text_dir.mkdir(parents=True, exist_ok=True)
    pages = []
    empty_pages = []
    for idx, page in enumerate(reader.pages, 1):
        text = page.extract_text() or ""
        if not text.strip():
            empty_pages.append(idx)
        pages.append(text)
        write(page_text_dir / f"page_{idx:03d}.txt", text)
    full_parts = [f"===== PAGE {idx:03d} =====\n{text}" for idx, text in enumerate(pages, 1)]
    write(RAW / "full_text.txt", "\n\n".join(full_parts))
    metadata = reader.metadata or {}
    return {
        "page_count": len(reader.pages),
        "empty_pages": empty_pages,
        "metadata": {str(k): str(v) for k, v in metadata.items()},
        "pages": pages,
    }


SECTION_RANGES = [
    ("01_abstract.txt", "Abstract", r"(?m)^Abstract$", r"(?m)^1 Introduction$"),
    ("02_introduction.txt", "1 Introduction", r"(?m)^1 Introduction$", r"(?m)^2 Related work and background$"),
    ("03_background.txt", "2 Related work and background", r"(?m)^2 Related work and background$", r"(?m)^3 Dataset creation$"),
    ("04_method.txt", "3 Dataset creation / 4 Lifetime estimation", r"(?m)^3 Dataset creation$", r"(?m)^5 Results$"),
    ("05_experiments.txt", "5 Results", r"(?m)^5 Results$", r"(?m)^6 Implications and discussion$"),
    ("06_evaluation.txt", "6 Implications and discussion", r"(?m)^6 Implications and discussion$", r"(?m)^7 Threats to validity$"),
    ("08_limitations.txt", "7 Threats to validity", r"(?m)^7 Threats to validity$", r"(?m)^8 Conclusion$"),
    ("07_related_work.txt", "Related work subsection", r"(?m)^2\.1 Related work on vulnerability measure-", r"(?m)^2\.2 Vulnerability lifetimes in version control$"),
    ("09_references.txt", "References", r"(?m)^References$", r"$^"),
]


def split_sections(full_text: str) -> list[dict]:
    section_dir = RAW / "section_text"
    section_dir.mkdir(parents=True, exist_ok=True)
    sections = []
    for filename, label, start_pattern, end_pattern in SECTION_RANGES:
        start = re.search(start_pattern, full_text, re.IGNORECASE | re.MULTILINE)
        if not start:
            sections.append({"label": label, "file": filename, "status": "[NEEDS SECTION SPLIT]"})
            continue
        end = re.search(end_pattern, full_text[start.end():], re.IGNORECASE | re.MULTILINE)
        end_pos = start.end() + end.start() if end else len(full_text)
        body = full_text[start.start():end_pos].strip()
        write(section_dir / filename, body)
        sections.append({"label": label, "file": f"section_text/{filename}", "status": "extracted", "chars": len(body)})
    lines = ["Section Split Status: heuristic from extracted PDF text", ""]
    for s in sections:
        lines.append(f"- {s['label']}: {s['status']} -> {s.get('file', '')} chars={s.get('chars', '')}")
    write(RAW / "sections.txt", "\n".join(lines) + "\n")
    ref_path = section_dir / "09_references.txt"
    if ref_path.exists():
        write(RAW / "references.txt", ref_path.read_text(encoding="utf-8"))
    else:
        write(RAW / "references.txt", "[NEEDS CITATION VERIFICATION]\n")
    return sections


def extract_caption_units(pages: list[str]) -> tuple[list[dict], list[dict]]:
    fig_dir = RAW / "figures"
    tab_dir = RAW / "tables"
    fig_dir.mkdir(parents=True, exist_ok=True)
    tab_dir.mkdir(parents=True, exist_ok=True)
    figures = []
    tables = []
    for page_no, text in enumerate(pages, 1):
        compact = re.sub(r"\s+", " ", text)
        for m in re.finditer(r"(Figure\s+\d+:\s+.{20,260}?)(?=(?:Figure\s+\d+:|Table\s+\d+:| [A-Z][a-z]+ \d|$))", compact):
            cap = m.group(1).strip()
            fid = f"figure_{len(figures)+1:03d}"
            write(fig_dir / f"{fid}_caption.txt", cap + "\n")
            write(fig_dir / f"{fid}_context.txt", compact[max(0, m.start()-350):m.end()+350] + "\n")
            write(fig_dir / f"{fid}_agent_summary.txt", f"Caption-only evidence. [NEEDS FIGURE EXTRACTION]\nCaption: {cap}\n")
            figures.append({"id": fid, "page": page_no, "caption": cap})
        for m in re.finditer(r"(Table\s+\d+:\s+.{20,300}?)(?=(?:Figure\s+\d+:|Table\s+\d+:| [A-Z][a-z]+ \d|$))", compact):
            cap = m.group(1).strip()
            tid = f"table_{len(tables)+1:03d}"
            raw = compact[max(0, m.start()-400):m.end()+600]
            write(tab_dir / f"{tid}_raw.txt", raw + "\n[NEEDS TABLE REPAIR]\n")
            write(tab_dir / f"{tid}.md", f"| Field | Value |\n| --- | --- |\n| Page | {page_no} |\n| Caption | {cap} |\n| Status | caption/context only; [NEEDS TABLE REPAIR] |\n")
            with (tab_dir / f"{tid}.csv").open("w", encoding="utf-8", newline="") as fh:
                writer = csv.writer(fh)
                writer.writerow(["field", "value"])
                writer.writerow(["page", page_no])
                writer.writerow(["caption", cap])
                writer.writerow(["status", "[NEEDS TABLE REPAIR]"])
            write(tab_dir / f"{tid}_cells.json", json.dumps({"page": page_no, "caption": cap, "cells": [], "repair_needed": True}, indent=2))
            tables.append({"id": tid, "page": page_no, "caption": cap})
    write(fig_dir / "figure_index.txt", "\n".join(f"- {f['id']}: page {f['page']}; {f['caption']} [NEEDS FIGURE EXTRACTION]" for f in figures) + "\n")
    write(tab_dir / "table_index.txt", "\n".join(f"- {t['id']}: page {t['page']}; {t['caption']} [NEEDS TABLE REPAIR]" for t in tables) + "\n")
    return figures, tables


def inspect_source() -> dict:
    files = []
    dirs = []
    for path in SOURCE.rglob("*"):
        rel = path.relative_to(SOURCE)
        if ".git" in rel.parts or "__pycache__" in rel.parts:
            continue
        if path.is_dir():
            dirs.append(str(rel))
        else:
            files.append({"path": str(rel), "size": path.stat().st_size, "ext": path.suffix.lower()})
    py_summaries = []
    for item in files:
        if item["ext"] != ".py":
            continue
        path = SOURCE / item["path"]
        text = read(path)
        try:
            tree = ast.parse(text)
            funcs = [n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
            imports = []
            for n in ast.walk(tree):
                if isinstance(n, ast.Import):
                    imports.extend(alias.name for alias in n.names)
                elif isinstance(n, ast.ImportFrom):
                    imports.append(n.module or "")
            py_summaries.append({
                "path": item["path"],
                "functions": funcs[:30],
                "classes": classes[:20],
                "imports": sorted(set(i for i in imports if i))[:30],
                "lines": text.count("\n") + 1,
            })
        except SyntaxError as exc:
            py_summaries.append({"path": item["path"], "parse_error": str(exc)})
    samples = {}
    for name in ["README.md", "config.py", "time.txt", "bad_case_result.txt"]:
        path = SOURCE / name
        if path.exists():
            samples[name] = read(path, 4000)
    inventory = {"source_path": str(SOURCE), "directories": dirs, "files": files, "python": py_summaries, "samples": samples}
    write(RAW / "source_static_inventory.json", json.dumps(inventory, indent=2, ensure_ascii=False))
    lines = [
        f"Source Path: {SOURCE}",
        "Analysis Mode: static-only",
        "Runtime Behavior: [EXECUTION NOT REQUESTED]",
        "",
        "Repository / File Layout Observed:",
    ]
    for d in dirs[:80]:
        lines.append(f"- dir: {d}")
    for item in files[:160]:
        lines.append(f"- file: {item['path']} ({item['size']} bytes)")
    lines += ["", "Primary Files:"]
    for p in py_summaries:
        lines.append(f"- {p['path']}: lines={p.get('lines', '[NEEDS EVIDENCE]')}; functions={', '.join(p.get('functions', [])[:12]) or '[NEEDS EVIDENCE]'}; imports={', '.join(p.get('imports', [])[:10]) or '[NEEDS EVIDENCE]'}")
    lines += [
        "",
        "Key Static Evidence:",
        "- Python scripts are visible for lifetime analysis, affected-version generation, continued-block discovery, logging, and orchestration.",
        "- Local data/output directories are visible: affected_version, tmp, vccs_output.",
        "- README.md is minimal and does not provide full reproduction instructions.",
        "- JSON/text artifacts are present, including continue_added_block_cve_dict.json, bad_case_result.txt, and time.txt.",
        "",
        "Static Consistency Notes:",
        "- The artifact appears aligned with vulnerability lifetime / affected-version processing by file names and script names.",
        "- Exact reproduction of paper results is not checked. [EXECUTION NOT REQUESTED]",
        "- Dataset completeness and mapping to all paper experiments require artifact verification. [NEEDS ARTIFACT]",
        "",
        "Observed Local Output / Data Artifacts:",
    ]
    for item in files:
        if item["ext"] in [".json", ".txt", ".csv"]:
            lines.append(f"- {item['path']} ({item['size']} bytes)")
    lines += ["", "Missing Data / Missing Entrypoints:", "- Full environment/dependency manifest not visible. [NEEDS ARTIFACT]", "- Runtime outputs not regenerated. [EXECUTION NOT REQUESTED]"]
    write(RAW / "source_static_inventory.txt", "\n".join(lines) + "\n")
    return inventory


def write_manifest_metadata(pdf: Path, pdf_info: dict) -> None:
    write(RAW / "00_source_manifest.txt", f"""Paper ID: {PAPER_ID}
Original PDF Path: {pdf}
Original Text Path: {RAW / 'full_text.txt'}
Source Code Path or URL: {SOURCE}
Artifact/Data Path or URL: {SOURCE}
Extraction Date: {datetime.now().isoformat(timespec='seconds')}
Extraction Tools: pypdf text extraction; Python static AST/file inventory
Artifact Type: Type A
Notes: Static analysis only; no dependency installation, code execution, or experiment reproduction.
""")
    metadata = {
        "paper_id": PAPER_ID,
        "title": TITLE,
        "authors": ["Nikolaos Alexopoulos", "Manuel Brack", "Jan Philipp Wagner", "Tim Grube", "Max Mühlhäuser"],
        "venue": "",
        "year": YEAR,
        "doi": "",
        "arxiv": "",
        "pdf_path": str(pdf),
        "source_path": str(SOURCE),
        "artifact_type": "Type A",
        "page_count": pdf_info["page_count"],
        "citation_status": "unverified",
        "pdf_metadata": pdf_info["metadata"],
    }
    write(RAW / "metadata.json", json.dumps(metadata, indent=2, ensure_ascii=False))


def write_logs(pdf_info: dict, sections: list[dict], figs: list[dict], tabs: list[dict]) -> None:
    write(RAW / "extraction_log.txt", f"""Status: partial-success
Tools Used: pypdf; Python static AST/file inventory
Successful Outputs: full_text.txt, page_text/*.txt, sections.txt, section_text/*.txt, references.txt, caption/context table and figure indexes, source_static_inventory.txt
Failed Outputs: verified layout blocks, verified table cells, figure image crops, citation metadata verification
Pages With Empty Text: {pdf_info['empty_pages'] or 'none'}
OCR Needed: no
Tables Extracted: {len(tabs)} caption/context records; [NEEDS TABLE REPAIR]
Figures/Captions Extracted: {len(figs)} caption/context records; [NEEDS FIGURE EXTRACTION]
References Extracted: yes, from text layer; [NEEDS CITATION VERIFICATION]
Known Losses: multi-column order may be imperfect; table cells and figure images are not citation-ready; formulas may lose layout.
Next Repair Step: run a layout/table/figure extraction pass if exact numeric table claims or figure reuse is required.
PDF Text Complete: yes
PDF Layout Partial: yes
Citation-Ready Tables: no
Figure-Ready: no
Agent Index: partial
""")
    write(RAW / "extraction_profile.txt", f"""Primary Consumer: agent
PDF Text Layer: complete
Layout Block Layer: missing/not attempted
Table Layer: caption/context-only
Figure Layer: caption-only
Formula Layer: not attempted
Algorithm Layer: not attempted
Prompt Layer: not detected
Known Ordering Losses: pypdf text from a multi-column paper may have imperfect reading order.
Known Layout Losses: tables, equations, and figure images are not layout-verified.
Agent Retrieval Usability: medium
Citation Readiness: low
Next Repair Step: [NEEDS TABLE REPAIR], [NEEDS FIGURE EXTRACTION], [NEEDS LAYOUT BLOCK EXTRACTION], [NEEDS CITATION VERIFICATION]
""")


def seed_agent_index(sections: list[dict], figs: list[dict], tabs: list[dict]) -> None:
    units = []
    for s in sections:
        if s["status"] != "extracted":
            units.append({
                "id": f"{PAPER_ID}:gap:{stable_id(s['label'])}",
                "type": "gap",
                "page": None,
                "section": s["label"],
                "topic": "section split gap",
                "text_anchor": s["status"],
                "bbox": None,
                "files": ["sections.txt"],
                "confidence": "low",
                "repair_needed": True,
                "usable_for": ["repair"],
                "do_not_use_for": ["paper claim", "exact numeric claim"],
                "notes": "[NEEDS SECTION SPLIT]",
            })
            continue
        units.append({
            "id": f"{PAPER_ID}:section:{stable_id(s['label'])}",
            "type": "section",
            "page": None,
            "section": s["label"],
            "topic": s["label"],
            "text_anchor": s["label"],
            "bbox": None,
            "files": ["full_text.txt", s["file"]],
            "confidence": "medium",
            "repair_needed": False,
            "usable_for": ["abstract", "introduction", "method", "evaluation", "limitations", "related_work"],
            "do_not_use_for": ["exact numeric claim without page/PDF verification"],
            "notes": "Heuristic section split from PDF text layer.",
        })
    for f in figs:
        units.append({
            "id": f"{PAPER_ID}:figure:{f['id']}",
            "type": "figure",
            "page": f["page"],
            "section": None,
            "topic": "figure caption",
            "text_anchor": f["caption"][:120],
            "bbox": None,
            "files": [f"figures/{f['id']}_caption.txt", f"figures/{f['id']}_context.txt"],
            "confidence": "partial",
            "repair_needed": True,
            "usable_for": ["method", "evaluation"],
            "do_not_use_for": ["figure reuse", "visual detail claim"],
            "notes": "[NEEDS FIGURE EXTRACTION]",
        })
    for t in tabs:
        units.append({
            "id": f"{PAPER_ID}:table:{t['id']}",
            "type": "table",
            "page": t["page"],
            "section": None,
            "topic": "table caption/context",
            "text_anchor": t["caption"][:120],
            "bbox": None,
            "files": [f"tables/{t['id']}_raw.txt", f"tables/{t['id']}.md", f"tables/{t['id']}.csv"],
            "confidence": "partial",
            "repair_needed": True,
            "usable_for": ["evaluation"],
            "do_not_use_for": ["citation-ready numeric claim"],
            "notes": "[NEEDS TABLE REPAIR]",
        })
    units.append({
        "id": f"{PAPER_ID}:artifact:source_static_inventory",
        "type": "artifact",
        "page": None,
        "section": "source artifact",
        "topic": "static source inventory",
        "text_anchor": "static-only source inventory",
        "bbox": None,
        "files": ["source_static_inventory.txt", "source_static_inventory.json"],
        "confidence": "medium",
        "repair_needed": False,
        "usable_for": ["method", "reproducibility", "artifact_consistency"],
        "do_not_use_for": ["runtime behavior", "reproduced result claim"],
        "notes": "[EXECUTION NOT REQUESTED]",
    })
    index = {
        "paper_id": PAPER_ID,
        "title": TITLE,
        "source_manifest": "00_source_manifest.txt",
        "extraction_profile": "extraction_profile.txt",
        "evidence_units": units,
        "known_gaps": [
            "[NEEDS TABLE REPAIR]",
            "[NEEDS FIGURE EXTRACTION]",
            "[NEEDS LAYOUT BLOCK EXTRACTION]",
            "[NEEDS CITATION VERIFICATION]",
            "[EXECUTION NOT REQUESTED]",
        ],
    }
    write(RAW / "agent_index.json", json.dumps(index, indent=2, ensure_ascii=False))


def main() -> None:
    pdf = find_pdf()
    for sub in ["page_text", "section_text", "tables", "figures", "formulas", "algorithms", "prompts", "layout_blocks"]:
        (RAW / sub).mkdir(parents=True, exist_ok=True)
    pdf_info = extract_pdf(pdf)
    full_text = (RAW / "full_text.txt").read_text(encoding="utf-8")
    sections = split_sections(full_text)
    figs, tabs = extract_caption_units(pdf_info["pages"])
    inspect_source()
    write_manifest_metadata(pdf, pdf_info)
    write_logs(pdf_info, sections, figs, tabs)
    seed_agent_index(sections, figs, tabs)
    write(RAW / "appendix.txt", "[NEEDS EVIDENCE] No appendix was separately extracted from the PDF text layer.\n")
    write(RAW / "formulas" / "formula_index.txt", "[NEEDS FORMULA REPAIR] Formula extraction was not attempted as a layout-aware pass.\n")
    write(RAW / "algorithms" / "algorithm_index.txt", "[NEEDS ALGORITHM REPAIR] Algorithm/pseudocode extraction was not confirmed by layout-aware parsing.\n")
    write(RAW / "prompts" / "prompt_index.txt", "Prompt Layer: not detected in text extraction.\n")
    write(RAW / "layout_blocks" / "layout_status.txt", "[NEEDS LAYOUT BLOCK EXTRACTION] Layout blocks were not extracted in this static pass.\n")


if __name__ == "__main__":
    main()
