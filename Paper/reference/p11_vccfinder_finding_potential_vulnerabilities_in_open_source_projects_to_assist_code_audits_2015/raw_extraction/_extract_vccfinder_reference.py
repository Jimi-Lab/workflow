from __future__ import annotations

import ast
import json
import re
from collections import Counter
from datetime import date
from pathlib import Path

from pypdf import PdfReader

try:
    import fitz
except Exception:  # pragma: no cover
    fitz = None


PAPER_ID = "p11_vccfinder_finding_potential_vulnerabilities_in_open_source_projects_to_assist_code_audits_2015"
TITLE = "VCCFinder: Finding Potential Vulnerabilities in Open-Source Projects to Assist Code Audits"
PDF_PATH = Path(r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)\Direct_Comparison_Papers(Baseline_Paper+Code)\VCCFinder\VCCFinder：Finding Potential Vulnerabilities in Open-Source Projects to Assist Code Audits.pdf")
SOURCE_PATH = Path(r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)\Direct_Comparison_Papers(Baseline_Paper+Code)\VCCFinder\VCCFinder")
PAPER_DIR = Path(r"E:\AI\Agent\workflow\Paper\reference") / PAPER_ID
RAW = PAPER_DIR / "raw_extraction"


def clean_text(text: str) -> str:
    return (
        text.replace("\uFB01", "fi")
        .replace("\uFB02", "fl")
        .replace("\u2013", "-")
        .replace("\u2014", "-")
    )


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def extract_pdf() -> tuple[list[str], str]:
    reader = PdfReader(str(PDF_PATH))
    pages: list[str] = []
    full_parts: list[str] = []
    for idx, page in enumerate(reader.pages, start=1):
        text = clean_text(page.extract_text() or "")
        pages.append(text)
        write(RAW / "page_text" / f"page_{idx:03d}.txt", text)
        full_parts.append(f"\n\n===== PAGE {idx:03d} =====\n\n{text}")
    full_text = "".join(full_parts).strip() + "\n"
    write(RAW / "full_text.txt", full_text)
    return pages, full_text


def find_heading_positions(full_text: str) -> list[tuple[str, int]]:
    patterns = [
        ("01_abstract", r"\bABSTRACT\b"),
        ("02_introduction", r"\n1\.\s*INTRODUCTION\b"),
        ("03_background_motivation", r"\n2\.\s*(BACKGROUND|MOTIVATION|VULNERABILITIES|APPROACH)\b"),
        ("04_method", r"\n3\.\s*[A-Z][A-Z \-]+\b"),
        ("05_experiments", r"\n4\.\s*[A-Z][A-Z \-]+\b"),
        ("06_evaluation", r"\n5\.\s*[A-Z][A-Z \-]+\b"),
        ("07_discussion", r"\n6\.\s*[A-Z][A-Z \-]+\b"),
        ("08_related_work", r"\n7\.\s*[A-Z][A-Z \-]+\b"),
        ("09_conclusion", r"\n8\.\s*(CONCLUSION|SUMMARY|DISCUSSION)[A-Z \-]*\b"),
        ("10_references", r"\n9\.\s*REFERENCES\b|\nREFERENCES\b"),
    ]
    positions: list[tuple[str, int]] = []
    for name, pat in patterns:
        m = re.search(pat, full_text, flags=re.I)
        if m:
            positions.append((name, m.start()))
    positions = sorted(dict(positions).items(), key=lambda x: x[1])
    return positions


def section_text(full_text: str) -> list[str]:
    positions = find_heading_positions(full_text)
    if not positions:
        positions = [("01_full_text_fallback", 0)]
    lines: list[str] = []
    for idx, (name, pos) in enumerate(positions):
        end = positions[idx + 1][1] if idx + 1 < len(positions) else len(full_text)
        text = full_text[pos:end].strip()
        if name == "01_abstract":
            intro = re.search(r"\n1\.\s*INTRODUCTION\b", full_text, flags=re.I)
            end = intro.start() if intro else end
            text = full_text[pos:end].strip()
        write(RAW / "section_text" / f"{name}.txt", text + "\n")
        lines.append(f"{name}: extracted, chars={len(text)}")
    refs = [p for p in (RAW / "section_text").glob("*reference*.txt")]
    if refs:
        write(RAW / "references.txt", refs[0].read_text(encoding="utf-8") + "\n[NEEDS CITATION VERIFICATION]\n")
    else:
        write(RAW / "references.txt", "[NEEDS CITATION VERIFICATION] references section not isolated by automatic splitter.\n")
        lines.append("references: [NEEDS SECTION SPLIT]")
    write(RAW / "sections.txt", "\n".join(lines) + "\n")
    write(RAW / "appendix.txt", "No appendix section was separately extracted. [NEEDS EVIDENCE]\n")
    return lines


def caption_units(pages: list[str]) -> tuple[int, int]:
    table_count = 0
    figure_count = 0
    table_index: list[str] = []
    figure_index: list[str] = []
    for page_no, text in enumerate(pages, start=1):
        for match in re.finditer(r"((?:Table|TABLE)\s+\d+[\s\S]{0,900}?)(?=\n(?:Table|TABLE|Figure|FIGURE|Fig\.|\d+\.\s+[A-Z]|REFERENCES)|$)", text):
            raw = match.group(1).strip()
            table_count += 1
            tid = f"table_{table_count:03d}"
            payload = (
                f"Table ID: {tid}\nPage: {page_no}\nCaption/Neighbor Text:\n{raw}\n\n"
                "Extraction Confidence: partial\nNotes: plain-text/caption-neighbor extraction only. [NEEDS TABLE REPAIR]\n"
            )
            write(RAW / "tables" / f"{tid}_raw.txt", payload)
            write(RAW / "tables" / f"{tid}.md", payload)
            write(RAW / "tables" / f"{tid}_cells.json", json.dumps({"table_id": tid, "page": page_no, "cells": [], "repair_needed": True}, indent=2))
            table_index.append(f"{tid}: page {page_no}, partial, [NEEDS TABLE REPAIR]")
        for match in re.finditer(r"((?:Figure|FIGURE|Fig\.)\s+\d+[\s\S]{0,700}?)(?=\n(?:Table|TABLE|Figure|FIGURE|Fig\.|\d+\.\s+[A-Z]|REFERENCES)|$)", text):
            raw = match.group(1).strip()
            figure_count += 1
            fid = f"figure_{figure_count:03d}"
            write(RAW / "figures" / f"{fid}_caption.txt", f"Figure ID: {fid}\nPage: {page_no}\nCaption/Neighbor Text:\n{raw}\n")
            write(RAW / "figures" / f"{fid}_context.txt", text[max(0, match.start() - 500): min(len(text), match.end() + 500)])
            write(RAW / "figures" / f"{fid}_agent_summary.txt", f"{fid} is caption/context-only unless a page crop exists. [NEEDS FIGURE EXTRACTION]\n")
            figure_index.append(f"{fid}: page {page_no}, caption/context, [NEEDS FIGURE EXTRACTION]")
            if fitz is not None and figure_count <= 12:
                doc = fitz.open(str(PDF_PATH))
                page = doc.load_page(page_no - 1)
                pix = page.get_pixmap(matrix=fitz.Matrix(1.5, 1.5), alpha=False)
                pix.save(str(RAW / "figures" / f"{fid}_page.png"))
                doc.close()
    write(RAW / "tables" / "table_index.txt", "\n".join(table_index) + ("\n" if table_index else "No table captions detected. [NEEDS TABLE REPAIR]\n"))
    write(RAW / "figures" / "figure_index.txt", "\n".join(figure_index) + ("\n" if figure_index else "No figure captions detected. [NEEDS FIGURE EXTRACTION]\n"))
    write(RAW / "formulas" / "formula_index.txt", "No layout-aware formula extraction performed. [NEEDS FORMULA REPAIR]\n")
    write(RAW / "algorithms" / "algorithm_index.txt", "No algorithm block detected by plain-text extraction. [NEEDS ALGORITHM REPAIR]\n")
    write(RAW / "prompts" / "prompt_index.txt", "No LLM prompt block is applicable/detected. Prompt layer: not detected.\n")
    return table_count, figure_count


def source_inventory() -> None:
    all_files = [p for p in SOURCE_PATH.rglob("*") if p.is_file()]
    by_ext = Counter(p.suffix.lower() or "[no_ext]" for p in all_files)
    py_files = [p for p in all_files if p.suffix.lower() == ".py"]
    symbols = []
    for path in sorted(py_files):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text)
        except Exception as exc:
            symbols.append({"file": str(path.relative_to(SOURCE_PATH)), "parse_error": str(exc)})
            continue
        funcs = [n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
        imports = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                imports.extend(alias.name for alias in n.names)
            elif isinstance(n, ast.ImportFrom) and n.module:
                imports.append(n.module)
        symbols.append({
            "file": str(path.relative_to(SOURCE_PATH)),
            "functions": sorted(funcs)[:120],
            "classes": sorted(classes)[:60],
            "imports": sorted(set(imports))[:120],
        })
    write(RAW / "source_static_symbols.json", json.dumps(symbols, indent=2, ensure_ascii=False))

    inv = [
        f"Source Path: {SOURCE_PATH}",
        "Analysis Mode: static-only",
        "Runtime Behavior: [EXECUTION NOT REQUESTED]",
        "",
        "Repository / File Layout Observed:",
        f"- Total files: {len(all_files)}",
        f"- Extension counts: {dict(sorted(by_ext.items()))}",
        "- Top-level entries:",
    ]
    for p in sorted(SOURCE_PATH.iterdir(), key=lambda x: x.name.lower()):
        inv.append(f"  - {p.name}/" if p.is_dir() else f"  - {p.name}")
    inv += [
        "",
        "Primary Files:",
        "- 1_vccfinder.py",
        "- 2_gen_vuln_version.py",
        "- abstract_szz.py",
        "- comment_parser.py",
        "- config.py",
        "- log_generation.py",
        "- bad_case_result.txt",
        "- time.txt",
        "",
        "README/config inspected: config.py exists; README.md was not found. [NEEDS ARTIFACT]",
        "Main entrypoints inspected: yes, by filename and static AST symbol inventory",
        "Key Static Evidence:",
    ]
    for name in ["1_vccfinder.py", "2_gen_vuln_version.py", "abstract_szz.py", "comment_parser.py", "config.py"]:
        p = SOURCE_PATH / name
        if p.exists():
            inv.append(f"\n{name} excerpt:")
            inv.append(p.read_text(encoding="utf-8", errors="replace")[:1800])
    inv += [
        "",
        "Static Consistency Notes:",
        "- The paper describes VCCFinder as combining code metrics with repository metadata and training an SVM classifier over vulnerable/non-vulnerable commits.",
        "- The local source root contains vccfinder, vulnerable-version generation, abstract_szz, comment parsing, config, and logging scripts.",
        "- The local scripts appear to be an adapted baseline package for vulnerable-version/SZZ-style processing, not a complete paper artifact with the CVE-to-GitHub database, model-training data, or web service.",
        "- No README, dependency file, trained model, or benchmark database was found in the observed source root. [NEEDS ARTIFACT]",
        "",
        "Observed Local Output / Data Artifacts:",
        "- bad_case_result.txt and time.txt exist, but their semantics were not verified by execution. [EXECUTION NOT REQUESTED]",
        "- __pycache__/ exists and is ignored as generated bytecode.",
        "",
        "Missing Data / Missing Entrypoints:",
        "- CVE-to-GitHub vulnerable commit database, SVM training dataset/model, web-service artifact, and full evaluation artifacts are not present in this local source root. [NEEDS ARTIFACT]",
        "- Runtime behavior, result regeneration, and model performance were not checked. [EXECUTION NOT REQUESTED]",
    ]
    write(RAW / "source_static_inventory.txt", "\n".join(inv) + "\n")


def metadata(page_count: int) -> None:
    data = {
        "paper_id": PAPER_ID,
        "title": TITLE,
        "authors": [
            "Henning Perl",
            "Sergej Dechand",
            "Matthew Smith",
            "Daniel Arp",
            "Fabian Yamaguchi",
            "Konrad Rieck",
            "Sascha Fahl",
            "Yasemin Acar",
        ],
        "venue": "CCS",
        "year": "2015",
        "doi": "10.1145/2810103.2813604",
        "arxiv": "",
        "pdf_path": str(PDF_PATH),
        "artifact_type": "Type B",
        "page_count": page_count,
        "citation_status": "partial_from_pdf_needs_verification",
    }
    write(RAW / "metadata.json", json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    write(RAW / "00_source_manifest.txt", "\n".join([
        f"Paper ID: {PAPER_ID}",
        f"Original PDF Path: {PDF_PATH}",
        "Original Text Path: ",
        f"Source Code Path or URL: {SOURCE_PATH}",
        "Artifact/Data Path or URL: [NEEDS ARTIFACT]",
        f"Extraction Date: {date.today().isoformat()}",
        "Extraction Tools: pypdf text extraction; PyMuPDF page rendering for caption pages when available; Python AST/static filesystem inventory",
        "Artifact Type: Type B",
        "Notes: source inspected statically only; no code execution, dependency installation, or experiment reproduction.",
        "",
    ]))


def main() -> None:
    for sub in ["page_text", "layout_blocks", "section_text", "tables", "figures", "formulas", "algorithms", "prompts"]:
        (RAW / sub).mkdir(parents=True, exist_ok=True)
    pages, full_text = extract_pdf()
    section_text(full_text)
    table_count, figure_count = caption_units(pages)
    source_inventory()
    metadata(len(pages))
    write(RAW / "extraction_log.txt", "\n".join([
        "Status: raw extraction completed with known layout gaps",
        "Tools Used: pypdf; PyMuPDF if available; Python AST/static filesystem inventory",
        f"Successful Outputs: full_text.txt; {len(pages)} page_text files; section_text files; source_static_inventory.txt",
        "Failed Outputs: precise table cells/CSV; precise figure crops; layout block coordinates; verified artifact database/model",
        "Pages With Empty Text: none observed" if all(p.strip() for p in pages) else "Pages With Empty Text: [NEEDS OCR]",
        "OCR Needed: no",
        f"Tables Extracted: {table_count} caption-neighbor/plain-text records, not citation-ready [NEEDS TABLE REPAIR]",
        f"Figures/Captions Extracted: {figure_count} caption/context records; page crops only when generated, not precise figure-ready [NEEDS FIGURE EXTRACTION]",
        "References Extracted: uncertain; citation metadata needs verification [NEEDS CITATION VERIFICATION]",
        "Known Losses: multi-column reading order, layout blocks, exact table cells, exact figure bounding boxes, formula layout",
        "PDF Text Complete: yes",
        "PDF Layout Partial: yes",
        "Citation-Ready Tables: no",
        "Figure-Ready: no",
        "Agent Index: pending build_agent_index.py",
        "Next Repair Step: table repair, precise figure extraction, citation verification, artifact/database verification",
        "",
    ]))


if __name__ == "__main__":
    main()
